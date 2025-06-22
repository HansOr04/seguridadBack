import { Asset } from '../models/Asset';
import { IAsset, PaginationOptions, ApiResponse } from '../types';
import { AppError } from '../middleware/errorHandler';
import logger from '../utils/logger';

export class AssetService {
  // Crear nuevo activo
  async createAsset(assetData: Partial<IAsset>): Promise<IAsset> {
    try {
      // Verificar si el código ya existe
      const existingAsset = await Asset.findOne({ codigo: assetData.codigo });
      if (existingAsset) {
        throw new AppError('El código de activo ya existe', 400);
      }

      const asset = new Asset(assetData);
      await asset.save();
      
      logger.info(`Activo creado: ${asset.codigo}`);
      return asset;
    } catch (error) {
      logger.error('Error creando activo:', error);
      throw error;
    }
  }

  // Obtener lista paginada de activos
  async getAssets(options: PaginationOptions): Promise<{
    assets: IAsset[];
    pagination: any;
  }> {
    try {
      const { page = 1, limit = 10, sort = '-fechaCreacion', filter = {} } = options;
      
      const skip = (page - 1) * limit;
      
      // Construir filtros
      const query: any = {};
      if (filter.tipo) query.tipo = filter.tipo;
      if (filter.propietario) query.propietario = new RegExp(filter.propietario, 'i');
      if (filter.search) {
        query.$or = [
          { nombre: new RegExp(filter.search, 'i') },
          { codigo: new RegExp(filter.search, 'i') },
          { categoria: new RegExp(filter.search, 'i') }
        ];
      }

      const [assets, total] = await Promise.all([
        Asset.find(query)
          .populate('dependencias', 'codigo nombre')
          .sort(sort)
          .skip(skip)
          .limit(limit)
          .lean(),
        Asset.countDocuments(query)
      ]);

      return {
        assets: assets as IAsset[],
        pagination: {
          page,
          limit,
          total,
          pages: Math.ceil(total / limit)
        }
      };
    } catch (error) {
      logger.error('Error obteniendo activos:', error);
      throw error;
    }
  }

  // Obtener activo por ID
  async getAssetById(id: string): Promise<IAsset> {
    try {
      const asset = await Asset.findById(id)
        .populate('dependencias', 'codigo nombre tipo')
        .lean();

      if (!asset) {
        throw new AppError('Activo no encontrado', 404);
      }

      return asset as IAsset;
    } catch (error) {
      logger.error(`Error obteniendo activo ${id}:`, error);
      throw error;
    }
  }

  // Actualizar activo
  async updateAsset(id: string, updateData: Partial<IAsset>): Promise<IAsset> {
    try {
      // Si se está actualizando el código, verificar que no exista
      if (updateData.codigo) {
        const existingAsset = await Asset.findOne({ 
          codigo: updateData.codigo, 
          _id: { $ne: id } 
        });
        if (existingAsset) {
          throw new AppError('El código de activo ya existe', 400);
        }
      }

      const asset = await Asset.findByIdAndUpdate(
        id,
        { ...updateData, fechaActualizacion: new Date() },
        { new: true, runValidators: true }
      ).populate('dependencias', 'codigo nombre');

      if (!asset) {
        throw new AppError('Activo no encontrado', 404);
      }

      logger.info(`Activo actualizado: ${asset.codigo}`);
      return asset;
    } catch (error) {
      logger.error(`Error actualizando activo ${id}:`, error);
      throw error;
    }
  }

  // Eliminar activo
  async deleteAsset(id: string): Promise<void> {
    try {
      // Verificar si hay dependencias
      const dependentAssets = await Asset.find({ dependencias: id });
      if (dependentAssets.length > 0) {
        throw new AppError(
          `No se puede eliminar el activo. ${dependentAssets.length} activos dependen de él`,
          400
        );
      }

      const asset = await Asset.findByIdAndDelete(id);
      if (!asset) {
        throw new AppError('Activo no encontrado', 404);
      }

      logger.info(`Activo eliminado: ${asset.codigo}`);
    } catch (error) {
      logger.error(`Error eliminando activo ${id}:`, error);
      throw error;
    }
  }

  // Obtener estadísticas de activos
  async getAssetStats(): Promise<any> {
    try {
      const stats = await Asset.aggregate([
        {
          $group: {
            _id: null,
            totalActivos: { $sum: 1 },
            valorTotalEconomico: { $sum: '$valorEconomico' },
            criticidadPromedio: {
              $avg: {
                $max: [
                  '$valoracion.confidencialidad',
                  '$valoracion.integridad',
                  '$valoracion.disponibilidad',
                  '$valoracion.autenticidad',
                  '$valoracion.trazabilidad'
                ]
              }
            }
          }
        }
      ]);

      const tipoStats = await Asset.aggregate([
        {
          $group: {
            _id: '$tipo',
            count: { $sum: 1 },
            valorTotal: { $sum: '$valorEconomico' }
          }
        }
      ]);

      const criticidadStats = await Asset.aggregate([
        {
          $project: {
            criticidad: {
              $max: [
                '$valoracion.confidencialidad',
                '$valoracion.integridad',
                '$valoracion.disponibilidad',
                '$valoracion.autenticidad',
                '$valoracion.trazabilidad'
              ]
            }
          }
        },
        {
          $bucket: {
            groupBy: '$criticidad',
            boundaries: [0, 3, 6, 8, 10, 11],
            default: 'Otros',
            output: {
              count: { $sum: 1 }
            }
          }
        }
      ]);

      return {
        general: stats[0] || { totalActivos: 0, valorTotalEconomico: 0, criticidadPromedio: 0 },
        porTipo: tipoStats,
        porCriticidad: criticidadStats
      };
    } catch (error) {
      logger.error('Error obteniendo estadísticas de activos:', error);
      throw error;
    }
  }

  // Obtener dependencias de un activo
  async getAssetDependencies(id: string): Promise<{
    dependeDe: IAsset[];
    dependientes: IAsset[];
  }> {
    try {
      const asset = await Asset.findById(id).populate('dependencias');
      if (!asset) {
        throw new AppError('Activo no encontrado', 404);
      }

      const dependientes = await Asset.find({ dependencias: id })
        .select('codigo nombre tipo valoracion');

      return {
        dependeDe: asset.dependencias as any,
        dependientes: dependientes as IAsset[]
      };
    } catch (error) {
      logger.error(`Error obteniendo dependencias del activo ${id}:`, error);
      throw error;
    }
  }

  // Importación masiva de activos
  async bulkImportAssets(assetsData: Partial<IAsset>[]): Promise<{
    successful: number;
    failed: number;
    errors: string[];
  }> {
    const results = {
      successful: 0,
      failed: 0,
      errors: [] as string[]
    };

    for (const assetData of assetsData) {
      try {
        await this.createAsset(assetData);
        results.successful++;
      } catch (error) {
        results.failed++;
        results.errors.push(`${assetData.codigo}: ${(error as Error).message}`);
      }
    }

    logger.info(`Importación masiva completada: ${results.successful} exitosos, ${results.failed} fallidos`);
    return results;
  }
}

export const assetService = new AssetService();