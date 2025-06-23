import { Threat } from '../models/Threat';
import { Asset } from '../models/Asset';
import { IThreat, TipoAmenaza, PaginationOptions } from '../types';
import { AppError } from '../middleware/errorHandler';
import logger from '../utils/logger';

export class ThreatService {
  // Crear nueva amenaza
  async createThreat(threatData: Partial<IThreat>): Promise<IThreat> {
    try {
      // Verificar si el código ya existe
      const existingThreat = await Threat.findOne({ codigo: threatData.codigo });
      if (existingThreat) {
        throw new AppError('El código de amenaza ya existe', 400);
      }

      const threat = new Threat(threatData);
      await threat.save();
      
      logger.info(`Amenaza creada: ${threat.codigo}`);
      return threat;
    } catch (error) {
      logger.error('Error creando amenaza:', error);
      throw error;
    }
  }

  // Obtener lista paginada de amenazas
  async getThreats(options: PaginationOptions): Promise<{
    threats: IThreat[];
    pagination: any;
  }> {
    try {
      const { page = 1, limit = 10, sort = '-fechaDescubrimiento', filter = {} } = options;
      
      const skip = (page - 1) * limit;
      
      // Construir filtros
      const query: any = {};
      if (filter.tipo) query.tipo = filter.tipo;
      if (filter.origen) query.origen = filter.origen;
      if (filter.probabilidad) {
        const prob = parseInt(filter.probabilidad);
        query.probabilidad = { $gte: prob, $lt: prob + 1 };
      }
      if (filter.search) {
        query.$or = [
          { nombre: new RegExp(filter.search, 'i') },
          { codigo: new RegExp(filter.search, 'i') },
          { descripcion: new RegExp(filter.search, 'i') }
        ];
      }

      const [threats, total] = await Promise.all([
        Threat.find(query)
          .populate('aplicaA', 'codigo nombre tipo')
          .sort(sort)
          .skip(skip)
          .limit(limit)
          .lean(),
        Threat.countDocuments(query)
      ]);

      return {
        threats: threats as IThreat[],
        pagination: {
          page,
          limit,
          total,
          pages: Math.ceil(total / limit)
        }
      };
    } catch (error) {
      logger.error('Error obteniendo amenazas:', error);
      throw error;
    }
  }

  // Obtener amenaza por ID
  async getThreatById(id: string): Promise<IThreat> {
    try {
      const threat = await Threat.findById(id)
        .populate('aplicaA', 'codigo nombre tipo valorEconomico')
        .lean();

      if (!threat) {
        throw new AppError('Amenaza no encontrada', 404);
      }

      return threat as IThreat;
    } catch (error) {
      logger.error(`Error obteniendo amenaza ${id}:`, error);
      throw error;
    }
  }

  // Actualizar amenaza
  async updateThreat(id: string, updateData: Partial<IThreat>): Promise<IThreat> {
    try {
      // Si se está actualizando el código, verificar que no exista
      if (updateData.codigo) {
        const existingThreat = await Threat.findOne({ 
          codigo: updateData.codigo, 
          _id: { $ne: id } 
        });
        if (existingThreat) {
          throw new AppError('El código de amenaza ya existe', 400);
        }
      }

      const threat = await Threat.findByIdAndUpdate(
        id,
        { ...updateData, ultimaActualizacion: new Date() },
        { new: true, runValidators: true }
      ).populate('aplicaA');

      if (!threat) {
        throw new AppError('Amenaza no encontrada', 404);
      }

      logger.info(`Amenaza actualizada: ${threat.codigo}`);
      return threat;
    } catch (error) {
      logger.error(`Error actualizando amenaza ${id}:`, error);
      throw error;
    }
  }

  // Eliminar amenaza
  async deleteThreat(id: string): Promise<void> {
    try {
      const threat = await Threat.findByIdAndDelete(id);
      if (!threat) {
        throw new AppError('Amenaza no encontrada', 404);
      }

      logger.info(`Amenaza eliminada: ${threat.codigo}`);
    } catch (error) {
      logger.error(`Error eliminando amenaza ${id}:`, error);
      throw error;
    }
  }

  // Obtener amenazas por tipo
  async getThreatsByTipo(tipo: TipoAmenaza): Promise<IThreat[]> {
    try {
      return await Threat.find({ tipo })
        .populate('aplicaA', 'codigo nombre')
        .sort({ probabilidad: -1 })
        .lean() as IThreat[];
    } catch (error) {
      logger.error(`Error obteniendo amenazas por tipo ${tipo}:`, error);
      throw error;
    }
  }

  // Obtener amenaza por CVE
  async getThreatByCVE(cveId: string): Promise<IThreat | null> {
    try {
      const threat = await Threat.findOne({ 'cveData.cveId': cveId })
        .populate('aplicaA')
        .lean();

      return threat as IThreat;
    } catch (error) {
      logger.error(`Error obteniendo amenaza por CVE ${cveId}:`, error);
      throw error;
    }
  }

  // Obtener estadísticas de amenazas
  async getThreatStats(): Promise<any> {
    try {
      const stats = await Threat.aggregate([
        {
          $group: {
            _id: null,
            totalAmenazas: { $sum: 1 },
            probabilidadPromedio: { $avg: '$probabilidad' },
            amenazasCriticas: {
              $sum: { $cond: [{ $gte: ['$probabilidad', 8] }, 1, 0] }
            },
            amenazasAltas: {
              $sum: { $cond: [{ $and: [{ $gte: ['$probabilidad', 6] }, { $lt: ['$probabilidad', 8] }] }, 1, 0] }
            }
          }
        }
      ]);

      const tipoStats = await Threat.aggregate([
        {
          $group: {
            _id: '$tipo',
            count: { $sum: 1 },
            probabilidadPromedio: { $avg: '$probabilidad' }
          }
        }
      ]);

      const origenStats = await Threat.aggregate([
        {
          $group: {
            _id: '$origen',
            count: { $sum: 1 }
          }
        }
      ]);

      return {
        general: stats[0] || { totalAmenazas: 0, probabilidadPromedio: 0, amenazasCriticas: 0, amenazasAltas: 0 },
        porTipo: tipoStats,
        porOrigen: origenStats
      };
    } catch (error) {
      logger.error('Error obteniendo estadísticas de amenazas:', error);
      throw error;
    }
  }

  // Obtener amenazas para un activo específico
  async getThreatsForAsset(assetId: string): Promise<IThreat[]> {
    try {
      // Verificar que el activo existe
      const asset = await Asset.findById(assetId);
      if (!asset) {
        throw new AppError('Activo no encontrado', 404);
      }

      // Buscar amenazas que aplican a este activo
      const threats = await Threat.find({ aplicaA: assetId })
        .sort({ probabilidad: -1 })
        .lean();

      return threats as IThreat[];
    } catch (error) {
      logger.error(`Error obteniendo amenazas para activo ${assetId}:`, error);
      throw error;
    }
  }

  // Asignar amenaza a un activo
  async assignThreatToAsset(threatId: string, assetId: string): Promise<IThreat> {
    try {
      // Verificar que el activo existe
      const asset = await Asset.findById(assetId);
      if (!asset) {
        throw new AppError('Activo no encontrado', 404);
      }

      const threat = await Threat.findById(threatId);
      if (!threat) {
        throw new AppError('Amenaza no encontrada', 404);
      }

      // Agregar activo si no está ya asignado
      if (!threat.aplicaA.includes(assetId as any)) {
        threat.aplicaA.push(assetId as any);
        await threat.save();
      }

      await threat.populate('aplicaA', 'codigo nombre tipo');
      return threat;
    } catch (error) {
      logger.error(`Error asignando amenaza ${threatId} a activo ${assetId}:`, error);
      throw error;
    }
  }

  // Importar amenazas MAGERIT (implementación básica)
  async importMageritThreats(categoria?: string, overwrite = false): Promise<{
    imported: number;
    updated: number;
    errors: number;
  }> {
    try {
      logger.info('Iniciando importación de amenazas MAGERIT...');
      
      // Esta sería una implementación básica
      // En un proyecto real, tendrías un archivo con las amenazas MAGERIT
      const mageritThreats = [
        {
          codigo: 'A.25.01',
          nombre: 'Acceso no autorizado',
          tipo: TipoAmenaza.ATAQUES_INTENCIONADOS,
          descripcion: 'Acceso de personal no autorizado a los sistemas',
          probabilidad: 6,
          vectores: ['Físico', 'Red']
        },
        {
          codigo: 'A.25.02', 
          nombre: 'Abuso de privilegios',
          tipo: TipoAmenaza.ATAQUES_INTENCIONADOS,
          descripcion: 'Uso indebido de privilegios de acceso',
          probabilidad: 5,
          vectores: ['Interno']
        }
        // Agregar más amenazas MAGERIT según necesidad
      ];

      const results = {
        imported: 0,
        updated: 0,
        errors: 0
      };

      for (const threatData of mageritThreats) {
        try {
          const existingThreat = await Threat.findOne({ codigo: threatData.codigo });
          
          if (existingThreat) {
            if (overwrite) {
              await Threat.findByIdAndUpdate(existingThreat._id, {
                ...threatData,
                origen: 'MAGERIT',
                ultimaActualizacion: new Date()
              });
              results.updated++;
            }
          } else {
            await Threat.create({
              ...threatData,
              origen: 'MAGERIT',
              aplicaA: [],
              fechaDescubrimiento: new Date()
            });
            results.imported++;
          }
        } catch (error) {
          results.errors++;
          logger.error(`Error importando amenaza ${threatData.codigo}:`, error);
        }
      }

      logger.info(`Importación MAGERIT completada: ${results.imported} importadas, ${results.updated} actualizadas, ${results.errors} errores`);
      return results;
    } catch (error) {
      logger.error('Error en importación MAGERIT:', error);
      throw error;
    }
  }

  // Obtener estadísticas del dashboard
  async getDashboardStats(): Promise<any> {
    try {
      const [generalStats, recentThreats, criticalThreats] = await Promise.all([
        this.getThreatStats(),
        Threat.find({ fechaDescubrimiento: { $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) } })
          .countDocuments(),
        Threat.find({ probabilidad: { $gte: 8 } }).countDocuments()
      ]);

      return {
        ...generalStats.general,
        amenazasRecientes: recentThreats,
        amenazasCriticas: criticalThreats,
        distribuccion: {
          porTipo: generalStats.porTipo,
          porOrigen: generalStats.porOrigen
        }
      };
    } catch (error) {
      logger.error('Error obteniendo estadísticas del dashboard:', error);
      throw error;
    }
  }
}

export const threatService = new ThreatService();