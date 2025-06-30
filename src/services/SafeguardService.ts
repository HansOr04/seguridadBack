import { Safeguard } from '../models/Safeguard';
import { Risk } from '../models/Risk';
import { Asset } from '../models/Asset';
import { ISafeguard, EstadoSalvaguarda, PaginationOptions } from '../types';
import { AppError } from '../middleware/errorHandler';
import logger from '../utils/logger';

export class SafeguardService {
  // Crear nueva salvaguarda
  async createSafeguard(safeguardData: Partial<ISafeguard>): Promise<ISafeguard> {
    try {
      // Verificar si el código ya existe
      const existingSafeguard = await Safeguard.findOne({ codigo: safeguardData.codigo });
      if (existingSafeguard) {
        throw new AppError('El código de salvaguarda ya existe', 400);
      }

      const safeguard = new Safeguard(safeguardData);
      await safeguard.save();
      
      logger.info(`Salvaguarda creada: ${safeguard.codigo}`);
      return safeguard;
    } catch (error) {
      logger.error('Error creando salvaguarda:', error);
      throw error;
    }
  }

  // Obtener lista paginada de salvaguardas
  async getSafeguards(options: PaginationOptions): Promise<{
    safeguards: ISafeguard[];
    pagination: any;
  }> {
    try {
      const { page = 1, limit = 10, sort = '-fechaCreacion', filter = {} } = options;
      
      const skip = (page - 1) * limit;
      
      // Construir filtros
      const query: any = {};
      if (filter.tipo) query.tipo = filter.tipo;
      if (filter.categoria) query.categoria = filter.categoria;
      if (filter.estado) query.estado = filter.estado;
      if (filter.responsable) query.responsable = new RegExp(filter.responsable, 'i');
      if (filter.search) {
        query.$or = [
          { nombre: new RegExp(filter.search, 'i') },
          { codigo: new RegExp(filter.search, 'i') },
          { descripcion: new RegExp(filter.search, 'i') }
        ];
      }

      const [safeguards, total] = await Promise.all([
        Safeguard.find(query)
          .populate('activos', 'codigo nombre tipo')
          .populate('protege')
          .sort(sort)
          .skip(skip)
          .limit(limit)
          .lean(),
        Safeguard.countDocuments(query)
      ]);

      return {
        safeguards: safeguards as ISafeguard[],
        pagination: {
          page,
          limit,
          total,
          pages: Math.ceil(total / limit)
        }
      };
    } catch (error) {
      logger.error('Error obteniendo salvaguardas:', error);
      throw error;
    }
  }

  // Obtener salvaguarda por ID
  async getSafeguardById(id: string): Promise<ISafeguard> {
    try {
      const safeguard = await Safeguard.findById(id)
        .populate('activos', 'codigo nombre tipo valorEconomico')
        .populate('protege')
        .populate('amenazas', 'codigo nombre tipo')
        .populate('vulnerabilidades', 'codigo nombre categoria')
        .lean();

      if (!safeguard) {
        throw new AppError('Salvaguarda no encontrada', 404);
      }

      return safeguard as ISafeguard;
    } catch (error) {
      logger.error(`Error obteniendo salvaguarda ${id}:`, error);
      throw error;
    }
  }

  // Actualizar salvaguarda
  async updateSafeguard(id: string, updateData: Partial<ISafeguard>): Promise<ISafeguard> {
    try {
      // Si se está actualizando el código, verificar que no exista
      if (updateData.codigo) {
        const existingSafeguard = await Safeguard.findOne({ 
          codigo: updateData.codigo, 
          _id: { $ne: id } 
        });
        if (existingSafeguard) {
          throw new AppError('El código de salvaguarda ya existe', 400);
        }
      }

      const safeguard = await Safeguard.findByIdAndUpdate(
        id,
        { ...updateData, fechaActualizacion: new Date() },
        { new: true, runValidators: true }
      ).populate('activos protege');

      if (!safeguard) {
        throw new AppError('Salvaguarda no encontrada', 404);
      }

      logger.info(`Salvaguarda actualizada: ${safeguard.codigo}`);
      return safeguard;
    } catch (error) {
      logger.error(`Error actualizando salvaguarda ${id}:`, error);
      throw error;
    }
  }

  // Eliminar salvaguarda
  async deleteSafeguard(id: string): Promise<void> {
    try {
      const safeguard = await Safeguard.findByIdAndDelete(id);
      if (!safeguard) {
        throw new AppError('Salvaguarda no encontrada', 404);
      }

      logger.info(`Salvaguarda eliminada: ${safeguard.codigo}`);
    } catch (error) {
      logger.error(`Error eliminando salvaguarda ${id}:`, error);
      throw error;
    }
  }

  // Implementar salvaguarda
  async implementSafeguard(id: string, fechaImplementacion?: Date): Promise<ISafeguard> {
    try {
      const safeguard = await Safeguard.findById(id);
      if (!safeguard) {
        throw new AppError('Salvaguarda no encontrada', 404);
      }

      safeguard.estado = EstadoSalvaguarda.IMPLEMENTADA;
      safeguard.fechaImplementacion = fechaImplementacion || new Date();
      
      // Programar revisión automática
      safeguard.programarRevision();
      
      await safeguard.save();

      logger.info(`Salvaguarda implementada: ${safeguard.codigo}`);
      return safeguard;
    } catch (error) {
      logger.error(`Error implementando salvaguarda ${id}:`, error);
      throw error;
    }
  }

  // Agregar KPI a salvaguarda
  async addKPI(id: string, kpiData: { nombre: string; valor: number; unidad: string }): Promise<ISafeguard> {
    try {
      const safeguard = await Safeguard.findById(id);
      if (!safeguard) {
        throw new AppError('Salvaguarda no encontrada', 404);
      }

      safeguard.agregarKPI(kpiData.nombre, kpiData.valor, kpiData.unidad);
      await safeguard.save();

      logger.info(`KPI agregado a salvaguarda ${safeguard.codigo}: ${kpiData.nombre}`);
      return safeguard;
    } catch (error) {
      logger.error(`Error agregando KPI a salvaguarda ${id}:`, error);
      throw error;
    }
  }

  // Obtener salvaguardas por estado
  async getSafeguardsByEstado(estado: EstadoSalvaguarda): Promise<ISafeguard[]> {
    try {
      return await Safeguard.findByEstado(estado);
    } catch (error) {
      logger.error(`Error obteniendo salvaguardas por estado ${estado}:`, error);
      throw error;
    }
  }

  // Obtener salvaguardas vencidas
  async getExpiredSafeguards(): Promise<ISafeguard[]> {
    try {
      return await Safeguard.findVencidas();
    } catch (error) {
      logger.error('Error obteniendo salvaguardas vencidas:', error);
      throw error;
    }
  }

  // Obtener salvaguardas próximas a revisión
  async getUpcomingReviews(days: number = 30): Promise<ISafeguard[]> {
    try {
      return await Safeguard.findProximasRevision(days);
    } catch (error) {
      logger.error('Error obteniendo próximas revisiones:', error);
      throw error;
    }
  }

  // Calcular efectividad del programa de salvaguardas
  async calculateProgramEffectiveness(): Promise<{
    totalSafeguards: number;
    implementedSafeguards: number;
    averageEffectiveness: number;
    totalCost: number;
    averageROI: number;
    coverageByCategory: any[];
  }> {
    try {
      const safeguards = await Safeguard.find({}).lean();
      
      const implemented = safeguards.filter(s => s.estado === EstadoSalvaguarda.IMPLEMENTADA);
      
      const totalCost = safeguards.reduce((sum, s) => sum + s.costo + (s.costeMantenenimiento * 12), 0);
      
      const averageEffectiveness = implemented.length > 0 
        ? implemented.reduce((sum, s) => sum + s.eficacia, 0) / implemented.length 
        : 0;

      // Calcular ROI promedio (implementación básica)
      const avgROI = implemented.length > 0
        ? implemented.reduce((sum, s) => {
            const costoAnual = s.costo + (s.costeMantenenimiento * 12);
            const reduccionRiesgo = s.eficacia / 100;
            return sum + ((reduccionRiesgo * 100000) / costoAnual) * 100; // Asumiendo valor promedio de activos
          }, 0) / implemented.length
        : 0;

      // Cobertura por categoría
      const coverageByCategory = await Safeguard.aggregate([
        {
          $group: {
            _id: '$categoria',
            count: { $sum: 1 },
            implemented: {
              $sum: { $cond: [{ $eq: ['$estado', 'Implementada'] }, 1, 0] }
            },
            avgEffectiveness: { $avg: '$eficacia' },
            totalCost: { $sum: { $add: ['$costo', { $multiply: ['$costeMantenenimiento', 12] }] } }
          }
        }
      ]);

      return {
        totalSafeguards: safeguards.length,
        implementedSafeguards: implemented.length,
        averageEffectiveness,
        totalCost,
        averageROI: avgROI,
        coverageByCategory
      };
    } catch (error) {
      logger.error('Error calculando efectividad del programa:', error);
      throw error;
    }
  }

  // Recomendar salvaguardas para un riesgo específico
  async recommendSafeguardsForRisk(riskId: string): Promise<{
    existingSafeguards: ISafeguard[];
    recommendedSafeguards: any[];
  }> {
    try {
      // Obtener riesgo con sus relaciones
      const risk = await Risk.findById(riskId)
        .populate('activo amenaza vulnerabilidad');

      if (!risk) {
        throw new AppError('Riesgo no encontrado', 404);
      }

      // Buscar salvaguardas existentes para este riesgo
      const existingSafeguards = await Safeguard.find({
        protege: riskId
      }).lean();

      // Generar recomendaciones básicas basadas en el tipo de amenaza
      const recommendedSafeguards = this.generateSafeguardRecommendations(risk);

      return {
        existingSafeguards: existingSafeguards as ISafeguard[],
        recommendedSafeguards
      };
    } catch (error) {
      logger.error(`Error recomendando salvaguardas para riesgo ${riskId}:`, error);
      throw error;
    }
  }

  // Generar recomendaciones de salvaguardas (implementación básica)
  private generateSafeguardRecommendations(risk: any): any[] {
    const recommendations = [];

    // Recomendaciones basadas en el nivel de riesgo
    if (risk.nivelRiesgo === 'Crítico' || risk.nivelRiesgo === 'Alto') {
      recommendations.push({
        tipo: 'Preventiva',
        categoria: 'Técnica',
        nombre: 'Implementación de controles de acceso avanzados',
        descripcion: 'Controles técnicos para prevenir acceso no autorizado',
        prioridad: 'Alta',
        costoEstimado: 5000
      });

      recommendations.push({
        tipo: 'Detectiva',
        categoria: 'Técnica',
        nombre: 'Sistema de monitoreo y alertas',
        descripcion: 'Detección temprana de actividades sospechosas',
        prioridad: 'Alta',
        costoEstimado: 3000
      });
    }

    // Recomendaciones basadas en el tipo de activo
    if (risk.activo?.tipo === 'Software') {
      recommendations.push({
        tipo: 'Preventiva',
        categoria: 'Técnica',
        nombre: 'Gestión de parches y actualizaciones',
        descripcion: 'Programa sistemático de actualización de software',
        prioridad: 'Media',
        costoEstimado: 2000
      });
    }

    return recommendations;
  }

  async getSafeguardStats(): Promise<{
    general: {
      totalSalvaguardas: number;
      salvaguardasImplementadas: number;
      salvaguardasPlanificadas: number;
      salvaguardasObsoletas: number;
      efectividadPromedio: number;
      costoTotalImplementacion: number;
      costoTotalMantenimiento: number;
      porcentajeImplementacion: number;
    };
    distribucion: {
      porTipo: Array<{ _id: string; count: number; efectividadPromedio: number }>;
      porCategoria: Array<{ _id: string; count: number; costoPromedio: number }>;
      porEstado: Array<{ _id: string; count: number; porcentaje: number }>;
      porResponsable: Array<{ _id: string; count: number; efectividadPromedio: number }>;
    };
    efectividad: {
      porRangoEficacia: Array<{ rango: string; count: number; porcentaje: number }>;
      mejoresPerformers: Array<{ 
        _id: string; 
        nombre: string; 
        eficacia: number; 
        costoEfectividad: number 
      }>;
      necesitanMejora: Array<{ 
        _id: string; 
        nombre: string; 
        eficacia: number; 
        estadoRevision: string 
      }>;
    };
    costos: {
      totalInversion: number;
      costoPromedioImplementacion: number;
      costoPromedioMantenimiento: number;
      roiPromedio: number;
      distribuccionCostos: Array<{ categoria: string; costo: number; porcentaje: number }>;
    };
    timeline: {
      implementacionesPorMes: Array<{ mes: string; implementadas: number; planificadas: number }>;
      revisionesPendientes: Array<{ 
        _id: string; 
        nombre: string; 
        fechaRevision: Date; 
        diasVencido: number 
      }>;
    };
    metricas: {
      tiempoPromedioImplementacion: number;
      tasaExito: number;
      coberturaAmenazas: number;
      coberturaActivos: number;
    };
  }> {
    try {
      // Estadísticas generales
      const generalStats = await Safeguard.aggregate([
        {
          $group: {
            _id: null,
            totalSalvaguardas: { $sum: 1 },
            salvaguardasImplementadas: {
              $sum: { $cond: [{ $eq: ['$estado', 'Implementada'] }, 1, 0] }
            },
            salvaguardasPlanificadas: {
              $sum: { $cond: [{ $eq: ['$estado', 'Planificada'] }, 1, 0] }
            },
            salvaguardasObsoletas: {
              $sum: { $cond: [{ $eq: ['$estado', 'Obsoleta'] }, 1, 0] }
            },
            efectividadPromedio: { $avg: '$eficacia' },
            costoTotalImplementacion: { $sum: '$costo' },
            costoTotalMantenimiento: { $sum: '$costeMantenenimiento' }
          }
        }
      ]);

      // Distribución por tipo
      const distribucionTipo = await Safeguard.aggregate([
        {
          $group: {
            _id: '$tipo',
            count: { $sum: 1 },
            efectividadPromedio: { $avg: '$eficacia' }
          }
        },
        { $sort: { count: -1 } }
      ]);

      // Distribución por categoría
      const distribucionCategoria = await Safeguard.aggregate([
        {
          $group: {
            _id: '$categoria',
            count: { $sum: 1 },
            costoPromedio: { $avg: { $add: ['$costo', { $multiply: ['$costeMantenenimiento', 12] }] } }
          }
        },
        { $sort: { count: -1 } }
      ]);

      // Distribución por estado
      const distribucionEstado = await Safeguard.aggregate([
        {
          $group: {
            _id: '$estado',
            count: { $sum: 1 }
          }
        }
      ]);

      // Calcular porcentajes para distribución por estado
      const totalSafeguards = distribucionEstado.reduce((sum, item) => sum + item.count, 0);
      const distribucionEstadoWithPercentage = distribucionEstado.map(item => ({
        ...item,
        porcentaje: totalSafeguards > 0 ? Math.round((item.count / totalSafeguards) * 100) : 0
      }));

      // Distribución por responsable
      const distribucionResponsable = await Safeguard.aggregate([
        {
          $group: {
            _id: '$responsable',
            count: { $sum: 1 },
            efectividadPromedio: { $avg: '$eficacia' }
          }
        },
        { $sort: { count: -1 } },
        { $limit: 10 }
      ]);

      // Rangos de eficacia - FIXED VERSION
      const rangoEficacia = await Safeguard.aggregate([
        {
          $addFields: {
            rangoEficacia: {
              $switch: {
                branches: [
                  { case: { $lt: ['$eficacia', 25] }, then: 'Muy Baja (0-24%)' },
                  { case: { $lt: ['$eficacia', 50] }, then: 'Baja (25-49%)' },
                  { case: { $lt: ['$eficacia', 75] }, then: 'Media (50-74%)' },
                  { case: { $lt: ['$eficacia', 90] }, then: 'Alta (75-89%)' },
                  { case: { $gte: ['$eficacia', 90] }, then: 'Muy Alta (90-100%)' }
                ],
                default: 'Sin clasificar'
              }
            }
          }
        },
        {
          $group: {
            _id: '$rangoEficacia',
            count: { $sum: 1 }
          }
        },
        {
          $addFields: {
            rango: '$_id'
          }
        },
        { $sort: { '_id': 1 } }
      ]);

      // Calculate total count for percentage calculation
      const rangoEficaciaTotal = rangoEficacia.reduce((sum, item) => sum + item.count, 0);
      const rangoEficaciaWithPercentage = rangoEficacia.map(item => ({
        ...item,
        porcentaje: rangoEficaciaTotal > 0 ? Math.round((item.count / rangoEficaciaTotal) * 100) : 0
      }));

      // Mejores performers (Top 5 por eficacia)
      const mejoresPerformers = await Safeguard.aggregate([
        { $match: { estado: 'Implementada', eficacia: { $gte: 80 } } },
        {
          $addFields: {
            costoAnual: { $add: ['$costo', { $multiply: ['$costeMantenenimiento', 12] }] },
            costoEfectividad: {
              $cond: {
                if: { $eq: ['$costo', 0] },
                then: '$eficacia',
                else: { $divide: ['$eficacia', { $add: ['$costo', { $multiply: ['$costeMantenenimiento', 12] }] }] }
              }
            }
          }
        },
        { $sort: { eficacia: -1, costoEfectividad: -1 } },
        { $limit: 5 },
        {
          $project: {
            nombre: 1,
            eficacia: 1,
            costoEfectividad: 1
          }
        }
      ]);

      // Salvaguardas que necesitan mejora (eficacia < 50% o vencidas)
      const necesitanMejora = await Safeguard.aggregate([
        {
          $match: {
            $or: [
              { eficacia: { $lt: 50 } },
              { fechaRevision: { $lt: new Date() } }
            ]
          }
        },
        {
          $addFields: {
            estadoRevision: {
              $cond: {
                if: { $lt: ['$fechaRevision', new Date()] },
                then: 'Revisión vencida',
                else: 'Eficacia baja'
              }
            }
          }
        },
        { $sort: { eficacia: 1 } },
        { $limit: 10 },
        {
          $project: {
            nombre: 1,
            eficacia: 1,
            estadoRevision: 1
          }
        }
      ]);

      // Timeline de implementaciones (últimos 12 meses)
      const hace12Meses = new Date();
      hace12Meses.setMonth(hace12Meses.getMonth() - 12);

      const implementacionesPorMes = await Safeguard.aggregate([
        {
          $match: {
            $or: [
              { fechaImplementacion: { $gte: hace12Meses } },
              { fechaCreacion: { $gte: hace12Meses } }
            ]
          }
        },
        {
          $group: {
            _id: {
              $dateToString: { format: '%Y-%m', date: '$fechaImplementacion' }
            },
            implementadas: {
              $sum: { $cond: [{ $eq: ['$estado', 'Implementada'] }, 1, 0] }
            },
            planificadas: {
              $sum: { $cond: [{ $eq: ['$estado', 'Planificada'] }, 1, 0] }
            }
          }
        },
        { $sort: { '_id': 1 } },
        {
          $project: {
            mes: '$_id',
            implementadas: 1,
            planificadas: 1,
            _id: 0
          }
        }
      ]);

      // Revisiones pendientes/vencidas
      const revisionesPendientes = await Safeguard.aggregate([
        {
          $match: {
            fechaRevision: { $exists: true },
            estado: 'Implementada'
          }
        },
        {
          $addFields: {
            diasVencido: {
              $divide: [
                { $subtract: [new Date(), '$fechaRevision'] },
                1000 * 60 * 60 * 24
              ]
            }
          }
        },
        { $match: { diasVencido: { $gte: -30 } } }, // Próximas a vencer o ya vencidas
        { $sort: { diasVencido: -1 } },
        { $limit: 10 },
        {
          $project: {
            nombre: 1,
            fechaRevision: 1,
            diasVencido: { $round: ['$diasVencido', 0] }
          }
        }
      ]);

      // Procesar datos
      const general = generalStats[0] || {
        totalSalvaguardas: 0,
        salvaguardasImplementadas: 0,
        salvaguardasPlanificadas: 0,
        salvaguardasObsoletas: 0,
        efectividadPromedio: 0,
        costoTotalImplementacion: 0,
        costoTotalMantenimiento: 0
      };

      // Calcular porcentaje de implementación
      const porcentajeImplementacion = general.totalSalvaguardas > 0 
        ? Math.round((general.salvaguardasImplementadas / general.totalSalvaguardas) * 100)
        : 0;

      // Distribución de costos
      const costoTotal = general.costoTotalImplementacion + (general.costoTotalMantenimiento * 12);
      const distribuccionCostos = distribucionCategoria.map(cat => ({
        categoria: cat._id,
        costo: cat.costoPromedio * cat.count,
        porcentaje: costoTotal > 0 ? Math.round(((cat.costoPromedio * cat.count) / costoTotal) * 100) : 0
      }));

      return {
        general: {
          ...general,
          porcentajeImplementacion,
          efectividadPromedio: Math.round(general.efectividadPromedio || 0)
        },
        distribucion: {
          porTipo: distribucionTipo,
          porCategoria: distribucionCategoria,
          porEstado: distribucionEstadoWithPercentage,
          porResponsable: distribucionResponsable
        },
        efectividad: {
          porRangoEficacia: rangoEficaciaWithPercentage,
          mejoresPerformers,
          necesitanMejora
        },
        costos: {
          totalInversion: costoTotal,
          costoPromedioImplementacion: general.totalSalvaguardas > 0 
            ? Math.round(general.costoTotalImplementacion / general.totalSalvaguardas)
            : 0,
          costoPromedioMantenimiento: general.totalSalvaguardas > 0
            ? Math.round(general.costoTotalMantenimiento / general.totalSalvaguardas)
            : 0,
          roiPromedio: 0, // TODO: Implementar cálculo de ROI
          distribuccionCostos
        },
        timeline: {
          implementacionesPorMes,
          revisionesPendientes
        },
        metricas: {
          tiempoPromedioImplementacion: 0, // TODO: Implementar si se tienen fechas
          tasaExito: porcentajeImplementacion,
          coberturaAmenazas: 0, // TODO: Implementar cálculo de cobertura
          coberturaActivos: 0 // TODO: Implementar cálculo de cobertura
        }
      };
    } catch (error) {
      logger.error('Error obteniendo estadísticas de salvaguardas:', error);
      throw error;
    }
  }
}

export const safeguardService = new SafeguardService();