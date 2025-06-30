import { Asset } from '../models/Asset';
import { Threat } from '../models/Threat';
import { Vulnerability } from '../models/Vulnerability';
import { Risk } from '../models/Risk';
import { IRisk, CalculosRiesgo, NivelRiesgo, IAsset } from '../types';
import { AppError } from '../middleware/errorHandler';
import logger from '../utils/logger';

export class RiskService {
  // ===========================
  // MÉTODOS EXISTENTES (mantener todos)
  // ===========================

  // Calcular riesgo individual
  async calculateRisk(
    assetId: string, 
    threatId: string, 
    vulnerabilityId?: string
  ): Promise<CalculosRiesgo> {
    try {
      const [asset, threat, vulnerability] = await Promise.all([
        Asset.findById(assetId),
        Threat.findById(threatId),
        vulnerabilityId ? Vulnerability.findById(vulnerabilityId) : null
      ]);

      if (!asset) throw new AppError('Activo no encontrado', 404);
      if (!threat) throw new AppError('Amenaza no encontrada', 404);

      // Cálculo base MAGERIT
      const probabilidadBase = threat.probabilidad;
      const impactoMaximo = Math.max(
        asset.valoracion.confidencialidad,
        asset.valoracion.integridad,
        asset.valoracion.disponibilidad,
        asset.valoracion.autenticidad,
        asset.valoracion.trazabilidad
      );

      // Factor de vulnerabilidad
      const factorVulnerabilidad = vulnerability 
        ? vulnerability.facilidadExplotacion / 10 
        : 0.5; // Valor por defecto si no hay vulnerabilidad específica

      // Factor temporal (degrada la probabilidad con el tiempo)
      const factorTemporal = this.calculateTemporalFactor(threat.fechaDescubrimiento);

      // Cálculos finales
      const probabilidadAjustada = probabilidadBase * factorVulnerabilidad * factorTemporal;
      const impactoCalculado = impactoMaximo * (asset.valorEconomico / 100000); // Normalizado
      const exposicion = probabilidadAjustada * impactoCalculado;
      const riesgoInherente = probabilidadBase * impactoMaximo;

      return {
        riesgoInherente,
        probabilidadAjustada,
        impactoCalculado,
        exposicion,
        factorTemporal
      };
    } catch (error) {
      logger.error('Error calculando riesgo:', error);
      throw error;
    }
  }

  // Calcular factor temporal
  private calculateTemporalFactor(fechaDescubrimiento: Date): number {
    const now = new Date();
    const daysSinceDiscovery = Math.floor(
      (now.getTime() - fechaDescubrimiento.getTime()) / (1000 * 60 * 60 * 24)
    );

    // La probabilidad aumenta con el tiempo hasta estabilizarse
    if (daysSinceDiscovery <= 30) return 0.5 + (daysSinceDiscovery / 60); // 0.5 a 1.0 en 30 días
    if (daysSinceDiscovery <= 90) return 1.0; // Máximo por 60 días
    return Math.max(0.8, 1.0 - ((daysSinceDiscovery - 90) / 365)); // Degrada después de 90 días
  }

  // Determinar nivel de riesgo
  private determineRiskLevel(riesgoCalculado: number): NivelRiesgo {
    if (riesgoCalculado >= 80) return NivelRiesgo.CRITICO;
    if (riesgoCalculado >= 60) return NivelRiesgo.ALTO;
    if (riesgoCalculado >= 40) return NivelRiesgo.MEDIO;
    if (riesgoCalculado >= 20) return NivelRiesgo.BAJO;
    return NivelRiesgo.MUY_BAJO;
  }

  // Calcular Value at Risk (VaR)
  private calculateVaR(asset: IAsset, probabilidad: number, impacto: number): number {
    return asset.valorEconomico * (probabilidad / 10) * (impacto / 10);
  }

  // Crear o actualizar registro de riesgo
  async createOrUpdateRisk(
    assetId: string,
    threatId: string,
    vulnerabilityId?: string
  ): Promise<IRisk> {
    try {
      const calculos = await this.calculateRisk(assetId, threatId, vulnerabilityId);
      const asset = await Asset.findById(assetId);
      
      if (!asset) throw new AppError('Activo no encontrado', 404);
      
      const riesgoFinal = calculos.exposicion;
      const nivelRiesgo = this.determineRiskLevel(riesgoFinal);
      const valorRiesgo = this.calculateVaR(asset, calculos.probabilidadAjustada, calculos.impactoCalculado);

      // Buscar riesgo existente
      const existingRisk = await Risk.findOne({
        activo: assetId,
        amenaza: threatId,
        vulnerabilidad: vulnerabilityId || null
      });

      if (existingRisk) {
        // Actualizar riesgo existente
        existingRisk.calculos = calculos;
        existingRisk.valorRiesgo = valorRiesgo;
        existingRisk.nivelRiesgo = nivelRiesgo;
        existingRisk.probabilidad = calculos.probabilidadAjustada;
        existingRisk.impacto = calculos.impactoCalculado;
        existingRisk.fechaCalculo = new Date();
        existingRisk.vigente = true;

        await existingRisk.save();
        return existingRisk;
      } else {
        // Crear nuevo riesgo
        const newRisk = new Risk({
          activo: assetId,
          amenaza: threatId,
          vulnerabilidad: vulnerabilityId || null,
          calculos,
          valorRiesgo,
          nivelRiesgo,
          probabilidad: calculos.probabilidadAjustada,
          impacto: calculos.impactoCalculado,
          fechaCalculo: new Date(),
          vigente: true
        });

        await newRisk.save();
        return newRisk;
      }
    } catch (error) {
      logger.error('Error creando/actualizando riesgo:', error);
      throw error;
    }
  }

  // Recalcular todos los riesgos
  async recalculateAllRisks(): Promise<{ processed: number; errors: number }> {
    try {
      logger.info('Iniciando recálculo masivo de riesgos...');
      
      const risks = await Risk.find({ vigente: true })
        .populate('activo amenaza vulnerabilidad');

      let processed = 0;
      let errors = 0;

      for (const risk of risks) {
        try {
            await this.createOrUpdateRisk(
            risk.activo._id.toString(),
            risk.amenaza._id.toString(),
            risk.vulnerabilidad?._id.toString()
            );
            processed++;
        } catch (error) {
            errors++;
            logger.error(`Error recalculando riesgo ${risk._id}:`, error);
        }
        }

      logger.info(`Recálculo completado: ${processed} procesados, ${errors} errores`);
      return { processed, errors };
    } catch (error) {
      logger.error('Error en recálculo masivo:', error);
      throw error;
    }
  }

  // Obtener matriz de riesgos
  async getRiskMatrix(): Promise<{
    matrix: {
      criticos: IRisk[];
      altos: IRisk[];
      medios: IRisk[];
      bajos: IRisk[];
      muyBajos: IRisk[];
    };
    stats: {
      totalRiesgos: number;
      valorTotalEnRiesgo: number;
      riesgoPromedio: number;
    };
  }> {
    try {
      const risks = await Risk.find({ vigente: true })
        .populate('activo', 'codigo nombre')
        .populate('amenaza', 'codigo nombre')
        .populate('vulnerabilidad', 'codigo nombre')
        .sort({ valorRiesgo: -1 });

      // Agrupar por nivel de riesgo
      const riskMatrix = {
        criticos: risks.filter((r: IRisk) => r.nivelRiesgo === NivelRiesgo.CRITICO),
        altos: risks.filter((r: IRisk) => r.nivelRiesgo === NivelRiesgo.ALTO),
        medios: risks.filter((r: IRisk) => r.nivelRiesgo === NivelRiesgo.MEDIO),
        bajos: risks.filter((r: IRisk) => r.nivelRiesgo === NivelRiesgo.BAJO),
        muyBajos: risks.filter((r: IRisk) => r.nivelRiesgo === NivelRiesgo.MUY_BAJO)
      };

      // Estadísticas generales
      const stats = {
        totalRiesgos: risks.length,
        valorTotalEnRiesgo: risks.reduce((sum: number, r: IRisk) => sum + r.valorRiesgo, 0),
        riesgoPromedio: risks.length > 0 
          ? risks.reduce((sum: number, r: IRisk) => sum + r.probabilidad * r.impacto, 0) / risks.length 
          : 0
      };

      return { matrix: riskMatrix, stats };
    } catch (error) {
      logger.error('Error obteniendo matriz de riesgos:', error);
      throw error;
    }
  }

  // Obtener top riesgos
  async getTopRisks(limit: number = 10): Promise<IRisk[]> {
    try {
      return await Risk.find({ vigente: true })
        .populate('activo', 'codigo nombre valorEconomico')
        .populate('amenaza', 'codigo nombre tipo')
        .populate('vulnerabilidad', 'codigo nombre')
        .sort({ valorRiesgo: -1 })
        .limit(limit);
    } catch (error) {
      logger.error('Error obteniendo top riesgos:', error);
      throw error;
    }
  }

  // Obtener KPIs del dashboard
  async getDashboardKPIs(): Promise<{
    totalRiesgos: number;
    riesgosCriticos: number;
    riesgosAltos: number;
    valorTotalRiesgo: number;
    valorTotalActivos: number;
    exposicionPromedio: number;
    porcentajeEnRiesgo: number;
  }> {
    try {
      const [riskStats, assetStats] = await Promise.all([
        Risk.aggregate([
          { $match: { vigente: true } },
          {
            $group: {
              _id: null,
              totalRiesgos: { $sum: 1 },
              valorTotalRiesgo: { $sum: '$valorRiesgo' },
              riesgosCriticos: {
                $sum: { $cond: [{ $eq: ['$nivelRiesgo', 'Crítico'] }, 1, 0] }
              },
              riesgosAltos: {
                $sum: { $cond: [{ $eq: ['$nivelRiesgo', 'Alto'] }, 1, 0] }
              },
              exposicionPromedio: { $avg: '$calculos.exposicion' }
            }
          }
        ]),
        Asset.aggregate([
          {
            $group: {
              _id: null,
              totalActivos: { $sum: 1 },
              valorTotalActivos: { $sum: '$valorEconomico' }
            }
          }
        ])
      ]);

      const riskData = riskStats[0] || {};
      const assetData = assetStats[0] || {};

      return {
        totalRiesgos: riskData.totalRiesgos || 0,
        riesgosCriticos: riskData.riesgosCriticos || 0,
        riesgosAltos: riskData.riesgosAltos || 0,
        valorTotalRiesgo: riskData.valorTotalRiesgo || 0,
        valorTotalActivos: assetData.valorTotalActivos || 0,
        exposicionPromedio: riskData.exposicionPromedio || 0,
        porcentajeEnRiesgo: assetData.valorTotalActivos > 0 
          ? ((riskData.valorTotalRiesgo || 0) / assetData.valorTotalActivos) * 100 
          : 0
      };
    } catch (error) {
      logger.error('Error obteniendo KPIs del dashboard:', error);
      throw error;
    }
  }

  // ===========================
  // MÉTODOS NUEVOS FALTANTES
  // ===========================

  // ✅ MÉTODO FALTANTE: getRisks con filtros y paginación
  async getRisks(options: {
    page?: number;
    limit?: number;
    sort?: string;
    filter?: {
      nivel?: string;
      estado?: string;
      activo?: string;
      amenaza?: string;
      valorMinimo?: number;
      valorMaximo?: number;
      search?: string;
    };
  }): Promise<{
    risks: IRisk[];
    pagination: any;
  }> {
    try {
      const { page = 1, limit = 10, sort = '-fechaCalculo', filter = {} } = options;
      const skip = (page - 1) * limit;

      // Construir query de MongoDB
      const query: any = { vigente: true };

      // Filtros específicos
      if (filter.nivel) query.nivelRiesgo = filter.nivel;
      if (filter.activo) query.activo = filter.activo;
      if (filter.amenaza) query.amenaza = filter.amenaza;
      
      if (filter.valorMinimo !== undefined || filter.valorMaximo !== undefined) {
        query.valorRiesgo = {};
        if (filter.valorMinimo !== undefined) query.valorRiesgo.$gte = filter.valorMinimo;
        if (filter.valorMaximo !== undefined) query.valorRiesgo.$lte = filter.valorMaximo;
      }

      // Para búsqueda general, necesitamos usar agregación para buscar en campos populados
      let risks: IRisk[];
      let total: number;

      if (filter.search) {
        // Usar agregación para búsqueda en campos relacionados
        const aggregationPipeline = [
          { $match: { vigente: true } },
          {
            $lookup: {
              from: 'assets',
              localField: 'activo',
              foreignField: '_id',
              as: 'activoData'
            }
          },
          {
            $lookup: {
              from: 'threats',
              localField: 'amenaza',
              foreignField: '_id',
              as: 'amenazaData'
            }
          },
          {
            $lookup: {
              from: 'vulnerabilities',
              localField: 'vulnerabilidad',
              foreignField: '_id',
              as: 'vulnerabilidadData'
            }
          },
          {
            $match: {
              $or: [
                { nivelRiesgo: new RegExp(filter.search, 'i') },
                { 'activoData.nombre': new RegExp(filter.search, 'i') },
                { 'activoData.codigo': new RegExp(filter.search, 'i') },
                { 'amenazaData.nombre': new RegExp(filter.search, 'i') },
                { 'amenazaData.codigo': new RegExp(filter.search, 'i') },
                { 'vulnerabilidadData.nombre': new RegExp(filter.search, 'i') }
              ]
            }
          }
        ];

        // Obtener total con búsqueda
        const totalPipeline = [...aggregationPipeline, { $count: 'total' }];
        const totalResult = await Risk.aggregate(totalPipeline);
        total = totalResult[0]?.total || 0;

        // Obtener datos con paginación
        const dataPipeline = [
          ...aggregationPipeline,
          { $sort: this.parseSortString(sort) },
          { $skip: skip },
          { $limit: limit },
          {
            $project: {
              activo: { $arrayElemAt: ['$activoData', 0] },
              amenaza: { $arrayElemAt: ['$amenazaData', 0] },
              vulnerabilidad: { $arrayElemAt: ['$vulnerabilidadData', 0] },
              calculos: 1,
              valorRiesgo: 1,
              nivelRiesgo: 1,
              probabilidad: 1,
              impacto: 1,
              fechaCalculo: 1,
              vigente: 1
            }
          }
        ];

        risks = await Risk.aggregate(dataPipeline);
      } else {
        // Sin búsqueda, usar find normal
        [risks, total] = await Promise.all([
          Risk.find(query)
            .populate('activo', 'codigo nombre tipo valorEconomico')
            .populate('amenaza', 'codigo nombre tipo probabilidad')
            .populate('vulnerabilidad', 'codigo nombre categoria')
            .sort(sort)
            .skip(skip)
            .limit(limit)
            .lean(),
          Risk.countDocuments(query)
        ]);
      }

      return {
        risks: risks as IRisk[],
        pagination: {
          page,
          limit,
          total,
          pages: Math.ceil(total / limit),
          hasNextPage: page < Math.ceil(total / limit),
          hasPrevPage: page > 1
        }
      };
    } catch (error) {
      logger.error('Error obteniendo riesgos:', error);
      throw error;
    }
  }

  // Helper para parsear string de ordenamiento
  private parseSortString(sort: string): any {
    const sortObj: any = {};
    if (sort.startsWith('-')) {
      sortObj[sort.slice(1)] = -1;
    } else {
      sortObj[sort] = 1;
    }
    return sortObj;
  }

  // ✅ MÉTODO FALTANTE: getRiskStats - Estadísticas detalladas
  async getRiskStats(): Promise<{
    general: {
      totalRiesgos: number;
      riesgosCriticos: number;
      riesgosAltos: number;
      riesgosMedios: number;
      riesgosBajos: number;
      riesgosMuyBajos: number;
      valorTotalEnRiesgo: number;
      riesgoPromedio: number;
    };
    distribucion: {
      porNivel: Array<{ _id: string; count: number; valorTotal: number }>;
      porActivo: Array<{ _id: string; nombre: string; count: number; valorTotal: number }>;
      porAmenaza: Array<{ _id: string; nombre: string; count: number }>;
    };
    tendencias: {
      ultimasSemanas: Array<{ semana: string; nuevos: number; modificados: number }>;
      evolucionNiveles: Array<{ fecha: string; criticos: number; altos: number }>;
    };
    metricas: {
      tiempoPromedioResolucion: number;
      porcentajeConSalvaguardas: number;
      efectividadPromedio: number;
    };
  }> {
    try {
      // Estadísticas generales
      const generalStats = await Risk.aggregate([
        { $match: { vigente: true } },
        {
          $group: {
            _id: null,
            totalRiesgos: { $sum: 1 },
            valorTotalEnRiesgo: { $sum: '$valorRiesgo' },
            riesgoPromedio: { $avg: { $multiply: ['$probabilidad', '$impacto'] } },
            riesgosCriticos: { $sum: { $cond: [{ $eq: ['$nivelRiesgo', 'Crítico'] }, 1, 0] } },
            riesgosAltos: { $sum: { $cond: [{ $eq: ['$nivelRiesgo', 'Alto'] }, 1, 0] } },
            riesgosMedios: { $sum: { $cond: [{ $eq: ['$nivelRiesgo', 'Medio'] }, 1, 0] } },
            riesgosBajos: { $sum: { $cond: [{ $eq: ['$nivelRiesgo', 'Bajo'] }, 1, 0] } },
            riesgosMuyBajos: { $sum: { $cond: [{ $eq: ['$nivelRiesgo', 'Muy Bajo'] }, 1, 0] } }
          }
        }
      ]);

      // Distribución por nivel con valores
      const distribucionNivel = await Risk.aggregate([
        { $match: { vigente: true } },
        {
          $group: {
            _id: '$nivelRiesgo',
            count: { $sum: 1 },
            valorTotal: { $sum: '$valorRiesgo' }
          }
        },
        { $sort: { valorTotal: -1 } }
      ]);

      // Top activos con más riesgos
      const distribucionActivo = await Risk.aggregate([
        { $match: { vigente: true } },
        {
          $lookup: {
            from: 'assets',
            localField: 'activo',
            foreignField: '_id',
            as: 'activoData'
          }
        },
        { $unwind: '$activoData' },
        {
          $group: {
            _id: '$activo',
            nombre: { $first: '$activoData.nombre' },
            count: { $sum: 1 },
            valorTotal: { $sum: '$valorRiesgo' }
          }
        },
        { $sort: { count: -1 } },
        { $limit: 10 }
      ]);

      // Top amenazas
      const distribucionAmenaza = await Risk.aggregate([
        { $match: { vigente: true } },
        {
          $lookup: {
            from: 'threats',
            localField: 'amenaza',
            foreignField: '_id',
            as: 'amenazaData'
          }
        },
        { $unwind: '$amenazaData' },
        {
          $group: {
            _id: '$amenaza',
            nombre: { $first: '$amenazaData.nombre' },
            count: { $sum: 1 }
          }
        },
        { $sort: { count: -1 } },
        { $limit: 10 }
      ]);

      // Tendencias últimas 8 semanas
      const hace8Semanas = new Date();
      hace8Semanas.setDate(hace8Semanas.getDate() - 56);

      const tendenciasSemanales = await Risk.aggregate([
        { $match: { fechaCalculo: { $gte: hace8Semanas }, vigente: true } },
        {
          $group: {
            _id: {
              $dateToString: { format: '%Y-W%U', date: '$fechaCalculo' }
            },
            nuevos: { $sum: 1 }
          }
        },
        { $sort: { '_id': 1 } },
        {
          $project: {
            semana: '$_id',
            nuevos: 1,
            modificados: '$nuevos', // Simplificado
            _id: 0
          }
        }
      ]);

      const general = generalStats[0] || {
        totalRiesgos: 0,
        riesgosCriticos: 0,
        riesgosAltos: 0,
        riesgosMedios: 0,
        riesgosBajos: 0,
        riesgosMuyBajos: 0,
        valorTotalEnRiesgo: 0,
        riesgoPromedio: 0
      };

      return {
        general,
        distribucion: {
          porNivel: distribucionNivel,
          porActivo: distribucionActivo,
          porAmenaza: distribucionAmenaza
        },
        tendencias: {
          ultimasSemanas: tendenciasSemanales,
          evolucionNiveles: [] // Simplificado por ahora
        },
        metricas: {
          tiempoPromedioResolucion: 0, // TODO: Implementar cuando haya fechas de resolución
          porcentajeConSalvaguardas: 0, // TODO: Implementar
          efectividadPromedio: 0 // TODO: Implementar
        }
      };
    } catch (error) {
      logger.error('Error obteniendo estadísticas de riesgos:', error);
      throw error;
    }
  }

  // ✅ MÉTODO FALTANTE: getRiskById
  async getRiskById(id: string): Promise<IRisk> {
    try {
      const risk = await Risk.findById(id)
        .populate('activo', 'codigo nombre tipo valoracion valorEconomico')
        .populate('amenaza', 'codigo nombre tipo probabilidad descripcion')
        .populate('vulnerabilidad', 'codigo nombre categoria facilidadExplotacion')
        .lean();

      if (!risk) {
        throw new AppError('Riesgo no encontrado', 404);
      }

      return risk as IRisk;
    } catch (error) {
      logger.error(`Error obteniendo riesgo ${id}:`, error);
      throw error;
    }
  }

  // ✅ MÉTODO FALTANTE: createRisk
  async createRisk(riskData: {
    activo: string;
    amenaza: string;
    vulnerabilidad?: string;
    probabilidad?: number;
    impacto?: number;
  }): Promise<IRisk> {
    try {
      // Si no se proporcionan probabilidad/impacto, calcular automáticamente
      if (!riskData.probabilidad || !riskData.impacto) {
        const calculatedRisk = await this.createOrUpdateRisk(
          riskData.activo,
          riskData.amenaza,
          riskData.vulnerabilidad
        );
        return calculatedRisk;
      }

      // Crear riesgo manual
      const calculos = await this.calculateRisk(
        riskData.activo,
        riskData.amenaza,
        riskData.vulnerabilidad
      );

      const riesgoFinal = riskData.probabilidad * riskData.impacto;
      const nivelRiesgo = this.determineRiskLevel(riesgoFinal);

      const newRisk = new Risk({
        activo: riskData.activo,
        amenaza: riskData.amenaza,
        vulnerabilidad: riskData.vulnerabilidad || null,
        calculos,
        valorRiesgo: riesgoFinal,
        nivelRiesgo,
        probabilidad: riskData.probabilidad,
        impacto: riskData.impacto,
        fechaCalculo: new Date(),
        vigente: true
      });

      await newRisk.save();
      await newRisk.populate('activo amenaza vulnerabilidad');

      logger.info(`Riesgo creado: ${newRisk._id}`);
      return newRisk;
    } catch (error) {
      logger.error('Error creando riesgo:', error);
      throw error;
    }
  }

  // ✅ MÉTODO FALTANTE: updateRisk
  async updateRisk(id: string, updateData: Partial<IRisk>): Promise<IRisk> {
    try {
      // Si se actualizan probabilidad o impacto, recalcular
      if (updateData.probabilidad !== undefined || updateData.impacto !== undefined) {
        const currentRisk = await Risk.findById(id);
        if (!currentRisk) {
          throw new AppError('Riesgo no encontrado', 404);
        }

        const newProbabilidad = updateData.probabilidad ?? currentRisk.probabilidad;
        const newImpacto = updateData.impacto ?? currentRisk.impacto;
        const newValorRiesgo = newProbabilidad * newImpacto;
        const newNivelRiesgo = this.determineRiskLevel(newValorRiesgo);

        updateData.valorRiesgo = newValorRiesgo;
        updateData.nivelRiesgo = newNivelRiesgo;
        updateData.fechaCalculo = new Date();
      }

      const risk = await Risk.findByIdAndUpdate(
        id,
        updateData,
        { new: true, runValidators: true }
      ).populate('activo amenaza vulnerabilidad');

      if (!risk) {
        throw new AppError('Riesgo no encontrado', 404);
      }

      logger.info(`Riesgo actualizado: ${risk._id}`);
      return risk;
    } catch (error) {
      logger.error(`Error actualizando riesgo ${id}:`, error);
      throw error;
    }
  }

  // ✅ MÉTODO FALTANTE: deleteRisk
  async deleteRisk(id: string): Promise<void> {
    try {
      const risk = await Risk.findById(id);
      if (!risk) {
        throw new AppError('Riesgo no encontrado', 404);
      }

      // Marcar como no vigente en lugar de eliminar físicamente
      risk.vigente = false;
      await risk.save();

      // O eliminar físicamente si se prefiere:
      // await Risk.findByIdAndDelete(id);

      logger.info(`Riesgo eliminado: ${id}`);
    } catch (error) {
      logger.error(`Error eliminando riesgo ${id}:`, error);
      throw error;
    }
  }
}

export const riskService = new RiskService();