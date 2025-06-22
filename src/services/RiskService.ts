import { Asset } from '../models/Asset';
import { Threat } from '../models/Threat';
import { Vulnerability } from '../models/Vulnerability';
import { Risk } from '../models/Risk';
import { IRisk, CalculosRiesgo, NivelRiesgo, IAsset } from '../types';
import { AppError } from '../middleware/errorHandler';
import logger from '../utils/logger';

export class RiskService {
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
}

export const riskService = new RiskService();