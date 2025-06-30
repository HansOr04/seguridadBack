// src/services/DashboardService.ts - OPTIMIZADO CON CACHÉ Y TIPOS CORREGIDOS
import { Asset } from '../models/Asset';
import { Risk } from '../models/Risk';
import { Vulnerability } from '../models/Vulnerability';
import { Safeguard } from '../models/Safeguard';
import { Threat } from '../models/Threat';
import { AppError } from '../middleware/errorHandler';
import logger from '../utils/logger';

interface DashboardKPIs {
  totalActivos: number;
  riesgosCriticos: number;
  vulnerabilidadesActivas: number;
  salvaguardasImplementadas: number;
  tendenciaRiesgos: 'up' | 'down' | 'stable';
  efectividadPrograma: number;
  cvesCriticos: number;
  cvesTotal: number;
  timestamp: string;
}

interface TrendData {
  date: string;
  riesgos: number;
  vulnerabilidades: number;
  salvaguardas: number;
  cves: number;
}

interface Activity {
  id: string;
  type: 'vulnerability' | 'asset' | 'risk' | 'safeguard' | 'threat' | 'cve';
  action: 'created' | 'updated' | 'deleted' | 'mitigated' | 'implemented' | 'detected';
  title: string;
  description: string;
  timestamp: string;
  user: string;
  severity?: 'low' | 'medium' | 'high' | 'critical';
}

interface CacheEntry<T> {
  data: T;
  timestamp: number;
  ttl: number;
}

interface AssetStats {
  total: number;
  porTipo: Record<string, number>;
  porCriticidad: Record<string, number>;
}

interface RiskStats {
  total: number;
  criticos: number;
  altos: number;
  medios: number;
  bajos: number;
  tendencia: 'up' | 'down' | 'stable';
}

interface VulnerabilityStats {
  total: number;
  activas: number;
  criticas: number;
  porEstado: Record<string, number>;
}

interface SafeguardStats {
  total: number;
  implementadas: number;
  efectividad: number;
  porEstado: Record<string, number>;
}

interface CVEStats {
  total: number;
  criticos: number;
  recientes: number;
  frecuentes: number;
}

// ✅ INTERFACES PARA TIPADO DE AGREGACIONES MONGODB
interface AggregationCountResult {
  _id: string | null;
  count: number;
}

interface TotalCountResult {
  count: number;
}

interface TrendPeriodResult {
  _id: string;
  count: number;
}

interface TrendDataResult {
  date: string;
  count: number;
}

interface AssetAggregationResult {
  total: TotalCountResult[];
  porTipo: AggregationCountResult[];
  porCriticidad: AggregationCountResult[];
}

interface RiskAggregationResult {
  total: TotalCountResult[];
  porNivel: AggregationCountResult[];
  tendenciaData: TrendPeriodResult[];
}

interface VulnerabilityAggregationResult {
  total: TotalCountResult[];
  activas: TotalCountResult[];
  criticas: TotalCountResult[];
  porEstado: AggregationCountResult[];
}

interface SafeguardAggregationResult {
  total: TotalCountResult[];
  implementadas: TotalCountResult[];
  efectividad: Array<{ _id: null; avgEficacia: number }>;
  porEstado: AggregationCountResult[];
}

interface CVEAggregationResult {
  total: TotalCountResult[];
  criticos: TotalCountResult[];
  recientes: TotalCountResult[];
  frecuentes: TotalCountResult[];
}

export class DashboardService {
  private cache = new Map<string, CacheEntry<any>>();
  private readonly CACHE_TTL = 5 * 60 * 1000; // 5 minutos
  private readonly CACHE_TTL_TRENDS = 15 * 60 * 1000; // 15 minutos para tendencias
  
  // ✅ MÉTODO PRINCIPAL OPTIMIZADO - ENDPOINT UNIFICADO
  async getDashboardKPIs(): Promise<DashboardKPIs> {
    const cacheKey = 'dashboard:kpis';
    
    // Verificar caché
    const cached = this.getFromCache<DashboardKPIs>(cacheKey);
    if (cached) {
      logger.info('📦 KPIs obtenidos desde caché');
      return cached;
    }

    try {
      logger.info('📊 Calculando KPIs del dashboard con agregaciones optimizadas...');

      // ✅ AGREGACIÓN UNIFICADA - Una sola consulta por colección
      const [
        assetStats,
        riskStats, 
        vulnerabilityStats,
        safeguardStats,
        cveStats,
        tendenciaData
      ] = await Promise.all([
        this.getAssetStats(),
        this.getRiskStats(),
        this.getVulnerabilityStats(),
        this.getSafeguardStats(),
        this.getCVEStats(),
        this.calculateRiskTrend()
      ]);

      // Calcular efectividad del programa
      const efectividadPrograma = safeguardStats.total > 0 
        ? Math.round((safeguardStats.implementadas / safeguardStats.total) * 100)
        : 0;

      const kpis: DashboardKPIs = {
        totalActivos: assetStats.total,
        riesgosCriticos: riskStats.criticos + riskStats.altos, // Críticos + Altos
        vulnerabilidadesActivas: vulnerabilityStats.activas,
        salvaguardasImplementadas: safeguardStats.implementadas,
        tendenciaRiesgos: riskStats.tendencia,
        efectividadPrograma,
        cvesCriticos: cveStats.criticos,
        cvesTotal: cveStats.total,
        timestamp: new Date().toISOString()
      };

      // Guardar en caché
      this.setCache(cacheKey, kpis, this.CACHE_TTL);

      logger.info('✅ KPIs calculados y cacheados exitosamente:', {
        ...kpis,
        timestamp: undefined // No loggear timestamp
      });
      
      return kpis;

    } catch (error) {
      logger.error('❌ Error calculando KPIs del dashboard:', error);
      throw new AppError('Error al calcular KPIs del dashboard', 500);
    }
  }

  // ✅ MÉTODOS PRIVADOS OPTIMIZADOS CON AGREGACIONES

  private async getAssetStats(): Promise<AssetStats> {
    const cacheKey = 'stats:assets';
    const cached = this.getFromCache<AssetStats>(cacheKey);
    if (cached) return cached;

    try {
      // Agregación unificada para obtener todas las estadísticas de activos
      const [aggregationResult] = await Asset.aggregate<AssetAggregationResult>([
        {
          $facet: {
            total: [{ $count: "count" }],
            porTipo: [
              { $group: { _id: "$tipo", count: { $sum: 1 } } }
            ],
            porCriticidad: [
              { $group: { _id: "$criticidad", count: { $sum: 1 } } }
            ]
          }
        }
      ]);

      const stats: AssetStats = {
        total: aggregationResult.total[0]?.count || 0,
        porTipo: {},
        porCriticidad: {}
      };

      // ✅ CORRECCIÓN: Tipado específico para los elementos
      aggregationResult.porTipo.forEach((item: AggregationCountResult) => {
        if (item._id) {
          stats.porTipo[item._id] = item.count;
        }
      });

      aggregationResult.porCriticidad.forEach((item: AggregationCountResult) => {
        if (item._id) {
          stats.porCriticidad[item._id] = item.count;
        }
      });

      this.setCache(cacheKey, stats, this.CACHE_TTL);
      return stats;

    } catch (error) {
      logger.error('❌ Error obteniendo estadísticas de activos:', error);
      return { total: 0, porTipo: {}, porCriticidad: {} };
    }
  }

  private async getRiskStats(): Promise<RiskStats> {
    const cacheKey = 'stats:risks';
    const cached = this.getFromCache<RiskStats>(cacheKey);
    if (cached) return cached;

    try {
      // Agregación unificada para riesgos
      const [aggregationResult] = await Risk.aggregate<RiskAggregationResult>([
        {
          $facet: {
            total: [{ $count: "count" }],
            porNivel: [
              { $group: { _id: "$nivelRiesgo", count: { $sum: 1 } } }
            ],
            tendenciaData: [
              {
                $match: {
                  fechaCreacion: { 
                    $gte: new Date(Date.now() - 14 * 24 * 60 * 60 * 1000) // Últimas 2 semanas
                  }
                }
              },
              {
                $group: {
                  _id: {
                    $cond: {
                      if: { $gte: ["$fechaCreacion", new Date(Date.now() - 7 * 24 * 60 * 60 * 1000)] },
                      then: "current",
                      else: "previous"
                    }
                  },
                  count: { $sum: 1 }
                }
              }
            ]
          }
        }
      ]);

      const stats: RiskStats = {
        total: aggregationResult.total[0]?.count || 0,
        criticos: 0,
        altos: 0,
        medios: 0,
        bajos: 0,
        tendencia: 'stable'
      };

      // ✅ CORRECCIÓN: Tipado específico para los elementos
      aggregationResult.porNivel.forEach((item: AggregationCountResult) => {
        const nivel = item._id?.toLowerCase();
        if (nivel === 'crítico' || nivel === 'critico') {
          stats.criticos = item.count;
        } else if (nivel === 'alto') {
          stats.altos = item.count;
        } else if (nivel === 'medio') {
          stats.medios = item.count;
        } else if (nivel === 'bajo') {
          stats.bajos = item.count;
        }
      });

      // Calcular tendencia
      const tendenciaMap = new Map<string, number>();
      aggregationResult.tendenciaData.forEach((item: TrendPeriodResult) => {
        tendenciaMap.set(item._id, item.count);
      });

      const currentWeek = tendenciaMap.get('current') || 0;
      const previousWeek = tendenciaMap.get('previous') || 0;

      if (currentWeek > previousWeek) {
        stats.tendencia = 'up';
      } else if (currentWeek < previousWeek) {
        stats.tendencia = 'down';
      }

      this.setCache(cacheKey, stats, this.CACHE_TTL);
      return stats;

    } catch (error) {
      logger.error('❌ Error obteniendo estadísticas de riesgos:', error);
      return { total: 0, criticos: 0, altos: 0, medios: 0, bajos: 0, tendencia: 'stable' };
    }
  }

  private async getVulnerabilityStats(): Promise<VulnerabilityStats> {
    const cacheKey = 'stats:vulnerabilities';
    const cached = this.getFromCache<VulnerabilityStats>(cacheKey);
    if (cached) return cached;

    try {
      // Agregación unificada para vulnerabilidades
      const [aggregationResult] = await Vulnerability.aggregate<VulnerabilityAggregationResult>([
        {
          $facet: {
            total: [{ $count: "count" }],
            activas: [
              { $match: { estado: 'abierta' } },
              { $count: "count" }
            ],
            criticas: [
              { 
                $match: { 
                  estado: 'abierta',
                  facilidadExplotacion: { $gte: 8 }
                }
              },
              { $count: "count" }
            ],
            porEstado: [
              { $group: { _id: "$estado", count: { $sum: 1 } } }
            ]
          }
        }
      ]);

      const stats: VulnerabilityStats = {
        total: aggregationResult.total[0]?.count || 0,
        activas: aggregationResult.activas[0]?.count || 0,
        criticas: aggregationResult.criticas[0]?.count || 0,
        porEstado: {}
      };

      // ✅ CORRECCIÓN: Tipado específico para los elementos
      aggregationResult.porEstado.forEach((item: AggregationCountResult) => {
        if (item._id) {
          stats.porEstado[item._id] = item.count;
        }
      });

      this.setCache(cacheKey, stats, this.CACHE_TTL);
      return stats;

    } catch (error) {
      logger.error('❌ Error obteniendo estadísticas de vulnerabilidades:', error);
      return { total: 0, activas: 0, criticas: 0, porEstado: {} };
    }
  }

  private async getSafeguardStats(): Promise<SafeguardStats> {
    const cacheKey = 'stats:safeguards';
    const cached = this.getFromCache<SafeguardStats>(cacheKey);
    if (cached) return cached;

    try {
      // Agregación unificada para salvaguardas
      const [aggregationResult] = await Safeguard.aggregate<SafeguardAggregationResult>([
        {
          $facet: {
            total: [{ $count: "count" }],
            implementadas: [
              { $match: { estado: 'implementada' } },
              { $count: "count" }
            ],
            efectividad: [
              { 
                $match: { 
                  estado: 'implementada',
                  eficacia: { $exists: true, $ne: null }
                }
              },
              {
                $group: {
                  _id: null,
                  avgEficacia: { $avg: "$eficacia" }
                }
              }
            ],
            porEstado: [
              { $group: { _id: "$estado", count: { $sum: 1 } } }
            ]
          }
        }
      ]);

      const stats: SafeguardStats = {
        total: aggregationResult.total[0]?.count || 0,
        implementadas: aggregationResult.implementadas[0]?.count || 0,
        efectividad: Math.round(aggregationResult.efectividad[0]?.avgEficacia || 0),
        porEstado: {}
      };

      // ✅ CORRECCIÓN: Tipado específico para los elementos
      aggregationResult.porEstado.forEach((item: AggregationCountResult) => {
        if (item._id) {
          stats.porEstado[item._id] = item.count;
        }
      });

      this.setCache(cacheKey, stats, this.CACHE_TTL);
      return stats;

    } catch (error) {
      logger.error('❌ Error obteniendo estadísticas de salvaguardas:', error);
      return { total: 0, implementadas: 0, efectividad: 0, porEstado: {} };
    }
  }

  private async getCVEStats(): Promise<CVEStats> {
    const cacheKey = 'stats:cves';
    const cached = this.getFromCache<CVEStats>(cacheKey);
    if (cached) return cached;

    try {
      // Agregación unificada para CVEs desde la colección de threats
      const [aggregationResult] = await Threat.aggregate<CVEAggregationResult>([
        {
          $match: { origen: 'CVE' }
        },
        {
          $facet: {
            total: [{ $count: "count" }],
            criticos: [
              { 
                $match: { 
                  "cveData.severity": { $in: ['CRITICAL', 'HIGH'] }
                }
              },
              { $count: "count" }
            ],
            recientes: [
              {
                $match: {
                  "cveData.publishedDate": {
                    $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) // Últimos 30 días
                  }
                }
              },
              { $count: "count" }
            ],
            frecuentes: [
              {
                $match: {
                  aplicaA: { $exists: true, $ne: [] }
                }
              },
              {
                $addFields: {
                  numActivos: { $size: { $ifNull: ["$aplicaA", []] } }
                }
              },
              {
                $match: {
                  numActivos: { $gte: 3 } // CVEs que afectan 3+ activos
                }
              },
              { $count: "count" }
            ]
          }
        }
      ]);

      const stats: CVEStats = {
        total: aggregationResult.total[0]?.count || 0,
        criticos: aggregationResult.criticos[0]?.count || 0,
        recientes: aggregationResult.recientes[0]?.count || 0,
        frecuentes: aggregationResult.frecuentes[0]?.count || 0
      };

      this.setCache(cacheKey, stats, this.CACHE_TTL);
      return stats;

    } catch (error) {
      logger.error('❌ Error obteniendo estadísticas de CVEs:', error);
      return { total: 0, criticos: 0, recientes: 0, frecuentes: 0 };
    }
  }

  // ✅ MANTENER MÉTODO DE TENDENCIA OPTIMIZADO
  private async calculateRiskTrend(): Promise<'up' | 'down' | 'stable'> {
    const cacheKey = 'trend:risks';
    const cached = this.getFromCache<'up' | 'down' | 'stable'>(cacheKey);
    if (cached) return cached;

    try {
      const sevenDaysAgo = new Date();
      sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
      
      const fourteenDaysAgo = new Date();
      fourteenDaysAgo.setDate(fourteenDaysAgo.getDate() - 14);

      const [currentWeekRisks, previousWeekRisks] = await Promise.all([
        Risk.countDocuments({ 
          fechaCreacion: { $gte: sevenDaysAgo },
          nivelRiesgo: { $in: ['Crítico', 'Alto'] }
        }),
        Risk.countDocuments({ 
          fechaCreacion: { $gte: fourteenDaysAgo, $lt: sevenDaysAgo },
          nivelRiesgo: { $in: ['Crítico', 'Alto'] }
        })
      ]);

      let trend: 'up' | 'down' | 'stable' = 'stable';
      if (currentWeekRisks > previousWeekRisks) trend = 'up';
      else if (currentWeekRisks < previousWeekRisks) trend = 'down';

      this.setCache(cacheKey, trend, this.CACHE_TTL);
      return trend;

    } catch (error) {
      logger.error('❌ Error calculando tendencia de riesgos:', error);
      return 'stable';
    }
  }

  // ✅ MÉTODO DE TENDENCIAS OPTIMIZADO
  async getTrends(timeRange: '7d' | '30d' | '90d'): Promise<TrendData[]> {
    const cacheKey = `trends:${timeRange}`;
    const cached = this.getFromCache<TrendData[]>(cacheKey);
    if (cached) return cached;

    try {
      logger.info(`📈 Obteniendo tendencias para ${timeRange}...`);

      const days = timeRange === '7d' ? 7 : timeRange === '30d' ? 30 : 90;
      const startDate = new Date();
      startDate.setDate(startDate.getDate() - days);

      // Usar agregación para obtener todas las tendencias de una vez
      const [riskTrends, vulnTrends, safeguardTrends, cveTrends] = await Promise.all([
        this.getTrendDataForModel(Risk, 'fechaCreacion', startDate, days),
        this.getTrendDataForModel(Vulnerability, 'fechaDeteccion', startDate, days),
        this.getTrendDataForModel(Safeguard, 'fechaImplementacion', startDate, days),
        this.getCVETrendData(startDate, days)
      ]);

      // Combinar datos por fecha
      const trendsMap = new Map<string, TrendData>();
      
      // Inicializar fechas
      for (let i = 0; i < days; i++) {
        const date = new Date(startDate);
        date.setDate(date.getDate() + i);
        const dateStr = date.toISOString().split('T')[0];
        
        trendsMap.set(dateStr, {
          date: dateStr,
          riesgos: 0,
          vulnerabilidades: 0,
          salvaguardas: 0,
          cves: 0
        });
      }

      // Poblar con datos reales
      riskTrends.forEach((item: TrendDataResult) => {
        const existing = trendsMap.get(item.date);
        if (existing) existing.riesgos = item.count;
      });

      vulnTrends.forEach((item: TrendDataResult) => {
        const existing = trendsMap.get(item.date);
        if (existing) existing.vulnerabilidades = item.count;
      });

      safeguardTrends.forEach((item: TrendDataResult) => {
        const existing = trendsMap.get(item.date);
        if (existing) existing.salvaguardas = item.count;
      });

      cveTrends.forEach((item: TrendDataResult) => {
        const existing = trendsMap.get(item.date);
        if (existing) existing.cves = item.count;
      });

      const trendsData = Array.from(trendsMap.values()).sort((a, b) => 
        new Date(a.date).getTime() - new Date(b.date).getTime()
      );

      this.setCache(cacheKey, trendsData, this.CACHE_TTL_TRENDS);
      logger.info(`✅ Tendencias obtenidas: ${trendsData.length} puntos de datos`);
      
      return trendsData;

    } catch (error) {
      logger.error('❌ Error obteniendo tendencias:', error);
      throw new AppError('Error al obtener datos de tendencias', 500);
    }
  }

  private async getTrendDataForModel(model: any, dateField: string, startDate: Date, days: number): Promise<TrendDataResult[]> {
    const endDate = new Date(startDate);
    endDate.setDate(endDate.getDate() + days);

    return await model.aggregate([
      {
        $match: {
          [dateField]: { $gte: startDate, $lt: endDate }
        }
      },
      {
        $group: {
          _id: {
            $dateToString: {
              format: "%Y-%m-%d",
              date: `${dateField}`
            }
          },
          count: { $sum: 1 }
        }
      },
      {
        $project: {
          date: "$_id",
          count: 1,
          _id: 0
        }
      }
    ]);
  }

  private async getCVETrendData(startDate: Date, days: number): Promise<TrendDataResult[]> {
    const endDate = new Date(startDate);
    endDate.setDate(endDate.getDate() + days);

    return await Threat.aggregate([
      {
        $match: {
          origen: 'CVE',
          "cveData.publishedDate": { $gte: startDate, $lt: endDate }
        }
      },
      {
        $group: {
          _id: {
            $dateToString: {
              format: "%Y-%m-%d",
              date: "$cveData.publishedDate"
            }
          },
          count: { $sum: 1 }
        }
      },
      {
        $project: {
          date: "$_id",
          count: 1,
          _id: 0
        }
      }
    ]);
  }

  // ✅ ACTIVIDADES RECIENTES OPTIMIZADO
  async getRecentActivities(limit: number = 10): Promise<Activity[]> {
    const cacheKey = `activities:${limit}`;
    const cached = this.getFromCache<Activity[]>(cacheKey);
    if (cached) return cached;

    try {
      logger.info(`📝 Obteniendo ${limit} actividades recientes...`);

      const activities: Activity[] = [];
      const limitPerType = Math.ceil(limit / 4);

      // Obtener datos en paralelo de todas las fuentes
      const [vulnerabilities, assets, safeguards, cves] = await Promise.all([
        Vulnerability.find().sort({ fechaDeteccion: -1 }).limit(limitPerType).lean(),
        Asset.find().sort({ fechaCreacion: -1 }).limit(limitPerType).lean(),
        Safeguard.find({ estado: 'implementada' }).sort({ fechaImplementacion: -1 }).limit(limitPerType).lean(),
        Threat.find({ origen: 'CVE' }).sort({ "cveData.publishedDate": -1 }).limit(limitPerType).lean()
      ]);

      // Procesar vulnerabilidades
      vulnerabilities.forEach(vuln => {
        activities.push({
          id: vuln._id.toString(),
          type: 'vulnerability',
          action: 'created',
          title: `Nueva vulnerabilidad: ${vuln.categoria}`,
          description: `Vulnerabilidad detectada - Facilidad: ${vuln.facilidadExplotacion}/10`,
          timestamp: vuln.fechaDeteccion.toISOString(),
          user: 'Sistema Automático',
          severity: this.mapFacilityToSeverity(vuln.facilidadExplotacion)
        });
      });

      // Procesar activos
      assets.forEach(asset => {
        activities.push({
          id: asset._id.toString(),
          type: 'asset',
          action: 'created',
          title: `Nuevo activo registrado`,
          description: `${asset.nombre} - ${asset.tipo}`,
          timestamp: asset.fechaCreacion.toISOString(),
          user: asset.propietario || 'Usuario desconocido',
          severity: 'medium'
        });
      });

      // Procesar salvaguardas
      safeguards.forEach(safeguard => {
        activities.push({
          id: safeguard._id.toString(),
          type: 'safeguard',
          action: 'implemented',
          title: `Salvaguarda implementada`,
          description: `${safeguard.nombre} - ${safeguard.categoria}`,
          timestamp: safeguard.fechaImplementacion?.toISOString() || new Date().toISOString(),
          user: safeguard.responsable || 'Responsable desconocido',
          severity: 'low'
        });
      });

      // Procesar CVEs
      cves.forEach(cve => {
        activities.push({
          id: cve._id.toString(),
          type: 'cve',
          action: 'detected',
          title: `CVE detectado: ${cve.cveData?.cveId || 'Desconocido'}`,
          description: `Severidad: ${cve.cveData?.severity || 'N/A'}`,
          timestamp: (cve.cveData?.publishedDate || new Date()).toISOString(),
          user: 'Sistema CVE',
          severity: this.mapCVESeverityToLocal(cve.cveData?.severity)
        });
      });

      // Ordenar por timestamp y limitar
      const sortedActivities = activities
        .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
        .slice(0, limit);

      this.setCache(cacheKey, sortedActivities, this.CACHE_TTL);
      logger.info(`✅ ${sortedActivities.length} actividades obtenidas y cacheadas`);
      
      return sortedActivities;

    } catch (error) {
      logger.error('❌ Error obteniendo actividades:', error);
      throw new AppError('Error al obtener actividades recientes', 500);
    }
  }

  // ✅ ESTADÍSTICAS GENERALES OPTIMIZADO
  async getGeneralStats() {
    const cacheKey = 'stats:general';
    const cached = this.getFromCache(cacheKey);
    if (cached) return cached;

    try {
      // Usar las estadísticas ya calculadas y cacheadas
      const [assetStats, riskStats, vulnerabilityStats, safeguardStats, cveStats] = await Promise.all([
        this.getAssetStats(),
        this.getRiskStats(),
        this.getVulnerabilityStats(),
        this.getSafeguardStats(),
        this.getCVEStats()
      ]);

      const generalStats = {
        resumen: {
          totalActivos: assetStats.total,
          totalRiesgos: riskStats.total,
          totalVulnerabilidades: vulnerabilityStats.total,
          totalAmenazas: cveStats.total,
          totalSalvaguardas: safeguardStats.total
        },
        criticos: {
          riesgosCriticos: riskStats.criticos,
          vulnerabilidadesCriticas: vulnerabilityStats.criticas,
          cvesCriticos: cveStats.criticos
        },
        implementacion: {
          salvaguardasImplementadas: safeguardStats.implementadas,
          porcentajeImplementacion: safeguardStats.total > 0 
            ? Math.round((safeguardStats.implementadas / safeguardStats.total) * 100)
            : 0,
          efectividadPromedio: safeguardStats.efectividad
        },
        distribucion: {
          activosPorTipo: assetStats.porTipo,
          riesgosPorNivel: {
            criticos: riskStats.criticos,
            altos: riskStats.altos,
            medios: riskStats.medios,
            bajos: riskStats.bajos
          },
          vulnerabilidadesPorEstado: vulnerabilityStats.porEstado,
          salvaguardasPorEstado: safeguardStats.porEstado
        }
      };

      this.setCache(cacheKey, generalStats, this.CACHE_TTL_TRENDS);
      return generalStats;

    } catch (error) {
      logger.error('❌ Error obteniendo estadísticas generales:', error);
      throw new AppError('Error al obtener estadísticas generales', 500);
    }
  }

  // ✅ SISTEMA DE CACHÉ
  private getFromCache<T>(key: string): T | null {
    const entry = this.cache.get(key);
    if (!entry) return null;

    const now = Date.now();
    if (now - entry.timestamp > entry.ttl) {
      this.cache.delete(key);
      return null;
    }

    return entry.data as T;
  }

  private setCache<T>(key: string, data: T, ttl: number = this.CACHE_TTL): void {
    this.cache.set(key, {
      data,
      timestamp: Date.now(),
      ttl
    });
  }

  public clearCache(): void {
    this.cache.clear();
    logger.info('🗑️ Caché del dashboard limpiado');
  }

  public getCacheStats(): { size: number; keys: string[] } {
    return {
      size: this.cache.size,
      keys: Array.from(this.cache.keys())
    };
  }

  // ✅ INVALIDAR CACHÉ ESPECÍFICO
  public invalidateCache(pattern?: string): void {
    if (!pattern) {
      this.clearCache();
      return;
    }

    const keysToDelete: string[] = [];
    for (const key of this.cache.keys()) {
      if (key.includes(pattern)) {
        keysToDelete.push(key);
      }
    }

    keysToDelete.forEach(key => this.cache.delete(key));
    logger.info(`🗑️ Invalidado caché con patrón: ${pattern} (${keysToDelete.length} entradas)`);
  }

  // ✅ MÉTODOS AUXILIARES
  private mapFacilityToSeverity(facilidad: number): 'low' | 'medium' | 'high' | 'critical' {
    if (facilidad >= 8) return 'critical';
    if (facilidad >= 6) return 'high';
    if (facilidad >= 4) return 'medium';
    return 'low';
  }

  private mapCVESeverityToLocal(cveSeverity?: string): 'low' | 'medium' | 'high' | 'critical' {
    if (!cveSeverity) return 'medium';
    
    switch (cveSeverity.toUpperCase()) {
      case 'CRITICAL': return 'critical';
      case 'HIGH': return 'high';
      case 'MEDIUM': return 'medium';
      case 'LOW': return 'low';
      default: return 'medium';
    }
  }

  // ✅ MÉTODO PARA CALENTAMIENTO DE CACHÉ
  public async warmUpCache(): Promise<void> {
    logger.info('🔥 Iniciando calentamiento de caché...');
    
    try {
      await Promise.all([
        this.getDashboardKPIs(),
        this.getTrends('7d'),
        this.getTrends('30d'),
        this.getRecentActivities(10),
        this.getGeneralStats()
      ]);
      
      logger.info('✅ Caché calentado exitosamente');
    } catch (error) {
      logger.error('❌ Error calentando caché:', error);
    }
  }

  // ✅ MÉTODO PARA HEALTH CHECK
  public async getHealthCheck(): Promise<{
    status: 'healthy' | 'degraded' | 'unhealthy';
    cache: { size: number; hitRate?: number };
    performance: { avgResponseTime: number };
    timestamp: string;
  }> {
    const startTime = Date.now();
    
    try {
      // Verificar conexión a base de datos con query simple
      await Asset.findOne().limit(1);
      
      const responseTime = Date.now() - startTime;
      
      return {
        status: responseTime < 1000 ? 'healthy' : responseTime < 3000 ? 'degraded' : 'unhealthy',
        cache: {
          size: this.cache.size
        },
        performance: {
          avgResponseTime: responseTime
        },
        timestamp: new Date().toISOString()
      };
      
    } catch (error) {
      logger.error('❌ Health check failed:', error);
      return {
        status: 'unhealthy',
        cache: { size: this.cache.size },
        performance: { avgResponseTime: Date.now() - startTime },
        timestamp: new Date().toISOString()
      };
    }
  }
}

export const dashboardService = new DashboardService();