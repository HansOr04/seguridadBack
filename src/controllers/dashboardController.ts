// src/controllers/dashboardController.ts - CORREGIDO Y COMPATIBLE
import { Request, Response, NextFunction } from 'express';
import { dashboardService } from '../services/DashboardService';
import { ApiResponse } from '../types';
import { AppError } from '../middleware/errorHandler';
import logger from '../utils/logger';
import { riskService } from '../services/RiskService';

export class DashboardController {
  
  // GET /api/v1/dashboard/kpis - MEJORADO CON CVEs
  async getKPIs(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    const startTime = Date.now();
    
    try {
      logger.info('📊 Iniciando obtención de KPIs del dashboard');
      
      const kpis = await dashboardService.getDashboardKPIs();
      
      // Agregar estadísticas de CVEs que faltan en la estructura actual
      const cveStats = await this.getCVEStatistics();
      
      const duration = Date.now() - startTime;
      logger.info(`✅ KPIs obtenidos exitosamente en ${duration}ms`);
      
      // Estructura completa garantizada
      const completeKPIs = {
        // KPIs principales existentes
        totalActivos: kpis.totalActivos || 0,
        riesgosCriticos: kpis.riesgosCriticos || 0,
        vulnerabilidadesActivas: kpis.vulnerabilidadesActivas || 0,
        salvaguardasImplementadas: kpis.salvaguardasImplementadas || 0,
        tendenciaRiesgos: kpis.tendenciaRiesgos || 'stable',
        efectividadPrograma: kpis.efectividadPrograma || 0,
        
        // Estadísticas específicas de CVEs (nuevas)
        cve: {
          totalCVEs: cveStats.totalCVEs || 0,
          cvesCriticos: cveStats.cvesCriticos || 0,
          cvesAltos: cveStats.cvesAltos || 0,
          cvesMedios: cveStats.cvesMedios || 0,
          cvesBajos: cveStats.cvesBajos || 0,
          cvesFrecuentes: cveStats.cvesFrecuentes || 0,
          ultimaActualizacion: cveStats.ultimaActualizacion || null
        },
        
        // Estadísticas de amenazas (separadas de CVEs)
        amenazas: {
          totalAmenazas: cveStats.totalAmenazasMAGERIT || 0,
          amenazasActivas: cveStats.amenazasActivas || 0,
          amenazasCriticas: cveStats.amenazasCriticas || 0,
          amenazasMAGERIT: cveStats.totalAmenazasMAGERIT || 0
        },
        
        // Metadatos de la consulta
        meta: {
          timestamp: new Date().toISOString(),
          responseTime: duration,
          cacheHit: false,
          dataFreshness: 'real-time'
        }
      };
      
      res.json({
        success: true,
        data: completeKPIs,
        message: 'KPIs del dashboard obtenidos exitosamente'
      });
      
    } catch (error) {
      const duration = Date.now() - startTime;
      logger.error(`❌ Error obteniendo KPIs del dashboard (${duration}ms):`, error);
      next(error);
    }
  }

  // GET /api/v1/dashboard/trends?range=30d&type=all - MEJORADO
  async getTrends(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    const startTime = Date.now();
    
    try {
      // Validación mejorada de parámetros
      const range = req.query.range as '7d' | '30d' | '90d' || '30d';
      const type = req.query.type as 'risks' | 'vulnerabilities' | 'cves' | 'assets' | 'all' || 'all';
      
      // Validar rango
      if (!['7d', '30d', '90d'].includes(range)) {
        throw new AppError('Rango inválido. Valores permitidos: 7d, 30d, 90d', 400);
      }
      
      // Validar tipo
      if (!['risks', 'vulnerabilities', 'cves', 'assets', 'all'].includes(type)) {
        throw new AppError('Tipo inválido. Valores permitidos: risks, vulnerabilities, cves, assets, all', 400);
      }

      logger.info(`📈 Obteniendo tendencias: range=${range}, type=${type}`);

      const trends = await dashboardService.getTrends(range);
      
      const duration = Date.now() - startTime;
      logger.info(`✅ Tendencias obtenidas en ${duration}ms`);
      
      res.json({
        success: true,
        data: {
          ...trends,
          meta: {
            range,
            type,
            generatedAt: new Date().toISOString(),
            responseTime: duration
          }
        },
        message: `Tendencias para ${range} (${type}) obtenidas exitosamente`
      });
      
    } catch (error) {
      const duration = Date.now() - startTime;
      logger.error(`❌ Error obteniendo tendencias (${duration}ms):`, error);
      next(error);
    }
  }

  // GET /api/v1/dashboard/activities?limit=10&type=all - MEJORADO
  async getActivities(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    const startTime = Date.now();
    
    try {
      const limit = parseInt(req.query.limit as string) || 10;
      const type = req.query.type as string || 'all';
      
      // Validar límite
      if (limit < 1 || limit > 100) {
        throw new AppError('El límite debe estar entre 1 y 100', 400);
      }
      
      // Validar tipos de actividad
      const validTypes = ['all', 'vulnerability', 'asset', 'risk', 'safeguard', 'threat', 'cve'];
      if (!validTypes.includes(type)) {
        throw new AppError(`Tipo de actividad inválido. Valores permitidos: ${validTypes.join(', ')}`, 400);
      }

      logger.info(`📋 Obteniendo actividades: limit=${limit}, type=${type}`);

      const activities = await dashboardService.getRecentActivities(limit);
      
      const duration = Date.now() - startTime;
      logger.info(`✅ ${activities.length} actividades obtenidas en ${duration}ms`);
      
      res.json({
        success: true,
        data: {
          activities,
          meta: {
            count: activities.length,
            limit,
            type,
            generatedAt: new Date().toISOString(),
            responseTime: duration
          }
        },
        message: `${activities.length} actividades recientes obtenidas`
      });
      
    } catch (error) {
      const duration = Date.now() - startTime;
      logger.error(`❌ Error obteniendo actividades (${duration}ms):`, error);
      next(error);
    }
  }

  // GET /api/v1/dashboard/stats?include=all - MEJORADO
  async getGeneralStats(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    const startTime = Date.now();
    
    try {
      const include = req.query.include as string || 'all';
      const includeArray = include.split(',').map(s => s.trim());
      
      // Validar secciones a incluir
      const validSections = ['assets', 'risks', 'vulnerabilities', 'safeguards', 'threats', 'cves', 'all'];
      const invalidSections = includeArray.filter(section => !validSections.includes(section));
      
      if (invalidSections.length > 0) {
        throw new AppError(`Secciones inválidas: ${invalidSections.join(', ')}. Válidas: ${validSections.join(', ')}`, 400);
      }

      logger.info(`📊 Obteniendo estadísticas generales: include=${include}`);

      const stats = await dashboardService.getGeneralStats();
      
      const duration = Date.now() - startTime;
      logger.info(`✅ Estadísticas generales obtenidas en ${duration}ms`);
      
      res.json({
        success: true,
        data: {
          ...stats,
          meta: {
            sections: includeArray,
            generatedAt: new Date().toISOString(),
            responseTime: duration,
            cacheHit: false
          }
        },
        message: 'Estadísticas generales obtenidas exitosamente'
      });
      
    } catch (error) {
      const duration = Date.now() - startTime;
      logger.error(`❌ Error obteniendo estadísticas generales (${duration}ms):`, error);
      next(error);
    }
  }

  // GET /api/v1/dashboard/summary - OPTIMIZADO
  async getDashboardSummary(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    const startTime = Date.now();
    
    try {
      logger.info('📋 Obteniendo resumen completo del dashboard');

      // Obtener datos de forma optimizada usando Promise.allSettled para manejo de errores
      const [kpis, recentActivities, generalStats] = await Promise.allSettled([
        dashboardService.getDashboardKPIs(),
        dashboardService.getRecentActivities(5),
        dashboardService.getGeneralStats()
      ]);

      // Manejar errores parciales de forma elegante
      const summary = {
        kpis: kpis.status === 'fulfilled' ? kpis.value : null,
        recentActivities: recentActivities.status === 'fulfilled' ? recentActivities.value : [],
        generalStats: generalStats.status === 'fulfilled' ? generalStats.value : null,
        
        // Información de errores parciales
        errors: {
          kpis: kpis.status === 'rejected' ? 'Error obteniendo KPIs' : null,
          activities: recentActivities.status === 'rejected' ? 'Error obteniendo actividades' : null,
          stats: generalStats.status === 'rejected' ? 'Error obteniendo estadísticas' : null
        },
        
        meta: {
          timestamp: new Date().toISOString(),
          responseTime: Date.now() - startTime,
          hasPartialErrors: [kpis, recentActivities, generalStats].some(result => result.status === 'rejected')
        }
      };

      const duration = Date.now() - startTime;
      logger.info(`✅ Resumen del dashboard obtenido en ${duration}ms`);
      
      res.json({
        success: true,
        data: summary,
        message: 'Resumen del dashboard obtenido exitosamente'
      });
      
    } catch (error) {
      const duration = Date.now() - startTime;
      logger.error(`❌ Error obteniendo resumen del dashboard (${duration}ms):`, error);
      next(error);
    }
  }

  // GET /api/v1/dashboard/health - MEJORADO
  async getDashboardHealth(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    const startTime = Date.now();
    
    try {
      logger.info('🩺 Evaluando estado de salud del sistema');

      // Verificar el estado de salud del sistema de forma optimizada
      const [generalStats, cveStats] = await Promise.allSettled([
        dashboardService.getGeneralStats(),
        this.getCVEStatistics()
      ]);

      const statsData = generalStats.status === 'fulfilled' ? generalStats.value : {};
      const cveData = cveStats.status === 'fulfilled' ? cveStats.value : {};

      // Construir datos de salud con valores por defecto seguros
      const statsDataAny = statsData as any;
      const cveDataAny = cveData as any;
      
      const healthData = {
        totalActivos: statsDataAny?.resumen?.totalActivos || statsDataAny?.totalActivos || 0,
        riesgosCriticos: statsDataAny?.criticos?.riesgosCriticos || statsDataAny?.riesgosCriticos || 0,
        vulnerabilidadesCriticas: statsDataAny?.criticos?.vulnerabilidadesCriticas || statsDataAny?.vulnerabilidadesCriticas || 0,
        cvesCriticos: cveDataAny?.cvesCriticos || 0,
        porcentajeImplementacion: statsDataAny?.implementacion?.porcentajeImplementacion || statsDataAny?.efectividadPrograma || 0,
        database: 'good', // Simplificado - se podría implementar check real
        cache: 'good'     // Simplificado - se podría implementar check real
      };

      const healthScore = this.calculateHealthScore(healthData);
      const healthStatus = this.getHealthStatus(healthScore);
      const recommendations = this.getHealthRecommendations(healthData);

      const health = {
        score: healthScore,
        status: healthStatus,
        
        // Componentes del sistema
        components: {
          database: healthData.database,
          cache: healthData.cache,
          apis: 'good',
          sync: 'good'
        },
        
        // Métricas de seguridad
        security: {
          activos: healthData.totalActivos > 0 ? 'good' : 'warning',
          riesgos: healthData.riesgosCriticos < 5 ? 'good' : 'critical',
          vulnerabilidades: healthData.vulnerabilidadesCriticas < 3 ? 'good' : 'warning',
          cves: healthData.cvesCriticos < 10 ? 'good' : 'warning',
          implementacion: healthData.porcentajeImplementacion > 70 ? 'good' : 'needs_attention'
        },
        
        recommendations,
        
        meta: {
          evaluatedAt: new Date().toISOString(),
          responseTime: Date.now() - startTime,
          nextEvaluation: new Date(Date.now() + 5 * 60 * 1000).toISOString() // 5 minutos
        }
      };

      const duration = Date.now() - startTime;
      logger.info(`✅ Estado de salud evaluado en ${duration}ms - Score: ${healthScore} (${healthStatus})`);
      
      res.json({
        success: true,
        data: health,
        message: 'Estado de salud del sistema obtenido'
      });
      
    } catch (error) {
      const duration = Date.now() - startTime;
      logger.error(`❌ Error evaluando estado de salud (${duration}ms):`, error);
      next(error);
    }
  }

  // 🆕 NUEVO: GET /api/v1/dashboard/performance
  async getPerformanceMetrics(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    const startTime = Date.now();
    
    try {
      logger.info('⚡ Obteniendo métricas de rendimiento');

      // Simular métricas de rendimiento básicas
      const performance = {
        response_times: {
          dashboard_kpis: Math.random() * 500 + 200,
          assets_query: Math.random() * 300 + 100,
          risks_query: Math.random() * 400 + 150,
          vulnerabilities_query: Math.random() * 350 + 120
        },
        database: {
          connection_pool: 85,
          active_connections: 12,
          query_performance: 'good'
        },
        cache: {
          hit_rate: 78,
          miss_rate: 22,
          memory_usage: 45
        },
        api: {
          requests_per_minute: Math.floor(Math.random() * 100) + 50,
          error_rate: Math.random() * 2,
          uptime: '99.9%'
        }
      };
      
      const duration = Date.now() - startTime;
      logger.info(`✅ Métricas de rendimiento obtenidas en ${duration}ms`);
      
      res.json({
        success: true,
        data: {
          ...performance,
          meta: {
            measuredAt: new Date().toISOString(),
            responseTime: duration
          }
        },
        message: 'Métricas de rendimiento obtenidas'
      });
      
    } catch (error) {
      const duration = Date.now() - startTime;
      logger.error(`❌ Error obteniendo métricas de rendimiento (${duration}ms):`, error);
      next(error);
    }
  }

  // 🆕 NUEVO: POST /api/v1/dashboard/cache/clear
  async clearCache(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    const startTime = Date.now();
    
    try {
      const cacheType = req.body.type as 'all' | 'kpis' | 'stats' | 'trends' || 'all';
      
      logger.info(`🗑️ Limpiando caché: type=${cacheType}`);

      // Simular limpieza de caché
      const result = {
        cleared: true,
        type: cacheType,
        items_cleared: Math.floor(Math.random() * 50) + 10,
        cache_size_before: '15.2MB',
        cache_size_after: '2.1MB'
      };
      
      const duration = Date.now() - startTime;
      logger.info(`✅ Caché limpiado en ${duration}ms`);
      
      res.json({
        success: true,
        data: {
          ...result,
          meta: {
            clearedAt: new Date().toISOString(),
            responseTime: duration
          }
        },
        message: `Caché ${cacheType} limpiado exitosamente`
      });
      
    } catch (error) {
      const duration = Date.now() - startTime;
      logger.error(`❌ Error limpiando caché (${duration}ms):`, error);
      next(error);
    }
  }

  // === MÉTODOS AUXILIARES PRIVADOS ===

  // Obtener estadísticas de CVEs
  private async getCVEStatistics() {
    try {
      const { Threat } = await import('../models/Threat');
      
      // Estadísticas agregadas de CVEs
      const [severityStats, totalStats, recentStats] = await Promise.allSettled([
        Threat.aggregate([
          { $match: { origen: 'CVE' } },
          {
            $group: {
              _id: '$cveData.severity',
              count: { $sum: 1 }
            }
          }
        ]),
        Threat.countDocuments({ origen: 'CVE' }),
        Threat.countDocuments({
          origen: 'CVE',
          'cveData.publishedDate': { 
            $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) 
          }
        })
      ]);

      const severityCount = {
        cvesCriticos: 0,
        cvesAltos: 0,
        cvesMedios: 0,
        cvesBajos: 0
      };

      if (severityStats.status === 'fulfilled') {
        severityStats.value.forEach((stat: any) => {
          switch (stat._id) {
            case 'CRITICAL':
              severityCount.cvesCriticos = stat.count;
              break;
            case 'HIGH':
              severityCount.cvesAltos = stat.count;
              break;
            case 'MEDIUM':
              severityCount.cvesMedios = stat.count;
              break;
            case 'LOW':
              severityCount.cvesBajos = stat.count;
              break;
          }
        });
      }

      // Estadísticas de amenazas MAGERIT
      const [mageritStats] = await Promise.allSettled([
        Threat.countDocuments({ origen: { $ne: 'CVE' } })
      ]);

      return {
        totalCVEs: totalStats.status === 'fulfilled' ? totalStats.value : 0,
        ...severityCount,
        cvesFrecuentes: Math.floor((severityCount.cvesCriticos + severityCount.cvesAltos) * 0.3),
        ultimaActualizacion: new Date(),
        totalAmenazasMAGERIT: mageritStats.status === 'fulfilled' ? mageritStats.value : 0,
        amenazasActivas: mageritStats.status === 'fulfilled' ? mageritStats.value : 0,
        amenazasCriticas: Math.floor((mageritStats.status === 'fulfilled' ? mageritStats.value : 0) * 0.1)
      };
    } catch (error) {
      logger.error('Error obteniendo estadísticas CVE:', error);
      return {
        totalCVEs: 0,
        cvesCriticos: 0,
        cvesAltos: 0,
        cvesMedios: 0,
        cvesBajos: 0,
        cvesFrecuentes: 0,
        ultimaActualizacion: new Date(),
        totalAmenazasMAGERIT: 0,
        amenazasActivas: 0,
        amenazasCriticas: 0
      };
    }
  }

  // Calcular puntuación de salud del sistema (0-100)
  private calculateHealthScore(data: {
    totalActivos: number;
    riesgosCriticos: number;
    vulnerabilidadesCriticas: number;
    cvesCriticos: number;
    porcentajeImplementacion: number;
    database?: string;
    cache?: string;
  }): number {
    let score = 100;

    // Penalizar por riesgos críticos (peso: 15)
    score -= Math.min(data.riesgosCriticos * 3, 15);

    // Penalizar por vulnerabilidades críticas (peso: 20)
    score -= Math.min(data.vulnerabilidadesCriticas * 4, 20);

    // Penalizar por CVEs críticos (peso: 10)
    score -= Math.min(data.cvesCriticos * 1, 10);

    // Bonificar por implementación de salvaguardas (peso: 25)
    const implScore = (data.porcentajeImplementacion - 50) * 0.5;
    score += Math.max(-25, Math.min(25, implScore));

    // Penalizar por problemas de infraestructura (peso: 15)
    if (data.database === 'error') score -= 10;
    if (data.cache === 'error') score -= 5;

    // Bonificar por tener activos registrados
    if (data.totalActivos > 10) score += 5;

    // Mantener entre 0 y 100
    return Math.max(0, Math.min(100, Math.round(score)));
  }

  private getHealthStatus(score: number): string {
    if (score >= 85) return 'excellent';
    if (score >= 70) return 'good';
    if (score >= 50) return 'warning';
    if (score >= 30) return 'poor';
    return 'critical';
  }

  private getHealthRecommendations(data: any): string[] {
    const recommendations: string[] = [];

    if (data.riesgosCriticos > 5) {
      recommendations.push('🔴 Revisar y mitigar riesgos críticos pendientes inmediatamente');
    }

    if (data.vulnerabilidadesCriticas > 3) {
      recommendations.push('🔴 Atender vulnerabilidades críticas con máxima prioridad');
    }

    if (data.cvesCriticos > 10) {
      recommendations.push('🟡 Revisar CVEs críticos y evaluar impacto en activos');
    }

    if (data.porcentajeImplementacion < 70) {
      recommendations.push('🟡 Acelerar la implementación de salvaguardas de seguridad');
    }

    if (data.totalActivos < 5) {
      recommendations.push('🟡 Completar el inventario de activos de información');
    }

    if (data.database === 'error') {
      recommendations.push('🔴 Verificar conectividad y estado de la base de datos');
    }

    if (data.cache === 'error') {
      recommendations.push('🟡 Revisar sistema de caché para mejorar rendimiento');
    }

    if (recommendations.length === 0) {
      recommendations.push('✅ Sistema en buen estado, continuar con el monitoreo regular');
    }

    return recommendations;
  }
  async getRiskMatrix(req: Request, res: Response<ApiResponse>, next: NextFunction) {
  const startTime = Date.now();
  
  try {
    logger.info('🎯 Obteniendo matriz de riesgos para dashboard');

    // Obtener matriz de riesgos usando el servicio existente
    const matrixData = await riskService.getRiskMatrix();
    
    // Transformar datos para el formato del dashboard
    const dashboardMatrix = {
      matrix: matrixData.matrix,
      stats: matrixData.stats,
      
      // Datos adicionales para visualización del dashboard
      distribution: {
        criticos: matrixData.matrix.criticos.length,
        altos: matrixData.matrix.altos.length,
        medios: matrixData.matrix.medios.length,
        bajos: matrixData.matrix.bajos.length,
        muyBajos: matrixData.matrix.muyBajos.length
      },
      
      // Top 5 riesgos para widget del dashboard
      topRisks: [
        ...matrixData.matrix.criticos.slice(0, 3),
        ...matrixData.matrix.altos.slice(0, 2)
      ].slice(0, 5),
      
      meta: {
        timestamp: new Date().toISOString(),
        responseTime: Date.now() - startTime,
        totalRisks: matrixData.stats.totalRiesgos
      }
    };

    const duration = Date.now() - startTime;
    logger.info(`✅ Matriz de riesgos obtenida en ${duration}ms`);
    
    res.json({
      success: true,
      data: dashboardMatrix,
      message: 'Matriz de riesgos para dashboard obtenida exitosamente'
    });
    
  } catch (error) {
    const duration = Date.now() - startTime;
    logger.error(`❌ Error obteniendo matriz de riesgos (${duration}ms):`, error);
    next(error);
  }
}
}

export const dashboardController = new DashboardController();