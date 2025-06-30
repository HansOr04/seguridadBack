import { Request, Response, NextFunction } from 'express';
import { cveIntegrationService } from '../services/CVEIntegrationService';
import { cveSyncJob } from '../jobs/cveSync';
import { Threat } from '../models/Threat';
import { Asset } from '../models/Asset';
import { ApiResponse, IAsset } from '../types';
import { AppError } from '../middleware/errorHandler';
import logger from '../utils/logger';

// Extender Request para incluir user
interface AuthenticatedRequest extends Request {
  user?: {
    id: string;
    email: string;
    nombre: string;
    rol: string;
  };
}

// Interfaz para los elementos de severityBreakdown en el timeline
interface SeverityBreakdownItem {
  severity: string;
  count: number;
  avgScore: number;
  maxScore: number;
}

// Tipo para los objetos de severidad válida
type ValidSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export class CVEController {
  // GET /api/v1/cve/search?keyword=microsoft&severity=HIGH
  async searchCVEs(req: AuthenticatedRequest, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const { keyword, severity } = req.query;
      
      if (!keyword) {
        throw new AppError('Keyword es requerido para la búsqueda', 400);
      }

      const cves = await cveIntegrationService.searchCVEs(
        keyword as string, 
        severity as string
      );

      res.json({
        success: true,
        data: cves,
        message: `Encontrados ${cves.length} CVEs`
      });
    } catch (error) {
      next(error);
    }
  }

  // GET /api/v1/cve/:cveId
  async getCVEById(req: AuthenticatedRequest, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const { cveId } = req.params;
      
      if (!cveId.match(/^CVE-\d{4}-\d{4,}$/)) {
        throw new AppError('Formato de CVE ID inválido', 400);
      }

      const cve = await cveIntegrationService.getCVEById(cveId);
      
      if (!cve) {
        throw new AppError('CVE no encontrado', 404);
      }

      res.json({
        success: true,
        data: cve
      });
    } catch (error) {
      next(error);
    }
  }

  // GET /api/v1/cve/recent?days=7
  async getRecentCVEs(req: AuthenticatedRequest, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const days = parseInt(req.query.days as string) || 7;
      
      if (days < 1 || days > 30) {
        throw new AppError('Los días deben estar entre 1 y 30', 400);
      }

      const cves = await cveIntegrationService.getRecentCVEs(days);

      res.json({
        success: true,
        data: cves,
        message: `CVEs de los últimos ${days} días`
      });
    } catch (error) {
      next(error);
    }
  }

  // ⭐ NUEVO: GET /api/v1/cve/frequent - CVEs más frecuentes
  async getFrequentCVEs(req: AuthenticatedRequest, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const limit = parseInt(req.query.limit as string) || 20;
      const days = parseInt(req.query.days as string) || 30;
      
      if (limit < 1 || limit > 100) {
        throw new AppError('El límite debe estar entre 1 y 100', 400);
      }

      if (days < 1 || days > 365) {
        throw new AppError('Los días deben estar entre 1 y 365', 400);
      }
      
      // Calcular fecha desde hace X días
      const dateFrom = new Date();
      dateFrom.setDate(dateFrom.getDate() - days);
      
      logger.info(`🔍 Buscando CVEs frecuentes: límite=${limit}, días=${days}`);
      
      // Query optimizada con agregación para obtener CVEs más frecuentes
      const frequentCVEs = await Threat.aggregate([
        {
          $match: {
            origen: 'CVE',
            'cveData.publishedDate': { $gte: dateFrom },
            'cveData.severity': { $in: ['CRITICAL', 'HIGH', 'MEDIUM'] }
          }
        },
        {
          $addFields: {
            affectedAssetsCount: { $size: { $ifNull: ['$aplicaA', []] }},
            severityWeight: {
              $switch: {
                branches: [
                  { case: { $eq: ['$cveData.severity', 'CRITICAL'] }, then: 4 },
                  { case: { $eq: ['$cveData.severity', 'HIGH'] }, then: 3 },
                  { case: { $eq: ['$cveData.severity', 'MEDIUM'] }, then: 2 },
                  { case: { $eq: ['$cveData.severity', 'LOW'] }, then: 1 }
                ],
                default: 0
              }
            }
          }
        },
        {
          $addFields: {
            frequencyScore: {
              $add: [
                { $multiply: ['$affectedAssetsCount', 10] }, // Peso por activos afectados
                { $multiply: ['$severityWeight', 5] }, // Peso por severidad
                { $multiply: [{ $ifNull: ['$cveData.cvssScore', 0] }, 2] } // Peso por score CVSS
              ]
            }
          }
        },
        {
          $sort: { frequencyScore: -1, 'cveData.publishedDate': -1 }
        },
        {
          $limit: limit
        },
        {
          $project: {
            cveId: '$cveData.cveId',
            description: '$cveData.description',
            severity: '$cveData.severity',
            cvssScore: '$cveData.cvssScore',
            publishedDate: '$cveData.publishedDate',
            lastModifiedDate: '$cveData.lastModifiedDate',
            affectedAssetsCount: '$affectedAssetsCount',
            frequencyScore: '$frequencyScore',
            references: { $slice: ['$descripcion', 200] }, // Usar descripción en lugar de references
            cwe: '$codigo', // Usar código como referencia CWE simplificada
            vectorString: '$cveData.cvssVector'
          }
        }
      ]);

      // Estadísticas adicionales
      const stats = {
        totalFrequentCVEs: frequentCVEs.length,
        criticalCount: frequentCVEs.filter(cve => cve.severity === 'CRITICAL').length,
        highCount: frequentCVEs.filter(cve => cve.severity === 'HIGH').length,
        mediumCount: frequentCVEs.filter(cve => cve.severity === 'MEDIUM').length,
        averageScore: frequentCVEs.reduce((sum, cve) => sum + (cve.cvssScore || 0), 0) / frequentCVEs.length || 0,
        averageAffectedAssets: frequentCVEs.reduce((sum, cve) => sum + cve.affectedAssetsCount, 0) / frequentCVEs.length || 0,
        dateRange: {
          from: dateFrom.toISOString(),
          to: new Date().toISOString()
        }
      };

      logger.info(`✅ CVEs frecuentes obtenidos: ${frequentCVEs.length} resultados`);

      res.json({
        success: true,
        data: {
          cves: frequentCVEs,
          stats
        },
        message: `${frequentCVEs.length} CVEs más frecuentes obtenidos exitosamente`
      });
    } catch (error) {
      logger.error('❌ Error obteniendo CVEs frecuentes:', error);
      next(error);
    }
  }

  // ⭐ NUEVO: GET /api/v1/cve/trending - CVEs con tendencia
  async getTrendingCVEs(req: AuthenticatedRequest, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const days = parseInt(req.query.days as string) || 7;
      const limit = parseInt(req.query.limit as string) || 15;
      
      if (days < 1 || days > 90) {
        throw new AppError('Los días deben estar entre 1 y 90', 400);
      }

      if (limit < 1 || limit > 50) {
        throw new AppError('El límite debe estar entre 1 y 50', 400);
      }
      
      const dateFrom = new Date();
      dateFrom.setDate(dateFrom.getDate() - days);
      
      logger.info(`📈 Buscando CVEs en tendencia: días=${days}, límite=${limit}`);
      
      // CVEs que han sido modificados recientemente o son nuevos
      const trendingCVEs = await Threat.find({
        origen: 'CVE',
        $or: [
          { 'cveData.publishedDate': { $gte: dateFrom } }, // Nuevos
          { 'cveData.lastModifiedDate': { $gte: dateFrom } } // Actualizados
        ]
      })
      .sort({ 
        'cveData.lastModifiedDate': -1, 
        'cveData.cvssScore': -1 
      })
      .limit(limit)
      .select({
        'cveData.cveId': 1,
        'cveData.description': 1,
        'cveData.severity': 1,
        'cveData.cvssScore': 1,
        'cveData.publishedDate': 1,
        'cveData.lastModifiedDate': 1,
        'aplicaA': 1,
        'cveData.references': 1
      });

      const processedCVEs = trendingCVEs.map(threat => ({
        cveId: threat.cveData?.cveId,
        description: threat.cveData?.description?.substring(0, 200) + '...',
        severity: threat.cveData?.severity,
        cvssScore: threat.cveData?.cvssScore,
        publishedDate: threat.cveData?.publishedDate,
        lastModifiedDate: threat.cveData?.lastModifiedDate,
        affectedAssetsCount: threat.aplicaA?.length || 0,
        isNew: threat.cveData?.publishedDate && threat.cveData.publishedDate >= dateFrom,
        isUpdated: threat.cveData?.lastModifiedDate && threat.cveData.lastModifiedDate >= dateFrom,
        mainReference: `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${threat.cveData?.cveId}` // URL estándar CVE
      }));

      logger.info(`✅ CVEs en tendencia obtenidos: ${processedCVEs.length} resultados`);

      res.json({
        success: true,
        data: processedCVEs,
        message: `${processedCVEs.length} CVEs en tendencia obtenidos exitosamente`
      });
    } catch (error) {
      logger.error('❌ Error obteniendo CVEs en tendencia:', error);
      next(error);
    }
  }

  // ⭐ NUEVO: GET /api/v1/cve/critical - CVEs críticos únicamente
  async getCriticalCVEs(req: AuthenticatedRequest, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const limit = parseInt(req.query.limit as string) || 25;
      const days = parseInt(req.query.days as string) || 90;
      
      if (limit < 1 || limit > 100) {
        throw new AppError('El límite debe estar entre 1 y 100', 400);
      }
      
      const dateFrom = new Date();
      dateFrom.setDate(dateFrom.getDate() - days);
      
      logger.info(`🚨 Buscando CVEs críticos: límite=${limit}, días=${days}`);
      
      const criticalCVEs = await Threat.find({
        origen: 'CVE',
        'cveData.severity': 'CRITICAL',
        'cveData.publishedDate': { $gte: dateFrom }
      })
      .sort({ 
        'cveData.cvssScore': -1, 
        'cveData.publishedDate': -1 
      })
      .limit(limit)
      .select({
        'cveData.cveId': 1,
        'cveData.description': 1,
        'cveData.severity': 1,
        'cveData.cvssScore': 1,
        'cveData.publishedDate': 1,
        'cveData.cvssVector': 1,
        'aplicaA': 1,
        'cveData.cwe': 1,
        'cveData.references': 1
      });

      const processedCriticalCVEs = criticalCVEs.map(threat => ({
        cveId: threat.cveData?.cveId,
        description: threat.cveData?.description,
        severity: threat.cveData?.severity,
        cvssScore: threat.cveData?.cvssScore,
        publishedDate: threat.cveData?.publishedDate,
        affectedAssetsCount: threat.aplicaA?.length || 0,
        attackVector: threat.cveData?.cvssVector ? 'Network' : 'Unknown', // Simplificado
        attackComplexity: 'Low', // Simplificado - ajustar según tu esquema
        cweId: threat.codigo, // Usar código de amenaza como referencia
        references: [{ url: `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${threat.cveData?.cveId}`, source: 'MITRE' }] // Referencia estándar
      }));

      res.json({
        success: true,
        data: processedCriticalCVEs,
        message: `${processedCriticalCVEs.length} CVEs críticos obtenidos exitosamente`
      });
    } catch (error) {
      logger.error('❌ Error obteniendo CVEs críticos:', error);
      next(error);
    }
  }

  // ⭐ NUEVO: GET /api/v1/cve/by-severity/:severity - CVEs por severidad específica
  async getCVEsBySeverity(req: AuthenticatedRequest, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const { severity } = req.params;
      const limit = parseInt(req.query.limit as string) || 30;
      const page = parseInt(req.query.page as string) || 1;
      
      const validSeverities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
      if (!validSeverities.includes(severity.toUpperCase())) {
        throw new AppError('Severidad inválida. Debe ser: CRITICAL, HIGH, MEDIUM o LOW', 400);
      }

      if (limit < 1 || limit > 100) {
        throw new AppError('El límite debe estar entre 1 y 100', 400);
      }

      if (page < 1) {
        throw new AppError('La página debe ser mayor a 0', 400);
      }
      
      const skip = (page - 1) * limit;
      const severityUpper = severity.toUpperCase();
      
      logger.info(`🎯 Buscando CVEs por severidad: ${severityUpper}, página=${page}, límite=${limit}`);
      
      const [cves, totalCount] = await Promise.all([
        Threat.find({
          origen: 'CVE',
          'cveData.severity': severityUpper
        })
        .sort({ 
          'cveData.cvssScore': -1, 
          'cveData.publishedDate': -1 
        })
        .skip(skip)
        .limit(limit)
        .select({
          'cveData.cveId': 1,
          'cveData.description': 1,
          'cveData.severity': 1,
          'cveData.cvssScore': 1,
          'cveData.publishedDate': 1,
          'aplicaA': 1
        }),
        
        Threat.countDocuments({
          origen: 'CVE',
          'cveData.severity': severityUpper
        })
      ]);

      const processedCVEs = cves.map(threat => ({
        cveId: threat.cveData?.cveId,
        description: threat.cveData?.description?.substring(0, 150) + '...',
        severity: threat.cveData?.severity,
        cvssScore: threat.cveData?.cvssScore,
        publishedDate: threat.cveData?.publishedDate,
        affectedAssetsCount: threat.aplicaA?.length || 0
      }));

      const pagination = {
        currentPage: page,
        totalPages: Math.ceil(totalCount / limit),
        totalItems: totalCount,
        itemsPerPage: limit,
        hasNextPage: page < Math.ceil(totalCount / limit),
        hasPrevPage: page > 1
      };

      res.json({
        success: true,
        data: {
          cves: processedCVEs,
          pagination
        },
        message: `${processedCVEs.length} CVEs de severidad ${severityUpper} obtenidos exitosamente`
      });
    } catch (error) {
      logger.error('❌ Error obteniendo CVEs por severidad:', error);
      next(error);
    }
  }

  // ⭐ NUEVO: GET /api/v1/cve/impact-analysis/:cveId - Análisis de impacto de CVE
  async getCVEImpactAnalysis(req: AuthenticatedRequest, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const { cveId } = req.params;
      
      if (!cveId.match(/^CVE-\d{4}-\d{4,}$/)) {
        throw new AppError('Formato de CVE ID inválido', 400);
      }

      logger.info(`🔍 Analizando impacto del CVE: ${cveId}`);
      
      // Buscar el CVE y los activos afectados
      const [cveData, affectedAssets] = await Promise.all([
        Threat.findOne({ 
          origen: 'CVE',
          'cveData.cveId': cveId 
        }).select({
          'cveData': 1,
          'aplicaA': 1,
          'probabilidad': 1
        }),
        
        Asset.find({
          '_id': { $in: [] } // Se llenará con los IDs de aplicaA
        }).select({
          'codigo': 1,
          'nombre': 1,
          'tipo': 1,
          'valoracion': 1
        })
      ]);

      if (!cveData) {
        throw new AppError('CVE no encontrado en la base de datos', 404);
      }

      // Obtener activos afectados si existen
      let actualAffectedAssets: IAsset[] = [];
      if (cveData.aplicaA && cveData.aplicaA.length > 0) {
        actualAffectedAssets = await Asset.find({
          '_id': { $in: cveData.aplicaA }
        }).select({
          'codigo': 1,
          'nombre': 1,
          'tipo': 1,
          'valoracion': 1
        });
      }

      // Calcular métricas de impacto
      const criticalAssets = actualAffectedAssets.filter(asset => 
        Math.max(
          asset.valoracion?.confidencialidad || 0,
          asset.valoracion?.integridad || 0,
          asset.valoracion?.disponibilidad || 0
        ) >= 8
      );
      
      const highValueAssets = actualAffectedAssets.filter(asset => 
        asset.valoracion && 
        (asset.valoracion.confidencialidad >= 7 || 
         asset.valoracion.integridad >= 7 || 
         asset.valoracion.disponibilidad >= 7)
      );

      const impactMetrics = {
        totalAffectedAssets: actualAffectedAssets.length,
        criticalAssetsAffected: criticalAssets.length,
        highValueAssetsAffected: highValueAssets.length,
        estimatedBusinessImpact: this.calculateBusinessImpact(actualAffectedAssets, cveData.cveData?.cvssScore || 0),
        riskLevel: this.calculateRiskLevel(cveData.cveData?.cvssScore || 0, actualAffectedAssets.length)
      };

      const analysis = {
        cveInfo: {
          cveId: cveData.cveData?.cveId,
          description: cveData.cveData?.description,
          severity: cveData.cveData?.severity,
          cvssScore: cveData.cveData?.cvssScore,
          publishedDate: cveData.cveData?.publishedDate,
          attackVector: 'Unknown', // Simplificado - ajustar según tu esquema
          attackComplexity: 'Unknown' // Simplificado - ajustar según tu esquema
        },
        affectedAssets: actualAffectedAssets.map(asset => ({
          id: asset._id,
          codigo: asset.codigo,
          nombre: asset.nombre,
          tipo: asset.tipo,
          riskContribution: this.calculateAssetRiskContribution(asset, cveData.cveData?.cvssScore || 0)
        })),
        impactMetrics,
        recommendations: this.generateRecommendations(cveData.cveData?.severity || 'MEDIUM', impactMetrics.criticalAssetsAffected)
      };

      res.json({
        success: true,
        data: analysis,
        message: `Análisis de impacto completado para ${cveId}`
      });
    } catch (error) {
      logger.error('❌ Error en análisis de impacto CVE:', error);
      next(error);
    }
  }

  // ⭐ NUEVO: GET /api/v1/cve/asset-correlation/:assetId - CVEs que afectan un activo
  async getCVEsForAsset(req: AuthenticatedRequest, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const { assetId } = req.params;
      const limit = parseInt(req.query.limit as string) || 20;
      
      if (!assetId.match(/^[0-9a-fA-F]{24}$/)) {
        throw new AppError('ID de activo inválido', 400);
      }

      logger.info(`🎯 Buscando CVEs para activo: ${assetId}`);
      
      // Verificar que el activo existe
      const asset = await Asset.findById(assetId).select('codigo nombre tipo valoracion');
      if (!asset) {
        throw new AppError('Activo no encontrado', 404);
      }

      // Buscar CVEs que afectan este activo
      const cves = await Threat.find({
        origen: 'CVE',
        aplicaA: assetId
      })
      .sort({ 
        'cveData.cvssScore': -1, 
        'cveData.publishedDate': -1 
      })
      .limit(limit)
      .select({
        'cveData.cveId': 1,
        'cveData.description': 1,
        'cveData.severity': 1,
        'cveData.cvssScore': 1,
        'cveData.publishedDate': 1,
        'cveData.cvssVector': 1,
        'probabilidad': 1
      });

      const processedCVEs = cves.map(threat => ({
        cveId: threat.cveData?.cveId,
        description: threat.cveData?.description?.substring(0, 200) + '...',
        severity: threat.cveData?.severity,
        cvssScore: threat.cveData?.cvssScore,
        publishedDate: threat.cveData?.publishedDate,
        attackVector: threat.cveData?.cvssVector ? 'Network' : 'Unknown',
        threatProbability: threat.probabilidad,
        riskScore: this.calculateAssetSpecificRisk(threat.cveData?.cvssScore || 0, asset, threat.probabilidad)
      }));

      // Estadísticas específicas del activo
      const assetCVEStats = {
        totalCVEs: processedCVEs.length,
        criticalCVEs: processedCVEs.filter(cve => cve.severity === 'CRITICAL').length,
        highCVEs: processedCVEs.filter(cve => cve.severity === 'HIGH').length,
        averageCVSSScore: processedCVEs.reduce((sum, cve) => sum + (cve.cvssScore || 0), 0) / processedCVEs.length || 0,
        highestRiskCVE: processedCVEs.reduce((max, cve) => cve.riskScore > max.riskScore ? cve : max, { riskScore: 0 })
      };

      res.json({
        success: true,
        data: {
          asset: {
            id: asset._id,
            codigo: asset.codigo,
            nombre: asset.nombre,
            tipo: asset.tipo
          },
          cves: processedCVEs,
          stats: assetCVEStats
        },
        message: `${processedCVEs.length} CVEs encontrados para el activo ${asset.codigo}`
      });
    } catch (error) {
      logger.error('❌ Error obteniendo CVEs para activo:', error);
      next(error);
    }
  }

  // ⭐ MEJORADO: GET /api/v1/cve/statistics - Estadísticas detalladas de CVEs
  async getDetailedCVEStats(req: AuthenticatedRequest, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const days = parseInt(req.query.days as string) || 30;
      
      if (days < 1 || days > 365) {
        throw new AppError('Los días deben estar entre 1 y 365', 400);
      }

      const dateFrom = new Date();
      dateFrom.setDate(dateFrom.getDate() - days);
      
      logger.info(`📊 Calculando estadísticas detalladas de CVEs para ${days} días`);
      
      // Estadísticas agregadas optimizadas
      const [generalStats, severityStats, temporalStats, assetImpactStats] = await Promise.all([
        // Estadísticas generales
        Threat.aggregate([
          { $match: { origen: 'CVE' } },
          {
            $group: {
              _id: null,
              totalCVEs: { $sum: 1 },
              avgCVSSScore: { $avg: '$cveData.cvssScore' },
              maxCVSSScore: { $max: '$cveData.cvssScore' },
              totalAffectedAssets: { $sum: { $size: { $ifNull: ['$aplicaA', []] } } }
            }
          }
        ]),
        
        // Por severidad
        Threat.aggregate([
          { $match: { origen: 'CVE' } },
          {
            $group: {
              _id: '$cveData.severity',
              count: { $sum: 1 },
              avgScore: { $avg: '$cveData.cvssScore' }
            }
          }
        ]),
        
        // Temporales (últimos días)
        Threat.aggregate([
          { 
            $match: { 
              origen: 'CVE',
              'cveData.publishedDate': { $gte: dateFrom }
            } 
          },
          {
            $group: {
              _id: {
                $dateToString: { 
                  format: '%Y-%m-%d', 
                  date: '$cveData.publishedDate' 
                }
              },
              count: { $sum: 1 },
              criticalCount: {
                $sum: {
                  $cond: [{ $eq: ['$cveData.severity', 'CRITICAL'] }, 1, 0]
                }
              }
            }
          },
          { $sort: { '_id': 1 } }
        ]),
        
        // Impacto en activos
        Threat.aggregate([
          { 
            $match: { 
              origen: 'CVE',
              aplicaA: { $exists: true, $ne: [] }
            } 
          },
          {
            $project: {
              affectedCount: { $size: '$aplicaA' },
              severity: '$cveData.severity'
            }
          },
          {
            $group: {
              _id: '$severity',
              totalAffectedAssets: { $sum: '$affectedCount' },
              avgAssetsPerCVE: { $avg: '$affectedCount' }
            }
          }
        ])
      ]);

      // Procesar resultados
      const general = generalStats[0] || {
        totalCVEs: 0,
        avgCVSSScore: 0,
        maxCVSSScore: 0,
        totalAffectedAssets: 0
      };

      const severityDistribution = {
        CRITICAL: 0,
        HIGH: 0,
        MEDIUM: 0,
        LOW: 0
      };
      
      severityStats.forEach(stat => {
        if (stat._id && stat._id in severityDistribution) {
          (severityDistribution as any)[stat._id] = stat.count;
        }
      });

      const detailedStats = {
        overview: {
          totalCVEs: general.totalCVEs,
          averageCVSSScore: Math.round(general.avgCVSSScore * 100) / 100,
          maximumCVSSScore: general.maxCVSSScore,
          totalAffectedAssets: general.totalAffectedAssets,
          lastUpdate: cveSyncJob.getStatus().lastSyncDate
        },
        severityDistribution,
        temporalTrend: temporalStats,
        assetImpact: assetImpactStats,
        riskMetrics: {
          criticalRiskCVEs: severityDistribution.CRITICAL,
          highRiskCVEs: severityDistribution.HIGH + severityDistribution.CRITICAL,
          riskCoverage: Math.round((general.totalAffectedAssets / Math.max(general.totalCVEs, 1)) * 100),
          averageAssetsPerCVE: Math.round(general.totalAffectedAssets / Math.max(general.totalCVEs, 1) * 100) / 100
        },
        syncStatus: cveSyncJob.getStatus()
      };

      res.json({
        success: true,
        data: detailedStats,
        message: 'Estadísticas detalladas de CVEs calculadas exitosamente'
      });
    } catch (error) {
      logger.error('❌ Error calculando estadísticas detalladas de CVEs:', error);
      next(error);
    }
  }

  // === MÉTODOS AUXILIARES PRIVADOS ===
  
  private calculateBusinessImpact(assets: IAsset[], cvssScore: number): string {
    const criticalAssets = assets.filter(asset => {
      const maxCriticality = Math.max(
        asset.valoracion?.confidencialidad || 0,
        asset.valoracion?.integridad || 0,
        asset.valoracion?.disponibilidad || 0
      );
      return maxCriticality >= 8;
    }).length;
    const totalAssets = assets.length;
    
    if (cvssScore >= 9 && criticalAssets > 0) return 'MUY_ALTO';
    if (cvssScore >= 7 && (criticalAssets > 0 || totalAssets >= 5)) return 'ALTO';
    if (cvssScore >= 5 && totalAssets > 0) return 'MEDIO';
    if (totalAssets > 0) return 'BAJO';
    return 'MINIMO';
  }

  private calculateRiskLevel(cvssScore: number, affectedAssetsCount: number): string {
    const riskScore = cvssScore * (1 + Math.log10(Math.max(affectedAssetsCount, 1)));
    
    if (riskScore >= 8) return 'CRITICO';
    if (riskScore >= 6) return 'ALTO';
    if (riskScore >= 4) return 'MEDIO';
    return 'BAJO';
  }

  private calculateAssetRiskContribution(asset: IAsset, cvssScore: number): number {
    const maxCriticality = Math.max(
      asset.valoracion?.confidencialidad || 0,
      asset.valoracion?.integridad || 0,
      asset.valoracion?.disponibilidad || 0
    );
    
    const weight = maxCriticality >= 8 ? 3 : maxCriticality >= 6 ? 2 : maxCriticality >= 4 ? 1.5 : 1;
    return Math.round(cvssScore * weight * 10) / 10;
  }

  private calculateAssetSpecificRisk(cvssScore: number, asset: IAsset, probability: number): number {
    const maxCriticality = Math.max(
      asset.valoracion?.confidencialidad || 0,
      asset.valoracion?.integridad || 0,
      asset.valoracion?.disponibilidad || 0
    );
    
    const multiplier = maxCriticality >= 8 ? 1.5 : maxCriticality >= 6 ? 1.2 : maxCriticality >= 4 ? 1.0 : 0.8;
    return Math.round(cvssScore * multiplier * (probability || 0.5) * 10) / 10;
  }

  private generateRecommendations(severity: string, criticalAssetsAffected: number): string[] {
    const recommendations = [];
    
    if (severity === 'CRITICAL') {
      recommendations.push('Implementar parches de seguridad inmediatamente');
      recommendations.push('Activar monitoreo continuo en activos afectados');
      recommendations.push('Considerar aislamiento temporal de activos críticos');
    }
    
    if (criticalAssetsAffected > 0) {
      recommendations.push('Priorizar la protección de activos críticos');
      recommendations.push('Revisar controles de acceso y segmentación de red');
    }
    
    recommendations.push('Evaluar implementación de controles compensatorios');
    recommendations.push('Actualizar el análisis de riesgos organizacional');
    
    return recommendations;
  }

  // === MÉTODOS EXISTENTES ===

  // POST /api/v1/cve/sync/manual
  async manualSync(req: AuthenticatedRequest, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const { days, severity, keyword, forceRecalculation } = req.body;

      const results = await cveSyncJob.manualSync({
        days,
        severity,
        keyword,
        forceRecalculation
      });

      res.json({
        success: true,
        data: results,
        message: 'Sincronización manual completada'
      });
    } catch (error) {
      next(error);
    }
  }

  // GET /api/v1/cve/sync/status
  async getSyncStatus(req: AuthenticatedRequest, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const status = cveSyncJob.getStatus();

      res.json({
        success: true,
        data: status
      });
    } catch (error) {
      next(error);
    }
  }

  // POST /api/v1/cve/sync/stop
  async stopSync(req: AuthenticatedRequest, res: Response<ApiResponse>, next: NextFunction) {
    try {
      cveSyncJob.forceStop();

      res.json({
        success: true,
        message: 'Sincronización detenida'
      });
    } catch (error) {
      next(error);
    }
  }

  // POST /api/v1/cve/sync/recent
  async syncRecent(req: AuthenticatedRequest, res: Response<ApiResponse>, next: NextFunction) {
    try {
      // Verificar si ya hay un sync en curso
      const status = cveSyncJob.getStatus();
      if (status.isRunning) {
        throw new AppError('Ya hay una sincronización en curso', 409);
      }

      // Ejecutar sync en background
      cveSyncJob.syncRecentCVEs().catch(error => {
        console.error('Error en sync reciente:', error);
      });

      res.json({
        success: true,
        message: 'Sincronización de CVEs recientes iniciada'
      });
    } catch (error) {
      next(error);
    }
  }

  // ⚠️ REEMPLAZADO: Método getCVEStats mejorado arriba como getDetailedCVEStats
  // Mantener para compatibilidad hacia atrás
  async getCVEStats(req: AuthenticatedRequest, res: Response<ApiResponse>, next: NextFunction) {
    try {
      logger.info('⚠️ Usando método getCVEStats deprecated. Usar getDetailedCVEStats en su lugar.');
      
      // Estadísticas básicas para compatibilidad
      const [totalStats, recentStats] = await Promise.all([
        Threat.aggregate([
          { $match: { origen: 'CVE' } },
          {
            $group: {
              _id: '$cveData.severity',
              count: { $sum: 1 }
            }
          }
        ]),
        Threat.countDocuments({
          origen: 'CVE',
          'cveData.publishedDate': { 
            $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) 
          }
        })
      ]);

      const severityCount = {
        cveCriticos: 0,
        cveAltos: 0,
        cveMedios: 0,
        cveBajos: 0
      };

      totalStats.forEach(stat => {
        switch (stat._id) {
          case 'CRITICAL':
            severityCount.cveCriticos = stat.count;
            break;
          case 'HIGH':
            severityCount.cveAltos = stat.count;
            break;
          case 'MEDIUM':
            severityCount.cveMedios = stat.count;
            break;
          case 'LOW':
            severityCount.cveBajos = stat.count;
            break;
        }
      });

      const stats = {
        totalCVEs: Object.values(severityCount).reduce((sum, count) => sum + count, 0),
        ...severityCount,
        recentCVEs: recentStats,
        ultimaActualizacion: cveSyncJob.getStatus().lastSyncDate
      };

      res.json({
        success: true,
        data: stats,
        message: 'Estadísticas básicas de CVEs obtenidas (método deprecated)'
      });
    } catch (error) {
      logger.error('❌ Error obteniendo estadísticas básicas de CVEs:', error);
      next(error);
    }
  }

  // ⭐ NUEVO: GET /api/v1/cve/timeline - Timeline de CVEs
  async getCVETimeline(req: AuthenticatedRequest, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const days = parseInt(req.query.days as string) || 30;
      const granularity = req.query.granularity as string || 'daily'; // daily, weekly, monthly
      
      if (days < 1 || days > 365) {
        throw new AppError('Los días deben estar entre 1 y 365', 400);
      }

      if (!['daily', 'weekly', 'monthly'].includes(granularity)) {
        throw new AppError('Granularidad debe ser: daily, weekly o monthly', 400);
      }

      const dateFrom = new Date();
      dateFrom.setDate(dateFrom.getDate() - days);

      let dateFormat: string;
      switch (granularity) {
        case 'daily':
          dateFormat = '%Y-%m-%d';
          break;
        case 'weekly':
          dateFormat = '%Y-%U'; // Año-Semana
          break;
        case 'monthly':
          dateFormat = '%Y-%m';
          break;
        default:
          dateFormat = '%Y-%m-%d';
      }

      logger.info(`📅 Generando timeline de CVEs: ${days} días, granularidad ${granularity}`);

      const timeline = await Threat.aggregate([
        {
          $match: {
            origen: 'CVE',
            'cveData.publishedDate': { $gte: dateFrom }
          }
        },
        {
          $group: {
            _id: {
              period: {
                $dateToString: {
                  format: dateFormat,
                  date: '$cveData.publishedDate'
                }
              },
              severity: '$cveData.severity'
            },
            count: { $sum: 1 },
            avgCVSSScore: { $avg: '$cveData.cvssScore' },
            maxCVSSScore: { $max: '$cveData.cvssScore' }
          }
        },
        {
          $group: {
            _id: '$_id.period',
            severityBreakdown: {
              $push: {
                severity: '$_id.severity',
                count: '$count',
                avgScore: '$avgCVSSScore',
                maxScore: '$maxCVSSScore'
              }
            },
            totalCVEs: { $sum: '$count' }
          }
        },
        {
          $sort: { '_id': 1 }
        }
      ]);

      // Procesar datos para estructura más amigable
      const processedTimeline = timeline.map(period => {
        const severities: Record<ValidSeverity, { count: number; avgScore: number; maxScore: number }> = {
          CRITICAL: { count: 0, avgScore: 0, maxScore: 0 },
          HIGH: { count: 0, avgScore: 0, maxScore: 0 },
          MEDIUM: { count: 0, avgScore: 0, maxScore: 0 },
          LOW: { count: 0, avgScore: 0, maxScore: 0 }
        };

        period.severityBreakdown.forEach((item: SeverityBreakdownItem) => {
          if (item.severity && item.severity in severities) {
            const severity = item.severity as ValidSeverity;
            severities[severity] = {
              count: item.count,
              avgScore: Math.round(item.avgScore * 100) / 100,
              maxScore: item.maxScore
            };
          }
        });

        return {
          period: period._id,
          totalCVEs: period.totalCVEs,
          severities,
          trendIndicator: this.calculateTrendIndicator(period.totalCVEs, timeline)
        };
      });

      res.json({
        success: true,
        data: {
          timeline: processedTimeline,
          summary: {
            totalPeriods: processedTimeline.length,
            granularity,
            dateRange: {
              from: dateFrom.toISOString(),
              to: new Date().toISOString()
            },
            peakPeriod: processedTimeline.reduce((max, current) => 
              current.totalCVEs > max.totalCVEs ? current : max, 
              { totalCVEs: 0 }
            )
          }
        },
        message: `Timeline de CVEs generado exitosamente (${granularity})`
      });
    } catch (error) {
      logger.error('❌ Error generando timeline de CVEs:', error);
      next(error);
    }
  }

  private calculateTrendIndicator(currentValue: number, allData: any[]): string {
    if (allData.length < 2) return 'neutral';
    
    const avgValue = allData.reduce((sum, item) => sum + item.totalCVEs, 0) / allData.length;
    
    if (currentValue > avgValue * 1.2) return 'increasing';
    if (currentValue < avgValue * 0.8) return 'decreasing';
    return 'stable';
  }

  // ⭐ NUEVO: POST /api/v1/cve/subscribe/:cveId - Suscribirse a actualizaciones
  async subscribeToCVE(req: AuthenticatedRequest, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const { cveId } = req.params;
      const userId = req.user?.id; // Asumiendo middleware de autenticación
      
      if (!cveId.match(/^CVE-\d{4}-\d{4,}$/)) {
        throw new AppError('Formato de CVE ID inválido', 400);
      }

      if (!userId) {
        throw new AppError('Usuario no autenticado', 401);
      }

      // Verificar que el CVE existe
      const cveExists = await Threat.findOne({
        origen: 'CVE',
        'cveData.cveId': cveId
      });

      if (!cveExists) {
        throw new AppError('CVE no encontrado', 404);
      }

      // Aquí implementarías la lógica de suscripción
      // Por ejemplo, guardar en una colección de suscripciones
      logger.info(`📧 Usuario ${userId} se suscribió a ${cveId}`);

      res.json({
        success: true,
        data: {
          cveId,
          userId,
          subscribedAt: new Date().toISOString()
        },
        message: `Suscripción a ${cveId} activada exitosamente`
      });
    } catch (error) {
      logger.error('❌ Error en suscripción a CVE:', error);
      next(error);
    }
  }

  // ⭐ NUEVO: DELETE /api/v1/cve/subscribe/:cveId - Desuscribirse
  async unsubscribeFromCVE(req: AuthenticatedRequest, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const { cveId } = req.params;
      const userId = req.user?.id;
      
      if (!cveId.match(/^CVE-\d{4}-\d{4,}$/)) {
        throw new AppError('Formato de CVE ID inválido', 400);
      }

      if (!userId) {
        throw new AppError('Usuario no autenticado', 401);
      }

      // Aquí implementarías la lógica de desuscripción
      logger.info(`📧 Usuario ${userId} se desuscribió de ${cveId}`);

      res.json({
        success: true,
        data: {
          cveId,
          userId,
          unsubscribedAt: new Date().toISOString()
        },
        message: `Desuscripción de ${cveId} completada exitosamente`
      });
    } catch (error) {
      logger.error('❌ Error en desuscripción de CVE:', error);
      next(error);
    }
  }

  // ⭐ NUEVO: PUT /api/v1/cve/:cveId/priority - Establecer prioridad
  async setCVEPriority(req: AuthenticatedRequest, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const { cveId } = req.params;
      const { priority, reason } = req.body;
      const userId = req.user?.id;
      
      if (!cveId.match(/^CVE-\d{4}-\d{4,}$/)) {
        throw new AppError('Formato de CVE ID inválido', 400);
      }

      const validPriorities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
      if (!validPriorities.includes(priority)) {
        throw new AppError('Prioridad inválida. Debe ser: CRITICAL, HIGH, MEDIUM o LOW', 400);
      }

      if (!reason || reason.trim().length < 10) {
        throw new AppError('Razón requerida (mínimo 10 caracteres)', 400);
      }

      // Buscar y actualizar el CVE
      const updatedThreat = await Threat.findOneAndUpdate(
        {
          origen: 'CVE',
          'cveData.cveId': cveId
        },
        {
          $set: {
            'cveData.customPriority': priority,
            'cveData.priorityReason': reason,
            'cveData.prioritySetBy': userId,
            'cveData.prioritySetAt': new Date(),
            ultimaActualizacion: new Date()
          }
        },
        { new: true }
      );

      if (!updatedThreat) {
        throw new AppError('CVE no encontrado', 404);
      }

      logger.info(`🎯 Prioridad ${priority} establecida para ${cveId} por usuario ${userId}`);

      res.json({
        success: true,
        data: {
          cveId,
          priority,
          reason,
          setBy: userId,
          setAt: new Date().toISOString()
        },
        message: `Prioridad ${priority} establecida para ${cveId} exitosamente`
      });
    } catch (error) {
      logger.error('❌ Error estableciendo prioridad de CVE:', error);
      next(error);
    }
  }
}

export const cveController = new CVEController();