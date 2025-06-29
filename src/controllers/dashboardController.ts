// src/controllers/dashboardController.ts
import { Request, Response, NextFunction } from 'express';
import { dashboardService } from '../services/DashboardService';
import { ApiResponse } from '../types';
import { AppError } from '../middleware/errorHandler';

export class DashboardController {
  
  // GET /api/v1/dashboard/kpis
  async getKPIs(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const kpis = await dashboardService.getDashboardKPIs();
      
      res.json({
        success: true,
        data: kpis,
        message: 'KPIs del dashboard obtenidos exitosamente'
      });
    } catch (error) {
      next(error);
    }
  }

  // GET /api/v1/dashboard/trends?range=30d
  async getTrends(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const range = req.query.range as '7d' | '30d' | '90d' || '30d';
      
      // Validar rango
      if (!['7d', '30d', '90d'].includes(range)) {
        throw new AppError('Rango inválido. Use: 7d, 30d, o 90d', 400);
      }

      const trends = await dashboardService.getTrends(range);
      
      res.json({
        success: true,
        data: trends,
        message: `Tendencias para ${range} obtenidas exitosamente`
      });
    } catch (error) {
      next(error);
    }
  }

  // GET /api/v1/dashboard/activities?limit=10
  async getActivities(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const limit = parseInt(req.query.limit as string) || 10;
      
      // Validar límite
      if (limit < 1 || limit > 50) {
        throw new AppError('El límite debe estar entre 1 y 50', 400);
      }

      const activities = await dashboardService.getRecentActivities(limit);
      
      res.json({
        success: true,
        data: activities,
        message: `${activities.length} actividades recientes obtenidas`
      });
    } catch (error) {
      next(error);
    }
  }

  // GET /api/v1/dashboard/stats
  async getGeneralStats(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const stats = await dashboardService.getGeneralStats();
      
      res.json({
        success: true,
        data: stats,
        message: 'Estadísticas generales obtenidas exitosamente'
      });
    } catch (error) {
      next(error);
    }
  }

  // GET /api/v1/dashboard/summary
  async getDashboardSummary(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    try {
      // Obtener datos combinados para el dashboard principal
      const [kpis, recentActivities, generalStats] = await Promise.all([
        dashboardService.getDashboardKPIs(),
        dashboardService.getRecentActivities(5),
        dashboardService.getGeneralStats()
      ]);

      const summary = {
        kpis,
        recentActivities,
        generalStats,
        timestamp: new Date().toISOString()
      };
      
      res.json({
        success: true,
        data: summary,
        message: 'Resumen del dashboard obtenido exitosamente'
      });
    } catch (error) {
      next(error);
    }
  }

  // GET /api/v1/dashboard/health
  async getDashboardHealth(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    try {
      // Verificar el estado de salud del sistema
      const [
        totalActivos,
        riesgosAltos,
        vulnerabilidadesAbiertas,
        salvaguardasPendientes
      ] = await Promise.all([
        dashboardService.getGeneralStats(),
        // Agregar más verificaciones según necesites
        Promise.resolve(0), // placeholder
        Promise.resolve(0), // placeholder  
        Promise.resolve(0)  // placeholder
      ]);

      const healthScore = this.calculateHealthScore({
        totalActivos: totalActivos.resumen.totalActivos,
        riesgosCriticos: totalActivos.criticos.riesgosCriticos,
        vulnerabilidadesCriticas: totalActivos.criticos.vulnerabilidadesCriticas,
        implementacionRate: totalActivos.implementacion.porcentajeImplementacion
      });

      const health = {
        score: healthScore,
        status: this.getHealthStatus(healthScore),
        details: {
          activos: totalActivos.resumen.totalActivos > 0 ? 'good' : 'warning',
          riesgos: totalActivos.criticos.riesgosCriticos < 5 ? 'good' : 'critical',
          vulnerabilidades: totalActivos.criticos.vulnerabilidadesCriticas < 3 ? 'good' : 'warning',
          implementacion: totalActivos.implementacion.porcentajeImplementacion > 70 ? 'good' : 'needs_attention'
        },
        recommendations: this.getHealthRecommendations(totalActivos)
      };
      
      res.json({
        success: true,
        data: health,
        message: 'Estado de salud del sistema obtenido'
      });
    } catch (error) {
      next(error);
    }
  }

  // Calcular puntuación de salud del sistema (0-100)
  private calculateHealthScore(data: {
    totalActivos: number;
    riesgosCriticos: number;
    vulnerabilidadesCriticas: number;
    implementacionRate: number;
  }): number {
    let score = 100;

    // Penalizar por riesgos críticos
    score -= data.riesgosCriticos * 10;

    // Penalizar por vulnerabilidades críticas
    score -= data.vulnerabilidadesCriticas * 15;

    // Bonificar por implementación de salvaguardas
    score += (data.implementacionRate - 50) * 0.5;

    // Mantener entre 0 y 100
    return Math.max(0, Math.min(100, Math.round(score)));
  }

  private getHealthStatus(score: number): string {
    if (score >= 80) return 'excellent';
    if (score >= 60) return 'good';
    if (score >= 40) return 'warning';
    return 'critical';
  }

  private getHealthRecommendations(stats: any): string[] {
    const recommendations: string[] = [];

    if (stats.criticos.riesgosCriticos > 5) {
      recommendations.push('Revisar y mitigar riesgos críticos pendientes');
    }

    if (stats.criticos.vulnerabilidadesCriticas > 3) {
      recommendations.push('Atender vulnerabilidades críticas inmediatamente');
    }

    if (stats.implementacion.porcentajeImplementacion < 70) {
      recommendations.push('Acelerar la implementación de salvaguardas');
    }

    if (stats.resumen.totalActivos < 5) {
      recommendations.push('Completar el inventario de activos de información');
    }

    if (recommendations.length === 0) {
      recommendations.push('Sistema en buen estado, continuar con el monitoreo regular');
    }

    return recommendations;
  }
}

export const dashboardController = new DashboardController();