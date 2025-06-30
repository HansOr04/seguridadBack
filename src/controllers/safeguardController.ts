import { Request, Response, NextFunction } from 'express';
import { safeguardService } from '../services/SafeguardService';
import { ApiResponse, EstadoSalvaguarda } from '../types';
import { AppError } from '../middleware/errorHandler';

export class SafeguardController {
  // GET /api/v1/safeguards
  async getSafeguards(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const options = {
        page: parseInt(req.query.page as string) || 1,
        limit: parseInt(req.query.limit as string) || 10,
        sort: req.query.sort as string || '-fechaCreacion',
        filter: {
          tipo: req.query.tipo,
          categoria: req.query.categoria,
          estado: req.query.estado,
          responsable: req.query.responsable,
          search: req.query.search
        }
      };

      const result = await safeguardService.getSafeguards(options);

      res.json({
        success: true,
        data: result.safeguards,
        pagination: result.pagination
      });
    } catch (error) {
      next(error);
    }
  }

  // GET /api/v1/safeguards/:id
  async getSafeguardById(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const safeguard = await safeguardService.getSafeguardById(req.params.id);
      
      res.json({
        success: true,
        data: safeguard
      });
    } catch (error) {
      next(error);
    }
  }
  async getSafeguardStats(req: Request, res: Response<ApiResponse>, next: NextFunction) {
  try {
    const stats = await safeguardService.getSafeguardStats();
    
    res.json({
      success: true,
      data: stats,
      message: 'Estadísticas de salvaguardas obtenidas exitosamente'
    });
  } catch (error) {
    next(error);
  }
}

  // POST /api/v1/safeguards
  async createSafeguard(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const safeguard = await safeguardService.createSafeguard(req.body);
      
      res.status(201).json({
        success: true,
        data: safeguard,
        message: 'Salvaguarda creada exitosamente'
      });
    } catch (error) {
      next(error);
    }
  }

  // PUT /api/v1/safeguards/:id
  async updateSafeguard(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const safeguard = await safeguardService.updateSafeguard(req.params.id, req.body);
      
      res.json({
        success: true,
        data: safeguard,
        message: 'Salvaguarda actualizada exitosamente'
      });
    } catch (error) {
      next(error);
    }
  }

  // DELETE /api/v1/safeguards/:id
  async deleteSafeguard(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    try {
      await safeguardService.deleteSafeguard(req.params.id);
      
      res.json({
        success: true,
        message: 'Salvaguarda eliminada exitosamente'
      });
    } catch (error) {
      next(error);
    }
  }

  // POST /api/v1/safeguards/:id/implement
  async implementSafeguard(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const { fechaImplementacion } = req.body;
      const safeguard = await safeguardService.implementSafeguard(
        req.params.id, 
        fechaImplementacion ? new Date(fechaImplementacion) : undefined
      );
      
      res.json({
        success: true,
        data: safeguard,
        message: 'Salvaguarda implementada exitosamente'
      });
    } catch (error) {
      next(error);
    }
  }

  // POST /api/v1/safeguards/:id/kpi
  async addKPI(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const { nombre, valor, unidad } = req.body;
      
      if (!nombre || valor === undefined || !unidad) {
        throw new AppError('Nombre, valor y unidad son requeridos para el KPI', 400);
      }

      const safeguard = await safeguardService.addKPI(req.params.id, {
        nombre,
        valor: parseFloat(valor),
        unidad
      });
      
      res.json({
        success: true,
        data: safeguard,
        message: 'KPI agregado exitosamente'
      });
    } catch (error) {
      next(error);
    }
  }

  // GET /api/v1/safeguards/estado/:estado
  async getSafeguardsByEstado(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const { estado } = req.params;
      
      if (!Object.values(EstadoSalvaguarda).includes(estado as EstadoSalvaguarda)) {
        throw new AppError('Estado de salvaguarda inválido', 400);
      }

      const safeguards = await safeguardService.getSafeguardsByEstado(estado as EstadoSalvaguarda);
      
      res.json({
        success: true,
        data: safeguards
      });
    } catch (error) {
      next(error);
    }
  }

  // GET /api/v1/safeguards/expired
  async getExpiredSafeguards(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const safeguards = await safeguardService.getExpiredSafeguards();
      
      res.json({
        success: true,
        data: safeguards,
        message: `${safeguards.length} salvaguardas vencidas encontradas`
      });
    } catch (error) {
      next(error);
    }
  }

  // GET /api/v1/safeguards/upcoming-reviews?days=30
  async getUpcomingReviews(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const days = parseInt(req.query.days as string) || 30;
      const safeguards = await safeguardService.getUpcomingReviews(days);
      
      res.json({
        success: true,
        data: safeguards,
        message: `${safeguards.length} salvaguardas próximas a revisión en ${days} días`
      });
    } catch (error) {
      next(error);
    }
  }

  // GET /api/v1/safeguards/effectiveness
  async getProgramEffectiveness(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const effectiveness = await safeguardService.calculateProgramEffectiveness();
      
      res.json({
        success: true,
        data: effectiveness
      });
    } catch (error) {
      next(error);
    }
  }

  // GET /api/v1/safeguards/recommendations/:riskId
  async getRecommendationsForRisk(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const recommendations = await safeguardService.recommendSafeguardsForRisk(req.params.riskId);
      
      res.json({
        success: true,
        data: recommendations,
        message: 'Recomendaciones de salvaguardas generadas'
      });
    } catch (error) {
      next(error);
    }
  }

  // GET /api/v1/safeguards/dashboard
  async getDashboardStats(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const [effectiveness, expired, upcoming] = await Promise.all([
        safeguardService.calculateProgramEffectiveness(),
        safeguardService.getExpiredSafeguards(),
        safeguardService.getUpcomingReviews(30)
      ]);

      const dashboardStats = {
        ...effectiveness,
        expiredCount: expired.length,
        upcomingReviewsCount: upcoming.length,
        implementationRate: effectiveness.totalSafeguards > 0 
          ? (effectiveness.implementedSafeguards / effectiveness.totalSafeguards) * 100 
          : 0
      };
      
      res.json({
        success: true,
        data: dashboardStats
      });
    } catch (error) {
      next(error);
    }
  }
}

export const safeguardController = new SafeguardController();