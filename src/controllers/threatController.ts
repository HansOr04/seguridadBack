import { Request, Response, NextFunction } from 'express';
import { threatService } from '../services/ThreatService';
import { ApiResponse, TipoAmenaza } from '../types';
import { AppError } from '../middleware/errorHandler';

export class ThreatController {
  // GET /api/v1/threats
  async getThreats(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const options = {
        page: parseInt(req.query.page as string) || 1,
        limit: parseInt(req.query.limit as string) || 10,
        sort: req.query.sort as string || '-fechaDescubrimiento',
        filter: {
          tipo: req.query.tipo,
          origen: req.query.origen,
          probabilidad: req.query.probabilidad,
          search: req.query.search
        }
      };

      const result = await threatService.getThreats(options);

      res.json({
        success: true,
        data: result.threats,
        pagination: result.pagination
      });
    } catch (error) {
      next(error);
    }
  }

  // GET /api/v1/threats/:id
  async getThreatById(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const threat = await threatService.getThreatById(req.params.id);
      
      res.json({
        success: true,
        data: threat
      });
    } catch (error) {
      next(error);
    }
  }

  // POST /api/v1/threats
  async createThreat(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const threat = await threatService.createThreat(req.body);
      
      res.status(201).json({
        success: true,
        data: threat,
        message: 'Amenaza creada exitosamente'
      });
    } catch (error) {
      next(error);
    }
  }

  // PUT /api/v1/threats/:id
  async updateThreat(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const threat = await threatService.updateThreat(req.params.id, req.body);
      
      res.json({
        success: true,
        data: threat,
        message: 'Amenaza actualizada exitosamente'
      });
    } catch (error) {
      next(error);
    }
  }

  // DELETE /api/v1/threats/:id
  async deleteThreat(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    try {
      await threatService.deleteThreat(req.params.id);
      
      res.json({
        success: true,
        message: 'Amenaza eliminada exitosamente'
      });
    } catch (error) {
      next(error);
    }
  }

  // GET /api/v1/threats/tipo/:tipo
  async getThreatsByTipo(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const { tipo } = req.params;
      
      if (!Object.values(TipoAmenaza).includes(tipo as TipoAmenaza)) {
        throw new AppError('Tipo de amenaza inválido', 400);
      }

      const threats = await threatService.getThreatsByTipo(tipo as TipoAmenaza);
      
      res.json({
        success: true,
        data: threats
      });
    } catch (error) {
      next(error);
    }
  }

  // GET /api/v1/threats/cve/:cveId
  async getThreatByCVE(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const { cveId } = req.params;
      
      if (!cveId.match(/^CVE-\d{4}-\d{4,}$/)) {
        throw new AppError('Formato de CVE ID inválido', 400);
      }

      const threat = await threatService.getThreatByCVE(cveId);
      
      if (!threat) {
        throw new AppError('Amenaza CVE no encontrada', 404);
      }

      res.json({
        success: true,
        data: threat
      });
    } catch (error) {
      next(error);
    }
  }

  // GET /api/v1/threats/stats
  async getThreatStats(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const stats = await threatService.getThreatStats();
      
      res.json({
        success: true,
        data: stats
      });
    } catch (error) {
      next(error);
    }
  }

  // GET /api/v1/threats/activo/:assetId
  async getThreatsForAsset(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const { assetId } = req.params;
      const threats = await threatService.getThreatsForAsset(assetId);
      
      res.json({
        success: true,
        data: threats,
        message: `${threats.length} amenazas encontradas para el activo`
      });
    } catch (error) {
      next(error);
    }
  }

  // POST /api/v1/threats/:id/assign-asset
  async assignThreatToAsset(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const { id } = req.params;
      const { assetId } = req.body;
      
      if (!assetId) {
        throw new AppError('Asset ID es requerido', 400);
      }

      const threat = await threatService.assignThreatToAsset(id, assetId);
      
      res.json({
        success: true,
        data: threat,
        message: 'Amenaza asignada al activo exitosamente'
      });
    } catch (error) {
      next(error);
    }
  }

  // POST /api/v1/threats/magerit/import
  async importMageritThreats(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const { categoria, overwrite } = req.body;
      const result = await threatService.importMageritThreats(categoria, overwrite);
      
      res.json({
        success: true,
        data: result,
        message: 'Amenazas MAGERIT importadas exitosamente'
      });
    } catch (error) {
      next(error);
    }
  }

  // GET /api/v1/threats/dashboard
  async getDashboardStats(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const stats = await threatService.getDashboardStats();
      
      res.json({
        success: true,
        data: stats
      });
    } catch (error) {
      next(error);
    }
  }
}

export const threatController = new ThreatController();