import { Request, Response, NextFunction } from 'express';
import { riskService } from '../services/RiskService';
import { ApiResponse } from '../types';

export class RiskController {
  // GET /api/v1/risks/matrix
  async getRiskMatrix(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const matrix = await riskService.getRiskMatrix();
      
      res.json({
        success: true,
        data: matrix
      });
    } catch (error) {
      next(error);
    }
  }

  // GET /api/v1/risks/dashboard
  async getDashboardKPIs(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const kpis = await riskService.getDashboardKPIs();
      
      res.json({
        success: true,
        data: kpis
      });
    } catch (error) {
      next(error);
    }
  }

  // POST /api/v1/risks/calculate
  async calculateRisk(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const { assetId, threatId, vulnerabilityId } = req.body;
      const risk = await riskService.createOrUpdateRisk(assetId, threatId, vulnerabilityId);
      
      res.json({
        success: true,
        data: risk,
        message: 'Riesgo calculado exitosamente'
      });
    } catch (error) {
      next(error);
    }
  }

  // POST /api/v1/risks/recalculate-all
  async recalculateAllRisks(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const result = await riskService.recalculateAllRisks();
      
      res.json({
        success: true,
        data: result,
        message: 'Recálculo masivo completado'
      });
    } catch (error) {
      next(error);
    }
  }

  // GET /api/v1/risks/top/:limit?
  async getTopRisks(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const limit = parseInt(req.params.limit) || 10;
      const topRisks = await riskService.getTopRisks(limit);
      
      res.json({
        success: true,
        data: topRisks
      });
    } catch (error) {
      next(error);
    }
  }
}

export const riskController = new RiskController();