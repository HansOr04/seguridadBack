import { Request, Response, NextFunction } from 'express';
import { assetService } from '../services/AssetService';
import { ApiResponse } from '../types';
import { AppError } from '../middleware/errorHandler';

export class AssetController {
  // GET /api/v1/assets
  async getAssets(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const options = {
        page: parseInt(req.query.page as string) || 1,
        limit: parseInt(req.query.limit as string) || 10,
        sort: req.query.sort as string || '-fechaCreacion',
        filter: {
          tipo: req.query.tipo,
          propietario: req.query.propietario,
          search: req.query.search
        }
      };

      const result = await assetService.getAssets(options);

      res.json({
        success: true,
        data: result.assets,
        pagination: result.pagination
      });
    } catch (error) {
      next(error);
    }
  }

  // GET /api/v1/assets/:id
  async getAssetById(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const asset = await assetService.getAssetById(req.params.id);
      
      res.json({
        success: true,
        data: asset
      });
    } catch (error) {
      next(error);
    }
  }

  // POST /api/v1/assets
  async createAsset(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const asset = await assetService.createAsset(req.body);
      
      res.status(201).json({
        success: true,
        data: asset,
        message: 'Activo creado exitosamente'
      });
    } catch (error) {
      next(error);
    }
  }

  // PUT /api/v1/assets/:id
  async updateAsset(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const asset = await assetService.updateAsset(req.params.id, req.body);
      
      res.json({
        success: true,
        data: asset,
        message: 'Activo actualizado exitosamente'
      });
    } catch (error) {
      next(error);
    }
  }

  // DELETE /api/v1/assets/:id
  async deleteAsset(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    try {
      await assetService.deleteAsset(req.params.id);
      
      res.json({
        success: true,
        message: 'Activo eliminado exitosamente'
      });
    } catch (error) {
      next(error);
    }
  }

  // GET /api/v1/assets/stats
  async getAssetStats(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const stats = await assetService.getAssetStats();
      
      res.json({
        success: true,
        data: stats
      });
    } catch (error) {
      next(error);
    }
  }

  // GET /api/v1/assets/:id/dependencies
  async getAssetDependencies(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const dependencies = await assetService.getAssetDependencies(req.params.id);
      
      res.json({
        success: true,
        data: dependencies
      });
    } catch (error) {
      next(error);
    }
  }

  // POST /api/v1/assets/bulk-import
  async bulkImportAssets(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    try {
      if (!Array.isArray(req.body.assets)) {
        throw new AppError('Se requiere un array de activos', 400);
      }

      const result = await assetService.bulkImportAssets(req.body.assets);
      
      res.json({
        success: true,
        data: result,
        message: `Importación completada: ${result.successful} exitosos, ${result.failed} fallidos`
      });
    } catch (error) {
      next(error);
    }
  }
}

export const assetController = new AssetController();