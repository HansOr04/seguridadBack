import { Request, Response, NextFunction } from 'express';
import { cveIntegrationService } from '../services/CVEIntegrationService';
import { cveSyncJob } from '../jobs/cveSync';
import { ApiResponse } from '../types';
import { AppError } from '../middleware/errorHandler';

export class CVEController {
  // GET /api/v1/cve/search?keyword=microsoft&severity=HIGH
  async searchCVEs(req: Request, res: Response<ApiResponse>, next: NextFunction) {
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
  async getCVEById(req: Request, res: Response<ApiResponse>, next: NextFunction) {
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
  async getRecentCVEs(req: Request, res: Response<ApiResponse>, next: NextFunction) {
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

  // POST /api/v1/cve/sync/manual
  async manualSync(req: Request, res: Response<ApiResponse>, next: NextFunction) {
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
  async getSyncStatus(req: Request, res: Response<ApiResponse>, next: NextFunction) {
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
  async stopSync(req: Request, res: Response<ApiResponse>, next: NextFunction) {
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
  async syncRecent(req: Request, res: Response<ApiResponse>, next: NextFunction) {
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

  // GET /api/v1/cve/stats
  async getCVEStats(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    try {
      // Aquí podrías implementar estadísticas de CVEs desde tu base de datos
      // Por ahora, retornamos stats básicas
      const stats = {
        totalCVEs: 0, // Implementar query a Threat con origen CVE
        cveCriticos: 0,
        cveAltos: 0,
        cveMedios: 0,
        cveBajos: 0,
        ultimaActualizacion: cveSyncJob.getStatus().lastSyncDate
      };

      res.json({
        success: true,
        data: stats
      });
    } catch (error) {
      next(error);
    }
  }
}

export const cveController = new CVEController();