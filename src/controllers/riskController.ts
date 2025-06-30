import { Request, Response, NextFunction } from 'express';
import { riskService } from '../services/RiskService';
import { ApiResponse } from '../types';
import { AppError } from '../middleware/errorHandler';

export class RiskController {
  // ===========================
  // MÉTODOS NUEVOS FALTANTES (CRUD)
  // ===========================

  // ✅ NUEVO: GET /api/v1/risks - Listado general con filtros y paginación
  async getRisks(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const options = {
        page: parseInt(req.query.page as string) || 1,
        limit: parseInt(req.query.limit as string) || 10,
        sort: req.query.sort as string || '-fechaCalculo',
        filter: {
          // ✅ CONVERSIÓN EXPLÍCITA A STRING para evitar errores de tipo
          nivel: req.query.nivel ? String(req.query.nivel) : undefined,
          estado: req.query.estado ? String(req.query.estado) : undefined,
          activo: req.query.activo ? String(req.query.activo) : undefined,
          amenaza: req.query.amenaza ? String(req.query.amenaza) : undefined,
          valorMinimo: req.query.valorMinimo ? parseFloat(String(req.query.valorMinimo)) : undefined,
          valorMaximo: req.query.valorMaximo ? parseFloat(String(req.query.valorMaximo)) : undefined,
          search: req.query.search ? String(req.query.search) : undefined
        }
      };

      const result = await riskService.getRisks(options);

      res.json({
        success: true,
        data: result.risks,
        pagination: result.pagination,
        message: `${result.risks.length} riesgos obtenidos exitosamente`
      });
    } catch (error) {
      next(error);
    }
  }

  // ✅ NUEVO: GET /api/v1/risks/stats - Estadísticas detalladas
  async getRiskStats(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const stats = await riskService.getRiskStats();

      res.json({
        success: true,
        data: stats,
        message: 'Estadísticas de riesgos obtenidas exitosamente'
      });
    } catch (error) {
      next(error);
    }
  }

  // ✅ NUEVO: GET /api/v1/risks/:id - Obtener riesgo individual
  async getRiskById(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const { id } = req.params;
      
      if (!id) {
        throw new AppError('ID de riesgo requerido', 400);
      }

      const risk = await riskService.getRiskById(id);

      res.json({
        success: true,
        data: risk,
        message: 'Riesgo obtenido exitosamente'
      });
    } catch (error) {
      next(error);
    }
  }

  // ✅ NUEVO: POST /api/v1/risks - Crear nuevo riesgo
  async createRisk(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const riskData = req.body;
      
      // Validaciones básicas
      if (!riskData.activo || !riskData.amenaza) {
        throw new AppError('Activo y amenaza son requeridos', 400);
      }

      // Validaciones adicionales
      if (riskData.probabilidad !== undefined && (riskData.probabilidad < 0 || riskData.probabilidad > 10)) {
        throw new AppError('La probabilidad debe estar entre 0 y 10', 400);
      }

      if (riskData.impacto !== undefined && (riskData.impacto < 0 || riskData.impacto > 10)) {
        throw new AppError('El impacto debe estar entre 0 y 10', 400);
      }

      const risk = await riskService.createRisk(riskData);

      res.status(201).json({
        success: true,
        data: risk,
        message: 'Riesgo creado exitosamente'
      });
    } catch (error) {
      next(error);
    }
  }

  // ✅ NUEVO: PUT /api/v1/risks/:id - Actualizar riesgo
  async updateRisk(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const { id } = req.params;
      const updateData = req.body;

      if (!id) {
        throw new AppError('ID de riesgo requerido', 400);
      }

      // Validaciones de datos de actualización
      if (updateData.probabilidad !== undefined && (updateData.probabilidad < 0 || updateData.probabilidad > 10)) {
        throw new AppError('La probabilidad debe estar entre 0 y 10', 400);
      }

      if (updateData.impacto !== undefined && (updateData.impacto < 0 || updateData.impacto > 10)) {
        throw new AppError('El impacto debe estar entre 0 y 10', 400);
      }

      const risk = await riskService.updateRisk(id, updateData);

      res.json({
        success: true,
        data: risk,
        message: 'Riesgo actualizado exitosamente'
      });
    } catch (error) {
      next(error);
    }
  }

  // ✅ NUEVO: DELETE /api/v1/risks/:id - Eliminar riesgo
  async deleteRisk(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const { id } = req.params;

      if (!id) {
        throw new AppError('ID de riesgo requerido', 400);
      }

      await riskService.deleteRisk(id);

      res.json({
        success: true,
        message: 'Riesgo eliminado exitosamente'
      });
    } catch (error) {
      next(error);
    }
  }

  // ===========================
  // MÉTODOS EXISTENTES (mantener todos)
  // ===========================

  // GET /api/v1/risks/matrix - Matriz de riesgos (EXISTENTE)
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

  // GET /api/v1/risks/dashboard - KPIs del dashboard (EXISTENTE)
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

  // POST /api/v1/risks/calculate - Calcular riesgo específico (EXISTENTE)
  async calculateRisk(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const { assetId, threatId, vulnerabilityId } = req.body;
      
      if (!assetId || !threatId) {
        throw new AppError('Asset ID y Threat ID son requeridos', 400);
      }

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

  // POST /api/v1/risks/recalculate-all - Recálculo masivo (EXISTENTE)
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

  // GET /api/v1/risks/top/:limit? - Top riesgos (EXISTENTE)
  async getTopRisks(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const limit = parseInt(req.params.limit) || 10;
      
      if (limit < 1 || limit > 100) {
        throw new AppError('El límite debe estar entre 1 y 100', 400);
      }

      const topRisks = await riskService.getTopRisks(limit);
      
      res.json({
        success: true,
        data: topRisks,
        message: `Top ${topRisks.length} riesgos obtenidos`
      });
    } catch (error) {
      next(error);
    }
  }

  // ===========================
  // MÉTODOS ADICIONALES ÚTILES
  // ===========================

  // GET /api/v1/risks/by-asset/:assetId - Riesgos por activo
  async getRisksByAsset(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const { assetId } = req.params;
      
      if (!assetId) {
        throw new AppError('Asset ID requerido', 400);
      }

      const options = {
        page: parseInt(req.query.page as string) || 1,
        limit: parseInt(req.query.limit as string) || 20,
        sort: req.query.sort as string || '-valorRiesgo',
        filter: {
          activo: assetId
        }
      };

      const result = await riskService.getRisks(options);

      res.json({
        success: true,
        data: result.risks,
        pagination: result.pagination,
        message: `${result.risks.length} riesgos encontrados para el activo`
      });
    } catch (error) {
      next(error);
    }
  }

  // GET /api/v1/risks/by-threat/:threatId - Riesgos por amenaza
  async getRisksByThreat(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const { threatId } = req.params;
      
      if (!threatId) {
        throw new AppError('Threat ID requerido', 400);
      }

      const options = {
        page: parseInt(req.query.page as string) || 1,
        limit: parseInt(req.query.limit as string) || 20,
        sort: req.query.sort as string || '-valorRiesgo',
        filter: {
          amenaza: threatId
        }
      };

      const result = await riskService.getRisks(options);

      res.json({
        success: true,
        data: result.risks,
        pagination: result.pagination,
        message: `${result.risks.length} riesgos encontrados para la amenaza`
      });
    } catch (error) {
      next(error);
    }
  }

  // GET /api/v1/risks/by-level/:level - Riesgos por nivel
  async getRisksByLevel(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const { level } = req.params;
      
      const validLevels = ['Crítico', 'Alto', 'Medio', 'Bajo', 'Muy Bajo'];
      if (!validLevels.includes(level)) {
        throw new AppError(`Nivel inválido. Valores permitidos: ${validLevels.join(', ')}`, 400);
      }

      const options = {
        page: parseInt(req.query.page as string) || 1,
        limit: parseInt(req.query.limit as string) || 20,
        sort: req.query.sort as string || '-valorRiesgo',
        filter: {
          nivel: level
        }
      };

      const result = await riskService.getRisks(options);

      res.json({
        success: true,
        data: result.risks,
        pagination: result.pagination,
        message: `${result.risks.length} riesgos de nivel ${level} encontrados`
      });
    } catch (error) {
      next(error);
    }
  }

  // POST /api/v1/risks/bulk-recalculate - Recálculo de riesgos específicos
  async bulkRecalculateRisks(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const { riskIds } = req.body;
      
      if (!Array.isArray(riskIds) || riskIds.length === 0) {
        throw new AppError('Lista de IDs de riesgos requerida', 400);
      }

      if (riskIds.length > 100) {
        throw new AppError('Máximo 100 riesgos por operación', 400);
      }

      let processed = 0;
      let errors = 0;
      const results = [];

      for (const riskId of riskIds) {
        try {
          const risk = await riskService.getRiskById(riskId);
          await riskService.createOrUpdateRisk(
            risk.activo._id.toString(),
            risk.amenaza._id.toString(),
            risk.vulnerabilidad?._id?.toString()
          );
          processed++;
          results.push({ riskId, status: 'success' });
        } catch (error) {
          errors++;
          results.push({ 
            riskId, 
            status: 'error', 
            error: (error as Error).message 
          });
        }
      }

      res.json({
        success: true,
        data: {
          processed,
          errors,
          results
        },
        message: `Recálculo completado: ${processed} exitosos, ${errors} errores`
      });
    } catch (error) {
      next(error);
    }
  }

  // GET /api/v1/risks/export - Exportar riesgos (preparado para futuro)
  async exportRisks(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const format = req.query.format as string || 'json';
      const level = req.query.level as string;
      
      const options = {
        page: 1,
        limit: 10000, // Exportar todos
        sort: '-valorRiesgo',
        filter: level ? { nivel: level } : {}
      };

      const result = await riskService.getRisks(options);

      if (format === 'csv') {
        // TODO: Implementar exportación CSV en el futuro
        throw new AppError('Formato CSV no implementado aún', 501);
      }

      res.json({
        success: true,
        data: {
          risks: result.risks,
          exportedAt: new Date().toISOString(),
          totalExported: result.risks.length,
          format
        },
        message: `${result.risks.length} riesgos exportados exitosamente`
      });
    } catch (error) {
      next(error);
    }
  }
}

export const riskController = new RiskController();