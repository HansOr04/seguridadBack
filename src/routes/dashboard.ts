// ===========================
// src/routes/dashboard.ts - CORREGIDO
// ===========================
import { Router } from 'express';
import { dashboardController } from '../controllers/dashboardController';
import { authenticate, authorize } from '../middleware/auth';
import { RolUsuario } from '../types';
import { 
  cacheMiddleware, 
  dashboardCacheMiddleware, 
  kpisCacheMiddleware,
  CACHE_TTL 
} from '../middleware/cache';

const router = Router();

// Todas las rutas requieren autenticación
router.use(authenticate);

// ⭐ CRÍTICO: GET /api/v1/dashboard/kpis - KPIs principales del dashboard (CACHÉ OPTIMIZADO)
router.get('/kpis', 
  kpisCacheMiddleware, 
  dashboardController.getKPIs.bind(dashboardController)
);

// GET /api/v1/dashboard/trends - Datos de tendencias para gráficos (CACHÉ LARGO)
router.get('/trends', 
  cacheMiddleware(CACHE_TTL.risk_trends), 
  dashboardController.getTrends.bind(dashboardController)
);

// GET /api/v1/dashboard/activities - Feed de actividades recientes (CACHÉ CORTO)
router.get('/activities', 
  cacheMiddleware(60), // 1 minuto para actividades
  dashboardController.getActivities.bind(dashboardController)
);

// GET /api/v1/dashboard/stats - Estadísticas generales del sistema
router.get('/stats', 
  dashboardCacheMiddleware, 
  dashboardController.getGeneralStats.bind(dashboardController)
);

// GET /api/v1/dashboard/summary - Resumen completo del dashboard
router.get('/summary', 
  dashboardCacheMiddleware, 
  dashboardController.getDashboardSummary.bind(dashboardController)
);

// GET /api/v1/dashboard/health - Estado de salud del sistema (SIN CACHÉ)
router.get('/health', 
  authorize(RolUsuario.ADMIN, RolUsuario.AUDITOR),
  dashboardController.getDashboardHealth.bind(dashboardController)
);
router.get('/matrix', 
  cacheMiddleware(CACHE_TTL.risk_matrix), 
  dashboardController.getRiskMatrix.bind(dashboardController)
);

// GET /api/v1/dashboard/risk-matrix - Alias para compatibilidad
router.get('/risk-matrix', 
  cacheMiddleware(CACHE_TTL.risk_matrix), 
  dashboardController.getRiskMatrix.bind(dashboardController)
);

export default router;