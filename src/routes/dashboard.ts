// src/routes/dashboard.ts
import { Router } from 'express';
import { dashboardController } from '../controllers/dashboardController';
import { authenticate, authorize } from '../middleware/auth';
import { RolUsuario } from '../types';

const router = Router();

// Todas las rutas requieren autenticación
router.use(authenticate);

// GET /api/v1/dashboard/kpis - KPIs principales del dashboard
router.get('/kpis', dashboardController.getKPIs.bind(dashboardController));

// GET /api/v1/dashboard/trends - Datos de tendencias para gráficos
router.get('/trends', dashboardController.getTrends.bind(dashboardController));

// GET /api/v1/dashboard/activities - Feed de actividades recientes
router.get('/activities', dashboardController.getActivities.bind(dashboardController));

// GET /api/v1/dashboard/stats - Estadísticas generales del sistema
router.get('/stats', dashboardController.getGeneralStats.bind(dashboardController));

// GET /api/v1/dashboard/summary - Resumen completo del dashboard
router.get('/summary', dashboardController.getDashboardSummary.bind(dashboardController));

// GET /api/v1/dashboard/health - Estado de salud del sistema
router.get('/health', 
  authorize(RolUsuario.ADMIN, RolUsuario.AUDITOR), // Solo admins y auditores
  dashboardController.getDashboardHealth.bind(dashboardController)
);

export default router;