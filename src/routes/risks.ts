import { Router } from 'express';
import { riskController } from '../controllers/riskController';
import { authenticate, authorize } from '../middleware/auth';
import { RolUsuario } from '../types';

const router = Router();

// Todas las rutas requieren autenticación
router.use(authenticate);

// GET /api/v1/risks/matrix - Matriz de riesgos
router.get('/matrix', riskController.getRiskMatrix.bind(riskController));

// GET /api/v1/risks/dashboard - KPIs del dashboard
router.get('/dashboard', riskController.getDashboardKPIs.bind(riskController));

// GET /api/v1/risks/top/:limit? - Top riesgos
router.get('/top/:limit?', riskController.getTopRisks.bind(riskController));

// POST /api/v1/risks/calculate - Calcular riesgo específico
router.post(
  '/calculate',
  authorize(RolUsuario.ADMIN, RolUsuario.AUDITOR, RolUsuario.OPERADOR),
  riskController.calculateRisk.bind(riskController)
);

// POST /api/v1/risks/recalculate-all - Recálculo masivo
router.post(
  '/recalculate-all',
  authorize(RolUsuario.ADMIN, RolUsuario.AUDITOR),
  riskController.recalculateAllRisks.bind(riskController)
);

export default router;