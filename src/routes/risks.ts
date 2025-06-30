// ===========================
// src/routes/risks.ts - CORREGIDO
// ===========================
import { Router } from 'express';
import { riskController } from '../controllers/riskController';
import { authenticate, authorize } from '../middleware/auth';
import { RolUsuario } from '../types';
import { 
  cacheMiddleware, 
  cacheInvalidationMiddleware, 
  CACHE_TTL 
} from '../middleware/cache';

const router = Router();

// Todas las rutas requieren autenticación
router.use(authenticate);
router.use(cacheInvalidationMiddleware);

// GET /api/v1/risks/matrix - Matriz de riesgos (CACHÉ OPTIMIZADO)
router.get('/matrix', 
  cacheMiddleware(CACHE_TTL.risk_matrix), 
  riskController.getRiskMatrix.bind(riskController)
);

// GET /api/v1/risks/dashboard - KPIs del dashboard (CACHÉ)
router.get('/dashboard', 
  cacheMiddleware(CACHE_TTL.dashboard), 
  riskController.getDashboardKPIs.bind(riskController)
);

// GET /api/v1/risks/top/:limit? - Top riesgos (CACHÉ)
router.get('/top/:limit?', 
  cacheMiddleware(CACHE_TTL.risks), 
  riskController.getTopRisks.bind(riskController)
);

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