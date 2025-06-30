// ===========================
// src/routes/safeguards.ts - CORREGIDO
// ===========================
import { Router } from 'express';
import { safeguardController } from '../controllers/safeguardController';
import { authenticate, authorize } from '../middleware/auth';
import { validateSafeguard, validateSafeguardUpdate } from '../middleware/validation';
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

// GET /api/v1/safeguards - Obtener lista de salvaguardas (CACHÉ)
router.get('/', 
  cacheMiddleware(CACHE_TTL.safeguards), 
  safeguardController.getSafeguards.bind(safeguardController)
);

// GET /api/v1/safeguards/dashboard - Estadísticas del dashboard (CACHÉ)
router.get('/dashboard', 
  cacheMiddleware(CACHE_TTL.dashboard), 
  safeguardController.getDashboardStats.bind(safeguardController)
);

// GET /api/v1/safeguards/effectiveness - Efectividad del programa (CACHÉ OPTIMIZADO)
router.get('/effectiveness', 
  cacheMiddleware(CACHE_TTL.safeguard_stats), 
  safeguardController.getProgramEffectiveness.bind(safeguardController)
);

// GET /api/v1/safeguards/expired - Salvaguardas vencidas (CACHÉ CORTO)
router.get('/expired', 
  cacheMiddleware(CACHE_TTL.safeguards), 
  safeguardController.getExpiredSafeguards.bind(safeguardController)
);

// GET /api/v1/safeguards/upcoming-reviews - Próximas revisiones (CACHÉ CORTO)
router.get('/upcoming-reviews', 
  cacheMiddleware(CACHE_TTL.safeguards), 
  safeguardController.getUpcomingReviews.bind(safeguardController)
);

// GET /api/v1/safeguards/estado/:estado - Salvaguardas por estado (CACHÉ)
router.get('/estado/:estado', 
  cacheMiddleware(CACHE_TTL.safeguards), 
  safeguardController.getSafeguardsByEstado.bind(safeguardController)
);

// GET /api/v1/safeguards/recommendations/:riskId - Recomendaciones para un riesgo (CACHÉ)
router.get('/recommendations/:riskId', 
  cacheMiddleware(CACHE_TTL.safeguards), 
  safeguardController.getRecommendationsForRisk.bind(safeguardController)
);

// GET /api/v1/safeguards/:id - Obtener salvaguarda por ID (CACHÉ)
router.get('/:id', 
  cacheMiddleware(CACHE_TTL.safeguards), 
  safeguardController.getSafeguardById.bind(safeguardController)
);

// POST /api/v1/safeguards - Crear nueva salvaguarda
router.post(
  '/',
  authorize(RolUsuario.ADMIN, RolUsuario.OPERADOR),
  validateSafeguard,
  safeguardController.createSafeguard.bind(safeguardController)
);

// PUT /api/v1/safeguards/:id - Actualizar salvaguarda
router.put(
  '/:id',
  authorize(RolUsuario.ADMIN, RolUsuario.OPERADOR),
  validateSafeguardUpdate,
  safeguardController.updateSafeguard.bind(safeguardController)
);

// DELETE /api/v1/safeguards/:id - Eliminar salvaguarda
router.delete(
  '/:id',
  authorize(RolUsuario.ADMIN),
  safeguardController.deleteSafeguard.bind(safeguardController)
);

// POST /api/v1/safeguards/:id/implement - Implementar salvaguarda
router.post(
  '/:id/implement',
  authorize(RolUsuario.ADMIN, RolUsuario.OPERADOR),
  safeguardController.implementSafeguard.bind(safeguardController)
);

// POST /api/v1/safeguards/:id/kpi - Agregar KPI a salvaguarda
router.post(
  '/:id/kpi',
  authorize(RolUsuario.ADMIN, RolUsuario.OPERADOR, RolUsuario.AUDITOR),
  safeguardController.addKPI.bind(safeguardController)
);

export default router;