import { Router } from 'express';
import { safeguardController } from '../controllers/safeguardController';
import { authenticate, authorize } from '../middleware/auth';
import { validateSafeguard, validateSafeguardUpdate } from '../middleware/validation';
import { RolUsuario } from '../types';

const router = Router();

// Todas las rutas requieren autenticación
router.use(authenticate);

// GET /api/v1/safeguards - Obtener lista de salvaguardas
router.get('/', safeguardController.getSafeguards.bind(safeguardController));

// GET /api/v1/safeguards/dashboard - Estadísticas del dashboard
router.get('/dashboard', safeguardController.getDashboardStats.bind(safeguardController));

// GET /api/v1/safeguards/effectiveness - Efectividad del programa
router.get('/effectiveness', safeguardController.getProgramEffectiveness.bind(safeguardController));

// GET /api/v1/safeguards/expired - Salvaguardas vencidas
router.get('/expired', safeguardController.getExpiredSafeguards.bind(safeguardController));

// GET /api/v1/safeguards/upcoming-reviews - Próximas revisiones
router.get('/upcoming-reviews', safeguardController.getUpcomingReviews.bind(safeguardController));

// GET /api/v1/safeguards/estado/:estado - Salvaguardas por estado
router.get('/estado/:estado', safeguardController.getSafeguardsByEstado.bind(safeguardController));

// GET /api/v1/safeguards/recommendations/:riskId - Recomendaciones para un riesgo
router.get('/recommendations/:riskId', safeguardController.getRecommendationsForRisk.bind(safeguardController));

// GET /api/v1/safeguards/:id - Obtener salvaguarda por ID
router.get('/:id', safeguardController.getSafeguardById.bind(safeguardController));

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