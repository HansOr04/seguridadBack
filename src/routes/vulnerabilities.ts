import { Router } from 'express';
import { vulnerabilityController } from '../controllers/vulnerabilityController';
import { authenticate, authorize } from '../middleware/auth';
import { RolUsuario } from '../types';

const router = Router();

// Todas las rutas requieren autenticación
router.use(authenticate);

// GET /api/v1/vulnerabilities - Obtener lista de vulnerabilidades
router.get('/', vulnerabilityController.getVulnerabilities.bind(vulnerabilityController));

// GET /api/v1/vulnerabilities/stats - Estadísticas de vulnerabilidades
router.get('/stats', vulnerabilityController.getVulnerabilityStats.bind(vulnerabilityController));

// GET /api/v1/vulnerabilities/dashboard - Estadísticas del dashboard
router.get('/dashboard', vulnerabilityController.getDashboardStats.bind(vulnerabilityController));

// GET /api/v1/vulnerabilities/critical - Vulnerabilidades críticas
router.get('/critical', vulnerabilityController.getCriticalVulnerabilities.bind(vulnerabilityController));

// GET /api/v1/vulnerabilities/categoria/:categoria - Vulnerabilidades por categoría
router.get('/categoria/:categoria', vulnerabilityController.getVulnerabilitiesByCategoria.bind(vulnerabilityController));

// GET /api/v1/vulnerabilities/activo/:assetId - Vulnerabilidades para un activo
router.get('/activo/:assetId', vulnerabilityController.getVulnerabilitiesForAsset.bind(vulnerabilityController));

// POST /api/v1/vulnerabilities/bulk-action - Acciones en lote
router.post(
  '/bulk-action',
  authorize(RolUsuario.ADMIN, RolUsuario.OPERADOR),
  vulnerabilityController.bulkAction.bind(vulnerabilityController)
);

// POST /api/v1/vulnerabilities/scan/:assetId - Escanear vulnerabilidades de un activo
router.post(
  '/scan/:assetId',
  authorize(RolUsuario.ADMIN, RolUsuario.OPERADOR, RolUsuario.AUDITOR),
  vulnerabilityController.scanAssetVulnerabilities.bind(vulnerabilityController)
);

// GET /api/v1/vulnerabilities/:id - Obtener vulnerabilidad por ID
router.get('/:id', vulnerabilityController.getVulnerabilityById.bind(vulnerabilityController));

// POST /api/v1/vulnerabilities - Crear nueva vulnerabilidad
router.post(
  '/',
  authorize(RolUsuario.ADMIN, RolUsuario.OPERADOR),
  vulnerabilityController.createVulnerability.bind(vulnerabilityController)
);

// PUT /api/v1/vulnerabilities/:id - Actualizar vulnerabilidad
router.put(
  '/:id',
  authorize(RolUsuario.ADMIN, RolUsuario.OPERADOR),
  vulnerabilityController.updateVulnerability.bind(vulnerabilityController)
);

// DELETE /api/v1/vulnerabilities/:id - Eliminar vulnerabilidad
router.delete(
  '/:id',
  authorize(RolUsuario.ADMIN),
  vulnerabilityController.deleteVulnerability.bind(vulnerabilityController)
);

// POST /api/v1/vulnerabilities/:id/mitigate - Mitigar vulnerabilidad
router.post(
  '/:id/mitigate',
  authorize(RolUsuario.ADMIN, RolUsuario.OPERADOR),
  vulnerabilityController.mitigateVulnerability.bind(vulnerabilityController)
);

// POST /api/v1/vulnerabilities/:id/reopen - Reabrir vulnerabilidad
router.post(
  '/:id/reopen',
  authorize(RolUsuario.ADMIN, RolUsuario.OPERADOR),
  vulnerabilityController.reopenVulnerability.bind(vulnerabilityController)
);

export default router;