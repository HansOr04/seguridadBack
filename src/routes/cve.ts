import { Router } from 'express';
import { cveController } from '../controllers/cveController';
import { authenticate, authorize } from '../middleware/auth';
import { RolUsuario } from '../types';

const router = Router();

// Todas las rutas requieren autenticación
router.use(authenticate);

// GET /api/v1/cve/search - Buscar CVEs
router.get('/search', cveController.searchCVEs.bind(cveController));

// GET /api/v1/cve/recent - CVEs recientes
router.get('/recent', cveController.getRecentCVEs.bind(cveController));

// GET /api/v1/cve/stats - Estadísticas de CVEs
router.get('/stats', cveController.getCVEStats.bind(cveController));

// GET /api/v1/cve/:cveId - Obtener CVE específico
router.get('/:cveId', cveController.getCVEById.bind(cveController));

// === Rutas de sincronización (requieren permisos especiales) ===

// GET /api/v1/cve/sync/status - Estado de sincronización
router.get('/sync/status', cveController.getSyncStatus.bind(cveController));

// POST /api/v1/cve/sync/recent - Sincronización de CVEs recientes
router.post(
  '/sync/recent',
  authorize(RolUsuario.ADMIN, RolUsuario.AUDITOR),
  cveController.syncRecent.bind(cveController)
);

// POST /api/v1/cve/sync/manual - Sincronización manual
router.post(
  '/sync/manual',
  authorize(RolUsuario.ADMIN, RolUsuario.AUDITOR),
  cveController.manualSync.bind(cveController)
);

// POST /api/v1/cve/sync/stop - Detener sincronización
router.post(
  '/sync/stop',
  authorize(RolUsuario.ADMIN),
  cveController.stopSync.bind(cveController)
);

export default router;