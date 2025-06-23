import { Router } from 'express';
import { threatController } from '../controllers/threatController';
import { authenticate, authorize } from '../middleware/auth';
import { RolUsuario } from '../types';

const router = Router();

// Todas las rutas requieren autenticación
router.use(authenticate);

// GET /api/v1/threats - Obtener lista de amenazas
router.get('/', threatController.getThreats.bind(threatController));

// GET /api/v1/threats/stats - Estadísticas de amenazas
router.get('/stats', threatController.getThreatStats.bind(threatController));

// GET /api/v1/threats/dashboard - Estadísticas del dashboard
router.get('/dashboard', threatController.getDashboardStats.bind(threatController));

// GET /api/v1/threats/tipo/:tipo - Amenazas por tipo
router.get('/tipo/:tipo', threatController.getThreatsByTipo.bind(threatController));

// GET /api/v1/threats/cve/:cveId - Amenaza por CVE
router.get('/cve/:cveId', threatController.getThreatByCVE.bind(threatController));

// GET /api/v1/threats/activo/:assetId - Amenazas para un activo
router.get('/activo/:assetId', threatController.getThreatsForAsset.bind(threatController));

// POST /api/v1/threats/magerit/import - Importar amenazas MAGERIT
router.post(
  '/magerit/import',
  authorize(RolUsuario.ADMIN, RolUsuario.AUDITOR),
  threatController.importMageritThreats.bind(threatController)
);

// GET /api/v1/threats/:id - Obtener amenaza por ID
router.get('/:id', threatController.getThreatById.bind(threatController));

// POST /api/v1/threats - Crear nueva amenaza
router.post(
  '/',
  authorize(RolUsuario.ADMIN, RolUsuario.OPERADOR),
  threatController.createThreat.bind(threatController)
);

// PUT /api/v1/threats/:id - Actualizar amenaza
router.put(
  '/:id',
  authorize(RolUsuario.ADMIN, RolUsuario.OPERADOR),
  threatController.updateThreat.bind(threatController)
);

// DELETE /api/v1/threats/:id - Eliminar amenaza
router.delete(
  '/:id',
  authorize(RolUsuario.ADMIN),
  threatController.deleteThreat.bind(threatController)
);

// POST /api/v1/threats/:id/assign-asset - Asignar amenaza a activo
router.post(
  '/:id/assign-asset',
  authorize(RolUsuario.ADMIN, RolUsuario.OPERADOR),
  threatController.assignThreatToAsset.bind(threatController)
);

export default router;