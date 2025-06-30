// ===========================
// src/routes/threats.ts - CORREGIDO
// ===========================
import { Router } from 'express';
import { threatController } from '../controllers/threatController';
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

// GET /api/v1/threats - Obtener lista de amenazas (CACHÉ)
router.get('/', 
  cacheMiddleware(CACHE_TTL.threats), 
  threatController.getThreats.bind(threatController)
);

// GET /api/v1/threats/stats - Estadísticas de amenazas (CACHÉ OPTIMIZADO)
router.get('/stats', 
  cacheMiddleware(CACHE_TTL.threat_stats), 
  threatController.getThreatStats.bind(threatController)
);

// GET /api/v1/threats/dashboard - Estadísticas del dashboard (CACHÉ)
router.get('/dashboard', 
  cacheMiddleware(CACHE_TTL.dashboard), 
  threatController.getDashboardStats.bind(threatController)
);

// GET /api/v1/threats/tipo/:tipo - Amenazas por tipo (CACHÉ)
router.get('/tipo/:tipo', 
  cacheMiddleware(CACHE_TTL.threats), 
  threatController.getThreatsByTipo.bind(threatController)
);

// GET /api/v1/threats/cve/:cveId - Amenaza por CVE (CACHÉ)
router.get('/cve/:cveId', 
  cacheMiddleware(CACHE_TTL.threats), 
  threatController.getThreatByCVE.bind(threatController)
);

// GET /api/v1/threats/activo/:assetId - Amenazas para un activo (CACHÉ)
router.get('/activo/:assetId', 
  cacheMiddleware(CACHE_TTL.threats), 
  threatController.getThreatsForAsset.bind(threatController)
);

// POST /api/v1/threats/magerit/import - Importar amenazas MAGERIT
router.post(
  '/magerit/import',
  authorize(RolUsuario.ADMIN, RolUsuario.AUDITOR),
  threatController.importMageritThreats.bind(threatController)
);

// GET /api/v1/threats/:id - Obtener amenaza por ID (CACHÉ)
router.get('/:id', 
  cacheMiddleware(CACHE_TTL.threats), 
  threatController.getThreatById.bind(threatController)
);

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