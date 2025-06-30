// ===========================
// src/routes/assets.ts - CORREGIDO
// ===========================
import { Router } from 'express';
import { assetController } from '../controllers/assetController';
import { authenticate, authorize } from '../middleware/auth';
import { validateAsset, validateAssetUpdate } from '../middleware/validation';
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

// GET /api/v1/assets - Obtener lista de activos (CACHÉ)
router.get('/', 
  cacheMiddleware(CACHE_TTL.assets), 
  assetController.getAssets.bind(assetController)
);

// GET /api/v1/assets/stats - Estadísticas de activos (CACHÉ OPTIMIZADO)
router.get('/stats', 
  cacheMiddleware(CACHE_TTL.asset_stats), 
  assetController.getAssetStats.bind(assetController)
);

// POST /api/v1/assets/bulk-import - Importación masiva
router.post(
  '/bulk-import',
  authorize(RolUsuario.ADMIN, RolUsuario.OPERADOR),
  assetController.bulkImportAssets.bind(assetController)
);

// GET /api/v1/assets/:id - Obtener activo por ID (CACHÉ)
router.get('/:id', 
  cacheMiddleware(CACHE_TTL.assets), 
  assetController.getAssetById.bind(assetController)
);

// GET /api/v1/assets/:id/dependencies - Dependencias del activo (CACHÉ)
router.get('/:id/dependencies', 
  cacheMiddleware(CACHE_TTL.assets), 
  assetController.getAssetDependencies.bind(assetController)
);

// POST /api/v1/assets - Crear nuevo activo
router.post(
  '/',
  authorize(RolUsuario.ADMIN, RolUsuario.OPERADOR),
  validateAsset,
  assetController.createAsset.bind(assetController)
);

// PUT /api/v1/assets/:id - Actualizar activo
router.put(
  '/:id',
  authorize(RolUsuario.ADMIN, RolUsuario.OPERADOR),
  validateAssetUpdate,
  assetController.updateAsset.bind(assetController)
);

// DELETE /api/v1/assets/:id - Eliminar activo
router.delete(
  '/:id',
  authorize(RolUsuario.ADMIN),
  assetController.deleteAsset.bind(assetController)
);

export default router;