import { Router } from 'express';
import { assetController } from '../controllers/assetController';
import { authenticate, authorize } from '../middleware/auth';
import { validateAsset, validateAssetUpdate } from '../middleware/validation';
import { RolUsuario } from '../types';

const router = Router();

// Todas las rutas requieren autenticación
router.use(authenticate);

// GET /api/v1/assets - Obtener lista de activos
router.get('/', assetController.getAssets.bind(assetController));

// GET /api/v1/assets/stats - Estadísticas de activos
router.get('/stats', assetController.getAssetStats.bind(assetController));

// POST /api/v1/assets/bulk-import - Importación masiva
router.post(
  '/bulk-import',
  authorize(RolUsuario.ADMIN, RolUsuario.OPERADOR),
  assetController.bulkImportAssets.bind(assetController)
);

// GET /api/v1/assets/:id - Obtener activo por ID
router.get('/:id', assetController.getAssetById.bind(assetController));

// GET /api/v1/assets/:id/dependencies - Dependencias del activo
router.get('/:id/dependencies', assetController.getAssetDependencies.bind(assetController));

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