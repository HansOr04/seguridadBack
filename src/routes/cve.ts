// ===========================
// src/routes/cve.ts - CORREGIDO CON TODAS LAS NUEVAS FUNCIONALIDADES
// ===========================
import { Router } from 'express';
import { cveController } from '../controllers/cveController';
import { authenticate, authorize } from '../middleware/auth';
import { RolUsuario } from '../types';
import { 
  cacheMiddleware, 
  cacheInvalidationMiddleware, 
  cveFrequentCacheMiddleware,
  cveCacheMiddleware,
  CACHE_TTL 
} from '../middleware/cache';

const router = Router();

// Todas las rutas requieren autenticación
router.use(authenticate);

// Aplicar invalidación de caché para operaciones de escritura
router.use(cacheInvalidationMiddleware);

// === RUTAS DE CONSULTA BÁSICA CON CACHÉ ===

// GET /api/v1/cve/search - Buscar CVEs (caché dinámico)
router.get('/search', 
  cacheMiddleware(CACHE_TTL.cve_stats), 
  cveController.searchCVEs.bind(cveController)
);

// GET /api/v1/cve/recent - CVEs recientes (caché corto)
router.get('/recent', 
  cacheMiddleware(CACHE_TTL.cve_trending), 
  cveController.getRecentCVEs.bind(cveController)
);

// ⭐ NUEVO: GET /api/v1/cve/frequent - CVEs más frecuentes (caché optimizado)
router.get('/frequent', 
  cveFrequentCacheMiddleware, 
  cveController.getFrequentCVEs.bind(cveController)
);

// ⭐ NUEVO: GET /api/v1/cve/trending - CVEs en tendencia (caché dinámico)
router.get('/trending', 
  cacheMiddleware(CACHE_TTL.cve_trending), 
  cveController.getTrendingCVEs.bind(cveController)
);

// ⭐ NUEVO: GET /api/v1/cve/critical - CVEs críticos únicamente (caché medio)
router.get('/critical', 
  cacheMiddleware(CACHE_TTL.cve_critical), 
  cveController.getCriticalCVEs.bind(cveController)
);

// ⭐ NUEVO: GET /api/v1/cve/by-severity/:severity - CVEs por severidad específica
router.get('/by-severity/:severity', 
  cacheMiddleware(CACHE_TTL.cve_stats), 
  cveController.getCVEsBySeverity.bind(cveController)
);

// === RUTAS DE ESTADÍSTICAS Y ANÁLISIS CON CACHÉ ===

// ⚠️ DEPRECADO: GET /api/v1/cve/stats - Estadísticas básicas (mantener para compatibilidad)
router.get('/stats', 
  cveCacheMiddleware, 
  cveController.getCVEStats.bind(cveController)
);

// ⭐ NUEVO: GET /api/v1/cve/statistics - Estadísticas detalladas (reemplaza /stats)
router.get('/statistics', 
  cveCacheMiddleware, 
  cveController.getDetailedCVEStats.bind(cveController)
);

// ⭐ NUEVO: GET /api/v1/cve/timeline - Timeline de CVEs (caché largo)
router.get('/timeline', 
  cacheMiddleware(CACHE_TTL.risk_trends), 
  cveController.getCVETimeline.bind(cveController)
);

// === RUTAS DE ANÁLISIS ESPECÍFICO CON CACHÉ ===

// ⭐ NUEVO: GET /api/v1/cve/impact-analysis/:cveId - Análisis de impacto de CVE
router.get('/impact-analysis/:cveId', 
  cacheMiddleware(CACHE_TTL.cve_stats), 
  cveController.getCVEImpactAnalysis.bind(cveController)
);

// ⭐ NUEVO: GET /api/v1/cve/asset-correlation/:assetId - CVEs que afectan un activo
router.get('/asset-correlation/:assetId', 
  cacheMiddleware(CACHE_TTL.assets), 
  cveController.getCVEsForAsset.bind(cveController)
);

// === RUTAS DE GESTIÓN Y SUSCRIPCIONES (SIN CACHÉ) ===

// ⭐ NUEVO: POST /api/v1/cve/subscribe/:cveId - Suscribirse a actualizaciones de CVE
router.post('/subscribe/:cveId', cveController.subscribeToCVE.bind(cveController));

// ⭐ NUEVO: DELETE /api/v1/cve/subscribe/:cveId - Desuscribirse de CVE
router.delete('/subscribe/:cveId', cveController.unsubscribeFromCVE.bind(cveController));

// ⭐ NUEVO: PUT /api/v1/cve/:cveId/priority - Establecer prioridad personalizada de CVE
router.put(
  '/:cveId/priority',
  authorize(RolUsuario.ADMIN, RolUsuario.AUDITOR, RolUsuario.OPERADOR),
  cveController.setCVEPriority.bind(cveController)
);

// === RUTA ESPECÍFICA POR ID CON CACHÉ (debe ir antes de sync para evitar conflictos) ===

// GET /api/v1/cve/:cveId - Obtener CVE específico
router.get('/:cveId', 
  cacheMiddleware(CACHE_TTL.cve_stats), 
  cveController.getCVEById.bind(cveController)
);

// === RUTAS DE SINCRONIZACIÓN (SIN CACHÉ) ===

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