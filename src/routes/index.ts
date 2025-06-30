// ===========================
// src/routes/index.ts - CORREGIDO CON IMPORTS CORRECTOS
// ===========================
import { Router, Request, Response } from 'express';
import assetRoutes from './assets';
import riskRoutes from './risks';
import authRoutes from './auth';
import cveRoutes from './cve';
import safeguardRoutes from './safeguards';
import threatRoutes from './threats';
import vulnerabilityRoutes from './vulnerabilities';
import dashboardRoutes from './dashboard';
import { authorize } from '../middleware/auth';
import { RolUsuario } from '../types';
import { cacheStatsMiddleware } from '../middleware/cache';

const router = Router();

// Rutas de la API con caché optimizado
router.use('/auth', authRoutes);
router.use('/assets', assetRoutes);
router.use('/risks', riskRoutes);
router.use('/cve', cveRoutes);
router.use('/safeguards', safeguardRoutes);
router.use('/threats', threatRoutes);
router.use('/vulnerabilities', vulnerabilityRoutes);
router.use('/dashboard', dashboardRoutes);

// Ruta para estadísticas de caché (debugging/monitoreo)
router.get('/cache/stats', 
  authorize(RolUsuario.ADMIN), 
  cacheStatsMiddleware
);

// Health check optimizado
router.get('/health', (req: Request, res: Response) => {
  res.json({
    success: true,
    message: 'SIGRISK-EC Backend API funcionando correctamente',
    timestamp: new Date().toISOString(),
    version: '1.0.0',
    cache: 'Enabled with intelligent invalidation',
    performance: 'Optimized with MongoDB indexes',
    modules: {
      auth: 'Autenticación y autorización',
      assets: 'Gestión de activos MAGERIT (CACHED)',
      risks: 'Análisis cuantitativo de riesgos (CACHED)', 
      cve: 'Integración con CVE/NVD (CACHED + NEW FEATURES)',
      safeguards: 'Gestión de salvaguardas (CACHED)',
      threats: 'Gestión de amenazas (CACHED)',
      vulnerabilities: 'Gestión de vulnerabilidades (CACHED)',
      dashboard: 'Dashboard y estadísticas (OPTIMIZED)'
    }
  });
});

export default router;