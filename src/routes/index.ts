// src/routes/index.ts - ACTUALIZADO con dashboard
import { Router } from 'express';
import assetRoutes from './assets';
import riskRoutes from './risks';
import authRoutes from './auth';
import cveRoutes from './cve';
import safeguardRoutes from './safeguards';
import threatRoutes from './threats';
import vulnerabilityRoutes from './vulnerabilities';
import dashboardRoutes from './dashboard'; // NUEVO

const router = Router();

// Rutas de la API
router.use('/auth', authRoutes);
router.use('/assets', assetRoutes);
router.use('/risks', riskRoutes);
router.use('/cve', cveRoutes);
router.use('/safeguards', safeguardRoutes);
router.use('/threats', threatRoutes);
router.use('/vulnerabilities', vulnerabilityRoutes);
router.use('/dashboard', dashboardRoutes); // NUEVO

// Health check
router.get('/health', (req, res) => {
  res.json({
    success: true,
    message: 'SIGRISK-EC Backend API funcionando correctamente',
    timestamp: new Date().toISOString(),
    version: '1.0.0',
    modules: {
      auth: 'Autenticación y autorización',
      assets: 'Gestión de activos MAGERIT',
      risks: 'Análisis cuantitativo de riesgos',
      cve: 'Integración con CVE/NVD',
      safeguards: 'Gestión de salvaguardas',
      threats: 'Gestión de amenazas',
      vulnerabilities: 'Gestión de vulnerabilidades',
      dashboard: 'Dashboard y estadísticas' // AGREGADO
    }
  });
});

export default router;