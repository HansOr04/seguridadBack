// ===========================
// src/routes/auth.ts - CORREGIDO
// ===========================
import { Router } from 'express';
import { authController } from '../controllers/authController';
import { authenticate } from '../middleware/auth';
import { validateLogin, validateRegister } from '../middleware/validation';
import { authRateLimit } from '../middleware/rateLimit';

const router = Router();

// POST /api/v1/auth/register - Registro de usuario
router.post(
  '/register',
  authRateLimit,
  validateRegister,
  authController.register.bind(authController)
);

// POST /api/v1/auth/login - Login
router.post(
  '/login',
  authRateLimit,
  validateLogin,
  authController.login.bind(authController)
);

// POST /api/v1/auth/refresh - Renovar tokens
router.post('/refresh', authController.refreshToken.bind(authController));

// GET /api/v1/auth/me - Obtener perfil del usuario
router.get('/me', authenticate, authController.getMe.bind(authController));

// POST /api/v1/auth/logout - Logout
router.post('/logout', authenticate, authController.logout.bind(authController));

export default router;