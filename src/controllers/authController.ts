import { Request, Response, NextFunction } from 'express';
import * as jwt from 'jsonwebtoken';
import { User } from '../models/User';
import { config } from '../config/environment';
import { ApiResponse } from '../types';
import { AppError } from '../middleware/errorHandler';
import logger from '../utils/logger';
import { Types } from 'mongoose';

export class AuthController {
  // Generar tokens JWT - VERSIÓN CORREGIDA
  private generateTokens(userId: string): { accessToken: string; refreshToken: string } {
    const payload = { id: userId };
    
    const accessToken = jwt.sign(
      payload,
      config.JWT_SECRET,
      { expiresIn: config.JWT_EXPIRE } as jwt.SignOptions
    );

    const refreshToken = jwt.sign(
      payload,
      config.JWT_REFRESH_SECRET,
      { expiresIn: config.JWT_REFRESH_EXPIRE } as jwt.SignOptions
    );

    return { accessToken, refreshToken };
  }

  // POST /api/v1/auth/register
  async register(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const { email, password, nombre, apellido, rol } = req.body;

      // Verificar si el usuario ya existe
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        throw new AppError('El email ya está registrado', 400);
      }

      // Crear usuario
      const user = new User({
        email,
        password,
        nombre,
        apellido,
        rol
      });

      await user.save();

      // Generar tokens
      const tokens = this.generateTokens((user._id as Types.ObjectId).toString());

      logger.info(`Usuario registrado: ${email}`);

      res.status(201).json({
        success: true,
        data: {
          user: {
            id: user._id,
            email: user.email,
            nombre: user.nombre,
            apellido: user.apellido,
            rol: user.rol
          },
          ...tokens
        },
        message: 'Usuario registrado exitosamente'
      });
    } catch (error) {
      next(error);
    }
  }

  // POST /api/v1/auth/login
  async login(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const { email, password } = req.body;

      // Buscar usuario con password
      const user = await User.findOne({ email, activo: true }).select('+password');
      if (!user) {
        throw new AppError('Credenciales inválidas', 401);
      }

      // Verificar password
      const isPasswordValid = await user.comparePassword(password);
      if (!isPasswordValid) {
        throw new AppError('Credenciales inválidas', 401);
      }

      // Actualizar último acceso
      user.ultimoAcceso = new Date();
      await user.save();

      // Generar tokens
      const tokens = this.generateTokens((user._id as Types.ObjectId).toString());

      logger.info(`Usuario logueado: ${email}`);

      res.json({
        success: true,
        data: {
          user: {
            id: user._id,
            email: user.email,
            nombre: user.nombre,
            apellido: user.apellido,
            rol: user.rol,
            ultimoAcceso: user.ultimoAcceso
          },
          ...tokens
        },
        message: 'Login exitoso'
      });
    } catch (error) {
      next(error);
    }
  }

  // POST /api/v1/auth/refresh
  async refreshToken(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const { refreshToken } = req.body;

      if (!refreshToken) {
        throw new AppError('Refresh token requerido', 400);
      }

      // Verificar refresh token
      const decoded = jwt.verify(refreshToken, config.JWT_REFRESH_SECRET) as any;

      // Verificar que el usuario existe y está activo
      const user = await User.findById(decoded.id);
      if (!user || !user.activo) {
        throw new AppError('Usuario no encontrado o inactivo', 401);
      }

      // Generar nuevos tokens
      const tokens = this.generateTokens((user._id as Types.ObjectId).toString());

      res.json({
        success: true,
        data: tokens,
        message: 'Tokens renovados exitosamente'
      });
    } catch (error) {
      if (error instanceof jwt.TokenExpiredError) {
        return next(new AppError('Refresh token expirado', 401));
      }
      if (error instanceof jwt.JsonWebTokenError) {
        return next(new AppError('Refresh token inválido', 401));
      }
      next(error);
    }
  }

  // GET /api/v1/auth/me
  async getMe(req: any, res: Response<ApiResponse>, next: NextFunction) {
    try {
      const user = await User.findById(req.user.id);
      
      res.json({
        success: true,
        data: user
      });
    } catch (error) {
      next(error);
    }
  }

  // POST /api/v1/auth/logout
  async logout(req: Request, res: Response<ApiResponse>, next: NextFunction) {
    try {
      // En una implementación más robusta, aquí se invalidaría el token
      // Por ahora, solo retornamos éxito
      res.json({
        success: true,
        message: 'Logout exitoso'
      });
    } catch (error) {
      next(error);
    }
  }
}

export const authController = new AuthController();