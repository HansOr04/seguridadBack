import jwt from 'jsonwebtoken';
import { Request, Response, NextFunction } from 'express';
import { User } from '../models/User';
import { config } from '../config/environment';
import { AppError } from './errorHandler';
import { RolUsuario } from '../types';

interface AuthenticatedRequest extends Request {
  user?: any;
}

export const authenticate = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
) => {
  try {
    let token;

    // Obtener token del header
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
      return next(new AppError('Token de acceso requerido', 401));
    }

    // Verificar token
    const decoded = jwt.verify(token, config.JWT_SECRET) as any;

    // Verificar si el usuario existe
    const user = await User.findById(decoded.id);
    if (!user) {
      return next(new AppError('Usuario no encontrado', 401));
    }

    // Verificar si el usuario está activo
    if (!user.activo) {
      return next(new AppError('Usuario inactivo', 401));
    }

    req.user = user;
    next();
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      return next(new AppError('Token expirado', 401));
    }
    if (error instanceof jwt.JsonWebTokenError) {
      return next(new AppError('Token inválido', 401));
    }
    next(error);
  }
};

export const authorize = (...roles: RolUsuario[]) => {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    if (!req.user) {
      return next(new AppError('Usuario no autenticado', 401));
    }

    if (!roles.includes(req.user.rol)) {
      return next(new AppError('Permisos insuficientes', 403));
    }

    next();
  };
};