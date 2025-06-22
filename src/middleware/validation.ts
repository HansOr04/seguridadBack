import { body, validationResult } from 'express-validator';
import { Request, Response, NextFunction } from 'express';
import { AppError } from './errorHandler';
import { TipoActivo, RolUsuario, EstadoSalvaguarda } from '../types';

// Middleware para manejar errores de validación
export const handleValidationErrors = (req: Request, res: Response, next: NextFunction) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const errorMessage = errors.array().map(error => error.msg).join(', ');
    return next(new AppError(errorMessage, 400));
  }
  next();
};

// Validaciones para Asset
export const validateAsset = [
  body('codigo')
    .trim()
    .isLength({ min: 1, max: 50 })
    .withMessage('Código es requerido y debe tener máximo 50 caracteres'),
  
  body('nombre')
    .trim()
    .isLength({ min: 1, max: 200 })
    .withMessage('Nombre es requerido y debe tener máximo 200 caracteres'),
  
  body('tipo')
    .isIn(Object.values(TipoActivo))
    .withMessage('Tipo de activo no válido'),
  
  body('categoria')
    .trim()
    .isLength({ min: 1, max: 100 })
    .withMessage('Categoría es requerida y debe tener máximo 100 caracteres'),
  
  body('propietario')
    .trim()
    .isLength({ min: 1, max: 100 })
    .withMessage('Propietario es requerido'),
  
  body('custodio')
    .trim()
    .isLength({ min: 1, max: 100 })
    .withMessage('Custodio es requerido'),
  
  body('ubicacion')
    .trim()
    .isLength({ min: 1, max: 200 })
    .withMessage('Ubicación es requerida'),
  
  body('valoracion.confidencialidad')
    .isFloat({ min: 0, max: 10 })
    .withMessage('Confidencialidad debe estar entre 0 y 10'),
  
  body('valoracion.integridad')
    .isFloat({ min: 0, max: 10 })
    .withMessage('Integridad debe estar entre 0 y 10'),
  
  body('valoracion.disponibilidad')
    .isFloat({ min: 0, max: 10 })
    .withMessage('Disponibilidad debe estar entre 0 y 10'),
  
  body('valoracion.autenticidad')
    .isFloat({ min: 0, max: 10 })
    .withMessage('Autenticidad debe estar entre 0 y 10'),
  
  body('valoracion.trazabilidad')
    .isFloat({ min: 0, max: 10 })
    .withMessage('Trazabilidad debe estar entre 0 y 10'),
  
  body('valorEconomico')
    .isFloat({ min: 0 })
    .withMessage('Valor económico debe ser mayor o igual a 0'),
  
  handleValidationErrors
];

export const validateAssetUpdate = [
  body('codigo')
    .optional()
    .trim()
    .isLength({ min: 1, max: 50 })
    .withMessage('Código debe tener máximo 50 caracteres'),
  
  body('nombre')
    .optional()
    .trim()
    .isLength({ min: 1, max: 200 })
    .withMessage('Nombre debe tener máximo 200 caracteres'),
  
  body('tipo')
    .optional()
    .isIn(Object.values(TipoActivo))
    .withMessage('Tipo de activo no válido'),
  
  handleValidationErrors
];

// Validaciones para Safeguard
export const validateSafeguard = [
  body('codigo')
    .trim()
    .isLength({ min: 1, max: 50 })
    .withMessage('Código es requerido y debe tener máximo 50 caracteres'),
  
  body('nombre')
    .trim()
    .isLength({ min: 1, max: 200 })
    .withMessage('Nombre es requerido y debe tener máximo 200 caracteres'),
  
  body('tipo')
    .isIn(['Preventiva', 'Detectiva', 'Correctiva', 'Disuasoria', 'Compensatoria'])
    .withMessage('Tipo de salvaguarda no válido'),
  
  body('categoria')
    .isIn(['Física', 'Lógica', 'Técnica', 'Administrativa', 'Legal', 'Organizacional'])
    .withMessage('Categoría de salvaguarda no válida'),
  
  body('descripcion')
    .trim()
    .isLength({ min: 1, max: 1000 })
    .withMessage('Descripción es requerida y debe tener máximo 1000 caracteres'),
  
  body('estado')
    .optional()
    .isIn(Object.values(EstadoSalvaguarda))
    .withMessage('Estado de salvaguarda no válido'),
  
  body('eficacia')
    .isFloat({ min: 0, max: 100 })
    .withMessage('Eficacia debe estar entre 0 y 100'),
  
  body('costo')
    .isFloat({ min: 0 })
    .withMessage('Costo debe ser mayor o igual a 0'),
  
  body('costeMantenenimiento')
    .isFloat({ min: 0 })
    .withMessage('Costo de mantenimiento debe ser mayor o igual a 0'),
  
  body('responsable')
    .trim()
    .isLength({ min: 1, max: 100 })
    .withMessage('Responsable es requerido y debe tener máximo 100 caracteres'),
  
  body('periodicidadRevision')
    .optional()
    .isInt({ min: 1, max: 60 })
    .withMessage('Periodicidad de revisión debe estar entre 1 y 60 meses'),
  
  handleValidationErrors
];

export const validateSafeguardUpdate = [
  body('codigo')
    .optional()
    .trim()
    .isLength({ min: 1, max: 50 })
    .withMessage('Código debe tener máximo 50 caracteres'),
  
  body('nombre')
    .optional()
    .trim()
    .isLength({ min: 1, max: 200 })
    .withMessage('Nombre debe tener máximo 200 caracteres'),
  
  body('eficacia')
    .optional()
    .isFloat({ min: 0, max: 100 })
    .withMessage('Eficacia debe estar entre 0 y 100'),
  
  body('costo')
    .optional()
    .isFloat({ min: 0 })
    .withMessage('Costo debe ser mayor o igual a 0'),
  
  handleValidationErrors
];

// Validaciones para Auth
export const validateRegister = [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Email válido es requerido'),
  
  body('password')
    .isLength({ min: 8 })
    .withMessage('Password debe tener al menos 8 caracteres')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage('Password debe contener al menos: 1 minúscula, 1 mayúscula, 1 número y 1 símbolo'),
  
  body('nombre')
    .trim()
    .isLength({ min: 1, max: 50 })
    .withMessage('Nombre es requerido y debe tener máximo 50 caracteres'),
  
  body('apellido')
    .trim()
    .isLength({ min: 1, max: 50 })
    .withMessage('Apellido es requerido y debe tener máximo 50 caracteres'),
  
  body('rol')
    .optional()
    .isIn(Object.values(RolUsuario))
    .withMessage('Rol no válido'),
  
  handleValidationErrors
];

export const validateLogin = [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Email válido es requerido'),
  
  body('password')
    .notEmpty()
    .withMessage('Password es requerido'),
  
  handleValidationErrors
];