import rateLimit from 'express-rate-limit';
import { config } from '../config/environment';

export const createRateLimit = (windowMs?: number, max?: number) => {
  return rateLimit({
    windowMs: (windowMs || config.RATE_LIMIT_WINDOW) * 60 * 1000, // minutos a ms
    max: max || config.RATE_LIMIT_MAX,
    message: {
      success: false,
      error: 'Demasiadas peticiones, intenta más tarde'
    },
    standardHeaders: true,
    legacyHeaders: false
  });
};

export const authRateLimit = createRateLimit(15, 5); // 5 intentos por 15 min
export const generalRateLimit = createRateLimit(); // Config por defecto
export const apiRateLimit = createRateLimit(1, 1000); // 1000 por minuto