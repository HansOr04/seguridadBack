import { Request, Response, NextFunction } from 'express';
import { ApiResponse } from '../types';
import logger from '../utils/logger';

// Configuración de TTL por tipo de endpoint (en segundos)
export const CACHE_TTL = {
  // Dashboard y KPIs - datos críticos que cambian frecuentemente
  dashboard: 120, // 2 minutos
  kpis: 120, // 2 minutos
  
  // CVEs - datos que pueden cambiar varias veces al día
  cve_frequent: 300, // 5 minutos
  cve_trending: 180, // 3 minutos
  cve_critical: 300, // 5 minutos
  cve_stats: 600, // 10 minutos
  
  // Amenazas - datos relativamente estáticos
  threats: 600, // 10 minutos
  threat_stats: 900, // 15 minutos
  
  // Activos - datos que cambian ocasionalmente
  assets: 300, // 5 minutos
  asset_stats: 600, // 10 minutos
  
  // Riesgos - cálculos complejos que cambian moderadamente
  risks: 300, // 5 minutos
  risk_matrix: 600, // 10 minutos
  risk_trends: 1800, // 30 minutos
  
  // Salvaguardas - datos que cambian ocasionalmente
  safeguards: 600, // 10 minutos
  safeguard_stats: 900, // 15 minutos
  
  // Vulnerabilidades - datos dinámicos
  vulnerabilities: 300, // 5 minutos
  vuln_stats: 600, // 10 minutos
  
  // Por defecto
  default: 300 // 5 minutos
} as const;

// Interface para entrada de caché
interface CacheEntry {
  data: any;
  timestamp: number;
  ttl: number;
  key: string;
}

// Almacén de caché en memoria
class InMemoryCache {
  private cache = new Map<string, CacheEntry>();
  private cleanupInterval: NodeJS.Timeout;

  constructor() {
    // Limpiar caché cada 5 minutos
    this.cleanupInterval = setInterval(() => {
      this.cleanup();
    }, 5 * 60 * 1000);
  }

  // Obtener valor del caché
  get(key: string): any | null {
    const entry = this.cache.get(key);
    
    if (!entry) {
      return null;
    }

    // Verificar si ha expirado
    const now = Date.now();
    if (now - entry.timestamp > entry.ttl * 1000) {
      this.cache.delete(key);
      logger.debug(`🗑️ Cache expired for key: ${key}`);
      return null;
    }

    logger.debug(`✅ Cache hit for key: ${key}`);
    return entry.data;
  }

  // Establecer valor en caché
  set(key: string, data: any, ttl: number): void {
    const entry: CacheEntry = {
      data,
      timestamp: Date.now(),
      ttl,
      key
    };

    this.cache.set(key, entry);
    logger.debug(`💾 Cache set for key: ${key}, TTL: ${ttl}s`);
  }

  // Invalidar caché por patrón
  invalidatePattern(pattern: string): number {
    let deletedCount = 0;
    const regex = new RegExp(pattern);

    for (const [key] of this.cache) {
      if (regex.test(key)) {
        this.cache.delete(key);
        deletedCount++;
      }
    }

    if (deletedCount > 0) {
      logger.info(`🗑️ Invalidated ${deletedCount} cache entries matching pattern: ${pattern}`);
    }

    return deletedCount;
  }

  // Invalidar caché específico
  invalidate(key: string): boolean {
    const deleted = this.cache.delete(key);
    if (deleted) {
      logger.debug(`🗑️ Cache invalidated for key: ${key}`);
    }
    return deleted;
  }

  // Limpiar entradas expiradas
  private cleanup(): void {
    const now = Date.now();
    let cleanedCount = 0;

    for (const [key, entry] of this.cache) {
      if (now - entry.timestamp > entry.ttl * 1000) {
        this.cache.delete(key);
        cleanedCount++;
      }
    }

    if (cleanedCount > 0) {
      logger.debug(`🧹 Cleaned up ${cleanedCount} expired cache entries`);
    }
  }

  // Obtener estadísticas del caché
  getStats() {
    const now = Date.now();
    let activeEntries = 0;
    let expiredEntries = 0;

    for (const entry of this.cache.values()) {
      if (now - entry.timestamp > entry.ttl * 1000) {
        expiredEntries++;
      } else {
        activeEntries++;
      }
    }

    return {
      total: this.cache.size,
      active: activeEntries,
      expired: expiredEntries,
      memoryUsage: process.memoryUsage().heapUsed
    };
  }

  // Limpiar todo el caché
  clear(): void {
    const size = this.cache.size;
    this.cache.clear();
    logger.info(`🗑️ Cleared entire cache (${size} entries)`);
  }

  // Destructor para limpiar interval
  destroy(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
    }
    this.clear();
  }
}

// Instancia singleton del caché
const cache = new InMemoryCache();

// Función para generar clave de caché
function generateCacheKey(req: Request): string {
  const baseKey = `${req.method}:${req.route?.path || req.path}`;
  
  // Incluir parámetros de query relevantes
  const relevantParams = ['page', 'limit', 'sort', 'filter', 'severity', 'estado', 'tipo'];
  const queryParams = relevantParams
    .filter(param => req.query[param])
    .map(param => `${param}=${req.query[param]}`)
    .join('&');

  // Incluir parámetros de ruta
  const routeParams = Object.keys(req.params)
    .map(key => `${key}=${req.params[key]}`)
    .join('&');

  return [baseKey, routeParams, queryParams]
    .filter(Boolean)
    .join('?');
}

// Función para determinar TTL basado en la ruta
function getTTLForRoute(path: string): number {
  // Dashboard y KPIs
  if (path.includes('/dashboard')) return CACHE_TTL.dashboard;
  if (path.includes('/kpis')) return CACHE_TTL.kpis;
  
  // CVEs
  if (path.includes('/cve/frequent')) return CACHE_TTL.cve_frequent;
  if (path.includes('/cve/trending')) return CACHE_TTL.cve_trending;
  if (path.includes('/cve/critical')) return CACHE_TTL.cve_critical;
  if (path.includes('/cve') && path.includes('stats')) return CACHE_TTL.cve_stats;
  
  // Amenazas
  if (path.includes('/threats') && path.includes('stats')) return CACHE_TTL.threat_stats;
  if (path.includes('/threats')) return CACHE_TTL.threats;
  
  // Activos
  if (path.includes('/assets') && path.includes('stats')) return CACHE_TTL.asset_stats;
  if (path.includes('/assets')) return CACHE_TTL.assets;
  
  // Riesgos
  if (path.includes('/risks/matrix')) return CACHE_TTL.risk_matrix;
  if (path.includes('/risks/trends')) return CACHE_TTL.risk_trends;
  if (path.includes('/risks')) return CACHE_TTL.risks;
  
  // Salvaguardas
  if (path.includes('/safeguards') && path.includes('stats')) return CACHE_TTL.safeguard_stats;
  if (path.includes('/safeguards')) return CACHE_TTL.safeguards;
  
  // Vulnerabilidades
  if (path.includes('/vulnerabilities') && path.includes('stats')) return CACHE_TTL.vuln_stats;
  if (path.includes('/vulnerabilities')) return CACHE_TTL.vulnerabilities;
  
  return CACHE_TTL.default;
}

// Middleware principal de caché
export const cacheMiddleware = (customTTL?: number) => {
  return (req: Request, res: Response<ApiResponse>, next: NextFunction) => {
    // Solo cachear GET requests
    if (req.method !== 'GET') {
      return next();
    }

    const cacheKey = generateCacheKey(req);
    const cachedData = cache.get(cacheKey);

    // Si hay datos en caché, devolverlos
    if (cachedData) {
      // Agregar header para indicar que es una respuesta cacheada
      res.setHeader('X-Cache', 'HIT');
      res.setHeader('X-Cache-Timestamp', new Date().toISOString());
      
      return res.json({
        success: true,
        data: cachedData
      });
    }

    // Interceptar res.json para cachear la respuesta
    const originalJson = res.json.bind(res);
    res.json = function(data: any) {
      // Solo cachear respuestas exitosas
      if (data.success) {
        const ttl = customTTL || getTTLForRoute(req.path);
        cache.set(cacheKey, data.data, ttl);
      }
      
      return originalJson(data);
    };

    next();
  };
};

// Middleware para invalidación inteligente de caché
export const cacheInvalidationMiddleware = (req: Request, res: Response, next: NextFunction) => {
  const originalJson = res.json.bind(res);
  
  res.json = function(data: any) {
    // Solo invalidar en operaciones exitosas que modifican datos
    if (data.success && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) {
      const path = req.path;
      
      // Invalidar caché relacionado basado en la ruta
      if (path.includes('/cve')) {
        cache.invalidatePattern('.*\\/cve.*');
        cache.invalidatePattern('.*\\/dashboard.*');
      } else if (path.includes('/threats')) {
        cache.invalidatePattern('.*\\/threats.*');
        cache.invalidatePattern('.*\\/dashboard.*');
      } else if (path.includes('/assets')) {
        cache.invalidatePattern('.*\\/assets.*');
        cache.invalidatePattern('.*\\/risks.*'); // Los riesgos dependen de activos
        cache.invalidatePattern('.*\\/dashboard.*');
      } else if (path.includes('/risks')) {
        cache.invalidatePattern('.*\\/risks.*');
        cache.invalidatePattern('.*\\/dashboard.*');
      } else if (path.includes('/safeguards')) {
        cache.invalidatePattern('.*\\/safeguards.*');
        cache.invalidatePattern('.*\\/dashboard.*');
      } else if (path.includes('/vulnerabilities')) {
        cache.invalidatePattern('.*\\/vulnerabilities.*');
        cache.invalidatePattern('.*\\/dashboard.*');
      }
    }
    
    return originalJson(data);
  };
  
  next();
};

// Middleware específico para rutas críticas del dashboard
export const dashboardCacheMiddleware = cacheMiddleware(CACHE_TTL.dashboard);
export const kpisCacheMiddleware = cacheMiddleware(CACHE_TTL.kpis);

// Middleware específico para CVEs
export const cveCacheMiddleware = cacheMiddleware(CACHE_TTL.cve_stats);
export const cveFrequentCacheMiddleware = cacheMiddleware(CACHE_TTL.cve_frequent);

// Funciones utilitarias para manejo manual del caché
export const cacheUtils = {
  // Invalidar todo el caché
  clearAll: () => cache.clear(),
  
  // Invalidar por patrón
  invalidatePattern: (pattern: string) => cache.invalidatePattern(pattern),
  
  // Invalidar caché específico
  invalidate: (key: string) => cache.invalidate(key),
  
  // Obtener estadísticas
  getStats: () => cache.getStats(),
  
  // Invalidaciones específicas por módulo
  invalidateDashboard: () => cache.invalidatePattern('.*\\/dashboard.*'),
  invalidateCVEs: () => cache.invalidatePattern('.*\\/cve.*'),
  invalidateThreats: () => cache.invalidatePattern('.*\\/threats.*'),
  invalidateAssets: () => cache.invalidatePattern('.*\\/assets.*'),
  invalidateRisks: () => cache.invalidatePattern('.*\\/risks.*'),
  invalidateSafeguards: () => cache.invalidatePattern('.*\\/safeguards.*'),
  invalidateVulnerabilities: () => cache.invalidatePattern('.*\\/vulnerabilities.*'),
  
  // Destruir instancia de caché (para testing)
  destroy: () => cache.destroy()
};

// Middleware para estadísticas de caché (endpoint de monitoreo)
export const cacheStatsMiddleware = (req: Request, res: Response<ApiResponse>) => {
  const stats = cacheUtils.getStats();
  
  res.json({
    success: true,
    data: {
      ...stats,
      configuration: CACHE_TTL,
      uptime: process.uptime()
    }
  });
};

export default cacheMiddleware;