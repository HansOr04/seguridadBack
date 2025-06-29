import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import { connectDB } from './config/database';
import { config } from './config/environment';
import { errorHandler, notFound } from './middleware/errorHandler';
import { generalRateLimit } from './middleware/rateLimit';
import routes from './routes';
import logger from './utils/logger';

// Importar jobs programados
import { cveSyncJob } from './jobs/cveSync';

// Crear aplicación Express
const app = express();

// Variables para tracking del servidor
const startTime = Date.now();

// Conectar a MongoDB
connectDB();

// Inicializar jobs programados
if (config.NODE_ENV !== 'test') {
  logger.info('🔄 Inicializando jobs programados...');
  // cveSyncJob ya se inicializa automáticamente en su constructor
}

// Middleware de seguridad
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
}));

// CORS
app.use(cors({
  origin: config.NODE_ENV === 'production' 
    ? ['https://your-frontend-domain.com'] 
    : ['http://localhost:3000', 'http://localhost:3001'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Rate limiting
app.use(generalRateLimit);

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Logging
if (config.NODE_ENV !== 'test') {
  app.use(morgan('combined', {
    stream: {
      write: (message: string) => logger.info(message.trim())
    }
  }));
}

// Health Check Endpoint - AGREGADO
app.get('/api/v1/health', (req, res) => {
  const uptime = Date.now() - startTime;
  
  const formatUptime = (ms: number): string => {
    const seconds = Math.floor(ms / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);
    
    if (days > 0) return `${days}d ${hours % 24}h ${minutes % 60}m`;
    if (hours > 0) return `${hours}h ${minutes % 60}m`;
    if (minutes > 0) return `${minutes}m ${seconds % 60}s`;
    return `${seconds}s`;
  };

  // Información de memoria
  const memoryUsage = process.memoryUsage();
  
  try {
    res.json({
      status: 'success',
      data: {
        status: 'healthy',
        timestamp: new Date().toISOString(),
        uptime: formatUptime(uptime),
        version: process.env.npm_package_version || '1.0.0',
        environment: config.NODE_ENV || 'development',
        node_version: process.version,
        database: 'connected', // TODO: Verificar conexión real a MongoDB
        memory: {
          used: Math.round(memoryUsage.heapUsed / 1024 / 1024),
          total: Math.round(memoryUsage.heapTotal / 1024 / 1024),
          rss: Math.round(memoryUsage.rss / 1024 / 1024)
        },
        system: {
          platform: process.platform,
          arch: process.arch,
          cpu_count: require('os').cpus().length,
          load_avg: require('os').loadavg()
        }
      }
    });
  } catch (error) {
    logger.error('❌ Error en health check:', error);
    res.status(500).json({
      status: 'error',
      data: {
        status: 'unhealthy',
        timestamp: new Date().toISOString(),
        error: 'Internal server error during health check'
      }
    });
  }
});

// Routes
app.use('/api/v1', routes);

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    message: 'SIGRISK-EC Backend API',
    version: '1.0.0',
    description: 'Sistema de Análisis y Gestión de Riesgos basado en MAGERIT v3.0',
    endpoints: {
      health: '/api/v1/health',
      auth: '/api/v1/auth',
      assets: '/api/v1/assets',
      risks: '/api/v1/risks',
      cve: '/api/v1/cve',
      safeguards: '/api/v1/safeguards',
      threats: '/api/v1/threats',
      vulnerabilities: '/api/v1/vulnerabilities'
    }
  });
});

// Error handling
app.use(notFound);
app.use(errorHandler);

// Graceful shutdown
process.on('SIGTERM', () => {
  logger.info('SIGTERM signal received: closing HTTP server');
  process.exit(0);
});

process.on('SIGINT', () => {
  logger.info('SIGINT signal received: closing HTTP server');
  process.exit(0);
});

export default app;

// Iniciar servidor si no es un test
if (require.main === module) {
  const PORT = config.PORT || 3001;
  
  app.listen(PORT, () => {
    logger.info(`🚀 Servidor corriendo en puerto ${PORT}`);
    logger.info(`📝 Entorno: ${config.NODE_ENV}`);
    logger.info(`🔗 API disponible en: http://localhost:${PORT}/api/v1`);
    logger.info(`💚 Health check: http://localhost:${PORT}/api/v1/health`);
    logger.info(`🛡️  SIGRISK-EC Backend iniciado correctamente`);
  });
}