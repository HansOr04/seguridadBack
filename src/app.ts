import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import { connectDB } from './config/database';
import { config } from './config/environment';
import { setupSwagger } from './config/swagger';
import { errorHandler, notFound } from './middleware/errorHandler';
import { generalRateLimit } from './middleware/rateLimit';
import routes from './routes';
import logger from './utils/logger';

// Importar jobs programados
import { cveSyncJob } from './jobs/cveSync';

// Crear aplicación Express
const app = express();

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

// Swagger documentation
if (config.NODE_ENV === 'development') {
  setupSwagger(app);
}

// Routes
app.use('/api/v1', routes);

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    message: 'SIGRISK-EC Backend API',
    version: '1.0.0',
    description: 'Sistema de Análisis y Gestión de Riesgos basado en MAGERIT v3.0',
    documentation: config.NODE_ENV === 'development' 
      ? `http://localhost:${config.PORT}/api/docs`
      : '/api/docs',
    endpoints: {
      health: '/api/v1/health',
      auth: '/api/v1/auth',
      assets: '/api/v1/assets',
      risks: '/api/v1/risks',
      cve: '/api/v1/cve',
      safeguards: '/api/v1/safeguards'
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
    if (config.NODE_ENV === 'development') {
      logger.info(`📚 Documentación Swagger: http://localhost:${PORT}/api/docs`);
    }
    logger.info(`🛡️  SIGRISK-EC Backend iniciado correctamente`);
  });
}