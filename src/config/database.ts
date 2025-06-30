import mongoose from 'mongoose';
import { config } from './environment';
import logger from '../utils/logger';

export const connectDB = async (): Promise<void> => {
  try {
    const conn = await mongoose.connect(config.MONGODB_URI, {
      // Opciones de conexión optimizadas
      maxPoolSize: 10,
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
      family: 4,
      // Opciones adicionales para performance
      maxIdleTimeMS: 30000,
      connectTimeoutMS: 30000
    });

    logger.info(`MongoDB conectado: ${conn.connection.host}`);

    // Event listeners
    mongoose.connection.on('error', (err) => {
      logger.error('Error de conexión MongoDB:', err);
    });

    mongoose.connection.on('disconnected', () => {
      logger.warn('MongoDB desconectado');
    });

    // Graceful shutdown
    process.on('SIGINT', async () => {
      await mongoose.connection.close();
      logger.info('Conexión MongoDB cerrada por terminación de la aplicación');
      process.exit(0);
    });

  } catch (error) {
    logger.error('Error conectando a MongoDB:', error);
    process.exit(1);
  }
};

/**
 * Mostrar estadísticas de los índices existentes
 */
export const showIndexStats = async (): Promise<void> => {
  try {
    const db = mongoose.connection.db;
    const collections = ['threats', 'assets', 'risks', 'vulnerabilities', 'safeguards'];

    logger.info('📊 Estadísticas de índices existentes:');

    for (const collectionName of collections) {
      try {
        const indexes = await db.collection(collectionName).listIndexes().toArray();
        logger.info(`  ${collectionName}: ${indexes.length} índices`);
        
        // Mostrar detalles de índices personalizados (no el _id por defecto)
        const customIndexes = indexes.filter(idx => idx.name !== '_id_');
        if (customIndexes.length > 0) {
          customIndexes.forEach(idx => {
            logger.info(`    - ${idx.name}: ${JSON.stringify(idx.key)}`);
          });
        }
      } catch (collectionError) {
        logger.info(`  ${collectionName}: Colección no existe aún`);
      }
    }

  } catch (error) {
    logger.warn('⚠️ No se pudieron obtener estadísticas de índices:', error);
  }
};

/**
 * Eliminar todos los índices personalizados (útil para desarrollo)
 */
export const dropCustomIndexes = async (): Promise<void> => {
  try {
    logger.info('🗑️ Eliminando índices personalizados...');

    const db = mongoose.connection.db;
    const collections = ['threats', 'assets', 'risks', 'vulnerabilities', 'safeguards'];

    for (const collectionName of collections) {
      try {
        const indexes = await db.collection(collectionName).listIndexes().toArray();
        const customIndexes = indexes.filter(idx => idx.name !== '_id_');

        for (const index of customIndexes) {
          await db.collection(collectionName).dropIndex(index.name);
          logger.info(`  ✅ Eliminado: ${collectionName}.${index.name}`);
        }
      } catch (collectionError) {
        logger.info(`  ⚠️ Colección ${collectionName} no existe o sin índices personalizados`);
      }
    }

    logger.info('✅ Índices personalizados eliminados');

  } catch (error) {
    logger.error('❌ Error eliminando índices:', error);
    throw error;
  }
};

/**
 * Analizar performance de consultas (útil para debugging)
 */
export const analyzeQueryPerformance = async (): Promise<void> => {
  try {
    logger.info('🔍 Analizando performance de consultas...');

    const db = mongoose.connection.db;

    // Habilitar profiling de consultas lentas (>100ms)
    await db.admin().command({
      profile: 2,
      slowms: 100
    });

    logger.info('✅ Profiling habilitado para consultas >100ms');
    logger.info('📝 Ver resultados en: db.system.profile.find().pretty()');

  } catch (error) {
    logger.warn('⚠️ No se pudo habilitar profiling:', error);
  }
};

/**
 * Verificar estado de conexión de la base de datos
 */
export const getConnectionStatus = (): {
  status: 'connected' | 'disconnected' | 'connecting' | 'error';
  readyState: number;
  host?: string;
} => {
  const readyState = mongoose.connection.readyState;
  const statusMap = {
    0: 'disconnected' as const,
    1: 'connected' as const,
    2: 'connecting' as const,
    3: 'disconnected' as const,
    99: 'error' as const
  };

  return {
    status: statusMap[readyState] || 'error',
    readyState,
    host: mongoose.connection.host
  };
};