import mongoose from 'mongoose';
import { config } from './environment';
import logger from '../utils/logger';

export const connectDB = async (): Promise<void> => {
  try {
    const conn = await mongoose.connect(config.MONGODB_URI, {
      // Opciones de conexión
      maxPoolSize: 10,
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
      family: 4
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