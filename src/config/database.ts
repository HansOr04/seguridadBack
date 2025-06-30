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

    // Crear índices optimizados después de la conexión
    await createOptimizedIndexes();

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
 * Crear índices optimizados para mejorar el rendimiento de las consultas
 * Según los requerimientos del documento de optimización
 */
export const createOptimizedIndexes = async (): Promise<void> => {
  try {
    logger.info('🔧 Creando índices optimizados...');

    const db = mongoose.connection.db;

    // ÍNDICES PARA COLECCIÓN THREATS (CVE y amenazas)
    logger.info('📝 Creando índices para threats...');
    
    // Índice compuesto para origen y severidad CVE
    await db.collection('threats').createIndex(
      { 'origen': 1, 'cveData.severity': 1 },
      { name: 'idx_threats_origen_severity' }
    );

    // Índice para fecha de publicación CVE (consultas temporales)
    await db.collection('threats').createIndex(
      { 'cveData.publishedDate': -1 },
      { name: 'idx_threats_published_date' }
    );

    // Índice para fecha de modificación CVE (sincronización)
    await db.collection('threats').createIndex(
      { 'cveData.lastModifiedDate': -1 },
      { name: 'idx_threats_modified_date' }
    );

    // Índice para activos afectados (correlación CVE-Asset)
    await db.collection('threats').createIndex(
      { 'aplicaA': 1 },
      { name: 'idx_threats_aplica_a' }
    );

    // Índice compuesto para CVE ID y estado
    await db.collection('threats').createIndex(
      { 'cveData.id': 1, 'estado': 1 },
      { name: 'idx_threats_cve_id_estado' }
    );

    // ÍNDICES PARA COLECCIÓN ASSETS
    logger.info('📝 Creando índices para assets...');
    
    // Índice para criticidad (dashboard KPIs)
    await db.collection('assets').createIndex(
      { 'criticidad': 1 },
      { name: 'idx_assets_criticidad' }
    );

    // Índice compuesto para tipo y criticidad (filtros combinados)
    await db.collection('assets').createIndex(
      { 'tipo': 1, 'criticidad': 1 },
      { name: 'idx_assets_tipo_criticidad' }
    );

    // Índice para estado del activo
    await db.collection('assets').createIndex(
      { 'estado': 1 },
      { name: 'idx_assets_estado' }
    );

    // ÍNDICES PARA COLECCIÓN RISKS
    logger.info('📝 Creando índices para risks...');
    
    // Índice para impacto total (riesgos críticos)
    await db.collection('risks').createIndex(
      { 'impactoTotal': -1 },
      { name: 'idx_risks_impacto_total' }
    );

    // Índice para fecha de creación (tendencias)
    await db.collection('risks').createIndex(
      { 'fechaCreacion': -1 },
      { name: 'idx_risks_fecha_creacion' }
    );

    // Índice para nivel de riesgo (dashboard)
    await db.collection('risks').createIndex(
      { 'nivelRiesgo': 1 },
      { name: 'idx_risks_nivel_riesgo' }
    );

    // Índice compuesto para activo y estado
    await db.collection('risks').createIndex(
      { 'activoId': 1, 'estado': 1 },
      { name: 'idx_risks_activo_estado' }
    );

    // ÍNDICES PARA COLECCIÓN VULNERABILITIES
    logger.info('📝 Creando índices para vulnerabilities...');
    
    // Índice compuesto para estado y severidad (dashboard KPIs)
    await db.collection('vulnerabilities').createIndex(
      { 'estado': 1, 'severidad': 1 },
      { name: 'idx_vulnerabilities_estado_severidad' }
    );

    // Índice para fecha de descubrimiento
    await db.collection('vulnerabilities').createIndex(
      { 'fechaDescubrimiento': -1 },
      { name: 'idx_vulnerabilities_fecha_descubrimiento' }
    );

    // Índice para activo relacionado
    await db.collection('vulnerabilities').createIndex(
      { 'activoId': 1 },
      { name: 'idx_vulnerabilities_activo' }
    );

    // ÍNDICES PARA COLECCIÓN SAFEGUARDS
    logger.info('📝 Creando índices para safeguards...');
    
    // Índice compuesto para estado y eficacia (KPIs)
    await db.collection('safeguards').createIndex(
      { 'estado': 1, 'eficacia': 1 },
      { name: 'idx_safeguards_estado_eficacia' }
    );

    // Índice para tipo de salvaguarda
    await db.collection('safeguards').createIndex(
      { 'tipo': 1 },
      { name: 'idx_safeguards_tipo' }
    );

    // Índice para fecha de implementación
    await db.collection('safeguards').createIndex(
      { 'fechaImplementacion': -1 },
      { name: 'idx_safeguards_fecha_implementacion' }
    );

    // ÍNDICES ADICIONALES PARA OPTIMIZACIÓN ESPECÍFICA

    // Índice text para búsquedas de CVE
    await db.collection('threats').createIndex(
      { 
        'cveData.id': 'text',
        'descripcion': 'text',
        'cveData.descriptions.value': 'text'
      },
      { 
        name: 'idx_threats_text_search',
        weights: {
          'cveData.id': 10,
          'descripcion': 5,
          'cveData.descriptions.value': 1
        }
      }
    );

    // Índice para CVEs frecuentes (score calculado)
    await db.collection('threats').createIndex(
      { 'cveData.baseScore': -1, 'aplicaA': 1 },
      { name: 'idx_threats_frequency_score' }
    );

    logger.info('✅ Índices optimizados creados exitosamente');

    // Mostrar estadísticas de índices
    await showIndexStats();

  } catch (error) {
    logger.error('❌ Error creando índices optimizados:', error);
    throw error;
  }
};

/**
 * Mostrar estadísticas de los índices creados
 */
const showIndexStats = async (): Promise<void> => {
  try {
    const db = mongoose.connection.db;
    const collections = ['threats', 'assets', 'risks', 'vulnerabilities', 'safeguards'];

    logger.info('📊 Estadísticas de índices creados:');

    for (const collectionName of collections) {
      const indexes = await db.collection(collectionName).listIndexes().toArray();
      logger.info(`  ${collectionName}: ${indexes.length} índices`);
      
      // Mostrar detalles de índices personalizados (no el _id por defecto)
      const customIndexes = indexes.filter(idx => idx.name !== '_id_');
      if (customIndexes.length > 0) {
        customIndexes.forEach(idx => {
          logger.info(`    - ${idx.name}: ${JSON.stringify(idx.key)}`);
        });
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
      const indexes = await db.collection(collectionName).listIndexes().toArray();
      const customIndexes = indexes.filter(idx => idx.name !== '_id_');

      for (const index of customIndexes) {
        await db.collection(collectionName).dropIndex(index.name);
        logger.info(`  ✅ Eliminado: ${collectionName}.${index.name}`);
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