import cron from 'node-cron';
import { cveIntegrationService } from '../services/CVEIntegrationService';
import { riskService } from '../services/RiskService';
import logger from '../utils/logger';

export class CVESyncJob {
  private isRunning = false;
  private lastSyncDate: Date | null = null;

  constructor() {
    this.initializeJobs();
  }

  private initializeJobs() {
    // Job diario - Sincronización de CVEs modificados en las últimas 24 horas
    // Se ejecuta todos los días a las 2:00 AM
    cron.schedule('0 2 * * *', async () => {
      if (this.isRunning) {
        logger.warn('CVE sync job ya está en ejecución, omitiendo...');
        return;
      }

      try {
        logger.info('Iniciando sincronización diaria de CVEs...');
        await this.syncRecentCVEs();
      } catch (error) {
        logger.error('Error en sincronización diaria de CVEs:', error);
      }
    }, {
      timezone: 'America/Guayaquil' // Hora de Ecuador
    });

    // Job semanal - Sincronización completa de CVEs críticos
    // Se ejecuta todos los domingos a las 3:00 AM
    cron.schedule('0 3 * * 0', async () => {
      if (this.isRunning) {
        logger.warn('CVE sync job ya está en ejecución, omitiendo...');
        return;
      }

      try {
        logger.info('Iniciando sincronización semanal de CVEs críticos...');
        await this.syncCriticalCVEs();
      } catch (error) {
        logger.error('Error en sincronización semanal de CVEs:', error);
      }
    }, {
      timezone: 'America/Guayaquil'
    });

    // Job mensual - Recálculo completo de riesgos
    // Se ejecuta el primer día de cada mes a las 4:00 AM
    cron.schedule('0 4 1 * *', async () => {
      try {
        logger.info('Iniciando recálculo mensual de riesgos...');
        await this.recalculateAllRisks();
      } catch (error) {
        logger.error('Error en recálculo mensual de riesgos:', error);
      }
    }, {
      timezone: 'America/Guayaquil'
    });

    logger.info('Jobs de sincronización CVE inicializados');
  }

  // Sincronización de CVEs modificados recientemente
  async syncRecentCVEs(): Promise<void> {
    this.isRunning = true;
    
    try {
      const startTime = new Date();
      logger.info('=== Iniciando sincronización de CVEs recientes ===');

      // Calcular fecha de inicio (últimas 24 horas o desde última sincronización)
      const endDate = new Date();
      const startDate = this.lastSyncDate || new Date(Date.now() - 24 * 60 * 60 * 1000);

      const results = await cveIntegrationService.syncCVEs({
        lastModStartDate: startDate,
        lastModEndDate: endDate,
        resultsPerPage: 500
      });

      // Actualizar fecha de última sincronización
      this.lastSyncDate = endDate;

      const duration = (new Date().getTime() - startTime.getTime()) / 1000;
      
      logger.info(`=== Sincronización CVE completada en ${duration}s ===`);
      logger.info(`Resultados: ${results.processed} procesados, ${results.created} creados, ${results.updated} actualizados, ${results.errors} errores`);

      // Si hay nuevos CVEs, recalcular riesgos afectados
      if (results.created > 0 || results.updated > 0) {
        logger.info('Recalculando riesgos afectados por nuevos CVEs...');
        await this.recalculateAffectedRisks();
      }

    } catch (error) {
      logger.error('Error en sincronización de CVEs recientes:', error);
      throw error;
    } finally {
      this.isRunning = false;
    }
  }

  // Sincronización de CVEs críticos de la semana
  async syncCriticalCVEs(): Promise<void> {
    this.isRunning = true;
    
    try {
      const startTime = new Date();
      logger.info('=== Iniciando sincronización de CVEs críticos ===');

      // Últimos 7 días de CVEs críticos
      const endDate = new Date();
      const startDate = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);

      const results = await cveIntegrationService.syncCVEs({
        lastModStartDate: startDate,
        lastModEndDate: endDate,
        cvssV3Severity: 'CRITICAL',
        resultsPerPage: 200
      });

      // También sincronizar CVEs altos
      const highResults = await cveIntegrationService.syncCVEs({
        lastModStartDate: startDate,
        lastModEndDate: endDate,
        cvssV3Severity: 'HIGH',
        resultsPerPage: 500
      });

      const totalResults = {
        processed: results.processed + highResults.processed,
        created: results.created + highResults.created,
        updated: results.updated + highResults.updated,
        errors: results.errors + highResults.errors
      };

      const duration = (new Date().getTime() - startTime.getTime()) / 1000;
      
      logger.info(`=== Sincronización CVE críticos completada en ${duration}s ===`);
      logger.info(`Resultados: ${totalResults.processed} procesados, ${totalResults.created} creados, ${totalResults.updated} actualizados, ${totalResults.errors} errores`);

      // Recalcular riesgos críticos
      if (totalResults.created > 0 || totalResults.updated > 0) {
        logger.info('Recalculando riesgos críticos...');
        await this.recalculateAffectedRisks();
      }

    } catch (error) {
      logger.error('Error en sincronización de CVEs críticos:', error);
      throw error;
    } finally {
      this.isRunning = false;
    }
  }

  // Sincronización manual con parámetros personalizados
  async manualSync(options: {
    days?: number;
    severity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    keyword?: string;
    forceRecalculation?: boolean;
  } = {}): Promise<any> {
    if (this.isRunning) {
      throw new Error('Ya hay una sincronización en curso');
    }

    this.isRunning = true;
    
    try {
      const startTime = new Date();
      logger.info('=== Iniciando sincronización manual de CVEs ===');
      logger.info(`Parámetros: ${JSON.stringify(options)}`);

      const endDate = new Date();
      const startDate = new Date(Date.now() - (options.days || 30) * 24 * 60 * 60 * 1000);

      const syncOptions: any = {
        lastModStartDate: startDate,
        lastModEndDate: endDate,
        resultsPerPage: 500
      };

      if (options.severity) {
        syncOptions.cvssV3Severity = options.severity;
      }

      if (options.keyword) {
        syncOptions.keywordSearch = options.keyword;
      }

      const results = await cveIntegrationService.syncCVEs(syncOptions);

      const duration = (new Date().getTime() - startTime.getTime()) / 1000;
      
      logger.info(`=== Sincronización manual completada en ${duration}s ===`);
      logger.info(`Resultados: ${results.processed} procesados, ${results.created} creados, ${results.updated} actualizados, ${results.errors} errores`);

      // Recalcular riesgos si es necesario
      if (options.forceRecalculation || results.created > 0 || results.updated > 0) {
        logger.info('Recalculando riesgos...');
        const riskResults = await this.recalculateAllRisks();
        (results as any).riskRecalculation = riskResults;
      }

      return results;

    } catch (error) {
      logger.error('Error en sincronización manual:', error);
      throw error;
    } finally {
      this.isRunning = false;
    }
  }

  // Recálculo de riesgos afectados por nuevos CVEs
  private async recalculateAffectedRisks(): Promise<void> {
    try {
      // Por ahora, recalculamos todos los riesgos
      // En una implementación más sofisticada, podríamos identificar
      // qué activos están afectados por los nuevos CVEs
      const results = await riskService.recalculateAllRisks();
      logger.info(`Riesgos recalculados: ${results.processed} procesados, ${results.errors} errores`);
    } catch (error) {
      logger.error('Error recalculando riesgos afectados:', error);
    }
  }

  // Recálculo completo de todos los riesgos
  private async recalculateAllRisks(): Promise<any> {
    try {
      logger.info('Iniciando recálculo completo de riesgos...');
      const results = await riskService.recalculateAllRisks();
      logger.info(`Recálculo completo terminado: ${results.processed} procesados, ${results.errors} errores`);
      return results;
    } catch (error) {
      logger.error('Error en recálculo completo de riesgos:', error);
      throw error;
    }
  }

  // Obtener estado del job
  getStatus(): {
    isRunning: boolean;
    lastSyncDate: Date | null;
  } {
    return {
      isRunning: this.isRunning,
      lastSyncDate: this.lastSyncDate
    };
  }

  // Forzar parada del job (para emergencias)
  forceStop(): void {
    logger.warn('Forzando parada del CVE sync job...');
    this.isRunning = false;
  }
}

export const cveSyncJob = new CVESyncJob();