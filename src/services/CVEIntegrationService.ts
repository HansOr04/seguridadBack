import axios, { AxiosResponse } from 'axios';
import { config } from '../config/environment';
import { Threat } from '../models/Threat';
import { CVEData, TipoAmenaza } from '../types';
import logger from '../utils/logger';

// Interfaces para respuesta de NVD API
interface NVDResponse {
  resultsPerPage: number;
  startIndex: number;
  totalResults: number;
  format: string;
  version: string;
  timestamp: string;
  vulnerabilities: NVDVulnerability[];
}

interface NVDVulnerability {
  cve: {
    id: string;
    sourceIdentifier: string;
    published: string;
    lastModified: string;
    vulnStatus: string;
    descriptions: Array<{
      lang: string;
      value: string;
    }>;
    metrics?: {
      cvssMetricV31?: Array<{
        source: string;
        type: string;
        cvssData: {
          version: string;
          vectorString: string;
          baseScore: number;
          baseSeverity: string;
        };
      }>;
      cvssMetricV2?: Array<{
        source: string;
        type: string;
        cvssData: {
          version: string;
          vectorString: string;
          baseScore: number;
          baseSeverity: string;
        };
      }>;
    };
    configurations?: Array<{
      nodes: Array<{
        operator: string;
        negate: boolean;
        cpeMatch: Array<{
          vulnerable: boolean;
          criteria: string;
          versionStartIncluding?: string;
          versionEndExcluding?: string;
        }>;
      }>;
    }>;
  };
}

interface CVESyncOptions {
  lastModStartDate?: Date;
  lastModEndDate?: Date;
  pubStartDate?: Date;
  pubEndDate?: Date;
  cvssV3Severity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  keywordSearch?: string;
  resultsPerPage?: number;
  startIndex?: number;
}

export class CVEIntegrationService {
  private readonly baseUrl = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
  private readonly requestDelay = 6000; // 6 segundos entre requests (NVD rate limit)

  constructor() {
    // Configurar axios con headers por defecto
    axios.defaults.headers.common['User-Agent'] = 'SIGRISK-EC/1.0';
    
    if (config.NVD_API_KEY) {
      axios.defaults.headers.common['apiKey'] = config.NVD_API_KEY;
    }
  }

  // Método principal para sincronizar CVEs
  async syncCVEs(options: CVESyncOptions = {}): Promise<{
    processed: number;
    created: number;
    updated: number;
    errors: number;
  }> {
    try {
      logger.info('Iniciando sincronización de CVEs desde NVD...');
      
      const results = {
        processed: 0,
        created: 0,
        updated: 0,
        errors: 0
      };

      let startIndex = options.startIndex || 0;
      const resultsPerPage = options.resultsPerPage || 500; // Reducido para evitar timeouts
      let totalResults = 0;

      do {
        try {
          // Aplicar delay para respetar rate limit
          if (startIndex > 0) {
            await this.delay(this.requestDelay);
          }

          const response = await this.fetchCVEs({
            ...options,
            startIndex,
            resultsPerPage
          });

          if (!response || !response.vulnerabilities) {
            logger.warn('Respuesta vacía de NVD API');
            break;
          }

          totalResults = response.totalResults;
          logger.info(`Procesando lote: ${startIndex + 1}-${startIndex + response.vulnerabilities.length} de ${totalResults}`);

          // Procesar cada CVE del lote
          for (const vulnerability of response.vulnerabilities) {
            try {
              const processResult = await this.processCVE(vulnerability);
              if (processResult.created) results.created++;
              if (processResult.updated) results.updated++;
              results.processed++;
            } catch (error) {
              results.errors++;
              logger.error(`Error procesando CVE ${vulnerability.cve.id}:`, error);
            }
          }

          startIndex += response.vulnerabilities.length;

          // Verificar si hay más resultados
          if (startIndex >= totalResults) {
            break;
          }

        } catch (error) {
          results.errors++;
          logger.error(`Error en lote desde índice ${startIndex}:`, error);
          break;
        }
      } while (startIndex < totalResults);

      logger.info(`Sincronización CVE completada: ${results.processed} procesados, ${results.created} creados, ${results.updated} actualizados, ${results.errors} errores`);
      return results;

    } catch (error) {
      logger.error('Error en sincronización de CVEs:', error);
      throw error;
    }
  }

  // Obtener CVE específico por ID
  async getCVEById(cveId: string): Promise<CVEData | null> {
    try {
      const response = await this.fetchCVEs({ cveId });
      
      if (response && response.vulnerabilities && response.vulnerabilities.length > 0) {
        return this.transformNVDToCVEData(response.vulnerabilities[0]);
      }
      
      return null;
    } catch (error) {
      logger.error(`Error obteniendo CVE ${cveId}:`, error);
      return null;
    }
  }

  // Buscar CVEs por keyword
  async searchCVEs(keyword: string, severity?: string): Promise<CVEData[]> {
    try {
      const options: CVESyncOptions = {
        keywordSearch: keyword,
        resultsPerPage: 100
      };

      if (severity) {
        options.cvssV3Severity = severity as any;
      }

      const response = await this.fetchCVEs(options);
      
      if (!response || !response.vulnerabilities) {
        return [];
      }

      return response.vulnerabilities.map(vuln => this.transformNVDToCVEData(vuln));
    } catch (error) {
      logger.error(`Error buscando CVEs con keyword "${keyword}":`, error);
      return [];
    }
  }

  // Obtener CVEs modificados recientemente
  async getRecentCVEs(days: number = 7): Promise<CVEData[]> {
    try {
      const endDate = new Date();
      const startDate = new Date();
      startDate.setDate(startDate.getDate() - days);

      const options: CVESyncOptions = {
        lastModStartDate: startDate,
        lastModEndDate: endDate,
        resultsPerPage: 500
      };

      const response = await this.fetchCVEs(options);
      
      if (!response || !response.vulnerabilities) {
        return [];
      }

      return response.vulnerabilities.map(vuln => this.transformNVDToCVEData(vuln));
    } catch (error) {
      logger.error(`Error obteniendo CVEs recientes:`, error);
      return [];
    }
  }

  // Fetch CVEs desde NVD API
  private async fetchCVEs(options: CVESyncOptions & { cveId?: string } = {}): Promise<NVDResponse | null> {
    try {
      const params = new URLSearchParams();

      // Parámetros de búsqueda
      if (options.cveId) params.append('cveId', options.cveId);
      if (options.keywordSearch) params.append('keywordSearch', options.keywordSearch);
      if (options.cvssV3Severity) params.append('cvssV3Severity', options.cvssV3Severity);

      // Parámetros de fecha
      if (options.lastModStartDate) {
        params.append('lastModStartDate', options.lastModStartDate.toISOString());
      }
      if (options.lastModEndDate) {
        params.append('lastModEndDate', options.lastModEndDate.toISOString());
      }
      if (options.pubStartDate) {
        params.append('pubStartDate', options.pubStartDate.toISOString());
      }
      if (options.pubEndDate) {
        params.append('pubEndDate', options.pubEndDate.toISOString());
      }

      // Parámetros de paginación
      params.append('resultsPerPage', (options.resultsPerPage || 500).toString());
      params.append('startIndex', (options.startIndex || 0).toString());

      const url = `${this.baseUrl}?${params.toString()}`;
      logger.debug(`Fetching CVEs: ${url}`);

      const response: AxiosResponse<NVDResponse> = await axios.get(url, {
        timeout: 30000, // 30 segundos timeout
        headers: {
          'Content-Type': 'application/json'
        }
      });

      return response.data;
    } catch (error) {
      if (axios.isAxiosError(error)) {
        if (error.response?.status === 403) {
          logger.error('Error 403: Verificar API Key de NVD');
        } else if (error.response?.status === 429) {
          logger.warn('Rate limit alcanzado, esperando...');
          await this.delay(this.requestDelay * 2);
          throw error;
        }
      }
      logger.error('Error fetching CVEs:', error);
      throw error;
    }
  }

  // Procesar un CVE individual
  private async processCVE(nvdVulnerability: NVDVulnerability): Promise<{ created: boolean; updated: boolean }> {
    const cveData = this.transformNVDToCVEData(nvdVulnerability);
    
    // Buscar amenaza existente
    let threat = await Threat.findOne({ 'cveData.cveId': cveData.cveId });
    
    if (threat) {
      // Actualizar amenaza existente
      threat.cveData = cveData;
      threat.probabilidad = this.calculateProbabilityFromCVSS(cveData.cvssScore, cveData.severity);
      threat.ultimaActualizacion = new Date();
      await threat.save();
      
      return { created: false, updated: true };
    } else {
      // Crear nueva amenaza
      threat = new Threat({
        codigo: cveData.cveId,
        nombre: `Vulnerabilidad ${cveData.cveId}`,
        tipo: TipoAmenaza.ATAQUES_INTENCIONADOS,
        origen: 'CVE',
        descripcion: cveData.description,
        probabilidad: this.calculateProbabilityFromCVSS(cveData.cvssScore, cveData.severity),
        vectores: ['Red', 'Internet'],
        cveData: cveData,
        aplicaA: [],
        fechaDescubrimiento: cveData.publishedDate,
        ultimaActualizacion: cveData.lastModifiedDate
      });
      
      await threat.save();
      return { created: true, updated: false };
    }
  }

  // Transformar respuesta NVD a formato CVEData
  private transformNVDToCVEData(nvdVulnerability: NVDVulnerability): CVEData {
    const cve = nvdVulnerability.cve;
    
    // Obtener métricas CVSS (preferir v3.1, luego v2)
    let cvssScore = 0;
    let cvssVector = '';
    let severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = 'MEDIUM';
    
    if (cve.metrics?.cvssMetricV31 && cve.metrics.cvssMetricV31.length > 0) {
      const cvss = cve.metrics.cvssMetricV31[0].cvssData;
      cvssScore = cvss.baseScore;
      cvssVector = cvss.vectorString;
      severity = cvss.baseSeverity.toLowerCase() as any;
    } else if (cve.metrics?.cvssMetricV2 && cve.metrics.cvssMetricV2.length > 0) {
      const cvss = cve.metrics.cvssMetricV2[0].cvssData;
      cvssScore = cvss.baseScore;
      cvssVector = cvss.vectorString;
      // Mapear severidad CVSS v2 a v3
      if (cvssScore >= 7.0) severity = 'HIGH';
      else if (cvssScore >= 4.0) severity = 'MEDIUM';
      else severity = 'LOW';
    }

    // Obtener software afectado de las configuraciones
    const affectedSoftware: string[] = [];
    if (cve.configurations) {
      for (const config of cve.configurations) {
        for (const node of config.nodes) {
          for (const cpeMatch of node.cpeMatch) {
            if (cpeMatch.vulnerable) {
              affectedSoftware.push(cpeMatch.criteria);
            }
          }
        }
      }
    }

    // Obtener descripción en inglés
    const description = cve.descriptions.find(desc => desc.lang === 'en')?.value || 
                      cve.descriptions[0]?.value || 
                      'No description available';

    return {
      cveId: cve.id,
      cvssScore,
      cvssVector,
      severity,
      affectedSoftware,
      publishedDate: new Date(cve.published),
      lastModifiedDate: new Date(cve.lastModified),
      description
    };
  }

  // Calcular probabilidad MAGERIT desde CVSS
  private calculateProbabilityFromCVSS(cvssScore: number, severity: string): number {
    // Mapear CVSS score a escala MAGERIT (0-10)
    if (severity === 'CRITICAL' || cvssScore >= 9.0) return 9;
    if (severity === 'HIGH' || cvssScore >= 7.0) return 7;
    if (severity === 'MEDIUM' || cvssScore >= 4.0) return 5;
    if (severity === 'LOW' || cvssScore >= 0.1) return 3;
    return 1;
  }

  // Delay helper
  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

export const cveIntegrationService = new CVEIntegrationService();