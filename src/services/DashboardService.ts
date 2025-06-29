// src/services/DashboardService.ts - CORREGIDO
import { Asset } from '../models/Asset';
import { Risk } from '../models/Risk';
import { Vulnerability } from '../models/Vulnerability';
import { Safeguard } from '../models/Safeguard';
import { Threat } from '../models/Threat';
import { AppError } from '../middleware/errorHandler';
import logger from '../utils/logger';

interface DashboardKPIs {
  totalActivos: number;
  riesgosCriticos: number;
  vulnerabilidadesActivas: number;
  salvaguardasImplementadas: number;
  tendenciaRiesgos: 'up' | 'down' | 'stable';
  efectividadPrograma: number;
}

interface TrendData {
  date: string;
  riesgos: number;
  vulnerabilidades: number;
  salvaguardas: number;
}

interface Activity {
  id: string;
  type: 'vulnerability' | 'asset' | 'risk' | 'safeguard' | 'threat';
  action: 'created' | 'updated' | 'deleted' | 'mitigated' | 'implemented';
  title: string;
  description: string;
  timestamp: string;
  user: string;
  severity?: 'low' | 'medium' | 'high' | 'critical';
}

export class DashboardService {
  
  // Obtener KPIs principales del dashboard
  async getDashboardKPIs(): Promise<DashboardKPIs> {
    try {
      logger.info('📊 Calculando KPIs del dashboard...');

      // Ejecutar queries en paralelo para mejor performance
      const [
        totalActivos,
        riesgosCriticos, 
        vulnerabilidadesActivas,
        salvaguardasImplementadas,
        tendenciaData
      ] = await Promise.all([
        Asset.countDocuments(),
        Risk.countDocuments({ nivelRiesgo: { $in: ['Crítico', 'Alto'] } }),
        Vulnerability.countDocuments({ estado: 'abierta' }),
        Safeguard.countDocuments({ estado: 'implementada' }),
        this.calculateRiskTrend()
      ]);

      // Calcular efectividad del programa (ejemplo básico)
      const totalSafeguards = await Safeguard.countDocuments();
      const efectividadPrograma = totalSafeguards > 0 
        ? Math.round((salvaguardasImplementadas / totalSafeguards) * 100)
        : 0;

      const kpis: DashboardKPIs = {
        totalActivos,
        riesgosCriticos,
        vulnerabilidadesActivas,
        salvaguardasImplementadas,
        tendenciaRiesgos: tendenciaData,
        efectividadPrograma
      };

      logger.info('✅ KPIs calculados exitosamente:', kpis);
      return kpis;

    } catch (error) {
      logger.error('❌ Error calculando KPIs del dashboard:', error);
      throw new AppError('Error al calcular KPIs del dashboard', 500);
    }
  }

  // Calcular tendencia de riesgos (últimos 7 días vs anteriores)
  private async calculateRiskTrend(): Promise<'up' | 'down' | 'stable'> {
    try {
      const sevenDaysAgo = new Date();
      sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
      
      const fourteenDaysAgo = new Date();
      fourteenDaysAgo.setDate(fourteenDaysAgo.getDate() - 14);

      const [currentWeekRisks, previousWeekRisks] = await Promise.all([
        Risk.countDocuments({ 
          fechaCreacion: { $gte: sevenDaysAgo },
          nivelRiesgo: { $in: ['Crítico', 'Alto'] }
        }),
        Risk.countDocuments({ 
          fechaCreacion: { $gte: fourteenDaysAgo, $lt: sevenDaysAgo },
          nivelRiesgo: { $in: ['Crítico', 'Alto'] }
        })
      ]);

      if (currentWeekRisks > previousWeekRisks) return 'up';
      if (currentWeekRisks < previousWeekRisks) return 'down';
      return 'stable';

    } catch (error) {
      logger.error('❌ Error calculando tendencia de riesgos:', error);
      return 'stable';
    }
  }

  // Obtener datos de tendencias para gráficos
  async getTrends(timeRange: '7d' | '30d' | '90d'): Promise<TrendData[]> {
    try {
      logger.info(`📈 Obteniendo tendencias para ${timeRange}...`);

      const days = timeRange === '7d' ? 7 : timeRange === '30d' ? 30 : 90;
      const startDate = new Date();
      startDate.setDate(startDate.getDate() - days);

      // Generar fechas para el rango
      const dates: Date[] = [];
      for (let i = 0; i < days; i++) {
        const date = new Date(startDate);
        date.setDate(date.getDate() + i);
        dates.push(date);
      }

      // Obtener datos para cada fecha
      const trendsData: TrendData[] = await Promise.all(
        dates.map(async (date) => {
          const nextDay = new Date(date);
          nextDay.setDate(nextDay.getDate() + 1);

          const [riesgos, vulnerabilidades, salvaguardas] = await Promise.all([
            Risk.countDocuments({
              fechaCreacion: { $gte: date, $lt: nextDay }
            }),
            Vulnerability.countDocuments({
              fechaDeteccion: { $gte: date, $lt: nextDay }
            }),
            Safeguard.countDocuments({
              fechaImplementacion: { $gte: date, $lt: nextDay }
            })
          ]);

          return {
            date: date.toISOString().split('T')[0], // YYYY-MM-DD
            riesgos,
            vulnerabilidades,
            salvaguardas
          };
        })
      );

      logger.info(`✅ Tendencias obtenidas: ${trendsData.length} puntos de datos`);
      return trendsData;

    } catch (error) {
      logger.error('❌ Error obteniendo tendencias:', error);
      throw new AppError('Error al obtener datos de tendencias', 500);
    }
  }

  // Obtener feed de actividades recientes
  async getRecentActivities(limit: number = 10): Promise<Activity[]> {
    try {
      logger.info(`📝 Obteniendo ${limit} actividades recientes...`);

      const activities: Activity[] = [];

      // Obtener vulnerabilidades recientes - SIN POPULATE
      const recentVulns = await Vulnerability
        .find()
        .sort({ fechaDeteccion: -1 })
        .limit(Math.ceil(limit / 3));

      recentVulns.forEach(vuln => {
        activities.push({
          id: vuln._id.toString(),
          type: 'vulnerability',
          action: 'created',
          title: `Nueva vulnerabilidad: ${vuln.categoria}`,
          description: `Vulnerabilidad detectada - Facilidad: ${vuln.facilidadExplotacion}/10`,
          timestamp: vuln.fechaDeteccion.toISOString(),
          user: 'Sistema Automático',
          severity: this.mapFacilityToSeverity(vuln.facilidadExplotacion)
        });
      });

      // Obtener activos recientes
      const recentAssets = await Asset
        .find()
        .sort({ fechaCreacion: -1 })
        .limit(Math.ceil(limit / 3));

      recentAssets.forEach(asset => {
        activities.push({
          id: asset._id.toString(),
          type: 'asset',
          action: 'created',
          title: `Nuevo activo registrado`,
          description: `${asset.nombre} - ${asset.tipo}`,
          timestamp: asset.fechaCreacion.toISOString(),
          user: asset.propietario || 'Usuario desconocido',
          severity: 'medium'
        });
      });

      // Obtener salvaguardas recientes
      const recentSafeguards = await Safeguard
        .find({ estado: 'implementada' })
        .sort({ fechaImplementacion: -1 })
        .limit(Math.ceil(limit / 3));

      recentSafeguards.forEach(safeguard => {
        activities.push({
          id: safeguard._id.toString(),
          type: 'safeguard',
          action: 'implemented',
          title: `Salvaguarda implementada`,
          description: `${safeguard.nombre} - ${safeguard.categoria}`,
          timestamp: safeguard.fechaImplementacion?.toISOString() || new Date().toISOString(),
          user: safeguard.responsable || 'Responsable desconocido',
          severity: 'low'
        });
      });

      // Ordenar por timestamp y limitar
      const sortedActivities = activities
        .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
        .slice(0, limit);

      logger.info(`✅ ${sortedActivities.length} actividades obtenidas`);
      return sortedActivities;

    } catch (error) {
      logger.error('❌ Error obteniendo actividades:', error);
      throw new AppError('Error al obtener actividades recientes', 500);
    }
  }

  // Mapear facilidad de explotación a severidad
  private mapFacilityToSeverity(facilidad: number): 'low' | 'medium' | 'high' | 'critical' {
    if (facilidad >= 8) return 'critical';
    if (facilidad >= 6) return 'high';
    if (facilidad >= 4) return 'medium';
    return 'low';
  }

  // Obtener estadísticas generales para reportes
  async getGeneralStats() {
    try {
      const [
        totalActivos,
        totalRiesgos,
        totalVulnerabilidades,
        totalAmenazas,
        totalSalvaguardas,
        riesgosCriticos,
        vulnerabilidadesCriticas,
        salvaguardasImplementadas
      ] = await Promise.all([
        Asset.countDocuments(),
        Risk.countDocuments(),
        Vulnerability.countDocuments(),
        Threat.countDocuments(),
        Safeguard.countDocuments(),
        Risk.countDocuments({ nivelRiesgo: 'Crítico' }),
        Vulnerability.countDocuments({ 
          estado: 'abierta',
          facilidadExplotacion: { $gte: 8 }
        }),
        Safeguard.countDocuments({ estado: 'implementada' })
      ]);

      return {
        resumen: {
          totalActivos,
          totalRiesgos,
          totalVulnerabilidades,
          totalAmenazas,
          totalSalvaguardas
        },
        criticos: {
          riesgosCriticos,
          vulnerabilidadesCriticas
        },
        implementacion: {
          salvaguardasImplementadas,
          porcentajeImplementacion: totalSalvaguardas > 0 
            ? Math.round((salvaguardasImplementadas / totalSalvaguardas) * 100)
            : 0
        }
      };

    } catch (error) {
      logger.error('❌ Error obteniendo estadísticas generales:', error);
      throw new AppError('Error al obtener estadísticas generales', 500);
    }
  }
}

export const dashboardService = new DashboardService();