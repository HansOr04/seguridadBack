import { Document, Types } from 'mongoose';

// Tipos base MAGERIT
export interface Valoracion {
  confidencialidad: number;
  integridad: number;
  disponibilidad: number;
  autenticidad: number;
  trazabilidad: number;
}

export interface MetadatosActivo {
  sistemaOperativo?: string;
  version?: string;
  vendor?: string;
  fechaInstalacion?: Date;
  cpu?: string;
  memoria?: string;
  almacenamiento?: string;
}

export interface CVEData {
  cveId: string;
  cvssScore: number;
  cvssVector?: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  affectedSoftware: string[];
  publishedDate: Date;
  lastModifiedDate: Date;
  description: string;
}

export interface CalculosRiesgo {
  riesgoInherente: number;
  probabilidadAjustada: number;
  impactoCalculado: number;
  exposicion: number;
  factorTemporal: number;
}

// Enums
export enum TipoActivo {
  HARDWARE = 'Hardware',
  SOFTWARE = 'Software',
  DATOS = 'Datos/Información',
  COMUNICACIONES = 'Comunicaciones',
  SERVICIOS = 'Servicios',
  INSTALACIONES = 'Instalaciones',
  PERSONAL = 'Personal'
}

export enum TipoAmenaza {
  DESASTRES_NATURALES = 'Desastres naturales',
  FALLOS_TECNICOS = 'Fallos técnicos',
  FALLOS_SERVICIOS = 'Fallos de servicios',
  ERRORES_NO_INTENCIONADOS = 'Errores y fallos no intencionados',
  ATAQUES_INTENCIONADOS = 'Ataques intencionados'
}

export enum NivelRiesgo {
  MUY_BAJO = 'Muy Bajo',
  BAJO = 'Bajo',
  MEDIO = 'Medio',
  ALTO = 'Alto',
  CRITICO = 'Crítico'
}

export enum EstadoSalvaguarda {
  PROPUESTA = 'Propuesta',
  PLANIFICADA = 'Planificada',
  EN_IMPLEMENTACION = 'En Implementación',
  IMPLEMENTADA = 'Implementada',
  OBSOLETA = 'Obsoleta'
}

export enum RolUsuario {
  ADMIN = 'admin',
  AUDITOR = 'auditor',
  OPERADOR = 'operador',
  CONSULTA = 'consulta'
}

// Interfaces de documentos
export interface IAsset extends Document {
  codigo: string;
  nombre: string;
  tipo: TipoActivo;
  categoria: string;
  propietario: string;
  custodio: string;
  ubicacion: string;
  valoracion: Valoracion;
  valorEconomico: number;
  dependencias: Types.ObjectId[];
  servicios: string[];
  metadatos: MetadatosActivo;
  fechaCreacion: Date;
  fechaActualizacion: Date;
}

export interface IThreat extends Document {
  codigo: string;
  nombre: string;
  tipo: TipoAmenaza;
  origen: string;
  descripcion: string;
  probabilidad: number;
  vectores: string[];
  cveData?: CVEData;
  aplicaA: Types.ObjectId[];
  fechaDescubrimiento: Date;
  ultimaActualizacion: Date;
}

export interface IVulnerability extends Document {
  codigo: string;
  nombre: string;
  categoria: string;
  descripcion: string;
  facilidadExplotacion: number;
  vectoresAtaque: string[];
  afectaA: Types.ObjectId[];
  amenazasRelacionadas: Types.ObjectId[];
  estado: 'Activa' | 'Mitigada' | 'Aceptada' | 'En Tratamiento';
  fechaDeteccion: Date;
  fechaMitigacion?: Date;
}
export interface IRisk extends Document {
  activo: Types.ObjectId;
  amenaza: Types.ObjectId;
  vulnerabilidad?: Types.ObjectId;
  calculos: CalculosRiesgo;
  valorRiesgo: number;
  nivelRiesgo: NivelRiesgo;
  probabilidad: number;
  impacto: number;
  fechaCalculo: Date;
  vigente: boolean;
}

export interface ISafeguard extends Document {
  codigo: string;
  nombre: string;
  tipo: string;
  categoria: string;
  descripcion: string;
  estado: EstadoSalvaguarda;
  eficacia: number;
  costo: number;
  costeMantenenimiento: number;
  protege: Types.ObjectId[];
  activos: Types.ObjectId[];
  responsable: string; // AGREGADO
  periodicidadRevision: number; // AGREGADO
  documentacion: Array<{
    nombre: string;
    url?: string;
    descripcion?: string;
  }>; // AGREGADO
  kpis: Array<{
    nombre: string;
    valor: number;
    unidad: string;
    fechaMedicion: Date;
  }>; // AGREGADO
  fechaImplementacion?: Date;
  fechaRevision?: Date;
  fechaCreacion: Date;
  fechaActualizacion: Date; // AGREGADO
  
  // Métodos de instancia
  calcularEfectividadReal(): number;
  programarRevision(meses?: number): void;
  agregarKPI(nombre: string, valor: number, unidad: string): void;
}

export interface IUser extends Document {
  email: string;
  password: string;
  nombre: string;
  apellido: string;
  rol: RolUsuario;
  activo: boolean;
  ultimoAcceso?: Date;
  fechaCreacion: Date;
  comparePassword(candidatePassword: string): Promise<boolean>;
}

// Tipos de respuesta API
export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  message?: string;
  error?: string;
  pagination?: {
    page: number;
    limit: number;
    total: number;
    pages: number;
  };
}

export interface PaginationOptions {
  page: number;
  limit: number;
  sort?: string;
  filter?: any;
}