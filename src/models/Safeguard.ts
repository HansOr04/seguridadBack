import mongoose, { Schema, Model } from 'mongoose';
import { ISafeguard, EstadoSalvaguarda } from '../types';

// Schema para documentación
const documentacionSchema = new Schema({
  nombre: { type: String, required: true },
  url: { type: String },
  descripcion: { type: String }
}, { _id: false });

// Schema para KPIs
const kpisSchema = new Schema({
  nombre: { type: String, required: true },
  valor: { type: Number, required: true },
  unidad: { type: String, required: true },
  fechaMedicion: { type: Date, default: Date.now }
}, { _id: false });

// Interface para métodos estáticos
interface ISafeguardModel extends Model<ISafeguard> {
  findByEstado(estado: EstadoSalvaguarda): Promise<ISafeguard[]>;
  findVencidas(): Promise<ISafeguard[]>;
  findProximasRevision(dias?: number): Promise<ISafeguard[]>;
}

const safeguardSchema = new Schema<ISafeguard>({
  codigo: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    maxlength: 50
  },
  nombre: {
    type: String,
    required: true,
    trim: true,
    maxlength: 200
  },
  tipo: {
    type: String,
    required: true,
    enum: [
      'Preventiva',
      'Detectiva', 
      'Correctiva',
      'Disuasoria',
      'Compensatoria'
    ],
    default: 'Preventiva'
  },
  categoria: {
    type: String,
    required: true,
    enum: [
      'Física',
      'Lógica',
      'Técnica',
      'Administrativa',
      'Legal',
      'Organizacional'
    ]
  },
  descripcion: {
    type: String,
    required: true,
    maxlength: 1000
  },
  estado: {
    type: String,
    required: true,
    enum: Object.values(EstadoSalvaguarda),
    default: EstadoSalvaguarda.PROPUESTA
  },
  eficacia: {
    type: Number,
    required: true,
    min: 0,
    max: 100,
    default: 0
  },
  costo: {
    type: Number,
    required: true,
    min: 0,
    default: 0
  },
  costeMantenenimiento: {
    type: Number,
    required: true,
    min: 0,
    default: 0
  },
  protege: [{
    type: Schema.Types.ObjectId,
    ref: 'Risk',
    required: true
  }],
  activos: [{
    type: Schema.Types.ObjectId,
    ref: 'Asset'
  }],
  responsable: {
    type: String,
    required: true,
    trim: true,
    maxlength: 100
  },
  periodicidadRevision: {
    type: Number, // en meses
    min: 1,
    max: 60,
    default: 12
  },
  documentacion: [documentacionSchema],
  kpis: [kpisSchema],
  fechaImplementacion: {
    type: Date
  },
  fechaRevision: {
    type: Date
  },
  fechaCreacion: {
    type: Date,
    default: Date.now
  },
  fechaActualizacion: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: { createdAt: 'fechaCreacion', updatedAt: 'fechaActualizacion' }
});

// Índices
safeguardSchema.index({ codigo: 1 });
safeguardSchema.index({ tipo: 1 });
safeguardSchema.index({ categoria: 1 });
safeguardSchema.index({ estado: 1 });
safeguardSchema.index({ eficacia: -1 });
safeguardSchema.index({ costo: 1 });
safeguardSchema.index({ responsable: 1 });
safeguardSchema.index({ fechaImplementacion: 1 });
safeguardSchema.index({ fechaRevision: 1 });

// Índices compuestos
safeguardSchema.index({ tipo: 1, categoria: 1 });
safeguardSchema.index({ estado: 1, eficacia: -1 });

// Middleware pre-save
safeguardSchema.pre('save', function(next) {
  this.fechaActualizacion = new Date();
  
  // Calcular fecha de próxima revisión si está implementada
  if (this.estado === EstadoSalvaguarda.IMPLEMENTADA && this.fechaImplementacion && !this.fechaRevision) {
    const fechaRevision = new Date(this.fechaImplementacion);
    fechaRevision.setMonth(fechaRevision.getMonth() + this.periodicidadRevision);
    this.fechaRevision = fechaRevision;
  }
  
  next();
});

// Virtuals
safeguardSchema.virtual('costeTotalAnual').get(function(this: ISafeguard) {
  return this.costo + (this.costeMantenenimiento * 12);
});

safeguardSchema.virtual('roi').get(function(this: ISafeguard) {
  // ROI = (Reducción de riesgo * Valor activos) / Costo total
  if (this.costo === 0) return 0;
  
  const reduccionRiesgo = this.eficacia / 100;
  const costoTotal = this.costo + (this.costeMantenenimiento * 12);
  
  // Asumimos un valor promedio de activos protegidos
  const valorPromedio = 100000;
  
  return ((reduccionRiesgo * valorPromedio) / costoTotal) * 100;
});

safeguardSchema.virtual('nivelEficacia').get(function(this: ISafeguard) {
  if (this.eficacia >= 90) return 'Muy Alta';
  if (this.eficacia >= 70) return 'Alta';
  if (this.eficacia >= 50) return 'Media';
  if (this.eficacia >= 30) return 'Baja';
  return 'Muy Baja';
});

safeguardSchema.virtual('estadoRevision').get(function(this: ISafeguard) {
  if (!this.fechaRevision) return 'Sin programar';
  
  const ahora = new Date();
  const fechaRevision = new Date(this.fechaRevision);
  
  if (fechaRevision < ahora) return 'Vencida';
  
  const diasHastaRevision = Math.ceil((fechaRevision.getTime() - ahora.getTime()) / (1000 * 60 * 60 * 24));
  
  if (diasHastaRevision <= 30) return 'Próxima';
  return 'Programada';
});

safeguardSchema.virtual('diasImplementacion').get(function(this: ISafeguard) {
  if (!this.fechaImplementacion) return null;
  
  const ahora = new Date();
  const fechaImplementacion = new Date(this.fechaImplementacion);
  
  return Math.floor((ahora.getTime() - fechaImplementacion.getTime()) / (1000 * 60 * 60 * 24));
});

// Métodos estáticos - CORREGIDOS
safeguardSchema.static('findByEstado', function(estado: EstadoSalvaguarda) {
  return this.find({ estado }).populate('activos protege');
});

safeguardSchema.static('findVencidas', function() {
  const ahora = new Date();
  return this.find({ 
    fechaRevision: { $lt: ahora },
    estado: EstadoSalvaguarda.IMPLEMENTADA 
  });
});

safeguardSchema.static('findProximasRevision', function(dias: number = 30) {
  const ahora = new Date();
  const fechaLimite = new Date();
  fechaLimite.setDate(fechaLimite.getDate() + dias);
  
  return this.find({
    fechaRevision: { $gte: ahora, $lte: fechaLimite },
    estado: EstadoSalvaguarda.IMPLEMENTADA
  });
});

// Métodos de instancia
safeguardSchema.method('calcularEfectividadReal', function(this: ISafeguard) {
  // Calcular efectividad basada en KPIs y tiempo de implementación
  if (this.kpis.length === 0) return this.eficacia;
  
  const kpisRecientes = this.kpis.filter((kpi) => {
    const hace30Dias = new Date();
    hace30Dias.setDate(hace30Dias.getDate() - 30);
    return kpi.fechaMedicion >= hace30Dias;
  });
  
  if (kpisRecientes.length === 0) return this.eficacia;
  
  // Promedio de KPIs recientes como factor de ajuste
  const promedioKpis = kpisRecientes.reduce((sum, kpi) => sum + kpi.valor, 0) / kpisRecientes.length;
  
  // Ajustar eficacia base con datos reales
  return Math.min(100, this.eficacia * (promedioKpis / 100));
});

safeguardSchema.method('programarRevision', function(this: ISafeguard, meses?: number) {
  if (this.fechaImplementacion) {
    const periodicidad = meses || this.periodicidadRevision;
    const fechaRevision = new Date(this.fechaImplementacion);
    fechaRevision.setMonth(fechaRevision.getMonth() + periodicidad);
    this.fechaRevision = fechaRevision;
  }
});

safeguardSchema.method('agregarKPI', function(this: ISafeguard, nombre: string, valor: number, unidad: string) {
  this.kpis.push({
    nombre,
    valor,
    unidad,
    fechaMedicion: new Date()
  });
});

// Configurar toJSON para incluir virtuals
safeguardSchema.set('toJSON', { 
  virtuals: true,
  transform: function(doc, ret) {
    delete ret.__v;
    return ret;
  }
});

safeguardSchema.set('toObject', { virtuals: true });

export const Safeguard = mongoose.model<ISafeguard, ISafeguardModel>('Safeguard', safeguardSchema);