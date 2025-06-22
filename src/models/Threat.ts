import mongoose, { Schema } from 'mongoose';
import { IThreat, TipoAmenaza } from '../types';

const cveDataSchema = new Schema({
  cveId: { type: String, required: true },
  cvssScore: { type: Number, min: 0, max: 10 },
  cvssVector: { type: String },
  severity: { 
    type: String, 
    enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
    required: true
  },
  affectedSoftware: [{ type: String }],
  publishedDate: { type: Date, required: true },
  lastModifiedDate: { type: Date, required: true },
  description: { type: String, required: true }
}, { _id: false });

const threatSchema = new Schema<IThreat>({
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
    enum: Object.values(TipoAmenaza)
  },
  origen: {
    type: String,
    required: true,
    enum: ['MAGERIT', 'CVE', 'Manual', 'MISP'],
    default: 'Manual'
  },
  descripcion: {
    type: String,
    required: true,
    maxlength: 1000
  },
  probabilidad: {
    type: Number,
    required: true,
    min: 0,
    max: 10
  },
  vectores: [{
    type: String,
    trim: true,
    maxlength: 100
  }],
  cveData: {
    type: cveDataSchema,
    required: false
  },
  aplicaA: [{
    type: Schema.Types.ObjectId,
    ref: 'Asset'
  }],
  fechaDescubrimiento: {
    type: Date,
    default: Date.now
  },
  ultimaActualizacion: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: { createdAt: 'fechaDescubrimiento', updatedAt: 'ultimaActualizacion' }
});

// Índices
threatSchema.index({ codigo: 1 });
threatSchema.index({ tipo: 1 });
threatSchema.index({ origen: 1 });
threatSchema.index({ probabilidad: -1 });
threatSchema.index({ 'cveData.cveId': 1 });
threatSchema.index({ 'cveData.severity': 1 });
threatSchema.index({ fechaDescubrimiento: -1 });

// Método virtual para determinar nivel de amenaza
threatSchema.virtual('nivelAmenaza').get(function() {
  if (this.probabilidad >= 8) return 'Crítico';
  if (this.probabilidad >= 6) return 'Alto';
  if (this.probabilidad >= 4) return 'Medio';
  if (this.probabilidad >= 2) return 'Bajo';
  return 'Muy Bajo';
});

threatSchema.set('toJSON', { virtuals: true });

export const Threat = mongoose.model<IThreat>('Threat', threatSchema);