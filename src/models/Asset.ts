import mongoose, { Schema } from 'mongoose';
import { IAsset, TipoActivo } from '../types';

const valoracionSchema = new Schema({
  confidencialidad: { 
    type: Number, 
    required: true, 
    min: 0, 
    max: 10 
  },
  integridad: { 
    type: Number, 
    required: true, 
    min: 0, 
    max: 10 
  },
  disponibilidad: { 
    type: Number, 
    required: true, 
    min: 0, 
    max: 10 
  },
  autenticidad: { 
    type: Number, 
    required: true, 
    min: 0, 
    max: 10 
  },
  trazabilidad: { 
    type: Number, 
    required: true, 
    min: 0, 
    max: 10 
  }
}, { _id: false });

const metadatosActivoSchema = new Schema({
  sistemaOperativo: { type: String },
  version: { type: String },
  vendor: { type: String },
  fechaInstalacion: { type: Date },
  cpu: { type: String },
  memoria: { type: String },
  almacenamiento: { type: String }
}, { _id: false });

const assetSchema = new Schema<IAsset>({
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
    enum: Object.values(TipoActivo)
  },
  categoria: {
    type: String,
    required: true,
    trim: true,
    maxlength: 100
  },
  propietario: {
    type: String,
    required: true,
    trim: true,
    maxlength: 100
  },
  custodio: {
    type: String,
    required: true,
    trim: true,
    maxlength: 100
  },
  ubicacion: {
    type: String,
    required: true,
    trim: true,
    maxlength: 200
  },
  valoracion: {
    type: valoracionSchema,
    required: true
  },
  valorEconomico: {
    type: Number,
    required: true,
    min: 0
  },
  dependencias: [{
    type: Schema.Types.ObjectId,
    ref: 'Asset'
  }],
  servicios: [{
    type: String,
    trim: true,
    maxlength: 100
  }],
  metadatos: {
    type: metadatosActivoSchema,
    default: {}
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
assetSchema.index({ codigo: 1 });
assetSchema.index({ tipo: 1 });
assetSchema.index({ propietario: 1 });
assetSchema.index({ 'valoracion.confidencialidad': -1 });
assetSchema.index({ 'valoracion.integridad': -1 });
assetSchema.index({ 'valoracion.disponibilidad': -1 });
assetSchema.index({ valorEconomico: -1 });

// Middleware pre-save
assetSchema.pre('save', function(next) {
  this.fechaActualizacion = new Date();
  next();
});

// Métodos virtuales
assetSchema.virtual('criticidad').get(function() {
  const valoracion = this.valoracion;
  return Math.max(
    valoracion.confidencialidad,
    valoracion.integridad,
    valoracion.disponibilidad,
    valoracion.autenticidad,
    valoracion.trazabilidad
  );
});

assetSchema.virtual('valoracionPromedio').get(function() {
  const valoracion = this.valoracion;
  return (
    valoracion.confidencialidad +
    valoracion.integridad +
    valoracion.disponibilidad +
    valoracion.autenticidad +
    valoracion.trazabilidad
  ) / 5;
});

// Configurar toJSON para incluir virtuals
assetSchema.set('toJSON', { virtuals: true });

export const Asset = mongoose.model<IAsset>('Asset', assetSchema);