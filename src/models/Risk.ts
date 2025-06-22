import mongoose, { Schema } from 'mongoose';
import { IRisk, NivelRiesgo } from '../types';

const calculosRiesgoSchema = new Schema({
  riesgoInherente: { 
    type: Number, 
    required: true 
  },
  probabilidadAjustada: { 
    type: Number, 
    required: true 
  },
  impactoCalculado: { 
    type: Number, 
    required: true 
  },
  exposicion: { 
    type: Number, 
    required: true 
  },
  factorTemporal: { 
    type: Number, 
    required: true 
  }
}, { _id: false });

const riskSchema = new Schema<IRisk>({
  activo: {
    type: Schema.Types.ObjectId,
    ref: 'Asset',
    required: true
  },
  amenaza: {
    type: Schema.Types.ObjectId,
    ref: 'Threat',
    required: true
  },
  vulnerabilidad: {
    type: Schema.Types.ObjectId,
    ref: 'Vulnerability',
    required: false
  },
  calculos: {
    type: calculosRiesgoSchema,
    required: true
  },
  valorRiesgo: {
    type: Number,
    required: true,
    min: 0
  },
  nivelRiesgo: {
    type: String,
    required: true,
    enum: Object.values(NivelRiesgo)
  },
  probabilidad: {
    type: Number,
    required: true,
    min: 0,
    max: 10
  },
  impacto: {
    type: Number,
    required: true,
    min: 0,
    max: 10
  },
  fechaCalculo: {
    type: Date,
    default: Date.now
  },
  vigente: {
    type: Boolean,
    default: true
  }
}, {
  timestamps: { createdAt: 'fechaCalculo', updatedAt: false }
});

// Índices
riskSchema.index({ activo: 1, amenaza: 1, vulnerabilidad: 1 }, { unique: true });
riskSchema.index({ nivelRiesgo: 1 });
riskSchema.index({ valorRiesgo: -1 });
riskSchema.index({ probabilidad: -1 });
riskSchema.index({ impacto: -1 });
riskSchema.index({ fechaCalculo: -1 });
riskSchema.index({ vigente: 1 });

// Virtual para el score de riesgo combinado
riskSchema.virtual('scoreRiesgo').get(function() {
  return this.probabilidad * this.impacto;
});

// Virtual para determinar si es riesgo residual o inherente
riskSchema.virtual('tipoRiesgo').get(function() {
  return this.vulnerabilidad ? 'Residual' : 'Inherente';
});

riskSchema.set('toJSON', { virtuals: true });

export const Risk = mongoose.model<IRisk>('Risk', riskSchema);