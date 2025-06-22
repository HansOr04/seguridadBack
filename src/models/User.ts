import mongoose, { Schema } from 'mongoose';
import bcrypt from 'bcryptjs';
import { IUser, RolUsuario } from '../types';
import { config } from '../config/environment';

const userSchema = new Schema<IUser>({
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
    match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Email inválido']
  },
  password: {
    type: String,
    required: true,
    minlength: 8,
    select: false // No incluir por defecto en queries
  },
  nombre: {
    type: String,
    required: true,
    trim: true,
    maxlength: 50
  },
  apellido: {
    type: String,
    required: true,
    trim: true,
    maxlength: 50
  },
  rol: {
    type: String,
    required: true,
    enum: Object.values(RolUsuario),
    default: RolUsuario.CONSULTA
  },
  activo: {
    type: Boolean,
    default: true
  },
  ultimoAcceso: {
    type: Date
  },
  fechaCreacion: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: { createdAt: 'fechaCreacion', updatedAt: false }
});

// Índices
userSchema.index({ email: 1 });
userSchema.index({ rol: 1 });
userSchema.index({ activo: 1 });

// Middleware para hash de password antes de guardar
userSchema.pre('save', async function(next) {
  // Solo hash el password si ha sido modificado
  if (!this.isModified('password')) return next();

  try {
    const salt = await bcrypt.genSalt(config.BCRYPT_ROUNDS);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error as Error);
  }
});

// Método para comparar passwords
userSchema.methods.comparePassword = async function(candidatePassword: string): Promise<boolean> {
  return bcrypt.compare(candidatePassword, this.password);
};

// Virtual para nombre completo
userSchema.virtual('nombreCompleto').get(function() {
  return `${this.nombre} ${this.apellido}`;
});

userSchema.set('toJSON', { 
  virtuals: true,
  transform: function(doc, ret) {
    delete ret.password;
    return ret;
  }
});

export const User = mongoose.model<IUser>('User', userSchema);