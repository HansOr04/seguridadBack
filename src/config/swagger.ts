import swaggerJsdoc from 'swagger-jsdoc';
import swaggerUi from 'swagger-ui-express';
import { Express } from 'express';
import { config } from './environment';

const options = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'SIGRISK-EC API',
      version: '1.0.0',
      description: `
        API para el Sistema de Análisis y Gestión de Riesgos de los Sistemas de Información (SIGRISK-EC).
        Basado en la metodología MAGERIT v3.0 y adaptado para PYMES ecuatorianas.
        
        ## Características principales:
        - Gestión completa de activos según taxonomía MAGERIT
        - Análisis cuantitativo de riesgos  
        - Integración automática con NVD para CVEs
        - Gestión de salvaguardas con análisis ROI
        - Cumplimiento normativo Ecuador/España
        
        ## Autenticación:
        La API utiliza JWT (JSON Web Tokens) para autenticación. 
        Incluye el token en el header: \`Authorization: Bearer <token>\`
      `,
      contact: {
        name: 'SIGRISK-EC Support',
        email: 'support@sigrisk-ec.com'
      },
      license: {
        name: 'MIT',
        url: 'https://opensource.org/licenses/MIT'
      }
    },
    servers: [
      {
        url: config.NODE_ENV === 'production' 
          ? 'https://api.sigrisk-ec.com/api/v1'
          : `http://localhost:${config.PORT}/api/v1`,
        description: config.NODE_ENV === 'production' ? 'Servidor de Producción' : 'Servidor de Desarrollo'
      }
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
          description: 'Token JWT para autenticación'
        }
      },
      schemas: {
        // Schemas de respuesta
        ApiResponse: {
          type: 'object',
          properties: {
            success: {
              type: 'boolean',
              description: 'Indica si la operación fue exitosa'
            },
            data: {
              type: 'object',
              description: 'Datos de respuesta'
            },
            message: {
              type: 'string',
              description: 'Mensaje descriptivo'
            },
            error: {
              type: 'string',
              description: 'Mensaje de error si aplica'
            },
            pagination: {
              type: 'object',
              properties: {
                page: { type: 'integer' },
                limit: { type: 'integer' },
                total: { type: 'integer' },
                pages: { type: 'integer' }
              }
            }
          }
        },
        
        // Schemas de MAGERIT
        Valoracion: {
          type: 'object',
          required: ['confidencialidad', 'integridad', 'disponibilidad', 'autenticidad', 'trazabilidad'],
          properties: {
            confidencialidad: {
              type: 'integer',
              minimum: 0,
              maximum: 10,
              description: 'Valoración de confidencialidad (0-10)'
            },
            integridad: {
              type: 'integer',
              minimum: 0,
              maximum: 10,
              description: 'Valoración de integridad (0-10)'
            },
            disponibilidad: {
              type: 'integer',
              minimum: 0,
              maximum: 10,
              description: 'Valoración de disponibilidad (0-10)'
            },
            autenticidad: {
              type: 'integer',
              minimum: 0,
              maximum: 10,
              description: 'Valoración de autenticidad (0-10)'
            },
            trazabilidad: {
              type: 'integer',
              minimum: 0,
              maximum: 10,
              description: 'Valoración de trazabilidad (0-10)'
            }
          }
        },
        
        Asset: {
          type: 'object',
          required: ['codigo', 'nombre', 'tipo', 'categoria', 'propietario', 'custodio', 'ubicacion', 'valoracion', 'valorEconomico'],
          properties: {
            _id: {
              type: 'string',
              description: 'ID único del activo'
            },
            codigo: {
              type: 'string',
              maxLength: 50,
              description: 'Código único del activo según nomenclatura MAGERIT',
              example: 'SRV-001'
            },
            nombre: {
              type: 'string',
              maxLength: 200,
              description: 'Nombre descriptivo del activo',
              example: 'Servidor Principal de Aplicaciones'
            },
            tipo: {
              type: 'string',
              enum: ['Hardware', 'Software', 'Datos/Información', 'Comunicaciones', 'Servicios', 'Instalaciones', 'Personal'],
              description: 'Tipo de activo según taxonomía MAGERIT'
            },
            categoria: {
              type: 'string',
              maxLength: 100,
              description: 'Categoría específica del activo',
              example: 'Servidores de aplicaciones'
            },
            propietario: {
              type: 'string',
              maxLength: 100,
              description: 'Responsable o propietario del activo',
              example: 'Departamento de TI'
            },
            custodio: {
              type: 'string',
              maxLength: 100,
              description: 'Custodio o administrador del activo',
              example: 'Juan Pérez - Administrador de Sistemas'
            },
            ubicacion: {
              type: 'string',
              maxLength: 200,
              description: 'Ubicación física o lógica del activo',
              example: 'Datacenter Principal - Rack A1'
            },
            valoracion: {
              $ref: '#/components/schemas/Valoracion'
            },
            valorEconomico: {
              type: 'number',
              minimum: 0,
              description: 'Valor económico del activo en USD',
              example: 15000
            },
            dependencias: {
              type: 'array',
              items: {
                type: 'string'
              },
              description: 'IDs de activos de los que depende este activo'
            },
            servicios: {
              type: 'array',
              items: {
                type: 'string'
              },
              description: 'Servicios que soporta este activo',
              example: ['Aplicación web', 'Base de datos', 'API REST']
            },
            metadatos: {
              type: 'object',
              properties: {
                sistemaOperativo: { type: 'string', example: 'Ubuntu 20.04 LTS' },
                version: { type: 'string', example: '20.04.3' },
                vendor: { type: 'string', example: 'Dell Technologies' },
                fechaInstalacion: { type: 'string', format: 'date' },
                cpu: { type: 'string', example: 'Intel Xeon 16 cores' },
                memoria: { type: 'string', example: '32GB DDR4' },
                almacenamiento: { type: 'string', example: '1TB SSD NVMe' }
              }
            },
            fechaCreacion: {
              type: 'string',
              format: 'date-time',
              description: 'Fecha de creación del registro'
            },
            fechaActualizacion: {
              type: 'string',
              format: 'date-time',
              description: 'Fecha de última actualización'
            }
          }
        },
        
        Threat: {
          type: 'object',
          properties: {
            _id: { type: 'string' },
            codigo: {
              type: 'string',
              description: 'Código de la amenaza (MAGERIT o CVE-ID)',
              example: 'A.25.01 o CVE-2024-1234'
            },
            nombre: {
              type: 'string',
              description: 'Nombre de la amenaza',
              example: 'Acceso no autorizado'
            },
            tipo: {
              type: 'string',
              enum: ['Desastres naturales', 'Fallos técnicos', 'Fallos de servicios', 'Errores y fallos no intencionados', 'Ataques intencionados'],
              description: 'Tipo de amenaza según clasificación MAGERIT'
            },
            origen: {
              type: 'string',
              enum: ['MAGERIT', 'CVE', 'Manual', 'MISP'],
              description: 'Origen de la amenaza'
            },
            descripcion: {
              type: 'string',
              description: 'Descripción detallada de la amenaza'
            },
            probabilidad: {
              type: 'integer',
              minimum: 0,
              maximum: 10,
              description: 'Probabilidad de ocurrencia (0-10)'
            },
            cveData: {
              type: 'object',
              properties: {
                cveId: { type: 'string', example: 'CVE-2024-1234' },
                cvssScore: { type: 'number', example: 7.5 },
                severity: { type: 'string', enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] },
                affectedSoftware: { type: 'array', items: { type: 'string' } }
              }
            }
          }
        },
        
        Safeguard: {
          type: 'object',
          required: ['codigo', 'nombre', 'tipo', 'categoria', 'descripcion', 'responsable', 'eficacia', 'costo'],
          properties: {
            _id: { type: 'string' },
            codigo: {
              type: 'string',
              maxLength: 50,
              description: 'Código único de la salvaguarda',
              example: 'S.01.01'
            },
            nombre: {
              type: 'string',
              maxLength: 200,
              description: 'Nombre de la salvaguarda',
              example: 'Sistema de autenticación multifactor'
            },
            tipo: {
              type: 'string',
              enum: ['Preventiva', 'Detectiva', 'Correctiva', 'Disuasoria', 'Compensatoria'],
              description: 'Tipo de salvaguarda'
            },
            categoria: {
              type: 'string',
              enum: ['Física', 'Lógica', 'Técnica', 'Administrativa', 'Legal', 'Organizacional'],
              description: 'Categoría de la salvaguarda'
            },
            descripcion: {
              type: 'string',
              maxLength: 1000,
              description: 'Descripción detallada de la salvaguarda'
            },
            estado: {
              type: 'string',
              enum: ['Propuesta', 'Planificada', 'En Implementación', 'Implementada', 'Obsoleta'],
              description: 'Estado actual de la salvaguarda'
            },
            eficacia: {
              type: 'integer',
              minimum: 0,
              maximum: 100,
              description: 'Eficacia de la salvaguarda (0-100%)'
            },
            costo: {
              type: 'number',
              minimum: 0,
              description: 'Costo de implementación en USD'
            },
            costeMantenenimiento: {
              type: 'number',
              minimum: 0,
              description: 'Costo mensual de mantenimiento en USD'
            },
            responsable: {
              type: 'string',
              description: 'Responsable de la salvaguarda'
            }
          }
        },
        
        // Error schemas
        ValidationError: {
          type: 'object',
          properties: {
            success: { type: 'boolean', example: false },
            error: { type: 'string', example: 'Datos de entrada inválidos' }
          }
        },
        
        NotFoundError: {
          type: 'object',
          properties: {
            success: { type: 'boolean', example: false },
            error: { type: 'string', example: 'Recurso no encontrado' }
          }
        },
        
        UnauthorizedError: {
          type: 'object',
          properties: {
            success: { type: 'boolean', example: false },
            error: { type: 'string', example: 'Token de acceso requerido' }
          }
        }
      }
    },
    security: [
      {
        bearerAuth: []
      }
    ],
    tags: [
      {
        name: 'Autenticación',
        description: 'Endpoints para autenticación y autorización'
      },
      {
        name: 'Activos',
        description: 'Gestión de activos según metodología MAGERIT'
      },
      {
        name: 'Riesgos',
        description: 'Análisis cuantitativo de riesgos'
      },
      {
        name: 'CVE',
        description: 'Integración con NVD y gestión de vulnerabilidades'
      },
      {
        name: 'Salvaguardas',
        description: 'Gestión de controles y salvaguardas de seguridad'
      }
    ]
  },
  apis: [
    './src/routes/*.ts',
    './src/controllers/*.ts'
  ]
};

const specs = swaggerJsdoc(options);

export const setupSwagger = (app: Express): void => {
  // Swagger UI
  app.use('/api/docs', swaggerUi.serve);
  app.get('/api/docs', swaggerUi.setup(specs, {
    explorer: true,
    customCss: '.swagger-ui .topbar { display: none }',
    customSiteTitle: 'SIGRISK-EC API Documentation',
    swaggerOptions: {
      persistAuthorization: true,
      docExpansion: 'none',
      filter: true,
      showRequestDuration: true
    }
  }));

  // JSON endpoint
  app.get('/api/docs.json', (req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.send(specs);
  });
  
  console.log(`📚 Swagger UI disponible en: http://localhost:${config.PORT}/api/docs`);
};

export default specs;