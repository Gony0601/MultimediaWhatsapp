const express = require('express');
const { downloadMediaMessage } = require('@whiskeysockets/baileys');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const helmet = require('helmet');

// Instanciar app y configurar trust proxy para reconocer HTTPS tras Traefik
const app = express();
app.set('trust proxy', true);

// Middleware de seguridad con Helmet
app.use(helmet());

// Middleware para parsear JSON con límite aumentado
app.use(express.json({ limit: '50mb' }));

// Integración de Winston para logging
const winston = require('winston');
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.printf(({ timestamp, level, message, ...meta }) => {
      return `${timestamp} [${level}]: ${message} ${Object.keys(meta).length ? JSON.stringify(meta) : ''}`;
    })
  ),
  transports: [
    new winston.transports.Console()
    // Se puede agregar un transporte para archivo si se requiere:
    // new winston.transports.File({ filename: 'error.log', level: 'error' })
  ]
});

// Middleware de logging de solicitudes
app.use((req, res, next) => {
  logger.info(`Request: ${req.method} ${req.url}`);
  next();
});

// Verificar y crear la carpeta 'dowloadtmt' si no existe
const downloadFolder = 'dowloadtmt';
if (!fs.existsSync(downloadFolder)) {
  fs.mkdirSync(downloadFolder, { recursive: true });
  logger.info(`Carpeta ${downloadFolder} creada.`);
}

// Configurar el cliente de Supabase
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

// Middleware para verificar el Bearer token
async function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No se proporcionó el token Bearer' });
  }
  const token = authHeader.substring(7); // Elimina "Bearer "

  // Consulta a Supabase para buscar el token en la tabla "tokens"
  const { data, error } = await supabase
    .from('tokens')
    .select('*')
    .eq('token', token)
    .single();

  if (error || !data) {
    return res.status(401).json({ error: 'Token no válido' });
  }
  // Verificar que el token esté activo
  if (!data.active) {
    return res.status(401).json({ error: 'Token inactivo' });
  }
  // Verificar que no haya expirado
  const now = new Date();
  const expiresAt = new Date(data.expires_at);
  if (now > expiresAt) {
    return res.status(401).json({ error: 'Token expirado' });
  }
  req.tokenData = data;
  next();
}

/**
 * Endpoint para generar un token nuevo.
 * Se espera recibir en el body: { nombre, phone_id }
 * Se genera un token con expiración de 1 mes.
 */
app.post('/generateToken', async (req, res) => {
  try {
    const { nombre, phone_id } = req.body;
    if (!nombre || !phone_id) {
      return res.status(400).json({ error: 'Se requiere nombre y phone_id' });
    }
    // Generar token aleatorio
    const token = crypto.randomBytes(16).toString('hex');
    const now = new Date();
    const expiresAt = new Date(now.setMonth(now.getMonth() + 1)); // 1 mes de validez

    // Insertar el token en la tabla "tokens" usando { returning: 'representation' }
    let { data, error } = await supabase
      .from('tokens')
      .insert([{ nombre, token, phone_id, expires_at: expiresAt }], { returning: 'representation' })
      .maybeSingle();

    if (error) {
      logger.error('Error al insertar token en Supabase:', error);
      return res.status(500).json({ error: 'Error al generar token' });
    }

    // Si data es null, se obtiene el registro manualmente
    if (!data) {
      const { data: fetchedData, error: fetchError } = await supabase
        .from('tokens')
        .select('*')
        .eq('token', token)
        .maybeSingle();

      if (fetchError || !fetchedData) {
        logger.error('Error al obtener el token generado:', fetchError);
        return res.status(500).json({ error: 'Error al obtener el token generado' });
      }
      data = fetchedData;
    }

    res.status(200).json({ 
      message: 'Token generado correctamente',
      token: data.token,
      phone_id: data.phone_id,
      expires_at: data.expires_at
    });
    logger.info('Éxito: Token generado correctamente');
  } catch (err) {
    logger.error('Error en /generateToken:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Mapeo temporal para guardar tokens y la info del archivo (tokens para media)
const tempFiles = new Map();
// Duración del token para media: 2 minutos (120000 ms)
const TOKEN_VALIDITY_DURATION = 2 * 60 * 1000;

// Limpieza periódica de tokens expirados (cada 2 minutos)
setInterval(() => {
  const now = Date.now();
  for (const [token, data] of tempFiles) {
    if (data.expiresAt < now) {
      if (fs.existsSync(data.filePath)) {
        fs.unlink(data.filePath, (err) => {
          if (err) logger.error(`Error al eliminar ${data.filePath}:`, err);
          else logger.info(`Archivo ${data.filePath} eliminado por expiración.`);
        });
      }
      tempFiles.delete(token);
    }
  }
}, 120000);

// Endpoint para procesar mensajes multimedia y generar URL temporal
app.post('/processMedia', authenticateToken, async (req, res) => {
  try {
    logger.info("Payload recibido:");
    // Se asume que el JSON recibido es el objeto multimedia directamente
    const mediaObject = req.body;
    
    // Determinar el tipo de medio (sin modificar el formato original)
    let mediaType;
    if (mediaObject.imageMessage) {
      mediaType = 'imageMessage';
    } else if (mediaObject.videoMessage) {
      mediaType = 'videoMessage';
    } else if (mediaObject.documentMessage) {
      mediaType = 'documentMessage';
    } else if (mediaObject.audioMessage) {
      mediaType = 'audioMessage';
    } else {
      throw new Error('El mensaje no contiene un tipo multimedia soportado');
    }
    
    // Extraer la información relevante
    const mediaInfo = mediaObject[mediaType];
    logger.info("Caption: " + (mediaInfo.caption || 'Sin caption'));
    logger.info("URL: " + (mediaInfo.url || 'URL no proporcionada'));
    logger.info("MIME type: " + (mediaInfo.mimetype || 'MIME type no proporcionado'));
    
    if (!mediaInfo.url) {
      throw new Error('El campo URL está vacío, no se puede descargar el medio');
    }
    
    // Extraer la extensión:
    // Para documentos, si existe el title, usarlo para obtener la extensión.
    // Para otros, se extrae del mimetype.
    let fileExtension = '';
    if (mediaType === 'documentMessage' && mediaInfo.title) {
      fileExtension = path.extname(mediaInfo.title);
    } else if (mediaInfo.mimetype) {
      const mimeParts = mediaInfo.mimetype.split('/');
      if (mimeParts.length === 2) {
        fileExtension = '.' + mimeParts[1];
      }
    }
    
    // Envolver el objeto recibido para que tenga la estructura { message: ... }
    const messageWrapper = { message: mediaObject };
    
    // Descargar y descifrar el archivo multimedia
    let mediaData;
    try {
      mediaData = await downloadMediaMessage(messageWrapper, 'buffer');
    } catch (downloadError) {
      logger.error("Error en downloadMediaMessage:", downloadError);
      throw new Error("Error en la descarga del medio");
    }
    
    // Guardar el archivo en disco conservando el formato original
    const fileName = `archivo_${Date.now()}${fileExtension}`;
    const filePath = path.join(downloadFolder, fileName);
    fs.writeFileSync(filePath, mediaData);
    logger.info(`Medio descargado y guardado como ${filePath}`);
    
    // Generar token único para la descarga controlada
    const mediaToken = crypto.randomBytes(16).toString('hex');
    const expiresAt = Date.now() + TOKEN_VALIDITY_DURATION;
    tempFiles.set(mediaToken, { filePath, expiresAt });
    
    // La URL generada permitirá visualizar el archivo inline sin forzar la descarga
    const downloadUrl = `${req.protocol}://${req.get('host')}/download/${mediaToken}`;
    
    res.status(200).json({ 
      message: `Medio guardado como ${fileName}`, 
      url: downloadUrl, 
      expiresIn: TOKEN_VALIDITY_DURATION / 1000 
    });
  } catch (error) {
    logger.error('Error al procesar el mensaje multimedia:', error.stack);
    res.status(500).json({ error: error.message });
  }
});

// Endpoint para servir el archivo en línea (inline) sin forzar la descarga
app.get('/download/:token', (req, res) => {
  const token = req.params.token;
  if (!tempFiles.has(token)) {
    return res.status(404).json({ error: 'Token inválido o expirado' });
  }
  const data = tempFiles.get(token);
  if (Date.now() > data.expiresAt) {
    if (fs.existsSync(data.filePath)) {
      fs.unlink(data.filePath, (err) => {
        if (err) logger.error(`Error al eliminar ${data.filePath}:`, err);
        else logger.info(`Archivo ${data.filePath} eliminado por expiración.`);
      });
    }
    tempFiles.delete(token);
    return res.status(404).json({ error: 'Token inválido o expirado' });
  }
  
  // Obtener el nombre del archivo desde filePath
  const fileName = path.basename(data.filePath);
  
  // Establecer el encabezado para mostrar el contenido inline
  res.setHeader('Content-Disposition', `inline; filename="${fileName}"`);
  
  // Configurar Content-Type según la extensión del archivo (se conserva el formato original)
  const ext = path.extname(fileName).toLowerCase();
  let contentType = 'application/octet-stream';
  if (ext === '.jpg' || ext === '.jpeg') {
    contentType = 'image/jpeg';
  } else if (ext === '.png') {
    contentType = 'image/png';
  } else if (ext === '.mp4') {
    contentType = 'video/mp4';
  } else if (ext === '.pdf') {
    contentType = 'application/pdf';
  } else if (ext === '.mp3') {
    contentType = 'audio/mpeg';
  } else if (ext === '.docx' || ext === '.doc') {
    contentType = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';
  }
  res.setHeader('Content-Type', contentType);
  
  // Enviar el archivo usando sendFile para mostrarlo inline
  res.sendFile(path.resolve(data.filePath), err => {
    if (err) {
      logger.error('Error en el envío del archivo:', err);
      res.status(500).json({ error: 'Error al enviar el archivo' });
    } else {
      logger.info(`Archivo ${data.filePath} enviado correctamente`);
      // El archivo se mantendrá en disco hasta que expire el token (2 minutos) y sea eliminado por el proceso de limpieza
    }
  });
});

// Middleware de manejo de errores
app.use((err, req, res, next) => {
  logger.error('Unhandled error:', err.stack);
  res.status(500).json({ error: 'Internal Server Error' });
});

const PORT = process.env.PORT || 3060;
app.listen(PORT, () => {
  logger.info(`Servidor escuchando en el puerto ${PORT}`);
});
