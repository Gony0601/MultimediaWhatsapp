const express = require('express');
const { downloadMediaMessage } = require('@whiskeysockets/baileys');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const helmet = require('helmet');

// ======================
// MODIFICADO: Instanciar app antes de usar middleware
// ======================
const app = express();

// ======================
// MODIFICADO: Agregar middleware de seguridad con Helmet
// ======================
app.use(helmet());

// ======================
// MODIFICADO: Middleware para parsear JSON con límite aumentado
// ======================
app.use(express.json({ limit: '50mb' }));

// ======================
// MODIFICADO: Integración de Winston para logging
// ======================
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

// ======================
// MODIFICADO: Middleware de logging de solicitudes
// ======================
app.use((req, res, next) => {
  logger.info(`Request: ${req.method} ${req.url}`);
  next();
});

// ======================
// MODIFICADO: Verificar y crear la carpeta 'dowloadtmt' si no existe
// ======================
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
const TOKEN_VALIDITY_DURATION = 60 * 1000; // Duración de validez del token para media: 60 segundos

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
    // Log para ver el payload completo recibido
    logger.info("Payload recibido:", JSON.stringify(req.body));

    let messageData;
    if (Array.isArray(req.body)) {
      if (req.body.length === 0) {
        throw new Error('El payload está vacío');
      }
      messageData = req.body[0];
    } else {
      messageData = req.body;
    }
    
    const fullMessage = messageData.body;
    if (!fullMessage || !fullMessage.message) {
      throw new Error('No se encontró la información del mensaje');
    }
    
    // Determinar el tipo de medio y la extensión del archivo
    let mediaType, fileExtension;
    if (fullMessage.message.imageMessage) {
      mediaType = 'imageMessage';
      fileExtension = '.jpg';
    } else if (fullMessage.message.videoMessage) {
      mediaType = 'videoMessage';
      fileExtension = '.mp4';
    } else if (fullMessage.message.documentMessage) {
      mediaType = 'documentMessage';
      fileExtension = '.pdf';
    } else if (fullMessage.message.audioMessage) {
      mediaType = 'audioMessage';
      fileExtension = '.mp3';
    } else {
      throw new Error('El mensaje no contiene un tipo multimedia soportado');
    }
    
    // Registrar la información extraída del mensaje
    const mediaInfo = fullMessage.message[mediaType];
    logger.info("Caption:", mediaInfo.caption || 'Sin caption');
    logger.info("URL:", mediaInfo.url || 'URL no proporcionada');
    logger.info("MIME type:", mediaInfo.mimetype || 'MIME type no proporcionado');
    
    // Verificar que el campo URL no esté vacío
    if (!mediaInfo.url) {
      throw new Error('El campo URL está vacío, no se puede descargar el medio');
    }
    
    // Descargar y descifrar el archivo multimedia
    let mediaData;
    try {
      mediaData = await downloadMediaMessage(fullMessage, 'buffer');
    } catch (downloadError) {
      logger.error("Error al descargar el medio:", downloadError);
      throw new Error("Error en la descarga del medio");
    }
    
    // Generar un nombre único para el archivo
    const fileName = `archivo_${Date.now()}${fileExtension}`;
    const filePath = path.join(downloadFolder, fileName);
    fs.writeFileSync(filePath, mediaData);
    logger.info(`Medio descargado y guardado como ${filePath}`);
    
    // Generar un token único para la descarga de media
    const mediaToken = crypto.randomBytes(16).toString('hex');
    const expiresAt = Date.now() + TOKEN_VALIDITY_DURATION;
    tempFiles.set(mediaToken, { filePath, expiresAt });
    
    // URL para la descarga controlada
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


// Endpoint para la descarga temporal: el token es válido para 1 descarga o hasta que expire
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
  
  res.download(data.filePath, err => {
    if (err) {
      logger.error('Error en la descarga:', err);
    } else {
      fs.unlink(data.filePath, err => {
        if (err) logger.error(`Error al eliminar ${data.filePath}:`, err);
        else logger.info(`Archivo ${data.filePath} eliminado tras la descarga.`);
      });
      tempFiles.delete(token);
    }
  });
});

// ======================
// MODIFICADO: Middleware de manejo de errores
// ======================
app.use((err, req, res, next) => {
  logger.error('Unhandled error:', err.stack);
  res.status(500).json({ error: 'Internal Server Error' });
});

const PORT = process.env.PORT || 3060;
app.listen(PORT, () => {
  logger.info(`Servidor escuchando en el puerto ${PORT}`);
});
