const db = require('../config/db.config'); // Importamos la conexión a Supabase

const commonSqlKeywords = [
  'SELECT', 'UNION', 'DROP', 'ALTER', 'DELETE', 'INSERT', 'UPDATE',
  'OR 1=1', '--', '/*', 'xp_cmdshell'
];

const detectSqlInjection = async (req, res, next) => {
  // Función para sanitizar el payload antes de guardarlo en la base de datos
  const sanitizePayload = (obj) => {
    const sanitized = {};
    for (const key in obj) {
      if (obj[key] !== null && typeof obj[key] === 'object') {
        sanitized[key] = sanitizePayload(obj[key]);
      } else {
        sanitized[key] = String(obj[key]).substring(0, 500); // Truncar a 500 caracteres
      }
    }
    return sanitized;
  };
  
  const checkString = (str) => {
    if (typeof str !== 'string') return false;
    // Búsqueda de comillas simples sin escapar
    if (str.includes("'")) {
      return true;
    }

    // Búsqueda de palabras clave
    for (const keyword of commonSqlKeywords) {
      if (str.toUpperCase().includes(keyword)) {
        return true;
      }
    }
    return false;
  };

  const checkObject = (obj) => {
    for (const key in obj) {
      if (checkString(obj[key])) {
        return true;
      }
    }
    return false;
  };
  
  const isSuspicious = checkObject(req.body) || checkObject(req.query) || checkObject(req.params);

  if (isSuspicious) {
    console.warn(`[SQL Injection AVISO] Intento detectado desde IP: ${req.ip} en la ruta ${req.originalUrl}`);

    // Crear un registro del evento para la base de datos
    const attackPayload = {
      event_type: 'sql_injection_attempt',
      ip_address: req.ip || 'desconocida',
      user_agent: req.headers['user-agent'] || 'desconocido',
      payload: JSON.stringify(sanitizePayload({ ...req.body, ...req.query, ...req.params })),
      path: req.originalUrl,
    };

    try {
      // Insertar el registro en la nueva tabla
      const { data, error } = await db.from('security_events').insert(attackPayload);
      if (error) throw error;
      console.log('Intento de ataque registrado exitosamente.');
    } catch (err) {
      console.error('Error al registrar el ataque en la base de datos:', err);
    }
    
    // Bloquear la solicitud y enviar una respuesta de error al atacante
    return res.status(403).json({ message: 'Solicitud maliciosa detectada y bloqueada.' });
  }

  next();
};

module.exports = detectSqlInjection;
