const db = require('../config/db.config');

const pathTraversalKeywords = [
  '../', '..\\', '%2e%2e%2f', '%2e%2e%5c',
  '/etc/passwd', 'C:\\Windows\\system32'
];

const detectPathTraversal = async (req, res, next) => {
  const sanitizePayload = (obj) => {
    const sanitized = {};
    for (const key in obj) {
      if (obj[key] !== null && typeof obj[key] === 'object') {
        sanitized[key] = sanitizePayload(obj[key]);
      } else {
        sanitized[key] = String(obj[key]).substring(0, 500);
      }
    }
    return sanitized;
  };

  const checkString = (str) => {
    if (typeof str !== 'string') return false;
    for (const keyword of pathTraversalKeywords) {
      if (str.includes(keyword)) {
        return true;
      }
    }
    return false;
  };
  
  const checkObject = (obj) => {
    for (const key in obj) {
      const value = String(obj[key]);
      if (checkString(value)) {
        return true;
      }
    }
    return false;
  };
  
  const isSuspicious = checkObject(req.body) || checkObject(req.query) || checkObject(req.params);

  if (isSuspicious) {
    console.warn(`[PATH_TRAVERSAL_ATTEMPT] Intento detectado desde IP: ${req.ip} en la ruta ${req.originalUrl}`);

    const attackPayload = {
      event_type: 'path_traversal_attempt',
      ip_address: req.ip || 'desconocida',
      user_agent: req.headers['user-agent'] || 'desconocido',
      payload: JSON.stringify(sanitizePayload({ ...req.body, ...req.query, ...req.params })),
      path: req.originalUrl,
    };

    try {
      const { data, error } = await db.from('security_events').insert(attackPayload);
      if (error) throw error;
      console.log('Intento de ataque registrado exitosamente.');
    } catch (err) {
      console.error('Error al registrar el ataque en la base de datos:', err);
    }
    
    return res.status(403).json({ message: 'Solicitud maliciosa detectada y bloqueada.' });
  }

  next();
};

module.exports = detectPathTraversal;
