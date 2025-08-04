const db = require('../config/db.config'); // Importamos la conexión a Supabase

const rateLimiter = {}; // Almacena el conteo de solicitudes por IP

const WINDOW_SIZE_IN_SECONDS = 60; // Ventana de tiempo de 60 segundos
const MAX_REQUESTS = 10;          // Máximo 10 solicitudes por ventana
const COOL_DOWN_IN_SECONDS = 300; // Bloqueo por 5 minutos (300 segundos)

const blockList = {}; // Almacena las IPs bloqueadas

const limitRate = async (req, res, next) => {
  const ip = req.ip || req.connection.remoteAddress;

  // 1. Verificar si la IP está en la lista de bloqueo
  if (blockList[ip] && blockList[ip] > Date.now()) {
    return res.status(429).json({ message: 'Demasiadas solicitudes. Intenta de nuevo más tarde.' });
  }

  // 2. Limpiar la IP de la lista de bloqueo si el tiempo de castigo ha terminado
  if (blockList[ip] && blockList[ip] <= Date.now()) {
    delete blockList[ip];
  }

  // 3. Inicializar el contador para la IP si no existe
  if (!rateLimiter[ip]) {
    rateLimiter[ip] = {
      count: 0,
      firstRequestTime: Date.now()
    };
  }

  const { count, firstRequestTime } = rateLimiter[ip];

  // 4. Resetear el contador si la ventana de tiempo ha pasado
  if (Date.now() - firstRequestTime > WINDOW_SIZE_IN_SECONDS * 1000) {
    rateLimiter[ip] = {
      count: 1,
      firstRequestTime: Date.now()
    };
    return next();
  }

  // 5. Incrementar el contador de solicitudes
  rateLimiter[ip].count++;

  // 6. Si el contador excede el límite, bloquear la IP y registrar el evento
  if (rateLimiter[ip].count > MAX_REQUESTS) {
    console.warn(`[RATE_LIMIT_EXCEEDED] IP bloqueada temporalmente: ${ip}`);

    // Crear y registrar el evento en la base de datos
    const attackPayload = {
      event_type: 'rate_limit_exceeded',
      ip_address: ip || 'desconocida',
      user_agent: req.headers['user-agent'] || 'desconocido',
      payload: JSON.stringify({ message: 'Se excedió el límite de solicitudes' }),
      path: req.originalUrl,
    };
    try {
      await db.from('security_events').insert(attackPayload);
      console.log('Evento de limitación de tasa registrado en la base de datos.');
    } catch (err) {
      console.error('Error al registrar el evento de limitación de tasa:', err);
    }

    blockList[ip] = Date.now() + (COOL_DOWN_IN_SECONDS * 1000);
    return res.status(429).json({ message: 'Demasiadas solicitudes. Intenta de nuevo más tarde.' });
  }

  next();
};

module.exports = limitRate;
