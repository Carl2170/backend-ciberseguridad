const express = require('express');
const db = require('../config/db.config');
const verifyToken = require('../middlewares/auth.middleware');
const verifyRole = require('../middlewares/role.middleware');
const monitoringRouter = express.Router();

monitoringRouter.get('/data', verifyToken, verifyRole('admin'),async (req, res) => {
  try {
    const { data, error } = await db
      .from('security_events')
      .select('*')
      .order('created_at', { ascending: false });

    if (error) {
      console.error('Error de Supabase:', error.message);
      return res.status(500).json({ error: 'Error al obtener los datos de monitoreo.' });
    }

    res.json(data);
  } catch (err) {
    console.error('Error inesperado en el endpoint /data:', err.message);
    res.status(500).json({ error: 'Error interno del servidor.' });
  }
});

monitoringRouter.get('/data/blocked', verifyToken, verifyRole('admin'), async (req, res) => {
  try {
    const { data, error } = await db
      .from('security_events')
      .select('*')
      .eq('is_blocked', true)
      .order('created_at', { ascending: false });

    if (error) {
      console.error('Error de Supabase:', error.message);
      return res.status(500).json({ error: 'Error al obtener los eventos bloqueados.' });
    }

    res.json(data);
  } catch (err) {
    console.error('Error inesperado en el endpoint /data/blocked:', err.message);
    res.status(500).json({ error: 'Error interno del servidor.' });
  }
});

monitoringRouter.get('/data/:id', verifyToken, verifyRole('admin'), async (req, res) => {
  const { id } = req.params;
  try {
    const { data, error } = await db
      .from('security_events')
      .select('*')
      .eq('id', id)
      .single();

    if (error) {
      // Supabase devuelve un error si el registro no es encontrado
      if (error.code === 'PGRST116') {
        return res.status(404).json({ error: 'Evento de seguridad no encontrado.' });
      }
      console.error('Error de Supabase:', error.message);
      return res.status(500).json({ error: 'Error al obtener el evento por ID.' });
    }

    res.json(data);
  } catch (err) {
    console.error('Error inesperado en el endpoint /data/:id:', err.message);
    res.status(500).json({ error: 'Error interno del servidor.' });
  }
});

module.exports = monitoringRouter;
