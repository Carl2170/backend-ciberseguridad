require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');

// Crea el cliente de Supabase
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);

// Prueba una consulta básica
async function testConnection() {
  try {
    const { data, error } = await supabase.from('users').select().limit(1);

    if (error) {
      throw error;
    }

    console.log('✅ Conexión exitosa. Datos:', data);
  } catch (err) {
    console.error('❌ Error de conexión:', err.message);
  }
}

testConnection();
