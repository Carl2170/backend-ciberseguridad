const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(bodyParser.json());

// Importa rutas
const authRoutes = require('./routes/auth.routes');
const userRoutes = require('./routes/users.routes');
const protectedRoutes = require('./routes/protected.routes');
const roleRoutes = require('./routes/role.routes');

app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);
app.use('/api', protectedRoutes);
app.use('/api', roleRoutes);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
