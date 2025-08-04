const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
require('dotenv').config();
const sqlInjectionDetector = require('./middlewares/sq-injection-detector');
const detectPathTraversal = require('./middlewares/pathTraversalDetector');
const detectXss = require('./middlewares/xssDetector');
const limitRate = require('./middlewares/rateLimiter'); 

const app = express();
app.set('trust proxy', true);
app.use(cors());
app.use(bodyParser.json());

app.use(limitRate); 
app.use(sqlInjectionDetector);
app.use(detectPathTraversal);
app.use(detectXss);

// Importa rutas
const authRoutes = require('./routes/auth.routes');
const userRoutes = require('./routes/users.routes');
const protectedRoutes = require('./routes/protected.routes');
const roleRoutes = require('./routes/role.routes');
const monitoringRoutes = require('./controllers/monitoring.controller');

app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);
app.use('/api', protectedRoutes);
app.use('/api', roleRoutes);
app.use('/api/monitoring', monitoringRoutes);


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
