# Usa la imagen oficial de Node.js como base.
# Esto asegura que tengas un entorno de Node.js para ejecutar tu aplicación.
# '18-alpine' es una versión ligera, ideal para producción.
FROM node:18-alpine

# Establece el directorio de trabajo dentro del contenedor.
# Todas las operaciones siguientes se realizarán en este directorio.
WORKDIR /app

# Copia los archivos 'package.json' y 'package-lock.json' al directorio de trabajo.
# Esto se hace primero para que Docker pueda cachear la instalación de dependencias,
# lo que acelera las futuras compilaciones.
COPY package*.json ./

# Instala las dependencias del proyecto.
# El comando '--omit=dev' asegura que las dependencias de desarrollo no se incluyan
# en la imagen final, reduciendo su tamaño.
RUN npm install --omit=dev

# Copia el resto del código fuente al directorio de trabajo.
COPY . .

# Expone el puerto en el que la aplicación escuchará.
# Render usará esta información para enrutar el tráfico correctamente.
EXPOSE 3000

# Define el comando para iniciar la aplicación cuando el contenedor se inicie.
# El comando 'npm start' ejecutará el script definido en tu 'package.json'.
CMD ["npm", "start"]