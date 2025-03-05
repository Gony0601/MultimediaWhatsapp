# Usa una imagen ligera de Node para producción
FROM node:20-alpine

# Establece el directorio de trabajo en el contenedor
WORKDIR /app

# Copia los archivos de dependencias
COPY package.json package-lock.json* ./

# Instala solo las dependencias de producción
RUN npm install --production

# Copia el resto del código al contenedor
COPY . .

# Asegúrate de que la carpeta "public" exista para guardar archivos temporales
RUN mkdir -p public

# Expone el puerto en el que correrá la aplicación
EXPOSE 3060

# Comando para iniciar la aplicación
CMD ["node", "server.js"]
