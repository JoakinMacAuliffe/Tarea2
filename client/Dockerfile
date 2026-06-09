# 1. Usar una imagen oficial de Python ligera
FROM python:3.10-slim

# 2. Crear una carpeta de trabajo dentro del contenedor
WORKDIR /app

# 3. Copiar el archivo de requerimientos e instalar la librería Pika
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 4. Copiar tus scripts de Python al contenedor
COPY send.py receive.py ./

# 5. Indicar que, al iniciar, nos deje en una terminal interactiva (bash)
# Esto cumple el Paso 7 de tu rúbrica para el cliente.
CMD ["/bin/bash"]