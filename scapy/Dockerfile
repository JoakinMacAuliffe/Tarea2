FROM python:3.12-slim

LABEL maintainer="Tarea3 - Taller de Redes"
LABEL description="Contenedor Scapy para inyeccion/modificacion de trafico AMQP (Tarea 3)"

# Dependencias de sistema
# libpcap-dev  -> captura de paquetes (Scapy)
# iproute2     -> utilidades de red (ip, tc)
# iputils-ping -> ping (ICMP manual)
# tcpdump      -> inspeccion adicional opcional
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpcap-dev \
        iproute2 \
        iputils-ping \
        tcpdump \
        gcc \
        libffi-dev \
        net-tools \
    && rm -rf /var/lib/apt/lists/*

# Dependencias Python
RUN pip install --no-cache-dir \
        scapy \
        matplotlib

# Directorio de trabajo
WORKDIR /app

# Copiar el script principal
COPY tarea3.py /app/tarea3.py

# Variables de entorno por defecto
# El host 'rabbit_server' coincide con el nombre del servicio en docker-compose
ENV AMQP_HOST=rabbit_server
ENV AMQP_PORT=5672

# Punto de entrada: ejecuta el script; los resultados se guardan en /app/
CMD ["python3", "-u", "tarea3.py"]
