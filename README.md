# Tarea 2

Repositorio para trabajar con un broker RabbitMQ en Docker, un cliente basado en `amqp-tools` y el script `tarea3.py` como punto de entrada actual para pruebas con Scapy y mediciones de red.

## Que incluye

- `server/`: imagen Docker del servidor RabbitMQ con Management UI habilitada.
- `client/`: imagen Docker con `amqp-tools` para publicar y consumir mensajes.
- `tarea3.py`: script principal para inyeccion/modificacion de trafico AMQP y analisis de rendimiento.
- `captura_amqp.pcapng`: captura incluida en el repo.
- `resultados_analisis.txt`: salida registrada por el script.
- `metricas_throughput.png`: grafico generado por el script.

## Requisitos

- Docker Desktop en ejecucion.
- Python 3.
- Paquetes Python: `scapy` y `matplotlib`.
- En Windows, ejecutar como administrador para que Scapy pueda usar sockets raw.
- Si vas a capturar trafico en el sistema, Npcap puede ser necesario.

Instalacion de dependencias Python:

```bash
pip install scapy matplotlib
```

## Servidor RabbitMQ

Construye la imagen del servidor:

```bash
docker build -t amqp_server .\server
```

Ejecuta el contenedor:

```bash
docker run -it --rm --name rabbit_server -p 5672:5672 -p 15672:15672 amqp_server
```

Credenciales por defecto:

- Usuario: `admin`
- Clave: `1234`
- Virtual host: `entorno_amqp`

Puertos expuestos:

- `5672`: AMQP
- `15672`: interfaz web de administracion

## Cliente AMQP

Construye la imagen del cliente:

```bash
docker build -t amqp_client .\client
```

Abre un contenedor interactivo:

```bash
docker run -it --rm amqp_client
```

Ejemplo de consumo:

```bash
amqp-consume -u "amqp://admin:1234@host.docker.internal:5672/entorno_amqp" -q hello -d cat
```

Ejemplo de publicacion:

```bash
amqp-publish -u "amqp://admin:1234@host.docker.internal:5672/entorno_amqp" -r hello -b "Hola Mundo"
```

## Script `tarea3.py`

El script abre conexiones contra RabbitMQ, genera trafico AMQP malformado, mide respuestas del servicio y calcula metricas de latencia y throughput.

Ejecucion recomendada:

```bash
python .\tarea3.py
```

Si tu entorno requiere privilegios elevados, ejecutalo como administrador.

### Salidas

- `resultados_analisis.txt`: registro completo de las pruebas.
- `metricas_throughput.png`: grafico comparando las metricas calculadas.

## Notas

- El flujo principal de este repositorio es el que usan `server/Dockerfile`, `client/Dockerfile` y `tarea3.py`.