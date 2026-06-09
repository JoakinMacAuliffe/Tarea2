# Tarea2
Tarea 2, Taller de Redes y Servicios

# Server

Crear contenedor

docker build -t amqp_server .

Iniciar contenedor

docker run -it --rm --name rabbit_server -p 5672:5672 -p 15672:15672 amqp_server

# Client

Crear contenedor

docker build -t amqp_client .

Entrar en terminal del contenedor

docker run -it --rm --network host amqp_client