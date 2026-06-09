# Servidor

1. Construir contenedor

```bash
docker build -t amqp_server .
```

2. Ejecutar servidor RabbitMQ

```bash
docker run -it --rm --name rabbit_server -p 5672:5672 -p 15672:15672 amqp_server
```

# Cliente

1. Construir contenedor

```bash
docker build -t amqp_client .
```

2. Crear dos terminales y entrar a la terminal del contenedor en ambas terminales

```bash
docker run -it --rm amqp_client
```

3. Mediante amqp-tools, en una terminal generar el receptor y en la otra enviar un mensaje.

```bash
amqp-consume -u "amqp://admin:1234@host.docker.internal:5672/entorno_amqp" -q hello -d cat
```
```bash
amqp-publish -u "amqp://admin:1234@host.docker.internal:5672/entorno_amqp" -r hello -b "Hola Mundo"
```