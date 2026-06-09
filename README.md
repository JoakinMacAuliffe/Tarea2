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
docker run -it --rm --network host amqp_client
```

3. En una terminal ejecutar el receptor (receiver.py) y en la otra el emisor (send.py)

```bash
python receive.py
```
```bash
python send.py
```