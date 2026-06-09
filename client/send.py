import pika

# 1. Configurar las credenciales y el Virtual Host de tu servidor
credenciales = pika.PlainCredentials('admin', '1234')
parametros = pika.ConnectionParameters(
    host='host.docker.internal', 
    virtual_host='entorno_amqp', 
    credentials=credenciales
)

# 2. Establecer conexión
connection = pika.BlockingConnection(parametros)
channel = connection.channel()

# 3. Declarar la cola (durable=True para evitar el error de RabbitMQ 4.x)
channel.queue_declare(queue='hello', durable=True)

# 4. Enviar el mensaje
channel.basic_publish(exchange='',
                      routing_key='hello',
                      body='¡Mensaje desde el contenedor Cliente!')
print(" [x] Sent '¡Mensaje desde el contenedor Cliente!'")

connection.close()