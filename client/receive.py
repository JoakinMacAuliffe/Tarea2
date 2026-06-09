import pika, sys, os

def main():
    credenciales = pika.PlainCredentials('admin', '1234')
    parametros = pika.ConnectionParameters(
        host='host.docker.internal', 
        virtual_host='entorno_amqp', 
        credentials=credenciales
    )

    connection = pika.BlockingConnection(parametros)
    channel = connection.channel()

    channel.queue_declare(queue='hello', durable=True)

    def callback(ch, method, properties, body):
        print(f" [x] Recibido: {body.decode()}")

    channel.basic_consume(queue='hello',
                          auto_ack=True,
                          on_message_callback=callback)

    print(' [*] Esperando mensajes. Presiona CTRL+C para salir')
    channel.start_consuming()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('Interrumpido')
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)