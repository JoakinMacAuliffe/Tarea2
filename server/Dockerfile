# 1. Usar la imagen base oficial que incluye la interfaz de administración web
FROM rabbitmq:3-management

# 2. Copiar archivo de configuración personalizado al contenedor
COPY rabbitmq.conf /etc/rabbitmq/rabbitmq.conf

# 3. Exponer los puertos: 
# 5672 es para el tráfico AMQP (tu script en Python)
# 15672 es para la interfaz web (Management UI)
EXPOSE 5672 15672

# 4. Indicar que el contenedor inicie ejecutando el servidor (RabbitMQ ya lo hace por defecto, 
# pero es buena práctica declararlo si la pauta lo pide).
CMD ["rabbitmq-server"]