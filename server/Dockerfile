FROM ubuntu:22.04

# Evita interacciones durante instalación
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update -y && apt-get install curl gnupg apt-transport-https -y

## Team RabbitMQ's signing key
RUN curl -1sLf "https://keys.openpgp.org/vks/v1/by-fingerprint/0A9AF2115F4687BD29803A206B73A36E6026DFCA" | gpg --dearmor | tee /usr/share/keyrings/com.rabbitmq.team.gpg > /dev/null

## Add apt repositories maintained by Team RabbitMQ
RUN tee /etc/apt/sources.list.d/rabbitmq.list <<EOF
## Modern Erlang/OTP releases
##
deb [arch=amd64 signed-by=/usr/share/keyrings/com.rabbitmq.team.gpg] https://deb1.rabbitmq.com/rabbitmq-erlang/ubuntu/jammy jammy main
deb [arch=amd64 signed-by=/usr/share/keyrings/com.rabbitmq.team.gpg] https://deb2.rabbitmq.com/rabbitmq-erlang/ubuntu/jammy jammy main

## Latest RabbitMQ releases
##
deb [arch=amd64 signed-by=/usr/share/keyrings/com.rabbitmq.team.gpg] https://deb1.rabbitmq.com/rabbitmq-server/ubuntu/jammy jammy main
deb [arch=amd64 signed-by=/usr/share/keyrings/com.rabbitmq.team.gpg] https://deb2.rabbitmq.com/rabbitmq-server/ubuntu/jammy jammy main
EOF

## Update package indices
RUN apt-get update -y

## Install Erlang packages
RUN apt-get install -y erlang-base \
                        erlang-asn1 erlang-crypto erlang-eldap erlang-ftp erlang-inets \
                        erlang-mnesia erlang-os-mon erlang-parsetools erlang-public-key \
                        erlang-runtime-tools erlang-snmp erlang-ssl \
                        erlang-syntax-tools erlang-tftp erlang-tools erlang-xmerl

## Install rabbitmq-server and its dependencies
RUN apt-get install rabbitmq-server -y --fix-missing

RUN rabbitmq-plugins enable rabbitmq_management

RUN mkdir -p /etc/rabbitmq && \
    echo "default_user = admin" >> /etc/rabbitmq/rabbitmq.conf && \
    echo "default_pass = 1234" >> /etc/rabbitmq/rabbitmq.conf && \
    echo "default_vhost = entorno_amqp" >> /etc/rabbitmq/rabbitmq.conf && \
    echo "deprecated_features.permit.transient_nonexcl_queues = true" >> /etc/rabbitmq/rabbitmq.conf

EXPOSE 5672 15672

CMD ["rabbitmq-server"]

