# Tarea 2 — Análisis de Tráfico AMQP con Scapy

Análisis de un servicio de mensajería **RabbitMQ** (protocolo AMQP 0-9-1) mediante interceptación, inyección y modificación de tráfico de red utilizando **Scapy**.

## Arquitectura

```
┌──────────────────┐         Puerto 5672          ┌──────────────────┐
│   Cliente AMQP   │◄──────────────────────────►  │  RabbitMQ Server │
│  (amqp-tools)    │     Protocolo AMQP 0-9-1     │  (Docker)        │
│  Docker          │                              │  Docker          │
└──────────────────┘                              └──────────────────┘
                              ▲
                              │ Interceptación
                              │ Inyección
                              │ Análisis
                      ┌───────┴────────┐
                      │ analisis_scapy │
                      │    (Scapy)     │
                      └────────────────┘
```

- **Servidor**: RabbitMQ ejecutándose en Docker, expuesto en `localhost:5672` (AMQP) y `localhost:15672` (Management UI).
- **Cliente**: Contenedor Docker con `amqp-tools` para publicar y consumir mensajes.
- **Script de análisis**: `analisis_scapy.py` — intercepta, inyecta y mide métricas del tráfico AMQP.

## Requisitos previos

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) instalado y en ejecución.
- Python 3 con Scapy instalado:
  ```bash
  pip install scapy
  ```
- [Npcap](https://npcap.com/) instalado (en Windows, necesario para que Scapy capture paquetes).
- [Wireshark](https://www.wireshark.org/) (opcional, para verificación visual).

---

## 1. Servidor RabbitMQ

### Construir la imagen

```bash
cd server
docker build -t amqp_server .
```

### Ejecutar el servidor

```bash
docker run -it --rm --name rabbit_server -p 5672:5672 -p 15672:15672 amqp_server
```

| Puerto | Servicio |
|--------|----------|
| 5672   | AMQP 0-9-1 (comunicación cliente-servidor) |
| 15672  | Management UI (interfaz web de administración) |

**Credenciales**: `admin` / `1234`
**Virtual Host**: `entorno_amqp`

---

## 2. Cliente AMQP

### Construir la imagen

```bash
cd client
docker build -t amqp_client .
```

### Ejecutar el cliente

Abrir **dos terminales** y en cada una ejecutar:

```bash
docker run -it --rm amqp_client
```

### Consumir mensajes (Terminal 1)

```bash
amqp-consume -u "amqp://admin:1234@host.docker.internal:5672/entorno_amqp" -q hello -d cat
```

### Publicar mensajes (Terminal 2)

```bash
amqp-publish -u "amqp://admin:1234@host.docker.internal:5672/entorno_amqp" -r hello -b "Hola Mundo"
```

---

## 3. Script de análisis con Scapy

El script `analisis_scapy.py` cumple los tres objetivos de la tarea a través de un menú interactivo.

### Ejecución

> **Requiere permisos de administrador** para capturar e inyectar paquetes.

```bash
sudo python analisis_scapy.py
```

### Menú de opciones

| Opción | Descripción |
|--------|-------------|
| 1 | Ejecutar TODO (Objetivos 1, 2 y 3 completos) |
| 2 | Objetivo 1: Interceptar, inyectar y modificar tráfico |
| 3 | Objetivo 2: Análisis de repercusiones |
| 4 | Objetivo 3: Métricas de red y cotas de desempeño |
| 5 | Solo captura de tráfico en vivo (15 segundos) |
| 6 | Solo inyecciones (sin captura) |
| 7 | Solo métricas de red |
| 8 | Análisis de archivos PCAP existentes |
| 0 | Salir |

### Objetivo 1 — Interceptar, inyectar y modificar tráfico

| Test | Qué hace |
|------|----------|
| Captura en vivo | Captura tráfico AMQP por 15s en la interfaz Loopback, decodifica frames (Method, Body, Heartbeat) y muestra contenido de mensajes. |
| Inyección 1 | Envía un Protocol-Header con versión inválida (`AMQP 9.9.9.9`) para observar la negociación del servidor. |
| Inyección 2 | Envía un frame Method con class/method inválidos (255/255) tras un handshake correcto. |
| Inyección 3 | Envía datos aleatorios (16 B a 1 KB) al puerto AMQP para probar robustez. |
| Inyección 4 | Craftea un paquete TCP completo con Scapy (SYN → handshake → payload AMQP malformado → RST). |

### Objetivo 2 — Análisis de repercusiones

| Test | Qué hace |
|------|----------|
| Flood de conexiones | Abre 50 conexiones TCP simultáneas y mide tiempos de conexión + estado del servicio post-flood. |
| Half-open connections | Crea 20 handshakes AMQP sin completar para evaluar degradación del servicio. |
| Payload sobredimensionado | Envía un frame de 64 KB para exceder el `frame_max` del servidor. |

### Objetivo 3 — Métricas de red y cotas de desempeño

| Métrica | Qué mide |
|---------|----------|
| Latencia TCP + AMQP | 20 muestras de tiempo de conexión TCP y handshake AMQP (promedio, mín, máx). |
| Throughput TCP | Tasa de transferencia enviando bloques de 1 KB a 64 KB (KB/s, Mbps). |
| ICMP Ping | Latencia base de red mediante Echo Request/Reply con Scapy. |
| Parámetros TCP | Window Size, MSS, Window Scale extraídos del SYN-ACK del servidor. |
| Fragmentación IP | Comportamiento del servidor ante paquetes IP fragmentados. |
| Análisis PCAP | Parseo de `input.pcapng` y `output.pcapng` con estadísticas de métodos AMQP. |

### Archivos de salida

| Archivo | Contenido |
|---------|-----------|
| `resultados_analisis.txt` | Log completo con timestamps de todas las pruebas ejecutadas. |
| `captura_amqp.pcapng` | Captura de paquetes AMQP (generada por la opción 5). |

---

## 4. Verificación con Wireshark

Para verificar visualmente el funcionamiento del script:

1. Abrir **Wireshark como administrador**.
2. Seleccionar la interfaz **Npcap Loopback Adapter**.
3. Aplicar el filtro de captura:
   ```
   tcp port 5672
   ```
4. Ejecutar el script en otra terminal.

### Filtros útiles

| Filtro | Qué muestra |
|--------|-------------|
| `amqp` | Solo tráfico AMQP decodificado |
| `tcp.port == 5672` | Todo el tráfico al puerto RabbitMQ |
| `tcp.flags.syn == 1 && tcp.port == 5672` | Nuevas conexiones (SYN) |
| `tcp.flags.reset == 1 && tcp.port == 5672` | Conexiones cortadas (RST) |
| `tcp.port == 5672 && tcp.len > 0` | Solo paquetes con payload |
| `icmp` | Pings del Objetivo 3 |
| `ip.flags.mf == 1` | Paquetes IP fragmentados |

> **Tip**: Clic derecho en un paquete → **Follow → TCP Stream** para ver el intercambio completo de cada inyección.

---

## Estructura del proyecto

```
Tarea2/
├── server/
│   └── Dockerfile          # Imagen Docker de RabbitMQ
├── client/
│   └── Dockerfile          # Imagen Docker con amqp-tools
├── analisis_scapy.py       # Script principal de análisis con Scapy
├── input.pcapng            # Captura de tráfico AMQP (entrada)
├── output.pcapng           # Captura de tráfico AMQP (salida)
├── resultados_analisis.txt # Resultados generados por el script
├── captura_amqp.pcapng     # Captura generada por la opción 5
└── README.md
```