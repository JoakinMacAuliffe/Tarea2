#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 Tarea 2 - Análisis de Tráfico AMQP con Scapy
=============================================================================
 Servicio analizado: RabbitMQ (protocolo AMQP 0-9-1)
 Puerto: 5672
 Servidor: Docker en localhost (127.0.0.1)
 Credenciales: admin / 1234 | vhost: entorno_amqp

 Objetivos:
   1. Interceptar e inyectar/modificar tráfico AMQP (cliente/servidor)
   2. Analizar repercusiones del tráfico inyectado sobre el servicio
   3. Identificar y modificar métricas de red (cotas de desempeño)
=============================================================================
"""

import sys
import time
import struct
import socket
import random
import os
from datetime import datetime
from collections import defaultdict

import subprocess
import csv
try:
    import matplotlib.pyplot as plt
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False
# ── Importación de Scapy ────────────────────────────────────────────────────
try:
    from scapy.all import (
        IP, TCP, UDP, ICMP, Raw, Ether,
        sniff, send, sr1, sr, sendp, RandShort,
        conf, get_if_list, get_if_addr, wrpcap, rdpcap,
        fragment, TCPSession
    )
except ImportError:
    print("[ERROR] Scapy no está instalado. Instálalo con: pip install scapy")
    sys.exit(1)

# ── Configuración Global ────────────────────────────────────────────────────
AMQP_PORT       = 5672
SERVER_IP       = "127.0.0.1"
INTERFACE       = "\\Device\\NPF_Loopback"  # Loopback para Docker en localhost
CAPTURE_FILE    = "captura_amqp.pcapng"
RESULTS_FILE    = "resultados_analisis.txt"

# Constantes del protocolo AMQP 0-9-1
AMQP_PROTOCOL_HEADER = b'AMQP\x00\x00\x09\x01'
AMQP_FRAME_METHOD    = 1
AMQP_FRAME_HEADER    = 2
AMQP_FRAME_BODY      = 3
AMQP_FRAME_HEARTBEAT = 8
AMQP_FRAME_END       = 0xCE

# Clases y métodos AMQP relevantes
AMQP_CLASS_CONNECTION = 10
AMQP_CLASS_CHANNEL    = 20
AMQP_CLASS_BASIC      = 60
AMQP_CLASS_QUEUE      = 50

AMQP_METHOD_NAMES = {
    (10, 10): "Connection.Start",
    (10, 11): "Connection.Start-OK",
    (10, 30): "Connection.Tune",
    (10, 31): "Connection.Tune-OK",
    (10, 40): "Connection.Open",
    (10, 41): "Connection.Open-OK",
    (10, 50): "Connection.Close",
    (10, 51): "Connection.Close-OK",
    (20, 10): "Channel.Open",
    (20, 11): "Channel.Open-OK",
    (20, 40): "Channel.Close",
    (20, 41): "Channel.Close-OK",
    (50, 10): "Queue.Declare",
    (50, 11): "Queue.Declare-OK",
    (60, 20): "Basic.Consume",
    (60, 21): "Basic.Consume-OK",
    (60, 40): "Basic.Publish",
    (60, 60): "Basic.Deliver",
    (60, 70): "Basic.Get",
    (60, 71): "Basic.Get-OK",
    (60, 80): "Basic.Ack",
}

# ── Almacenamiento de resultados ────────────────────────────────────────────
resultados = []

def log(msg, seccion=None):
    """Registra un mensaje en consola y en la lista de resultados."""
    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    if seccion:
        linea = f"[{timestamp}] [{seccion}] {msg}"
    else:
        linea = f"[{timestamp}] {msg}"
    print(linea)
    resultados.append(linea)


def guardar_resultados():
    """Guarda todos los resultados en un archivo de texto."""
    ruta = os.path.join(os.path.dirname(os.path.abspath(__file__)), RESULTS_FILE)
    with open(ruta, "w", encoding="utf-8") as f:
        f.write("=" * 80 + "\n")
        f.write(" RESULTADOS - Análisis de Tráfico AMQP con Scapy\n")
        f.write(f" Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f" Servidor: {SERVER_IP}:{AMQP_PORT}\n")
        f.write("=" * 80 + "\n\n")
        for linea in resultados:
            f.write(linea + "\n")
    log(f"Resultados guardados en: {ruta}")


# =============================================================================
#  UTILIDADES DE PARSEO AMQP
# =============================================================================

def parsear_frame_amqp(payload):
    """
    Parsea un frame AMQP 0-9-1 a partir del payload TCP.
    Retorna una lista de diccionarios con la info de cada frame encontrado.
    """
    frames = []
    offset = 0

    # Detectar si es el header del protocolo AMQP
    if payload[:4] == b'AMQP':
        frames.append({
            "tipo": "Protocol-Header",
            "descripcion": f"AMQP {payload[4]}.{payload[5]}.{payload[6]}.{payload[7]}"
                           if len(payload) >= 8 else "AMQP (incompleto)"
        })
        return frames

    while offset + 7 <= len(payload):
        try:
            frame_type = payload[offset]
            channel = struct.unpack("!H", payload[offset+1:offset+3])[0]
            size = struct.unpack("!I", payload[offset+3:offset+7])[0]

            if offset + 7 + size + 1 > len(payload):
                break  # Frame incompleto

            frame_end = payload[offset + 7 + size]
            if frame_end != AMQP_FRAME_END:
                break  # Frame corrupto

            frame_data = payload[offset+7:offset+7+size]

            frame_info = {
                "tipo_num": frame_type,
                "channel": channel,
                "size": size,
            }

            if frame_type == AMQP_FRAME_METHOD and size >= 4:
                class_id = struct.unpack("!H", frame_data[0:2])[0]
                method_id = struct.unpack("!H", frame_data[2:4])[0]
                nombre = AMQP_METHOD_NAMES.get(
                    (class_id, method_id),
                    f"Class={class_id} Method={method_id}"
                )
                frame_info["tipo"] = "Method"
                frame_info["descripcion"] = nombre
                frame_info["class_id"] = class_id
                frame_info["method_id"] = method_id
            elif frame_type == AMQP_FRAME_HEADER:
                frame_info["tipo"] = "Content-Header"
                frame_info["descripcion"] = "Header de contenido"
            elif frame_type == AMQP_FRAME_BODY:
                frame_info["tipo"] = "Content-Body"
                frame_info["descripcion"] = f"Body ({size} bytes)"
                frame_info["body"] = frame_data
            elif frame_type == AMQP_FRAME_HEARTBEAT:
                frame_info["tipo"] = "Heartbeat"
                frame_info["descripcion"] = "Heartbeat"
            else:
                frame_info["tipo"] = f"Desconocido({frame_type})"
                frame_info["descripcion"] = f"Frame tipo {frame_type}"

            frames.append(frame_info)
            offset += 7 + size + 1

        except (struct.error, IndexError):
            break

    return frames


# =============================================================================
#  OBJETIVO 1: INTERCEPTAR, INYECTAR Y MODIFICAR TRÁFICO AMQP
# =============================================================================

def objetivo1_captura_trafico(duracion=15):
    """
    Captura tráfico AMQP en tiempo real, decodifica los frames del protocolo
    y almacena los paquetes para análisis posterior.
    """
    log("=" * 70)
    log("OBJETIVO 1: Interceptar e inyectar/modificar tráfico AMQP", "OBJ1")
    log("=" * 70)
    log(f"Capturando tráfico AMQP en puerto {AMQP_PORT} por {duracion}s...", "CAPTURA")

    paquetes_capturados = []
    estadisticas = defaultdict(int)

    def procesar_paquete(pkt):
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport

            if AMQP_PORT in (src_port, dst_port):
                payload = bytes(pkt[Raw].load)
                direccion = "S→C" if src_port == AMQP_PORT else "C→S"
                ip_src = pkt[IP].src if pkt.haslayer(IP) else "?"
                ip_dst = pkt[IP].dst if pkt.haslayer(IP) else "?"

                frames = parsear_frame_amqp(payload)
                for frame in frames:
                    desc = frame.get("descripcion", "desconocido")
                    tipo = frame.get("tipo", "?")
                    log(f"  [{direccion}] {ip_src}→{ip_dst} | "
                        f"Tipo: {tipo} | {desc}", "CAPTURA")
                    estadisticas[tipo] += 1

                    # Si es un body, mostrar contenido del mensaje
                    if "body" in frame:
                        try:
                            texto = frame["body"].decode("utf-8", errors="replace")
                            log(f"    └─ Contenido mensaje: \"{texto}\"", "CAPTURA")
                        except Exception:
                            log(f"    └─ Contenido binario: {frame['body'][:50]}...",
                                "CAPTURA")

                paquetes_capturados.append(pkt)

        elif pkt.haslayer(TCP):
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            if AMQP_PORT in (src_port, dst_port):
                flags = pkt[TCP].flags
                estadisticas[f"TCP-{str(flags)}"] += 1

    filtro = f"tcp port {AMQP_PORT}"
    log(f"Filtro BPF: '{filtro}'", "CAPTURA")
    log("Asegúrese de generar tráfico AMQP (publish/consume) durante la captura.",
        "CAPTURA")

    try:
        sniff(
            filter=filtro,
            prn=procesar_paquete,
            timeout=duracion,
            store=0,
            iface=INTERFACE
        )
    except PermissionError:
        log("ERROR: Se requieren permisos de administrador para capturar.", "CAPTURA")
        log("Ejecute: sudo python analisis_scapy.py", "CAPTURA")
        return [], {}
    except Exception as e:
        log(f"Error durante captura: {e}", "CAPTURA")

    log(f"\nResumen de captura ({duracion}s):", "CAPTURA")
    log(f"  Total paquetes AMQP con payload: {len(paquetes_capturados)}", "CAPTURA")
    for tipo, cantidad in sorted(estadisticas.items()):
        log(f"  {tipo}: {cantidad}", "CAPTURA")

    if paquetes_capturados:
        ruta_pcap = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), CAPTURE_FILE
        )
        wrpcap(ruta_pcap, paquetes_capturados)
        log(f"  Captura guardada en: {ruta_pcap}", "CAPTURA")

    return paquetes_capturados, dict(estadisticas)


def objetivo1_inyeccion_amqp_header_invalido():
    """
    Inyecta un Protocol-Header AMQP con versión inválida para observar
    cómo reacciona el servidor ante una negociación de protocolo incorrecta.
    """
    log("\n" + "-" * 70)
    log("INYECCIÓN 1: Protocol-Header AMQP con versión inválida", "INYECCIÓN")
    log("-" * 70)
    log("Enviando header AMQP con versión falsa (9.9.9) al servidor...", "INYECCIÓN")

    # Header AMQP con versión inválida (debería ser 0.0.9.1)
    header_falso = b'AMQP\x09\x09\x09\x09'

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((SERVER_IP, AMQP_PORT))
        log(f"  Conexión TCP establecida con {SERVER_IP}:{AMQP_PORT}", "INYECCIÓN")

        sock.send(header_falso)
        log(f"  Enviado header falso: {header_falso.hex()}", "INYECCIÓN")

        try:
            respuesta = sock.recv(4096)
            log(f"  Respuesta del servidor ({len(respuesta)} bytes): "
                f"{respuesta[:50].hex()}", "INYECCIÓN")

            if respuesta[:4] == b'AMQP':
                log(f"  → El servidor responde con su versión soportada: "
                    f"AMQP {respuesta[4]}.{respuesta[5]}.{respuesta[6]}.{respuesta[7]}",
                    "INYECCIÓN")
                log("  → ANÁLISIS: El servidor rechaza la versión y responde con "
                    "la versión correcta que soporta (mecanismo de negociación).",
                    "INYECCIÓN")
            else:
                log("  → El servidor envió una respuesta inesperada.", "INYECCIÓN")
        except socket.timeout:
            log("  → El servidor no respondió (timeout). "
                "Posible cierre silencioso de conexión.", "INYECCIÓN")

        sock.close()
        log("  Conexión cerrada.", "INYECCIÓN")

    except ConnectionRefusedError:
        log("  ERROR: Conexión rechazada. ¿Está el servidor RabbitMQ ejecutándose?",
            "INYECCIÓN")
    except Exception as e:
        log(f"  ERROR: {e}", "INYECCIÓN")


def objetivo1_inyeccion_frame_malformado():
    """
    Envía un frame AMQP malformado (class_id/method_id inválidos)
    después de una negociación correcta del protocolo.
    """
    log("\n" + "-" * 70)
    log("INYECCIÓN 2: Frame AMQP Method malformado", "INYECCIÓN")
    log("-" * 70)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((SERVER_IP, AMQP_PORT))

        # 1. Enviar el header correcto para iniciar la negociación
        sock.send(AMQP_PROTOCOL_HEADER)
        log("  Enviado Protocol-Header correcto (AMQP 0.0.9.1)", "INYECCIÓN")

        respuesta = sock.recv(4096)
        frames = parsear_frame_amqp(respuesta)
        for f in frames:
            log(f"  ← Recibido: {f.get('descripcion', 'desconocido')}", "INYECCIÓN")

        # 2. Enviar un frame Method con class_id y method_id inválidos
        class_id_invalido = 255   # No existe esta clase en AMQP
        method_id_invalido = 255
        frame_payload = struct.pack("!HH", class_id_invalido, method_id_invalido)
        frame_payload += b'\x00' * 10  # Datos basura adicionales

        frame = struct.pack("!BHI", AMQP_FRAME_METHOD, 0, len(frame_payload))
        frame += frame_payload
        frame += bytes([AMQP_FRAME_END])

        sock.send(frame)
        log(f"  Enviado frame malformado: class={class_id_invalido}, "
            f"method={method_id_invalido}", "INYECCIÓN")

        try:
            respuesta2 = sock.recv(4096)
            frames2 = parsear_frame_amqp(respuesta2)
            for f in frames2:
                log(f"  ← Respuesta: {f.get('descripcion', 'desconocido')}",
                    "INYECCIÓN")

            if any("Close" in f.get("descripcion", "") for f in frames2):
                log("  → ANÁLISIS: El servidor detecta el frame inválido y cierra "
                    "la conexión con Connection.Close (comportamiento esperado).",
                    "INYECCIÓN")
            else:
                log(f"  → ANÁLISIS: Respuesta inesperada del servidor: "
                    f"{respuesta2[:80].hex()}", "INYECCIÓN")

        except socket.timeout:
            log("  → El servidor cerró la conexión sin responder.", "INYECCIÓN")

        sock.close()

    except ConnectionRefusedError:
        log("  ERROR: Conexión rechazada. ¿Está el servidor ejecutándose?",
            "INYECCIÓN")
    except Exception as e:
        log(f"  ERROR: {e}", "INYECCIÓN")


def objetivo1_inyeccion_datos_aleatorios():
    """
    Inyecta datos completamente aleatorios al puerto AMQP para probar
    la robustez del servidor ante tráfico basura.
    """
    log("\n" + "-" * 70)
    log("INYECCIÓN 3: Datos aleatorios (garbage data) al puerto AMQP", "INYECCIÓN")
    log("-" * 70)

    tamaños = [16, 64, 256, 1024]
    for tam in tamaños:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((SERVER_IP, AMQP_PORT))

            datos = bytes(random.randint(0, 255) for _ in range(tam))
            sock.send(datos)
            log(f"  Enviado {tam} bytes aleatorios: {datos[:20].hex()}...",
                "INYECCIÓN")

            try:
                resp = sock.recv(4096)
                if resp[:4] == b'AMQP':
                    log(f"  ← Servidor responde con Protocol-Header AMQP "
                        f"(sugiere reconexión con versión correcta)", "INYECCIÓN")
                else:
                    log(f"  ← Respuesta: {resp[:40].hex()}", "INYECCIÓN")
            except socket.timeout:
                log("  ← Sin respuesta (timeout/cierre)", "INYECCIÓN")

            sock.close()
        except ConnectionRefusedError:
            log(f"  ERROR: Conexión rechazada para {tam} bytes.", "INYECCIÓN")
            break
        except Exception as e:
            log(f"  ERROR ({tam} bytes): {e}", "INYECCIÓN")

    log("  → ANÁLISIS: El servidor RabbitMQ descarta datos que no coinciden con "
        "el handshake AMQP esperado. En algunos casos responde con el "
        "Protocol-Header correcto, invitando al cliente a reiniciar.", "INYECCIÓN")


def objetivo1_inyeccion_paquete_scapy():
    """
    Usa Scapy directamente para craftear y enviar paquetes TCP con
    payload AMQP modificado al servidor.
    """
    log("\n" + "-" * 70)
    log("INYECCIÓN 4: Paquete TCP crafteado con Scapy (SYN + payload AMQP)",
        "INYECCIÓN")
    log("-" * 70)

    # Enviar SYN al puerto AMQP
    ip = IP(dst=SERVER_IP)
    syn = TCP(sport=RandShort(), dport=AMQP_PORT, flags="S")
    log(f"  Enviando SYN a {SERVER_IP}:{AMQP_PORT}...", "INYECCIÓN")

    resp_syn = sr1(ip / syn, timeout=3, verbose=0)
    if resp_syn and resp_syn.haslayer(TCP):
        flags = resp_syn[TCP].flags
        log(f"  ← Respuesta TCP flags: {flags}", "INYECCIÓN")

        if "SA" in str(flags):
            log("  → SYN-ACK recibido: puerto abierto y servicio activo.", "INYECCIÓN")

            # Completar handshake y enviar datos
            ack = TCP(
                sport=syn.sport,
                dport=AMQP_PORT,
                flags="A",
                seq=resp_syn[TCP].ack,
                ack=resp_syn[TCP].seq + 1
            )
            send(ip / ack, verbose=0)
            log("  → ACK enviado, handshake completo.", "INYECCIÓN")

            # Enviar payload AMQP malformado
            payload_falso = b'AMQP\x00\x00\x09\x01'  # Header válido
            payload_falso += struct.pack("!BHI", 1, 0, 4)  # Frame Method
            payload_falso += struct.pack("!HH", 999, 999)   # Class/Method inválidos
            payload_falso += bytes([AMQP_FRAME_END])

            push = TCP(
                sport=syn.sport,
                dport=AMQP_PORT,
                flags="PA",
                seq=resp_syn[TCP].ack,
                ack=resp_syn[TCP].seq + 1
            )
            send(ip / push / Raw(load=payload_falso), verbose=0)
            log(f"  → Payload AMQP malformado enviado ({len(payload_falso)} bytes)",
                "INYECCIÓN")

            # Enviar RST para cerrar
            rst = TCP(
                sport=syn.sport,
                dport=AMQP_PORT,
                flags="R",
                seq=resp_syn[TCP].ack + len(payload_falso),
                ack=resp_syn[TCP].seq + 1
            )
            send(ip / rst, verbose=0)
            log("  → RST enviado para cerrar conexión.", "INYECCIÓN")
        elif "RA" in str(flags):
            log("  → RST-ACK recibido: puerto cerrado.", "INYECCIÓN")
    else:
        log("  → Sin respuesta al SYN (filtrado o servidor no accesible).",
            "INYECCIÓN")

    log("  → ANÁLISIS: Se verifica que se puede completar el handshake TCP y "
        "enviar payloads AMQP crafteados. El servidor procesa el header y "
        "descarta el frame inválido.", "INYECCIÓN")


# =============================================================================
#  OBJETIVO 2: ANALIZAR REPERCUSIONES DEL TRÁFICO INYECTADO
# =============================================================================


def objetivo1_fuzzing_payload():
    '''
    Inyección Fuzzing 1: Envía frames AMQP válidos pero con payloads generados
    aleatoriamente para evaluar cómo reacciona el parser del servidor.
    '''
    log('\n' + '-' * 70)
    log('INYECCIÓN FUZZING 1: Fuzzing de Payload/Body AMQP', 'INYECCIÓN')
    log('-' * 70)
    for tam in [100, 500, 1000]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((SERVER_IP, AMQP_PORT))
            sock.send(AMQP_PROTOCOL_HEADER)
            resp = sock.recv(4096)
            
            fuzz_payload = bytes(random.randint(0, 255) for _ in range(tam))
            frame = struct.pack('!BHI', AMQP_FRAME_BODY, 1, len(fuzz_payload)) + fuzz_payload + bytes([AMQP_FRAME_END])
            sock.send(frame)
            log(f'  Enviado frame fuzzeado con {tam} bytes de payload.', 'INYECCIÓN')
            try:
                resp2 = sock.recv(4096)
                log(f'  ← Respuesta: {resp2[:40].hex()}', 'INYECCIÓN')
            except socket.timeout:
                log('  ← Sin respuesta tras inyección (posible cierre de conexión).', 'INYECCIÓN')
            sock.close()
        except Exception as e:
            log(f'  ERROR: {e}', 'INYECCIÓN')
    log('  → ANÁLISIS: Se espera que el servidor RabbitMQ cierre la conexión al recibir frames de Body sin métodos declarados o con datos inválidos.', 'INYECCIÓN')

def objetivo1_fuzzing_campos():
    '''
    Inyección Fuzzing 2: Envía frames Method con Class ID y Method ID
    aleatorios en un bucle para buscar comportamientos anómalos.
    '''
    log('\n' + '-' * 70)
    log('INYECCIÓN FUZZING 2: Fuzzing de Campos AMQP (Class/Method IDs)', 'INYECCIÓN')
    log('-' * 70)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((SERVER_IP, AMQP_PORT))
        sock.send(AMQP_PROTOCOL_HEADER)
        resp = sock.recv(4096)
        
        for _ in range(5):
            c_id = random.randint(0, 200)
            m_id = random.randint(0, 200)
            payload = struct.pack('!HH', c_id, m_id) + b'\x00\x00'
            frame = struct.pack('!BHI', AMQP_FRAME_METHOD, 0, len(payload)) + payload + bytes([AMQP_FRAME_END])
            sock.send(frame)
            log(f'  Enviado Method frame con Class={c_id} Method={m_id}.', 'INYECCIÓN')
            try:
                resp2 = sock.recv(4096)
                if b'Connection.Close' in resp2 or resp2:
                    log('  ← Servidor respondió (probablemente Connection.Close).', 'INYECCIÓN')
                    break
            except socket.timeout:
                pass
        sock.close()
    except Exception as e:
        log(f'  ERROR: {e}', 'INYECCIÓN')
    log('  → ANÁLISIS: Combinaciones no válidas de Class/Method causan un error de protocolo (Connection.Close) por parte del servidor.', 'INYECCIÓN')

def objetivo1_inyeccion_channel_invalido():
    '''
    Modificación 3: Enviar frame con un Channel ID no válido (ej. 9999).
    '''
    log('\n' + '-' * 70)
    log('INYECCIÓN MODIFICADA 3: Channel ID Inválido', 'INYECCIÓN')
    log('-' * 70)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((SERVER_IP, AMQP_PORT))
        sock.send(AMQP_PROTOCOL_HEADER)
        resp = sock.recv(4096)
        
        payload = struct.pack('!HH', 20, 10) + b'\x00'
        frame = struct.pack('!BHI', AMQP_FRAME_METHOD, 9999, len(payload)) + payload + bytes([AMQP_FRAME_END])
        sock.send(frame)
        log('  Enviado Channel.Open en canal 9999.', 'INYECCIÓN')
        
        try:
            resp2 = sock.recv(4096)
            log(f'  ← Respuesta: {resp2[:60].hex()}', 'INYECCIÓN')
        except socket.timeout:
            log('  ← Sin respuesta (cierre abrupto).', 'INYECCIÓN')
        sock.close()
    except Exception as e:
        log(f'  ERROR: {e}', 'INYECCIÓN')
    log('  → ANÁLISIS: Se espera un error de canal (Channel Error) o de conexión (Connection Error) al intentar usar un ID de canal fuera del rango negociado o muy alto.', 'INYECCIÓN')


def objetivo2_impacto_flood_conexiones():
    """
    Abre múltiples conexiones TCP simultáneas al servidor AMQP para medir
    el impacto en la capacidad del servicio (Connection Flood).
    """
    log("\n" + "=" * 70)
    log("OBJETIVO 2: Análisis de repercusiones del tráfico inyectado", "OBJ2")
    log("=" * 70)
    log("\n" + "-" * 70)
    log("TEST 1: Flood de conexiones TCP al servicio AMQP", "IMPACTO")
    log("-" * 70)

    num_conexiones = 50
    conexiones_exitosas = 0
    conexiones_fallidas = 0
    tiempos = []
    sockets_abiertos = []

    for i in range(num_conexiones):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            inicio = time.time()
            sock.connect((SERVER_IP, AMQP_PORT))
            fin = time.time()
            tiempos.append((fin - inicio) * 1000)  # ms
            sockets_abiertos.append(sock)
            conexiones_exitosas += 1
        except (ConnectionRefusedError, socket.timeout, OSError) as e:
            conexiones_fallidas += 1
            if conexiones_fallidas == 1:
                log(f"  Primera conexión fallida en intento #{i+1}: {e}", "IMPACTO")

    log(f"  Conexiones intentadas: {num_conexiones}", "IMPACTO")
    log(f"  Conexiones exitosas:   {conexiones_exitosas}", "IMPACTO")
    log(f"  Conexiones fallidas:   {conexiones_fallidas}", "IMPACTO")
    if tiempos:
        log(f"  Tiempo promedio conexión: {sum(tiempos)/len(tiempos):.2f} ms",
            "IMPACTO")
        log(f"  Tiempo mínimo: {min(tiempos):.2f} ms", "IMPACTO")
        log(f"  Tiempo máximo: {max(tiempos):.2f} ms", "IMPACTO")

    # Verificar si el servicio sigue respondiendo correctamente
    log("  Verificando estado del servicio tras el flood...", "IMPACTO")
    try:
        test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test_sock.settimeout(5)
        inicio = time.time()
        test_sock.connect((SERVER_IP, AMQP_PORT))
        test_sock.send(AMQP_PROTOCOL_HEADER)
        resp = test_sock.recv(4096)
        fin = time.time()
        test_sock.close()

        if resp:
            frames = parsear_frame_amqp(resp)
            for f in frames:
                log(f"  ← Servicio responde: {f.get('descripcion', '?')}",
                    "IMPACTO")
            log(f"  Tiempo de respuesta post-flood: "
                f"{(fin - inicio) * 1000:.2f} ms", "IMPACTO")
            log("  → ANÁLISIS: El servicio sigue operativo tras el flood. "
                "RabbitMQ maneja bien las conexiones múltiples.", "IMPACTO")
    except Exception as e:
        log(f"  → ANÁLISIS: El servicio NO responde tras el flood: {e}", "IMPACTO")
        log("  → Esto indica degradación del servicio por exceso de conexiones.",
            "IMPACTO")

    # Cerrar todas las conexiones
    for s in sockets_abiertos:
        try:
            s.close()
        except Exception:
            pass


def objetivo2_impacto_handshake_incompleto():
    """
    Inicia handshakes AMQP pero los deja incompletos (half-open) para
    medir el impacto de conexiones abandonadas.
    """
    log("\n" + "-" * 70)
    log("TEST 2: Handshakes AMQP incompletos (half-open)", "IMPACTO")
    log("-" * 70)

    num_intentos = 20
    sockets_abiertos = []

    for i in range(num_intentos):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((SERVER_IP, AMQP_PORT))

            # Enviar header AMQP válido pero NO responder al Connection.Start
            sock.send(AMQP_PROTOCOL_HEADER)
            resp = sock.recv(4096)
            # Deliberadamente NO respondemos Connection.Start-OK
            sockets_abiertos.append(sock)
        except Exception as e:
            if i == 0:
                log(f"  Error en primer intento: {e}", "IMPACTO")
            break

    log(f"  Conexiones half-open creadas: {len(sockets_abiertos)}", "IMPACTO")

    # Esperar un momento y verificar el servicio
    time.sleep(2)

    try:
        test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test_sock.settimeout(5)
        inicio = time.time()
        test_sock.connect((SERVER_IP, AMQP_PORT))
        test_sock.send(AMQP_PROTOCOL_HEADER)
        resp = test_sock.recv(4096)
        fin = time.time()
        test_sock.close()

        if resp:
            log(f"  Servicio respondió en {(fin-inicio)*1000:.2f} ms "
                f"con {len(sockets_abiertos)} half-opens.", "IMPACTO")
            log("  → ANÁLISIS: RabbitMQ tiene timeouts para conexiones inactivas. "
                "Las half-open connections son eventualmente limpiadas.", "IMPACTO")
    except Exception as e:
        log(f"  → Servicio degradado: {e}", "IMPACTO")

    for s in sockets_abiertos:
        try:
            s.close()
        except Exception:
            pass


def objetivo2_impacto_payload_grande():
    """
    Envía un payload excesivamente grande para probar los límites del
    frame_max del servidor AMQP.
    """
    log("\n" + "-" * 70)
    log("TEST 3: Payload AMQP sobredimensionado", "IMPACTO")
    log("-" * 70)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((SERVER_IP, AMQP_PORT))
        sock.send(AMQP_PROTOCOL_HEADER)
        resp = sock.recv(4096)

        frames = parsear_frame_amqp(resp)
        for f in frames:
            log(f"  ← {f.get('descripcion', 'desconocido')}", "IMPACTO")

        # Enviar un frame con tamaño declarado enorme (1 MB)
        payload_grande = b'\x00' * (1024 * 64)  # 64 KB de datos nulos
        frame = struct.pack("!BHI", AMQP_FRAME_BODY, 0, len(payload_grande))
        frame += payload_grande
        frame += bytes([AMQP_FRAME_END])

        log(f"  Enviando frame body sobredimensionado: {len(frame)} bytes",
            "IMPACTO")
        sock.send(frame)

        try:
            resp2 = sock.recv(4096)
            frames2 = parsear_frame_amqp(resp2)
            for f in frames2:
                log(f"  ← Respuesta: {f.get('descripcion', 'desconocido')}",
                    "IMPACTO")
            if any("Close" in f.get("descripcion", "") for f in frames2):
                log("  → ANÁLISIS: Servidor cierra la conexión por frame "
                    "sobredimensionado (excede frame_max).", "IMPACTO")
        except socket.timeout:
            log("  → Servidor cerró la conexión silenciosamente.", "IMPACTO")

        sock.close()

    except Exception as e:
        log(f"  ERROR: {e}", "IMPACTO")

    log("  → ANÁLISIS: RabbitMQ impone un frame_max (por defecto 131072 bytes). "
        "Frames que excedan este límite causan cierre de conexión.", "IMPACTO")


# =============================================================================
#  OBJETIVO 3: MÉTRICAS DE RED Y COTAS DE DESEMPEÑO
# =============================================================================

def objetivo3_latencia_servicio():
    """
    Mide la latencia del servicio AMQP realizando múltiples conexiones
    y handshakes completos, calculando estadísticas.
    """
    log("\n" + "=" * 70)
    log("OBJETIVO 3: Métricas de red y cotas de desempeño", "OBJ3")
    log("=" * 70)
    log("\n" + "-" * 70)
    log("MÉTRICA 1: Latencia del servicio AMQP (TCP + Protocol Handshake)", "MÉTRICA")
    log("-" * 70)

    num_muestras = 20
    latencias_tcp = []
    latencias_amqp = []

    for i in range(num_muestras):
        try:
            # Medir latencia TCP (solo connect)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            t0 = time.time()
            sock.connect((SERVER_IP, AMQP_PORT))
            t1 = time.time()
            latencias_tcp.append((t1 - t0) * 1000)

            # Medir latencia AMQP (enviar header, recibir Connection.Start)
            t2 = time.time()
            sock.send(AMQP_PROTOCOL_HEADER)
            resp = sock.recv(4096)
            t3 = time.time()
            latencias_amqp.append((t3 - t2) * 1000)

            sock.close()
            time.sleep(0.1)  # Pequeña pausa entre muestras
        except Exception as e:
            log(f"  Error en muestra {i+1}: {e}", "MÉTRICA")

    if latencias_tcp:
        prom_tcp = sum(latencias_tcp) / len(latencias_tcp)
        min_tcp = min(latencias_tcp)
        max_tcp = max(latencias_tcp)
        log(f"  Latencia TCP Connect ({len(latencias_tcp)} muestras):", "MÉTRICA")
        log(f"    Promedio: {prom_tcp:.2f} ms", "MÉTRICA")
        log(f"    Mínimo:   {min_tcp:.2f} ms", "MÉTRICA")
        log(f"    Máximo:   {max_tcp:.2f} ms", "MÉTRICA")

    if latencias_amqp:
        prom_amqp = sum(latencias_amqp) / len(latencias_amqp)
        min_amqp = min(latencias_amqp)
        max_amqp = max(latencias_amqp)
        log(f"  Latencia AMQP Handshake ({len(latencias_amqp)} muestras):",
            "MÉTRICA")
        log(f"    Promedio: {prom_amqp:.2f} ms", "MÉTRICA")
        log(f"    Mínimo:   {min_amqp:.2f} ms", "MÉTRICA")
        log(f"    Máximo:   {max_amqp:.2f} ms", "MÉTRICA")

    log("  → ANÁLISIS: La latencia TCP refleja el overhead de red, mientras que "
        "la latencia AMQP incluye procesamiento del servidor para generar "
        "Connection.Start.", "MÉTRICA")


def objetivo3_throughput_tcp():
    """
    Mide el throughput (rendimiento) del canal TCP hacia el servidor AMQP
    enviando bloques de datos y midiendo la tasa de transferencia.
    """
    log("\n" + "-" * 70)
    log("MÉTRICA 2: Throughput TCP al servicio AMQP", "MÉTRICA")
    log("-" * 70)

    tamaños_bloque = [1024, 4096, 16384, 65536]

    for tam in tamaños_bloque:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((SERVER_IP, AMQP_PORT))

            datos = bytes(random.randint(0, 255) for _ in range(tam))
            num_envios = 10
            total_bytes = 0

            inicio = time.time()
            for _ in range(num_envios):
                try:
                    enviados = sock.send(datos)
                    total_bytes += enviados
                except BrokenPipeError:
                    break
            fin = time.time()

            duracion = fin - inicio
            if duracion > 0:
                throughput_kbps = (total_bytes / 1024) / duracion
                throughput_mbps = (total_bytes * 8 / 1_000_000) / duracion
                log(f"  Bloque {tam} bytes × {num_envios}: "
                    f"{total_bytes} bytes en {duracion*1000:.1f} ms "
                    f"({throughput_kbps:.1f} KB/s, {throughput_mbps:.2f} Mbps)",
                    "MÉTRICA")

            sock.close()
        except Exception as e:
            log(f"  Error con bloque {tam}: {e}", "MÉTRICA")

    log("  → ANÁLISIS: El throughput se ve limitado por la ventana TCP y la "
        "respuesta del servidor al recibir datos inesperados.", "MÉTRICA")


def objetivo3_icmp_latencia():
    """
    Mide la latencia ICMP (ping) al servidor usando Scapy,
    como referencia de latencia de red base.
    """
    log("\n" + "-" * 70)
    log("MÉTRICA 3: Latencia ICMP (ping) al servidor", "MÉTRICA")
    log("-" * 70)

    latencias = []
    num_pings = 10

    for i in range(num_pings):
        pkt = IP(dst=SERVER_IP) / ICMP(seq=i)
        inicio = time.time()
        resp = sr1(pkt, timeout=2, verbose=0)
        fin = time.time()

        if resp:
            lat = (fin - inicio) * 1000
            latencias.append(lat)
        else:
            log(f"  Ping #{i+1}: Sin respuesta", "MÉTRICA")
        time.sleep(0.2)

    if latencias:
        log(f"  ICMP Ping ({len(latencias)}/{num_pings} respuestas):", "MÉTRICA")
        log(f"    Promedio: {sum(latencias)/len(latencias):.2f} ms", "MÉTRICA")
        log(f"    Mínimo:   {min(latencias):.2f} ms", "MÉTRICA")
        log(f"    Máximo:   {max(latencias):.2f} ms", "MÉTRICA")
    else:
        log("  No se recibieron respuestas ICMP (posible firewall).", "MÉTRICA")

    log("  → ANÁLISIS: La latencia ICMP es la línea base de red. La diferencia "
        "con la latencia AMQP indica el overhead del protocolo.", "MÉTRICA")


def objetivo3_tamano_ventana_tcp():
    """
    Analiza el tamaño de ventana TCP negociado con el servidor AMQP
    mediante un handshake SYN y observando el SYN-ACK.
    """
    log("\n" + "-" * 70)
    log("MÉTRICA 4: Parámetros TCP negociados con el servidor", "MÉTRICA")
    log("-" * 70)

    ip = IP(dst=SERVER_IP)
    syn = TCP(sport=RandShort(), dport=AMQP_PORT, flags="S",
              options=[("MSS", 1460), ("WScale", 7)])

    resp = sr1(ip / syn, timeout=3, verbose=0)
    if resp and resp.haslayer(TCP):
        tcp = resp[TCP]
        log(f"  Window Size (SYN-ACK):  {tcp.window}", "MÉTRICA")
        log(f"  Flags:                  {tcp.flags}", "MÉTRICA")

        # Parsear opciones TCP
        for opt_name, opt_val in tcp.options:
            log(f"  Opción TCP: {opt_name} = {opt_val}", "MÉTRICA")

        log(f"  Seq Number:             {tcp.seq}", "MÉTRICA")
        log(f"  Ack Number:             {tcp.ack}", "MÉTRICA")

        # Enviar RST para limpiar
        rst = TCP(sport=syn.sport, dport=AMQP_PORT, flags="R",
                  seq=tcp.ack, ack=tcp.seq + 1)
        send(ip / rst, verbose=0)

        log("  → ANÁLISIS: El tamaño de ventana TCP influye directamente en el "
            "throughput máximo. Window Scale permite ventanas mayores a 65535 bytes.",
            "MÉTRICA")
    else:
        log("  No se recibió SYN-ACK. Puerto cerrado o filtrado.", "MÉTRICA")


def objetivo3_fragmentacion():
    """
    Prueba el comportamiento del servicio ante paquetes IP fragmentados
    que transportan datos AMQP.
    """
    log("\n" + "-" * 70)
    log("MÉTRICA 5: Comportamiento ante fragmentación IP", "MÉTRICA")
    log("-" * 70)

    payload_amqp = AMQP_PROTOCOL_HEADER + (b'\x00' * 2000)

    # Crear paquete grande y fragmentar
    pkt = IP(dst=SERVER_IP) / TCP(dport=AMQP_PORT, flags="S") / Raw(load=payload_amqp)
    fragmentos = fragment(pkt, fragsize=500)

    log(f"  Payload original: {len(payload_amqp)} bytes", "MÉTRICA")
    log(f"  Fragmentos generados: {len(fragmentos)}", "MÉTRICA")

    for i, frag in enumerate(fragmentos):
        frag_offset = frag[IP].frag
        mf = "MF" if frag[IP].flags.MF else "Last"
        tam = len(frag[IP].payload)
        log(f"    Fragmento #{i+1}: offset={frag_offset}, "
            f"tamaño={tam}, flags={mf}", "MÉTRICA")

    # Enviar fragmentos
    for frag in fragmentos:
        send(frag, verbose=0)

    log("  Fragmentos enviados al servidor.", "MÉTRICA")
    log("  → ANÁLISIS: La fragmentación IP puede causar problemas de reensamblaje "
        "y afectar la latencia. Algunos firewalls bloquean fragmentos por seguridad.",
        "MÉTRICA")


def objetivo3_analisis_pcap_existente():
    """
    Analiza los archivos .pcapng existentes del proyecto para extraer
    métricas del tráfico AMQP previamente capturado.
    """
    log("\n" + "-" * 70)
    log("MÉTRICA 6: Análisis de capturas PCAP existentes", "MÉTRICA")
    log("-" * 70)

    archivos_pcap = ["input.pcapng", "output.pcapng"]
    base_dir = os.path.dirname(os.path.abspath(__file__))

    for archivo in archivos_pcap:
        ruta = os.path.join(base_dir, archivo)
        if not os.path.exists(ruta):
            log(f"  Archivo {archivo} no encontrado, omitiendo.", "MÉTRICA")
            continue

        log(f"\n  Analizando: {archivo}", "MÉTRICA")
        try:
            pkts = rdpcap(ruta)
            total = len(pkts)
            tcp_count = 0
            amqp_count = 0
            bytes_total = 0
            amqp_methods = defaultdict(int)
            ips_origen = set()
            ips_destino = set()

            for pkt in pkts:
                bytes_total += len(pkt)
                if pkt.haslayer(TCP):
                    tcp_count += 1
                    src_port = pkt[TCP].sport
                    dst_port = pkt[TCP].dport
                    if AMQP_PORT in (src_port, dst_port) and pkt.haslayer(Raw):
                        amqp_count += 1
                        payload = bytes(pkt[Raw].load)
                        frames = parsear_frame_amqp(payload)
                        for f in frames:
                            amqp_methods[f.get("descripcion", "?")] += 1

                if pkt.haslayer(IP):
                    ips_origen.add(pkt[IP].src)
                    ips_destino.add(pkt[IP].dst)

            log(f"    Total paquetes:      {total}", "MÉTRICA")
            log(f"    Paquetes TCP:        {tcp_count}", "MÉTRICA")
            log(f"    Paquetes AMQP:       {amqp_count}", "MÉTRICA")
            log(f"    Bytes totales:       {bytes_total}", "MÉTRICA")
            log(f"    IPs origen:          {', '.join(ips_origen)}", "MÉTRICA")
            log(f"    IPs destino:         {', '.join(ips_destino)}", "MÉTRICA")

            if amqp_methods:
                log("    Métodos AMQP detectados:", "MÉTRICA")
                for metodo, count in sorted(amqp_methods.items(),
                                            key=lambda x: -x[1]):
                    log(f"      {metodo}: {count}", "MÉTRICA")

        except Exception as e:
            log(f"    Error al analizar {archivo}: {e}", "MÉTRICA")


# =============================================================================
#  MENÚ PRINCIPAL
# =============================================================================


def objetivo3_metricas_modificadas():
    '''
    Evalúa el throughput del servidor modificando métricas de red mediante tc.
    Genera gráficos usando matplotlib.
    '''
    log('\n' + '-' * 70)
    log('MÉTRICA 7: Evaluación de Cotas de Desempeño variando Latencia y Pérdida de Paquetes', 'MÉTRICA')
    log('-' * 70)
    
    container_name = 'rabbit_server'
    
    def test_throughput():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((SERVER_IP, AMQP_PORT))
            datos = b'X' * 4096
            total = 0
            t0 = time.time()
            for _ in range(50):
                total += sock.send(datos)
            t1 = time.time()
            sock.close()
            return (total / 1024) / (t1 - t0)
        except Exception:
            return 0
    
    latencias = [0, 50, 100, 200, 300, 500]
    throughput_lat = []
    for lat in latencias:
        if lat > 0:
            subprocess.run(['docker', 'exec', container_name, 'tc', 'qdisc', 'add', 'dev', 'eth0', 'root', 'netem', 'delay', f'{lat}ms'], capture_output=True)
            time.sleep(1)
        th = test_throughput()
        throughput_lat.append(th)
        log(f'  Latencia {lat}ms -> Throughput: {th:.2f} KB/s', 'MÉTRICA')
        if lat > 0:
            subprocess.run(['docker', 'exec', container_name, 'tc', 'qdisc', 'del', 'dev', 'eth0', 'root'], capture_output=True)
            time.sleep(0.5)
            
    perdidas = [0, 5, 10, 20, 30, 50]
    throughput_loss = []
    for loss in perdidas:
        if loss > 0:
            subprocess.run(['docker', 'exec', container_name, 'tc', 'qdisc', 'add', 'dev', 'eth0', 'root', 'netem', 'loss', f'{loss}%'], capture_output=True)
            time.sleep(1)
        th = test_throughput()
        throughput_loss.append(th)
        log(f'  Pérdida {loss}% -> Throughput: {th:.2f} KB/s', 'MÉTRICA')
        if loss > 0:
            subprocess.run(['docker', 'exec', container_name, 'tc', 'qdisc', 'del', 'dev', 'eth0', 'root'], capture_output=True)
            time.sleep(0.5)

    if MATPLOTLIB_AVAILABLE:
        try:
            plt.figure(figsize=(10,4))
            
            plt.subplot(1, 2, 1)
            plt.plot(latencias, throughput_lat, marker='o', color='blue')
            plt.title('Throughput vs Latencia')
            plt.xlabel('Latencia (ms)')
            plt.ylabel('Throughput (KB/s)')
            plt.grid(True)
            
            plt.subplot(1, 2, 2)
            plt.plot(perdidas, throughput_loss, marker='o', color='red')
            plt.title('Throughput vs Pérdida de Paquetes')
            plt.xlabel('Pérdida de Paquetes (%)')
            plt.ylabel('Throughput (KB/s)')
            plt.grid(True)
            
            plt.tight_layout()
            plt.savefig('metricas_throughput.png')
            log('  Gráfico guardado en metricas_throughput.png', 'MÉTRICA')
        except Exception as e:
            log(f'  Error al graficar: {e}', 'MÉTRICA')
            
    log('  → ANÁLISIS: Las cotas de desempeño se observan cuando el throughput cae a 0 o la conexión falla sistemáticamente.', 'MÉTRICA')


def menu_principal():
    """Muestra el menú principal y ejecuta las opciones seleccionadas."""
    print("\n" + "=" * 70)
    print("  TAREA 2 - Análisis de Tráfico AMQP con Scapy")
    print(f"  Servidor: {SERVER_IP}:{AMQP_PORT} (RabbitMQ)")
    print("=" * 70)
    print("\nOpciones:")
    print("  [1] Ejecutar TODO (Objetivos 1, 2 y 3 completos)")
    print("  [2] Objetivo 1: Interceptar, inyectar y modificar tráfico")
    print("  [3] Objetivo 2: Análisis de repercusiones")
    print("  [4] Objetivo 3: Métricas de red y cotas de desempeño")
    print("  [5] Solo captura de tráfico (15 segundos)")
    print("  [6] Solo inyecciones (sin captura)")
    print("  [7] Solo métricas de red")
    print("  [8] Análisis de archivos PCAP existentes")
    print("  [9] Evaluar Cotas de Desempeño (Requiere Docker y tc)")
    print("  [0] Salir")
    print()

    opcion = input("Seleccione una opción: ").strip()
    return opcion


def ejecutar_objetivo1():
    """Ejecuta todas las pruebas del Objetivo 1."""
    objetivo1_captura_trafico(duracion=15)
    objetivo1_inyeccion_amqp_header_invalido()
    objetivo1_inyeccion_frame_malformado()
    objetivo1_inyeccion_datos_aleatorios()
    objetivo1_inyeccion_paquete_scapy()
    objetivo1_fuzzing_payload()
    objetivo1_fuzzing_campos()
    objetivo1_inyeccion_channel_invalido()


def ejecutar_objetivo2():
    """Ejecuta todas las pruebas del Objetivo 2."""
    objetivo2_impacto_flood_conexiones()
    objetivo2_impacto_handshake_incompleto()
    objetivo2_impacto_payload_grande()


def ejecutar_objetivo3():
    """Ejecuta todas las pruebas del Objetivo 3."""
    objetivo3_latencia_servicio()
    objetivo3_throughput_tcp()
    objetivo3_icmp_latencia()
    objetivo3_tamano_ventana_tcp()
    objetivo3_fragmentacion()
    objetivo3_analisis_pcap_existente()
    objetivo3_metricas_modificadas()


def main():
    while True:
        opcion = menu_principal()

        if opcion == "0":
            print("\n¡Hasta luego!")
            break
        elif opcion == "1":
            log("Ejecutando análisis completo...\n")
            ejecutar_objetivo1()
            ejecutar_objetivo2()
            ejecutar_objetivo3()
        elif opcion == "2":
            ejecutar_objetivo1()
        elif opcion == "3":
            ejecutar_objetivo2()
        elif opcion == "4":
            ejecutar_objetivo3()
        elif opcion == "5":
            objetivo1_captura_trafico(duracion=15)
        elif opcion == "6":
            objetivo1_inyeccion_amqp_header_invalido()
            objetivo1_inyeccion_frame_malformado()
            objetivo1_inyeccion_datos_aleatorios()
            objetivo1_inyeccion_paquete_scapy()
            objetivo1_fuzzing_payload()
            objetivo1_fuzzing_campos()
            objetivo1_inyeccion_channel_invalido()
        elif opcion == "7":
            objetivo3_latencia_servicio()
            objetivo3_throughput_tcp()
            objetivo3_icmp_latencia()
            objetivo3_tamano_ventana_tcp()
            objetivo3_fragmentacion()
        elif opcion == "8":
            objetivo3_analisis_pcap_existente()
        elif opcion == "9":
            objetivo3_metricas_modificadas()
        else:
            print("Opción no válida.")
            continue

        # Guardar resultados después de cada ejecución
        guardar_resultados()
        log("\n" + "=" * 70)
        log("Ejecución completada. Resultados guardados.")
        log("=" * 70)


if __name__ == "__main__":
    main()
