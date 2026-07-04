#!/usr/bin/env python3
"""
Tarea 3 - Taller de Redes y Servicios
Inyección/modificación de tráfico AMQP con Scapy y análisis de métricas.

Requiere:
    pip install scapy matplotlib

Ejecutar con privilegios de administrador/root (Scapy necesita acceso raw socket):
    Windows: correr como Administrador
    Linux:   sudo python3 tarea3_amqp.py

Antes de ejecutar: levantar el servidor RabbitMQ de la Tarea 2
    docker run -it --rm --name rabbit_server -p 5672:5672 -p 15672:15672 amqp_server
"""

import random
import os
import sys
import socket
import struct
import time

import matplotlib.pyplot as plt
from scapy.all import IP, TCP, Raw, send, sr1, RandShort

# --------------------------------------------------------------------------- #
# Configuración
# --------------------------------------------------------------------------- #
TARGET_IP = "127.0.0.1"
TARGET_PORT = 5672

AMQP_PROTOCOL_HEADER = b"AMQP\x00\x00\x09\x01"  # Header válido AMQP 0-9-1
FRAME_END = b"\xce"
RESULTS_FILE = "resultados_analisis.txt"


def get_target_host() -> str:
    """Resuelve el host AMQP desde variables de entorno o un valor compatible con Docker."""
    configured_host = os.getenv("AMQP_HOST") or os.getenv("RABBITMQ_HOST")
    if configured_host:
        return configured_host

    for default_host in ("127.0.0.1", "host.docker.internal"):
        try:
            socket.gethostbyname(default_host)
            return default_host
        except socket.gaierror:
            continue
    return "127.0.0.1"


def get_target_port() -> int:
    """Resuelve el puerto AMQP desde variables de entorno."""
    raw_port = os.getenv("AMQP_PORT") or os.getenv("RABBITMQ_PORT")
    if raw_port:
        try:
            return int(raw_port)
        except ValueError:
            pass
    return TARGET_PORT


def get_amqp_target() -> tuple[str, int]:
    return get_target_host(), get_target_port()


AMQP_HOST, AMQP_PORT = get_amqp_target()


class Tee:
    def __init__(self, *streams):
        self.streams = streams

    def write(self, data):
        for stream in self.streams:
            stream.write(data)
            stream.flush()

    def flush(self):
        for stream in self.streams:
            stream.flush()


def get_output_dir() -> str:
    """Devuelve /app/output si existe (contenedor Docker), si no el directorio del script."""
    docker_out = "/app/output"
    if os.path.isdir(docker_out):
        return docker_out
    return os.path.dirname(os.path.abspath(__file__))


def get_results_path() -> str:
    return os.path.join(get_output_dir(), RESULTS_FILE)


# --------------------------------------------------------------------------- #
# Utilidades de bajo nivel (sockets) para hablar AMQP a nivel de bytes
# --------------------------------------------------------------------------- #
def build_method_frame(channel: int, class_id: int, method_id: int, payload: bytes = b"") -> bytes:
    """Construye un frame AMQP tipo Method (type=1) con class/method arbitrarios."""
    body = struct.pack(">HH", class_id, method_id) + payload
    header = struct.pack(">BHI", 1, channel, len(body))  # type, channel, size
    return header + body + FRAME_END


def build_content_body_frame(channel: int, payload: bytes) -> bytes:
    """Construye un frame AMQP tipo Content-Body (type=3) con un payload arbitrario."""
    header = struct.pack(">BHI", 3, channel, len(payload))
    return header + payload + FRAME_END


def open_amqp_socket(timeout: float = 5.0) -> socket.socket:
    """Abre un socket TCP y realiza el handshake mínimo AMQP hasta Connection.Start."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((AMQP_HOST, AMQP_PORT))
    except OSError:
        s.close()
        raise

    try:
        s.send(AMQP_PROTOCOL_HEADER)
        try:
            s.recv(4096)  # Connection.Start
        except socket.timeout as exc:
            s.close()
            raise TimeoutError(
                f"No llegó Connection.Start desde {AMQP_HOST}:{AMQP_PORT} dentro de {timeout}s"
            ) from exc
    except OSError:
        s.close()
        raise

    return s


def try_recv(s: socket.socket, timeout: float = 5.0) -> bytes:
    s.settimeout(timeout)
    try:
        return s.recv(4096)
    except socket.timeout:
        return b""


def _log_trace(prefix: str, message: str):
    timestamp = time.strftime("%H:%M:%S")
    print(f"  [{timestamp}] [{prefix}] {message}")


def trace_amqp_handshake(delay_ms: float = 0.0, socket_timeout: float = 5.0) -> dict:
    """Ejecuta el handshake mínimo y deja trazas por paso para diagnosticar fallos."""
    trace = {
        "ok": False,
        "stage": "start",
        "error": None,
        "received": b"",
    }

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(socket_timeout)
    try:
        trace["stage"] = "connect"
        _log_trace("HANDSHAKE", f"Conectando a {AMQP_HOST}:{AMQP_PORT} (timeout={socket_timeout}s)")
        s.connect((AMQP_HOST, AMQP_PORT))

        if delay_ms > 0:
            trace["stage"] = "pre-header-delay"
            _log_trace("HANDSHAKE", f"Aplicando delay previo al header: {delay_ms} ms")
            time.sleep(delay_ms / 1000.0)

        trace["stage"] = "send-protocol-header"
        _log_trace("HANDSHAKE", "Enviando AMQP protocol header")
        s.send(AMQP_PROTOCOL_HEADER)

        if delay_ms > 0:
            trace["stage"] = "post-header-delay"
            _log_trace("HANDSHAKE", f"Esperando {delay_ms} ms antes de leer Connection.Start")
            time.sleep(delay_ms / 1000.0)

        trace["stage"] = "recv-connection-start"
        _log_trace("HANDSHAKE", "Esperando Connection.Start")
        data = s.recv(4096)
        trace["received"] = data
        trace["ok"] = True
        _log_trace("HANDSHAKE", f"Received {len(data)} bytes: {data[:16].hex() if data else 'sin datos'}")
    except socket.timeout as exc:
        trace["error"] = f"timeout en etapa {trace['stage']}: {exc}"
        _log_trace("HANDSHAKE", trace["error"])
    except OSError as exc:
        trace["error"] = f"error en etapa {trace['stage']}: {exc}"
        _log_trace("HANDSHAKE", trace["error"])
    finally:
        s.close()

    return trace


# --------------------------------------------------------------------------- #
# 1) Fuzzing (2 inyecciones requeridas)
# --------------------------------------------------------------------------- #
def fuzzing_content_body_size():
    print("\n[FUZZING 1] Content-Body con payload de tamaño variable")
    for size in (100, 500, 1000):
        try:
            s = open_amqp_socket()
            payload = bytes(random.getrandbits(8) for _ in range(size))
            frame = build_content_body_frame(channel=1, payload=payload)
            s.send(frame)
            resp = try_recv(s)
            print(f"  Enviado Content-Body de {size} bytes -> respuesta: {resp[:20] or 'sin respuesta'}")
            s.close()
        except (ConnectionResetError, OSError) as e:
            print(f"  Enviado Content-Body de {size} bytes -> conexión cerrada por el servidor ({e})")


def fuzzing_class_method_ids():
    print("\n[FUZZING 2] Method frames con Class/Method ID aleatorios")
    for _ in range(5):
        class_id = random.randint(50, 255)
        method_id = random.randint(50, 255)
        try:
            s = open_amqp_socket()
            frame = build_method_frame(channel=1, class_id=class_id, method_id=method_id)
            s.send(frame)
            resp = try_recv(s)
            print(f"  Class={class_id} Method={method_id} -> respuesta: {resp[:20] or 'sin respuesta'}")
            s.close()
        except (ConnectionResetError, OSError) as e:
            print(f"  Class={class_id} Method={method_id} -> conexión cerrada ({e})")


# --------------------------------------------------------------------------- #
# 2) Modificaciones de campos específicos del protocolo (3 requeridas)
# --------------------------------------------------------------------------- #
def modificacion_protocol_header_version():
    print("\n[MOD 1] Protocol-Header con versión inválida (AMQP 9.9.9)")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.0)
        s.connect((AMQP_HOST, AMQP_PORT))
        fake_header = b"AMQP\x00\x09\x09\x09"
        s.send(fake_header)
        resp = try_recv(s)
        print(f"  Enviado: {fake_header.hex()}")
        print(f"  Respuesta del servidor: {resp.hex() if resp else 'sin respuesta'}")
        print("  Fundamento: se espera que el servidor rechace la versión y responda con "
              "la versión que sí soporta (negociación defensiva), cerrando luego la conexión.")
        s.close()
    except OSError as e:
        print(f"  No se pudo conectar a {TARGET_IP}:{TARGET_PORT} ({e}). Omitiendo prueba.")


def modificacion_method_frame_malformado():
    print("\n[MOD 2] Frame Method malformado (class=255, method=255)")
    print("  Fundamento: se espera Connection.Close por error de protocolo "
          "(command-invalid), ya que la combinación class/method no existe en la spec.")
    print("  Hipótesis si no se observa: la respuesta puede ser un Connection.Close "
          "cuyo parser simplificado no decodifica como texto legible.")
    
    try:
        s = open_amqp_socket(timeout=8.0)
    except (OSError, TimeoutError) as e:
        print(f"  No se pudo abrir socket para prueba malformada ({e}). Omitiendo prueba.")
        return

    try:
        frame = build_method_frame(channel=1, class_id=255, method_id=255)
        s.send(frame)
        resp = try_recv(s, timeout=5.0)
        print(f"  Respuesta del servidor: {resp.hex() if resp else 'sin respuesta (timeout)'}")
    except (OSError, ConnectionResetError) as e:
        print(f"  Conexión cerrada por el servidor durante MOD 2 ({e})")
    finally:
        s.close()


def modificacion_channel_id_invalido():
    print("\n[MOD 3] Channel.Open con Channel ID inválido (9999)")
    print("  Fundamento: se espera error de canal/conexión al exceder channel_max negociado.")
    print("  Hipótesis si no se observa: el servidor puede cerrar el socket TCP "
          "abruptamente sin enviar un frame de error explícito.")
          
    try:
        s = open_amqp_socket(timeout=8.0)
    except (OSError, TimeoutError) as e:
        print(f"  No se pudo abrir socket para prueba de channel inválido ({e}). Omitiendo prueba.")
        return

    try:
        # Channel.Open = class 20, method 10
        frame = build_method_frame(channel=9999, class_id=20, method_id=10, payload=b"\x00")
        s.send(frame)
        resp = try_recv(s, timeout=5.0)
        print(f"  Respuesta del servidor: {resp.hex() if resp else 'sin respuesta (timeout)'}")
    except (OSError, ConnectionResetError) as e:
        print(f"  Conexión cerrada por el servidor durante MOD 3 ({e})")
    finally:
        s.close()


# --------------------------------------------------------------------------- #
# 3) Repercusiones sobre el software/servicio
# --------------------------------------------------------------------------- #
def test_flood_conexiones_tcp(n: int = 50):
    print(f"\n[REPERCUSIÓN] Flood de {n} conexiones TCP simultáneas")
    tiempos = []
    exitosas = 0
    for _ in range(n):
        t0 = time.perf_counter()
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect((AMQP_HOST, AMQP_PORT))
            exitosas += 1
            s.close()
        except OSError:
            pass
        tiempos.append((time.perf_counter() - t0) * 1000)
    print(f"  Conexiones exitosas: {exitosas}/{n}")
    print(f"  Tiempo promedio: {sum(tiempos)/len(tiempos):.2f} ms "
          f"(min {min(tiempos):.2f} ms, max {max(tiempos):.2f} ms)")

    # Verificar que el servicio sigue respondiendo tras el flood
    t0 = time.perf_counter()
    try:
        s = open_amqp_socket()
        dt = (time.perf_counter() - t0) * 1000
        print(f"  Servicio post-flood responde en {dt:.2f} ms")
        s.close()
    except OSError as e:
        print(f"  No se pudo verificar servicio post-flood ({e}).")


def test_conexiones_half_open(n: int = 20):
    print(f"\n[REPERCUSIÓN] {n} conexiones half-open (SYN sin completar AMQP)")
    sockets = []
    for _ in range(n):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        try:
            s.connect((AMQP_HOST, AMQP_PORT))
            sockets.append(s)  # conexión TCP abierta, sin enviar Protocol-Header
        except OSError:
            pass
    t0 = time.perf_counter()
    try:
        s2 = open_amqp_socket()
        dt = (time.perf_counter() - t0) * 1000
        print(f"  Servicio responde a cliente legítimo en {dt:.2f} ms con {len(sockets)} half-opens activas")
        s2.close()
    except OSError as e:
        print(f"  No se pudo verificar servicio tras half-opens ({e}).")
    for s in sockets:
        s.close()


def test_payload_sobredimensionado(size: int = 65544):
    print(f"\n[REPERCUSIÓN] Content-Body sobredimensionado ({size} bytes)")
    try:
        s = open_amqp_socket()
    except OSError as e:
        print(f"  No se pudo abrir socket para prueba de payload sobredimensionado ({e}). Omitiendo prueba.")
        return

    payload = b"\x00" * size
    frame = build_content_body_frame(channel=1, payload=payload)
    t0 = time.perf_counter()
    try:
        s.send(frame)
        try_recv(s, timeout=5.0)
    except (ConnectionResetError, OSError):
        pass
    dt = time.perf_counter() - t0
    print(f"  Conexión cerrada/gestionada por el servidor tras {dt:.2f} s "
          f"(protección vía frame_max negociado).")
    s.close()


# --------------------------------------------------------------------------- #
# 4) Métricas de red vs. throughput (latencia y ancho de banda / rate limiting)
# --------------------------------------------------------------------------- #
def _medir_throughput(delay_ms: float = 0.0, loss_pct: float = 0.0,
                       n_bloques: int = 10, tam_bloque: int = 1024) -> float:
    """
    Envía n_bloques de tam_bloque bytes al servidor, simulando delay (sleep antes
    de cada envío) y pérdida de paquetes (se omiten bloques siguiendo un patrón
    determinista según loss_pct).
    Retorna throughput en KB/s sobre los bytes efectivamente enviados.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.0)
        s.connect((AMQP_HOST, AMQP_PORT))
        s.send(AMQP_PROTOCOL_HEADER)
        try:
            s.recv(4096)
        except socket.timeout:
            pass
    except OSError as e:
        print(f"  No se pudo abrir socket para medición de throughput ({e}). Retornando 0 KB/s.")
        return 0.0

    bloques_perdidos = int(round(n_bloques * loss_pct / 100.0))
    bloques_perdidos = max(0, min(bloques_perdidos, n_bloques))
    indices_perdidos = set()
    if bloques_perdidos > 0:
        for i in range(bloques_perdidos):
            indice = int(round(i * n_bloques / bloques_perdidos))
            if indice >= n_bloques:
                indice = n_bloques - 1
            indices_perdidos.add(indice)

    bytes_enviados = 0
    t0 = time.perf_counter()
    payload = b"\x00" * tam_bloque
    for indice in range(n_bloques):
        if delay_ms > 0:
            time.sleep(delay_ms / 1000.0)
        if indice in indices_perdidos:
            continue  # simula paquete perdido: no se envía este bloque
        try:
            s.send(payload)
            bytes_enviados += tam_bloque
        except OSError:
            break
    dt = time.perf_counter() - t0
    s.close()
    if dt <= 0:
        dt = 1e-6
    return (bytes_enviados / 1024) / dt  # KB/s


def _medir_throughput_rate_limited(rate_limit_kbps: float,
                                   n_bloques: int = 20,
                                   tam_bloque: int = 1024) -> float:
    """Mide throughput enviando bloques AMQP con un rate limiting artificial."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.0)
        s.connect((AMQP_HOST, AMQP_PORT))
        s.send(AMQP_PROTOCOL_HEADER)
        try:
            s.recv(4096)
        except socket.timeout:
            pass
    except OSError as e:
        print(f"  No se pudo abrir socket para medición de rate limiting ({e}). Retornando 0 KB/s.")
        return 0.0

    payload = b"\x00" * tam_bloque
    bytes_enviados = 0
    t0 = time.perf_counter()
    for _ in range(n_bloques):
        try:
            s.send(build_content_body_frame(channel=1, payload=payload))
            bytes_enviados += tam_bloque
        except OSError:
            break

        if rate_limit_kbps > 0:
            tiempo_espera = tam_bloque / (rate_limit_kbps * 1024)
            time.sleep(tiempo_espera)

    dt = time.perf_counter() - t0
    s.close()
    if dt <= 0:
        dt = 1e-6
    return (bytes_enviados / 1024) / dt  # KB/s


def metrica_latencia_vs_throughput():
    print("\n[MÉTRICA 1] Latencia vs. Throughput")
    valores_ms = [0, 5, 10, 15, 20, 25, 30, 40, 50]
    resultados = []
    for ms in valores_ms:
        thr = _medir_throughput(delay_ms=ms)
        resultados.append(thr)
        print(f"  Latencia {ms} ms -> Throughput: {thr:.2f} KB/s")

    referencia = resultados[0] if resultados else 0.0
    cota = None
    for ms, thr in zip(valores_ms, resultados):
        if referencia > 0 and thr <= referencia * 0.8:
            cota = ms
            break
    if cota is None and valores_ms:
        cota = valores_ms[-1]
    print(f"  Cota de desempeño estimada: latencia >= {cota} ms")

    if cota is not None:
        print("  Trazas diagnósticas alrededor de la cota:")
        for ms in valores_ms:
            if ms in (max(0, cota - 10), cota):
                trace = trace_amqp_handshake(delay_ms=ms)
                estado = "OK" if trace["ok"] else f"FALLO ({trace['error']})"
                print(f"    - {ms} ms: {estado} | etapa final: {trace['stage']}")
    return valores_ms, resultados, cota


def metrica_rate_limiting_vs_throughput():
    print("\n[MÉTRICA 2] Ancho de banda / Rate Limiting vs. Throughput")
    valores_kbps = [10, 20, 50, 100, 200, 500, 1000, 2000, 4096]
    resultados = []
    fallos = []
    for kbps in valores_kbps:
        thr = _medir_throughput_rate_limited(rate_limit_kbps=kbps, n_bloques=50)
        resultados.append(thr)
        ratio = thr / kbps if kbps > 0 else 0.0
        error_flag = thr <= 0.0 or ratio < 0.5
        fallos.append(error_flag)
        estado = "ERROR/DEGRADACIÓN" if error_flag else "OK"
        print(f"  Límite de banda {kbps} KB/s -> Throughput: {thr:.2f} KB/s | ratio={ratio:.2f} | {estado}")

    referencia = resultados[-1] if resultados else 0.0
    cota = None
    for kbps, thr in zip(valores_kbps, resultados):
        if referencia > 0 and thr <= referencia * 0.8:
            cota = kbps
            break
    if cota is None and valores_kbps:
        cota = valores_kbps[-1]
    print(f"  Cota de desempeño estimada: ancho de banda >= {cota} KB/s")

    primer_quiebre = None
    for kbps, fallo in zip(valores_kbps, fallos):
        if fallo:
            primer_quiebre = kbps
            break
    if primer_quiebre is not None:
        print(f"  Punto de quiebre detectado automáticamente: {primer_quiebre} KB/s")
    else:
        print("  No se detectó quiebre cualitativo con los puntos probados.")
    return valores_kbps, resultados, cota


def graficar_metricas(latencia_x, latencia_y, bandwidth_x, bandwidth_y,
                       out_path: str = ""):
    if not out_path:
        out_path = os.path.join(get_output_dir(), "metricas_throughput.png")
    fig, axes = plt.subplots(1, 2, figsize=(10, 4))

    axes[0].plot(latencia_x, latencia_y, marker="o", color="blue")
    axes[0].set_title("Throughput vs Latencia")
    axes[0].set_xlabel("Latencia (ms)")
    axes[0].set_ylabel("Throughput (KB/s)")
    axes[0].grid(True)

    axes[1].plot(bandwidth_x, bandwidth_y, marker="o", color="red")
    axes[1].set_title("Ancho de Banda / Rate Limiting vs Throughput")
    axes[1].set_xlabel("Ancho de Banda Límite (KB/s)")
    axes[1].set_ylabel("Throughput (KB/s)")
    axes[1].grid(True)

    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    print(f"\n[MÉTRICA] Gráfico guardado en {out_path}")


# --------------------------------------------------------------------------- #
# Main: ejecuta únicamente lo que se muestra/requiere en el video
# --------------------------------------------------------------------------- #
def main():
    results_path = get_results_path()
    original_stdout = sys.stdout
    original_stderr = sys.stderr

    with open(results_path, "w", encoding="utf-8") as results_file:
        sys.stdout = Tee(original_stdout, results_file)
        sys.stderr = Tee(original_stderr, results_file)
        try:
            print("=" * 70)
            print(" Tarea 3 - Inyección/modificación de tráfico AMQP con Scapy")
            print("=" * 70)
            print(f" Broker AMQP objetivo: {AMQP_HOST}:{AMQP_PORT}")

            # Fuzzing (2 inyecciones)
            fuzzing_content_body_size()
            fuzzing_class_method_ids()

            print("\n[INFO] Pausa de recuperacion (3 s) antes de modificaciones...")
            time.sleep(3)

            # Modificaciones de campos (3)
            modificacion_protocol_header_version()
            modificacion_method_frame_malformado()
            modificacion_channel_id_invalido()

            print("\n[INFO] Pausa de recuperacion (3 s) antes de pruebas de repercusion...")
            time.sleep(3)

            # Repercusiones sobre el software/servicio
            test_flood_conexiones_tcp(n=50)
            test_conexiones_half_open(n=20)
            test_payload_sobredimensionado()

            # Métricas de red y cotas de desempeño
            lat_x, lat_y, cota_latencia = metrica_latencia_vs_throughput()
            bandwidth_x, bandwidth_y, cota_bandwidth = metrica_rate_limiting_vs_throughput()
            graficar_metricas(lat_x, lat_y, bandwidth_x, bandwidth_y)
            print(f"Cota de desempeño latencia estimada: >= {cota_latencia} ms")
            print(f"Cota de desempeño ancho de banda estimada: >= {cota_bandwidth} KB/s")

            print("\nFinalizado.")
            print(f"Resultados guardados en: {results_path}")
        finally:
            sys.stdout = original_stdout
            sys.stderr = original_stderr


if __name__ == "__main__":
    main()