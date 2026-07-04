#!/bin/bash
# ============================================================
# Tarea 3 - Orquestacion manual con Docker (sin docker-compose)
# Compatible con Linux / macOS
# Uso:
#   chmod +x run.sh
#   sudo ./run.sh          # sudo requerido para raw sockets de Scapy
#   ./run.sh --build       # solo construye imagenes
#   ./run.sh --clean       # elimina contenedores y red
# ============================================================

set -euo pipefail

NETWORK="amqp_net"
SERVER_IMG="amqp_server"
CLIENT_IMG="amqp_client"
SCAPY_IMG="scapy_tarea3"
SERVER_CTR="rabbit_server"
SCAPY_CTR="scapy_tarea3"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Colores ───────────────────────────────────────────────────────────────────
C_CYAN="\033[0;36m"; C_GREEN="\033[0;32m"; C_YELLOW="\033[1;33m"; C_RESET="\033[0m"

info()  { echo -e "${C_CYAN}$*${C_RESET}"; }
ok()    { echo -e "${C_GREEN}$*${C_RESET}"; }
warn()  { echo -e "${C_YELLOW}$*${C_RESET}"; }

# ── Limpieza ──────────────────────────────────────────────────────────────────
if [[ "${1:-}" == "--clean" ]]; then
    warn "\n[CLEAN] Deteniendo contenedores..."
    docker stop "$SERVER_CTR" "$SCAPY_CTR" 2>/dev/null || true
    docker rm   "$SERVER_CTR" "$SCAPY_CTR" 2>/dev/null || true
    docker network rm "$NETWORK" 2>/dev/null || true
    ok "[CLEAN] Listo."
    exit 0
fi

# ── Build ─────────────────────────────────────────────────────────────────────
info "\n[BUILD] Construyendo imagenes..."

info "  -> $SERVER_IMG (server/Dockerfile)"
docker build -t "$SERVER_IMG" "$SCRIPT_DIR/server"

info "  -> $CLIENT_IMG (client/Dockerfile)"
docker build -t "$CLIENT_IMG" "$SCRIPT_DIR/client"

info "  -> $SCAPY_IMG (scapy/Dockerfile)"
docker build -t "$SCAPY_IMG" -f "$SCRIPT_DIR/scapy/Dockerfile" "$SCRIPT_DIR"

if [[ "${1:-}" == "--build" ]]; then
    ok "\n[BUILD] Todas las imagenes construidas."
    exit 0
fi

# ── Red ───────────────────────────────────────────────────────────────────────
info "\n[NET] Creando red $NETWORK..."
docker network create "$NETWORK" 2>/dev/null || true

# ── Servidor RabbitMQ ─────────────────────────────────────────────────────────
info "\n[SERVER] Iniciando $SERVER_CTR..."
docker rm -f "$SERVER_CTR" 2>/dev/null || true
docker run -d \
    --name "$SERVER_CTR" \
    --network "$NETWORK" \
    -p 5672:5672 \
    -p 15672:15672 \
    "$SERVER_IMG"

echo -n "[SERVER] Esperando RabbitMQ (hasta 90 s)..."
for i in $(seq 1 18); do
    sleep 5
    if docker exec "$SERVER_CTR" rabbitmqctl status &>/dev/null; then
        ok " listo!"
        break
    fi
    echo -n " $((i*5))s..."
    if [[ $i -eq 18 ]]; then
        echo ""
        echo "ERROR: RabbitMQ no respondio. Revisa: docker logs $SERVER_CTR"
        exit 1
    fi
done

# ── Contenedor Scapy ──────────────────────────────────────────────────────────
info "\n[SCAPY] Ejecutando $SCAPY_CTR..."
mkdir -p "$SCRIPT_DIR/output"

docker rm -f "$SCAPY_CTR" 2>/dev/null || true
docker run --rm \
    --name "$SCAPY_CTR" \
    --network "$NETWORK" \
    --cap-add NET_ADMIN \
    --cap-add NET_RAW \
    -e AMQP_HOST="$SERVER_CTR" \
    -e AMQP_PORT=5672 \
    -v "$SCRIPT_DIR/output:/app/output" \
    "$SCAPY_IMG"

ok "\n[DONE] Resultados en ./output/"
echo "  - resultados_analisis.txt"
echo "  - metricas_throughput.png"

warn "\nPara el cliente AMQP (manual):"
echo "  # Publicar:"
echo "  docker run --rm -it --network $NETWORK $CLIENT_IMG \\"
echo "    amqp-publish -u 'amqp://admin:1234@${SERVER_CTR}:5672/entorno_amqp' -r hello -b 'Hola Mundo'"
echo "  # Consumir:"
echo "  docker run --rm -it --network $NETWORK $CLIENT_IMG \\"
echo "    amqp-consume -u 'amqp://admin:1234@${SERVER_CTR}:5672/entorno_amqp' -q hello -d cat"
