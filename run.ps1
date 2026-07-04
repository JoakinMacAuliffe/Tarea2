<#
.SYNOPSIS
    Tarea 3 - Orquestacion manual con Docker (sin docker-compose)
    Levanta RabbitMQ, cliente AMQP y el contenedor Scapy usando solo Dockerfiles.

.USAGE
    # Desde PowerShell (como Administrador si Scapy necesita raw sockets):
    .\run.ps1              # Construye, levanta y ejecuta todo
    .\run.ps1 -Build       # Solo construye las imagenes
    .\run.ps1 -Clean       # Para y elimina contenedores + red
#>

param(
    [switch]$Build,
    [switch]$Clean
)

$NETWORK     = "amqp_net"
$SERVER_IMG  = "amqp_server"
$CLIENT_IMG  = "amqp_client"
$SCAPY_IMG   = "scapy_tarea3"
$SERVER_CTR  = "rabbit_server"
$SCAPY_CTR   = "scapy_tarea3"

# ── Limpieza ──────────────────────────────────────────────────────────────────
if ($Clean) {
    Write-Host "`n[CLEAN] Deteniendo contenedores..." -ForegroundColor Yellow
    docker stop $SERVER_CTR $SCAPY_CTR 2>$null
    docker rm   $SERVER_CTR $SCAPY_CTR 2>$null
    docker network rm $NETWORK 2>$null
    Write-Host "[CLEAN] Listo." -ForegroundColor Green
    exit 0
}

# ── Build ─────────────────────────────────────────────────────────────────────
Write-Host "`n[BUILD] Construyendo imagenes..." -ForegroundColor Cyan

Write-Host "  -> $SERVER_IMG (server/Dockerfile)"
docker build -t $SERVER_IMG ./server
if ($LASTEXITCODE -ne 0) { Write-Error "Fallo build $SERVER_IMG"; exit 1 }

Write-Host "  -> $CLIENT_IMG (client/Dockerfile)"
docker build -t $CLIENT_IMG ./client
if ($LASTEXITCODE -ne 0) { Write-Error "Fallo build $CLIENT_IMG"; exit 1 }

Write-Host "  -> $SCAPY_IMG (scapy/Dockerfile)"
docker build -t $SCAPY_IMG -f scapy/Dockerfile .
if ($LASTEXITCODE -ne 0) { Write-Error "Fallo build $SCAPY_IMG"; exit 1 }

if ($Build) {
    Write-Host "`n[BUILD] Todas las imagenes construidas." -ForegroundColor Green
    exit 0
}

# ── Red ───────────────────────────────────────────────────────────────────────
Write-Host "`n[NET] Creando red $NETWORK..." -ForegroundColor Cyan
docker network create $NETWORK 2>$null
# Si ya existe, no es un error

# ── Servidor RabbitMQ ─────────────────────────────────────────────────────────
Write-Host "`n[SERVER] Iniciando $SERVER_CTR..." -ForegroundColor Cyan
docker rm -f $SERVER_CTR 2>$null
docker run -d `
    --name $SERVER_CTR `
    --network $NETWORK `
    -p 5672:5672 `
    -p 15672:15672 `
    $SERVER_IMG

Write-Host "[SERVER] Esperando que RabbitMQ este listo (hasta 90 s)..."
$ok = $false
for ($i = 0; $i -lt 18; $i++) {
    Start-Sleep -Seconds 5
    $status = docker exec $SERVER_CTR rabbitmqctl status 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[SERVER] RabbitMQ listo." -ForegroundColor Green
        $ok = $true
        break
    }
    Write-Host "  Intento $($i+1)/18 - aun no disponible..."
}
if (-not $ok) {
    Write-Error "[SERVER] RabbitMQ no respondio a tiempo. Revisa: docker logs $SERVER_CTR"
    exit 1
}

# ── Contenedor Scapy ──────────────────────────────────────────────────────────
Write-Host "`n[SCAPY] Ejecutando contenedor $SCAPY_CTR..." -ForegroundColor Cyan

# Crea carpeta output si no existe
New-Item -ItemType Directory -Force -Path ".\output" | Out-Null

docker rm -f $SCAPY_CTR 2>$null
docker run --rm `
    --name $SCAPY_CTR `
    --network $NETWORK `
    --cap-add NET_ADMIN `
    --cap-add NET_RAW `
    -e AMQP_HOST=$SERVER_CTR `
    -e AMQP_PORT=5672 `
    -v "${PWD}\output:/app/output" `
    $SCAPY_IMG

Write-Host "`n[DONE] Resultados en .\output\" -ForegroundColor Green
Write-Host "  - resultados_analisis.txt"
Write-Host "  - metricas_throughput.png"
Write-Host "`nPara detener el servidor:"
Write-Host "  docker stop $SERVER_CTR && docker rm $SERVER_CTR"

# ── Instrucciones para el cliente (uso manual) ────────────────────────────────
Write-Host "`n[INFO] Para usar el cliente AMQP manualmente:" -ForegroundColor Yellow
Write-Host "  # Publicar:"
Write-Host "  docker run --rm -it --network $NETWORK $CLIENT_IMG \`"
Write-Host "    amqp-publish -u 'amqp://admin:1234@${SERVER_CTR}:5672/entorno_amqp' -r hello -b 'Hola Mundo'"
Write-Host "  # Consumir:"
Write-Host "  docker run --rm -it --network $NETWORK $CLIENT_IMG \`"
Write-Host "    amqp-consume -u 'amqp://admin:1234@${SERVER_CTR}:5672/entorno_amqp' -q hello -d cat"
