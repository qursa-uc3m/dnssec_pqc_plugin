#!/bin/bash

# ===============================
# Parámetros de entrada
# ===============================
ALGO=$1
COREFILE=$2
PORT=1053
ZONENAME="mydomain.org"
DNS_SERVER="localhost"

# ===============================
# Directorios y logs
# ===============================
BASE_DIR=$(pwd)
RESULT_DIR="$BASE_DIR/resultados_${ALGO}_$(date +%s)"
mkdir -p "$RESULT_DIR"

cd /home/student/coredns || { echo "[-] Error: No se pudo cambiar al directorio de CoreDNS"; exit 1; }

echo "[+] Ejecutando 10 pruebas independientes con CoreDNS para algoritmo: $ALGO"

COREDNS_LOG="$RESULT_DIR/coredns.log"
DIG_LOG="$RESULT_DIR/dig_respuestas.txt"
TIME_LOG="$RESULT_DIR/time_total.txt"
PERF_LOG="$RESULT_DIR/perf.txt"
RED_STATS="$RESULT_DIR/red_stats.txt"

: > "$COREDNS_LOG"
: > "$DIG_LOG"
: > "$TIME_LOG"
: > "$PERF_LOG"
: > "$RED_STATS"

# ===============================
# Repetir prueba 10 veces
# ===============================
for i in {1..10}; do
  echo "[*] Iteración $i - Iniciando CoreDNS..."

  ./coredns -conf "$COREFILE" >> "$COREDNS_LOG" 2>&1 &
  SERVER_PID=$!
  sleep 2

  echo "[*] CoreDNS iniciado (PID $SERVER_PID)"

  # Captura de tráfico en paralelo
  TSHARK_TMP="$RESULT_DIR/tmp_tshark_iter${i}.txt"
  : > "$TSHARK_TMP"
  echo "[*] Iniciando captura de red con tshark..."
  sudo tshark -i lo -f "port $PORT" -q -z io,stat,0 > "$TSHARK_TMP" 2>/dev/null &
  TSHARK_PID=$!
  sleep 1  # Asegurar que tshark ha comenzado

  # Consulta DNS
  echo "[*] Ejecutando consulta DNS ($i)..."
  echo -e "\n===== Iteración $i =====" >> "$DIG_LOG"
  /usr/bin/time -v dig @$DNS_SERVER -p $PORT $ZONENAME DNSKEY +dnssec >> "$DIG_LOG" 2>> "$TIME_LOG"

  # Medición con perf
  echo -e "\n===== Iteración $i =====" >> "$PERF_LOG"
  sudo perf stat -p "$SERVER_PID" -o - sleep 2 2>> "$PERF_LOG"
  echo -e "\n[*] Métricas ps del proceso CoreDNS para iteración $i:" >> "$PERF_LOG"
  echo "%CPU %MEM   RSS" >> "$PERF_LOG"
  sudo ps -p "$SERVER_PID" -o %cpu,%mem,rss --no-headers >> "$PERF_LOG"
  # Finalizar tshark
  echo "[*] Finalizando tshark..."
  sudo kill "$TSHARK_PID" 2>/dev/null
  wait "$TSHARK_PID" 2>/dev/null

  # Guardar métricas de red
  echo -e "\n===== Iteración $i =====" >> "$RED_STATS"
  cat "$TSHARK_TMP" >> "$RED_STATS"
  rm -f "$TSHARK_TMP"

  # Finalizar CoreDNS
  echo "[*] Finalizando CoreDNS..."
  kill "$SERVER_PID" 2>/dev/null
  sleep 1

  echo "[✓] Iteración $i completada."
done

echo "[✓] Todas las pruebas completadas. Resultados guardados en: $RESULT_DIR"
