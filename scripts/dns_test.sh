#!/bin/bash

ALGO=$1
ITERATIONS=${2:-1}
PORT=1053
ZONENAME="mydomain.org"
DNS_SERVER="localhost"

# Calculate paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(dirname "$SCRIPT_DIR")"
KEYGEN_PATH="$BASE_DIR/keygen/keygen"
COREDNS_PATH="$BASE_DIR/coredns/coredns-pqc"

if [ -z "$ALGO" ]; then
    echo "Usage: $0 <ALGORITHM|all> [ITERATIONS]"
    echo "PQC Algorithms: Falcon-512, ML-DSA-44, SPHINCS+-SHA2-128f-simple, MAYO-1,"
    echo "                Falcon-1024, ML-DSA-65, SPHINCS+-SHAKE-128f-simple, MAYO-3,"
    echo "                Falcon-padded-512, ML-DSA-87, Falcon-padded-1024, SNOVA_24_5_4, SNOVA_24_5_4_SHAKE"
    echo "Traditional:    RSA-2048, RSA-4096, ECDSA-P256, ECDSA-P384, Ed25519"
    exit 1
fi

# Check for required tools
for tool in bc dnssec-keygen; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "[-] Error: $tool not found. Please install it."
        exit 1
    fi
done

declare -A LIBOQS_TO_ID=(
    ["Falcon-512"]="17"    
    ["ML-DSA-44"]="18"    
    ["SPHINCS+-SHA2-128f-simple"]="19"
    ["MAYO-1"]="20"        
    ["SNOVA_24_5_4"]="21"
    ["Falcon-1024"]="27"   
    ["ML-DSA-65"]="28"
    ["SPHINCS+-SHAKE-128f-simple"]="29" 
    ["MAYO-3"]="30"
    ["SNOVA_24_5_4_SHAKE"]="31"
    ["Falcon-padded-512"]="37"
    ["ML-DSA-87"]="38"    
    ["Falcon-padded-1024"]="47"
)

# Traditional algorithms (use dnssec-keygen)
declare -A TRADITIONAL_ALGOS=(
    ["RSA-2048"]="RSASHA256"
    ["RSA-4096"]="RSASHA256" 
    ["ECDSA-P256"]="ECDSAP256SHA256"
    ["ECDSA-P384"]="ECDSAP384SHA384"
    ["Ed25519"]="ED25519"
)

# Bash parsing functions
parse_memory_usage() {
    local MEMORY_FILE=$1
    local ALG=$2
    local ITERATION=$3
    local CSV_FILE=$4
    
    local PEAK_RSS=0
    local PEAK_VM=0
    
    if [ -f "$MEMORY_FILE" ] && [ -s "$MEMORY_FILE" ]; then
        # Parse /proc/PID/status output
        PEAK_RSS=$(grep "VmHWM:" "$MEMORY_FILE" | awk '{print $2}' || echo "0")
        PEAK_VM=$(grep "VmPeak:" "$MEMORY_FILE" | awk '{print $2}' || echo "0")
        
        [ -z "$PEAK_RSS" ] && PEAK_RSS=0
        [ -z "$PEAK_VM" ] && PEAK_VM=0
    fi
    
    # Create CSV header if file doesn't exist
    if [ ! -f "$CSV_FILE" ]; then
        echo "Algorithm,Iteration,Peak_RSS_KB,Peak_VM_KB" > "$CSV_FILE"
    fi
    
    # Append data
    echo "$ALG,$ITERATION,$PEAK_RSS,$PEAK_VM" >> "$CSV_FILE"
    
    echo "[*] Memory - Peak RSS: ${PEAK_RSS}KB, Peak VM: ${PEAK_VM}KB"
}

parse_cpu_cycles() {
    local PERF_FILE=$1
    local ALG=$2
    local ITERATION=$3
    local CSV_FILE=$4
    
    local CPU_CYCLES=0
    
    if [ -f "$PERF_FILE" ] && [ -s "$PERF_FILE" ]; then
        # Look for lines containing "cycles" (with or without leading whitespace)
        # Extract the number (with commas), then remove commas
        CPU_CYCLES=$(grep -E "cycles" "$PERF_FILE" | grep -v "insn per cycle" | head -1 | awk '{print $1}' | tr -d ',' || echo "0")
        [ -z "$CPU_CYCLES" ] && CPU_CYCLES=0
        
        # Validate that we got a number
        if ! [[ "$CPU_CYCLES" =~ ^[0-9]+$ ]]; then
            echo "[!] Warning: Could not parse CPU cycles from perf output, setting to 0"
            CPU_CYCLES=0
        fi
    fi
    
    # Create CSV header if file doesn't exist
    if [ ! -f "$CSV_FILE" ]; then
        echo "Algorithm,Iteration,CPU_Cycles" > "$CSV_FILE"
    fi
    
    # Append data
    echo "$ALG,$ITERATION,$CPU_CYCLES" >> "$CSV_FILE"
    
    echo "[*] CPU Cycles: $CPU_CYCLES"
}

parse_dns_response_size_from_dig() {
    local DIG_LOG=$1
    local ALG=$2
    local ITERATION=$3
    local CSV_FILE=$4
    
    local DNS_SIZE=0
    
    if [ -f "$DIG_LOG" ] && [ -s "$DIG_LOG" ]; then
        # Extract MSG SIZE from the specific iteration section
        # Look for the pattern ";; MSG SIZE  rcvd: XXXX" in the iteration section
        DNS_SIZE=$(awk "/=== Iteration $ITERATION ===/,/=== Iteration $((ITERATION+1)) ===/" "$DIG_LOG" | \
                  grep -E "MSG SIZE.*rcvd:" | \
                  grep -o "rcvd: [0-9]\+" | \
                  awk '{print $2}' | \
                  head -1)
        
        [ -z "$DNS_SIZE" ] && DNS_SIZE=0
        
        # Validate that we got a number
        if ! [[ "$DNS_SIZE" =~ ^[0-9]+$ ]]; then
            echo "[!] Warning: Could not parse DNS message size from dig output, setting to 0"
            DNS_SIZE=0
        fi
    fi
    
    # Create CSV header if file doesn't exist
    if [ ! -f "$CSV_FILE" ]; then
        echo "Algorithm,Iteration,DNS_Response_Size_Bytes" > "$CSV_FILE"
    fi
    
    # Append data
    echo "$ALG,$ITERATION,$DNS_SIZE" >> "$CSV_FILE"
    
    echo "[*] DNS Response Size: $DNS_SIZE bytes"
}

run_test() {
    local ALG=$1
    local ALG_ID=$2
    local RESULT_DIR=$3
    
    echo "[+] Testing $ALG ($ITERATIONS iterations)"
    
    # Setup directories and check dependencies
    KEYS_DIR="$RESULT_DIR/keys"
    mkdir -p "$KEYS_DIR"
    cd "$KEYS_DIR"
    
    # Check if this is a traditional algorithm or PQC
    if [[ -n "${TRADITIONAL_ALGOS[$ALG]}" ]]; then
        # Traditional algorithm - use dnssec-keygen
        local DNSSEC_ALG="${TRADITIONAL_ALGOS[$ALG]}"
        
        echo "[*] Generating traditional DNSSEC keys for $ALG"
        
        # Set key size for RSA algorithms
        if [[ "$ALG" == "RSA-2048" ]]; then
            dnssec-keygen -a "$DNSSEC_ALG" -b 2048 "$ZONENAME"
        elif [[ "$ALG" == "RSA-4096" ]]; then
            dnssec-keygen -a "$DNSSEC_ALG" -b 4096 "$ZONENAME"
        else
            # ECDSA and Ed25519 don't need -b parameter
            dnssec-keygen -a "$DNSSEC_ALG" "$ZONENAME"
        fi
        
        if [ $? -ne 0 ]; then
            echo "[-] Traditional key generation failed for $ALG"
            return 1
        fi
        
        echo "[*] Files created after key generation:"
        ls -la K* 2>/dev/null || echo "No K* files found"
        
        # Find the generated key file (traditional DNSSEC pattern: domain.+alg+keyid.key)
        KEY_FILE=$(ls K*.+*+*.key 2>/dev/null | head -1)
        if [ -z "$KEY_FILE" ]; then
            echo "[-] Traditional key file not found. Available files:"
            ls -la K* 2>/dev/null || echo "No K* files found"
            return 1
        fi
        KEY_BASE=$(basename "$KEY_FILE" .key)
        
        # Create Corefile for traditional DNSSEC
        cat > "$RESULT_DIR/Corefile" << EOF
${ZONENAME}:${PORT} {
    dnssec {
        key file ${KEYS_DIR}/${KEY_BASE}.key
    }
    forward . 8.8.8.8
    log
}
.:${PORT} {
    forward . 8.8.8.8
    log
}
EOF
        
    else
        # PQC algorithm - use liboqs-go keygen
        for cmd in "$KEYGEN_PATH" "$COREDNS_PATH"; do
            if [ ! -x "$cmd" ]; then
                echo "[-] Not found: $cmd"
                return 1
            fi
        done
        
        # Generate PQC keys
        if ! "$KEYGEN_PATH" -algorithm "$ALG" -number "$ALG_ID" -domain "$ZONENAME" >/dev/null; then
            echo "[-] PQC key generation failed for $ALG"
            return 1
        fi
        
        KEY_FILE=$(ls K${ZONENAME}+${ALG_ID}+*.key 2>/dev/null | head -1)
        if [ -z "$KEY_FILE" ]; then
            echo "[-] PQC key file not found"
            return 1
        fi
        KEY_BASE=$(basename "$KEY_FILE" .key)
        
        # Create Corefile for PQC
        cat > "$RESULT_DIR/Corefile" << EOF
${ZONENAME}:${PORT} {
    dnssec_pqc {
        key file ${KEYS_DIR}/${KEY_BASE}.key
    }
    forward . 8.8.8.8
    log
}
.:${PORT} {
    forward . 8.8.8.8
    log
}
EOF
    fi
    
    cd "$BASE_DIR"
    
    # Initialize log files and CSV files
    DIG_LOG="$RESULT_DIR/dig_responses.txt"
    TIMING_CSV="$RESULT_DIR/precise_timing.csv"
    CPU_CSV="$RESULT_DIR/cpu_cycles.csv"
    DNS_SIZE_CSV="$RESULT_DIR/dns_response_size.csv"
    MEMORY_CSV="$RESULT_DIR/memory_usage.csv"
    : > "$DIG_LOG"
    
    # Create high-precision timing CSV header
    echo "Algorithm,Iteration,Dig_Command_Time_microseconds" > "$TIMING_CSV"
    
    # Run test iterations
    for i in $(seq 1 $ITERATIONS); do
        echo "[*] Iteration $i/$ITERATIONS"
        
        # Start CoreDNS
        "$COREDNS_PATH" -conf "$RESULT_DIR/Corefile" > "$RESULT_DIR/coredns_${i}.log" 2>&1 &
        SERVER_PID=$!
        sleep 2  # Give CoreDNS time to fully start
        
        if ! kill -0 "$SERVER_PID" 2>/dev/null; then
            echo "[-] CoreDNS failed to start in iteration $i"
            cat "$RESULT_DIR/coredns_${i}.log"
            return 1
        fi
        
        echo "[*] Starting measurement (iteration $i)"
        echo "=== Iteration $i ===" >> "$DIG_LOG"
        
        # Capture initial memory stats
        if [ -f "/proc/$SERVER_PID/status" ]; then
            cp "/proc/$SERVER_PID/status" "$RESULT_DIR/memory_pre_${i}.txt"
        fi
        
        # Start perf measurement on server process
        perf stat -p "$SERVER_PID" \
            -e cycles,instructions,cache-misses,cache-references \
            -o "$RESULT_DIR/perf_${i}.log" &
        PERF_PID=$!
        sleep 0.035

        echo "[*] Executing DNS query..."
        
        # Get timestamp before dig command
        START_TIME=$(date +%s.%N)
        
        # Execute DNS query
        dig @$DNS_SERVER -p $PORT $ZONENAME DNSKEY +dnssec +bufsize=4096 +edns=0 >> "$DIG_LOG" 2>&1
        
        # Get timestamp after dig command
        END_TIME=$(date +%s.%N)
        
        # Calculate precise execution time in microseconds
        PRECISE_TIME_MICROSECONDS=$(echo "($END_TIME - $START_TIME) * 1000000" | bc -l | cut -d. -f1)
        
        # Save high-precision timing directly to CSV
        echo "$ALG,$i,$PRECISE_TIME_MICROSECONDS" >> "$TIMING_CSV"
        
        echo "[*] ✓ Precise dig timing: ${PRECISE_TIME_MICROSECONDS} microseconds"
        
        # Capture final memory stats (contains peak usage)
        if [ -f "/proc/$SERVER_PID/status" ]; then
            cp "/proc/$SERVER_PID/status" "$RESULT_DIR/memory_post_${i}.txt"
        fi
        
        # Stop perf measurement immediately when client finishes
        if kill -0 "$PERF_PID" 2>/dev/null; then
            kill -INT "$PERF_PID" 2>/dev/null
            sleep 1  # Wait for perf to finish writing
            wait "$PERF_PID" 2>/dev/null || true
            echo "[*] ✓ Perf measurement completed"
        fi
        
        # Parse and save data to CSV files using bash functions
        echo "[*] Parsing and saving data to CSV files..."
        
        parse_cpu_cycles "$RESULT_DIR/perf_${i}.log" "$ALG" "$i" "$CPU_CSV"
        parse_dns_response_size_from_dig "$DIG_LOG" "$ALG" "$i" "$DNS_SIZE_CSV"
        parse_memory_usage "$RESULT_DIR/memory_post_${i}.txt" "$ALG" "$i" "$MEMORY_CSV"
        
        # Stop CoreDNS
        kill "$SERVER_PID" 2>/dev/null
        wait "$SERVER_PID" 2>/dev/null || true
        
        # Extract the DNS response size for this iteration to show in summary
        DNS_RESPONSE_SIZE=$(awk "/=== Iteration $i ===/,/=== Iteration $((i+1)) ===/" "$DIG_LOG" | \
                           grep -E "MSG SIZE.*rcvd:" | \
                           grep -o "rcvd: [0-9]\+" | \
                           awk '{print $2}' | \
                           head -1)
        [ -z "$DNS_RESPONSE_SIZE" ] && DNS_RESPONSE_SIZE="Unknown"
        
        echo "[✓] Iteration $i completed (DNS Response: ${DNS_RESPONSE_SIZE} bytes, Timing: ${PRECISE_TIME_MICROSECONDS}μs)"
        echo ""
    done
    
    echo "[✓] $ALG testing completed"
    
    # Show CSV files created
    echo ""
    echo "=== CSV Files Generated ==="
    for csv_file in "$RESULT_DIR"/*.csv; do
        if [ -f "$csv_file" ]; then
            echo "  $(basename "$csv_file"): $(tail -n +2 "$csv_file" | wc -l) records"
        fi
    done
    echo "=========================="
    
    return 0
}

# Main execution
if [ "$ALGO" = "all" ]; then
    MAIN_RESULT_DIR="$BASE_DIR/results_all_$(date +%s)"
    mkdir -p "$MAIN_RESULT_DIR"
    
    echo "Testing all algorithms ($ITERATIONS iterations each)"
    echo "Results: $MAIN_RESULT_DIR"
    echo ""
    
    # Test PQC algorithms
    for ALG in "${!LIBOQS_TO_ID[@]}"; do
        ALG_ID=${LIBOQS_TO_ID[$ALG]}
        ALG_SAFE=$(echo "$ALG" | sed 's/[^a-zA-Z0-9]/_/g')
        ALG_RESULT_DIR="$MAIN_RESULT_DIR/$ALG_SAFE"
        mkdir -p "$ALG_RESULT_DIR"
        
        echo "Testing PQC: $ALG"
        run_test "$ALG" "$ALG_ID" "$ALG_RESULT_DIR" || continue
    done
    
    # Test traditional algorithms
    for ALG in "${!TRADITIONAL_ALGOS[@]}"; do
        ALG_SAFE=$(echo "$ALG" | sed 's/[^a-zA-Z0-9]/_/g')
        ALG_RESULT_DIR="$MAIN_RESULT_DIR/$ALG_SAFE"
        mkdir -p "$ALG_RESULT_DIR"
        
        echo "Testing Traditional: $ALG"
        run_test "$ALG" "" "$ALG_RESULT_DIR" || continue
    done
    
    echo ""
    echo "=== MASTER CSV CONSOLIDATION ==="
    echo "Consolidating all CSV files..."
    
    # Consolidate the 4 CSV files by type
    for csv_type in cpu_cycles dns_response_size precise_timing memory_usage; do
        MASTER_CSV="$MAIN_RESULT_DIR/${csv_type}_all_algorithms.csv"
        HEADER_WRITTEN=false
        
        for ALG_DIR in "$MAIN_RESULT_DIR"/*/; do
            if [ -f "${ALG_DIR}${csv_type}.csv" ]; then
                if [ "$HEADER_WRITTEN" = false ]; then
                    head -1 "${ALG_DIR}${csv_type}.csv" > "$MASTER_CSV"
                    HEADER_WRITTEN=true
                fi
                tail -n +2 "${ALG_DIR}${csv_type}.csv" >> "$MASTER_CSV"
            fi
        done
        
        if [ -f "$MASTER_CSV" ]; then
            RECORD_COUNT=$(tail -n +2 "$MASTER_CSV" | wc -l)
            echo "  $csv_type: $RECORD_COUNT records -> $(basename "$MASTER_CSV")"
        fi
    done

    sudo chown -R $SUDO_USER:$SUDO_USER "$MAIN_RESULT_DIR" 2>/dev/null || chown -R $USER:$USER "$MAIN_RESULT_DIR" 2>/dev/null
    echo "All testing completed: $MAIN_RESULT_DIR"
else
    # Determine algorithm type and ID
    if [[ -n "${LIBOQS_TO_ID[$ALGO]}" ]]; then
        ALG_ID=${LIBOQS_TO_ID[$ALGO]}
        ALG_TYPE="PQC"
    elif [[ -n "${TRADITIONAL_ALGOS[$ALGO]}" ]]; then
        ALG_ID=""
        ALG_TYPE="Traditional"
    else
        echo "[-] Algorithm '$ALGO' not supported"
        echo "Available PQC: ${!LIBOQS_TO_ID[@]}"
        echo "Available Traditional: ${!TRADITIONAL_ALGOS[@]}"
        exit 1
    fi
    
    ALG_SAFE=$(echo "$ALGO" | sed 's/[^a-zA-Z0-9]/_/g')
    RESULT_DIR="$BASE_DIR/results_${ALG_SAFE}_$(date +%s)"
    mkdir -p "$RESULT_DIR"
    
    echo "Testing $ALG_TYPE: $ALGO ($ITERATIONS iterations)"
    echo "Results: $RESULT_DIR"
    echo ""
    
    if run_test "$ALGO" "$ALG_ID" "$RESULT_DIR"; then
        echo ""
        echo "Testing completed successfully!"
        echo "Results saved in: $RESULT_DIR"
    else
        echo "Testing failed for $ALGO"
        exit 1
    fi
fi