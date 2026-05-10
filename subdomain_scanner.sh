#!/usr/bin/env bash
#
# subdomain_scanner.sh — Passive Subdomain Discovery & Port Reconnaissance
# Supports: macOS 13+ (bash 3.2+), Debian 12, Ubuntu 22/24, Kali Linux
# Dependencies: curl, jq, and one of: dig, drill, host, nslookup
# License: MIT

set -euo pipefail

# ============================================================
# COLORS
# ============================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ============================================================
# DEFAULTS (all overridable via CLI flags)
# ============================================================
OUTPUT_DIR=""
THREADS=5
CURL_TIMEOUT=30
CURL_CONNECT_TIMEOUT=10
API_DELAY=0.5
OUTPUT_FORMAT="all"
VERBOSE=0
QUIET=0
CURL_PROXY=""
NO_CACHE=0
CACHE_TTL=86400
API_KEYS_FILE="${HOME}/.config/subdomain_scanner/keys.conf"
CACHE_DIR="${HOME}/.cache/subdomain_scanner"

# API keys (loaded from config file)
SHODAN_API_KEY=""
SECURITYTRAILS_API_KEY=""
VIRUSTOTAL_API_KEY=""
CENSYS_API_ID=""
CENSYS_API_SECRET=""
BINARYEDGE_API_KEY=""

# Runtime state
OS_TYPE=""
DOMAIN=""
LOG_FILE=""
SCAN_START_TIME=0
SOURCES_USED=()
API_KEYS_ACTIVE=()

# ============================================================
# CROSS-PLATFORM stat mtime (detect once at startup)
# ============================================================
if stat -c '%Y' /dev/null >/dev/null 2>&1; then
    get_mtime() { stat -c '%Y' "$1" 2>/dev/null || printf '0'; }
else
    get_mtime() { stat -f '%m' "$1" 2>/dev/null || printf '0'; }
fi

get_now() { date +%s; }

# ============================================================
# LOGGING
# ============================================================
_log() {
    local level="$1" color="$2"
    shift 2
    local msg="$*"
    local ts
    ts=$(date '+%H:%M:%S')

    # Write to log file without ANSI codes
    [[ -n "$LOG_FILE" ]] && printf '[%s][%s] %s\n' "$ts" "$level" "$msg" >> "$LOG_FILE" 2>/dev/null || true

    case "$level" in
        ERROR|WARN)
            [[ "$QUIET" -eq 0 ]] && printf "${color}[%s]${NC} %s\n" "$level" "$msg" >&2 || true
            ;;
        OK|INFO)
            [[ "$QUIET" -eq 0 ]] && printf "${color}[%s]${NC} %s\n" "$level" "$msg" || true
            ;;
        DEBUG)
            [[ "$VERBOSE" -eq 1 ]] && printf "${CYAN}[DEBUG]${NC} %s\n" "$msg" || true
            ;;
    esac
}

log_info()  { _log "INFO"  "$BLUE"   "$@"; }
log_ok()    { _log "OK"    "$GREEN"  "$@"; }
log_warn()  { _log "WARN"  "$YELLOW" "$@"; }
log_error() { _log "ERROR" "$RED"    "$@"; }
log_debug() { _log "DEBUG" "$CYAN"   "$@"; }

# ============================================================
# SPINNER (stderr, TTY only)
# ============================================================
_spinner_pid=""

spinner_start() {
    [[ "$QUIET" -eq 1 ]] && return
    [[ -t 2 ]] || return
    local msg="$1"
    (
        local i=0
        local chars='|/-\'
        while true; do
            printf '\r\033[K%b[%s]%b %s' "$BLUE" "${chars:$((i % 4)):1}" "$NC" "$msg" >&2
            i=$(( i + 1 ))
            sleep 0.15
        done
    ) &
    _spinner_pid=$!
    disown "$_spinner_pid" 2>/dev/null || true
}

spinner_stop() {
    if [[ -n "$_spinner_pid" ]]; then
        kill "$_spinner_pid" 2>/dev/null || true
        wait "$_spinner_pid" 2>/dev/null || true
        _spinner_pid=""
        printf '\r\033[K' >&2
    fi
}

# ============================================================
# OS DETECTION
# ============================================================
detect_os() {
    case "$(uname -s)" in
        Darwin) OS_TYPE="macos" ;;
        Linux)
            if grep -qi "kali" /etc/os-release 2>/dev/null; then
                OS_TYPE="kali"
            elif grep -qi "ubuntu" /etc/os-release 2>/dev/null; then
                OS_TYPE="ubuntu"
            elif grep -qi "debian" /etc/os-release 2>/dev/null; then
                OS_TYPE="debian"
            elif grep -qi "rhel\|centos\|fedora" /etc/os-release 2>/dev/null; then
                OS_TYPE="rhel"
            elif grep -qi "alpine" /etc/os-release 2>/dev/null; then
                OS_TYPE="alpine"
            else
                OS_TYPE="linux"
            fi
            ;;
        *) OS_TYPE="unknown" ;;
    esac
    log_debug "Detected OS: $OS_TYPE"
}

# ============================================================
# DEPENDENCY CHECK
# ============================================================
check_dependencies() {
    log_info "Checking dependencies..."
    local missing=()

    for dep in curl jq; do
        command -v "$dep" >/dev/null 2>&1 || missing+=("$dep")
    done

    # Need at least one DNS resolver
    if ! command -v dig     >/dev/null 2>&1 && \
       ! command -v drill   >/dev/null 2>&1 && \
       ! command -v host    >/dev/null 2>&1 && \
       ! command -v nslookup >/dev/null 2>&1; then
        missing+=("dig (or drill/host/nslookup)")
    fi

    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Missing required dependencies: ${missing[*]}"
        printf '\nInstall missing packages:\n' >&2
        case "$OS_TYPE" in
            macos)            printf '  brew install curl jq bind\n' >&2 ;;
            kali|ubuntu|debian) printf '  sudo apt-get update && sudo apt-get install curl jq dnsutils\n' >&2 ;;
            rhel)             printf '  sudo yum install curl jq bind-utils\n' >&2 ;;
            alpine)           printf '  apk add curl jq bind-tools\n' >&2 ;;
            *)                printf '  Install curl, jq, and dnsutils with your package manager\n' >&2 ;;
        esac
        exit 1
    fi

    log_ok "All dependencies satisfied"
}

# ============================================================
# DNS RESOLVER — fallback chain: dig → drill → host → nslookup
# ============================================================
resolve_hostname() {
    local h="$1"
    local ip=""
    local IP_RE='^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'

    if command -v dig >/dev/null 2>&1; then
        ip=$(dig +short +time=5 +tries=2 "$h" A 2>/dev/null | grep -E "$IP_RE" | head -1)
    elif command -v drill >/dev/null 2>&1; then
        ip=$(drill "$h" A 2>/dev/null | awk '/^[^;].*[[:space:]]A[[:space:]]/{print $NF}' | grep -E "$IP_RE" | head -1)
    elif command -v host >/dev/null 2>&1; then
        ip=$(host -t A "$h" 2>/dev/null | awk '/has address/{print $NF}' | grep -E "$IP_RE" | head -1)
    elif command -v nslookup >/dev/null 2>&1; then
        ip=$(nslookup "$h" 2>/dev/null | awk '/^Address:/{print $2}' | grep -v '#' | grep -E "$IP_RE" | head -1)
    fi

    printf '%s' "${ip:-}"
}

# ============================================================
# CURL WITH RETRY + HTTP 429 BACKOFF
# Portable: uses -o tmpfile -w '%{http_code}' (no head -n -1)
# ============================================================
curl_with_retry() {
    local url="$1"; shift
    local attempt=1 backoff=5
    local proxy_args=()
    [[ -n "${CURL_PROXY:-}" ]] && proxy_args=(--proxy "$CURL_PROXY")

    while (( attempt <= 3 )); do
        local tmpf
        tmpf=$(mktemp)
        local http_code
        http_code=$(curl -sL \
            -o "$tmpf" \
            -w '%{http_code}' \
            --max-time "$CURL_TIMEOUT" \
            --connect-timeout "$CURL_CONNECT_TIMEOUT" \
            "${proxy_args[@]}" \
            "$@" \
            "$url" 2>/dev/null) || http_code="000"

        case "$http_code" in
            200)
                cat "$tmpf"; rm -f "$tmpf"; return 0
                ;;
            429)
                rm -f "$tmpf"
                log_warn "Rate limited — waiting ${backoff}s (attempt $attempt/3)..."
                sleep "$backoff"; backoff=$(( backoff * 2 ))
                ;;
            5[0-9][0-9])
                rm -f "$tmpf"
                log_debug "Server error $http_code — retrying in ${backoff}s (attempt $attempt/3)..."
                sleep "$backoff"; backoff=$(( backoff * 2 ))
                ;;
            000)
                rm -f "$tmpf"
                log_debug "Network error — retrying in ${backoff}s (attempt $attempt/3)..."
                sleep "$backoff"; backoff=$(( backoff * 2 ))
                ;;
            *)
                rm -f "$tmpf"; return 1
                ;;
        esac
        attempt=$(( attempt + 1 ))
    done
    return 1
}

# ============================================================
# API KEYS CONFIG
# ============================================================
init_keys_config() {
    local config_dir="${HOME}/.config/subdomain_scanner"
    local keys_file="${config_dir}/keys.conf"
    if [[ ! -f "$keys_file" ]]; then
        mkdir -p "$config_dir"
        cat > "$keys_file" << 'KEYSEOF'
# subdomain_scanner API keys configuration
# Uncomment and fill in keys to enable premium data sources.
# All free sources work without any keys — keys unlock enhanced data & higher rate limits.

# Shodan full API (richer port/banner/OS data, replaces InternetDB for resolved IPs)
# SHODAN_API_KEY=your_key_here

# SecurityTrails (subdomain enumeration + DNS history)
# SECURITYTRAILS_API_KEY=your_key_here

# VirusTotal (subdomain enumeration)
# VIRUSTOTAL_API_KEY=your_key_here

# Censys (certificate search, richer than crt.sh)
# CENSYS_API_ID=your_id_here
# CENSYS_API_SECRET=your_secret_here

# BinaryEdge (subdomain enumeration + port data)
# BINARYEDGE_API_KEY=your_key_here
KEYSEOF
        log_debug "Created API keys template: $keys_file"
    fi
}

load_api_keys() {
    local keys_file="$1"
    [[ -f "$keys_file" ]] || return 0

    # Safe parse: only honour lines matching KNOWN_KEY=value (no eval/source)
    while IFS='=' read -r key val; do
        [[ "$key" =~ ^[[:space:]]*# ]] && continue
        [[ -z "${key// /}" ]]          && continue
        # Trim leading/trailing whitespace from value
        val="${val#"${val%%[! ]*}"}"
        val="${val%"${val##*[! ]}"}"
        [[ -z "$val" ]] && continue
        case "$key" in
            SHODAN_API_KEY)         SHODAN_API_KEY="$val" ;;
            SECURITYTRAILS_API_KEY) SECURITYTRAILS_API_KEY="$val" ;;
            VIRUSTOTAL_API_KEY)     VIRUSTOTAL_API_KEY="$val" ;;
            CENSYS_API_ID)          CENSYS_API_ID="$val" ;;
            CENSYS_API_SECRET)      CENSYS_API_SECRET="$val" ;;
            BINARYEDGE_API_KEY)     BINARYEDGE_API_KEY="$val" ;;
        esac
    done < "$keys_file"

    [[ -n "$SHODAN_API_KEY" ]]         && API_KEYS_ACTIVE+=("shodan")
    [[ -n "$SECURITYTRAILS_API_KEY" ]] && API_KEYS_ACTIVE+=("securitytrails")
    [[ -n "$VIRUSTOTAL_API_KEY" ]]     && API_KEYS_ACTIVE+=("virustotal")
    [[ -n "$CENSYS_API_ID" ]]          && API_KEYS_ACTIVE+=("censys")
    [[ -n "$BINARYEDGE_API_KEY" ]]     && API_KEYS_ACTIVE+=("binaryedge")

    if [[ ${#API_KEYS_ACTIVE[@]} -gt 0 ]]; then
        log_ok "API keys loaded: ${API_KEYS_ACTIVE[*]}"
    fi
}

# ============================================================
# CACHE
# ============================================================
_cache_path_for_ip() {
    local ip="$1"
    local octet="${ip%%.*}"
    printf '%s/internetdb/%s/%s.json' "$CACHE_DIR" "$octet" "$ip"
}

cache_get() {
    local cache_file="$1"
    [[ "$NO_CACHE" -eq 1 ]] && return 1
    [[ -f "$cache_file" ]]  || return 1

    local now mtime age
    now=$(get_now)
    mtime=$(get_mtime "$cache_file")
    age=$(( now - mtime ))

    if (( age < CACHE_TTL )); then
        cat "$cache_file"
        return 0
    fi
    return 1
}

cache_set() {
    local cache_file="$1"
    [[ "$NO_CACHE" -eq 1 ]] && cat >/dev/null && return 0
    mkdir -p "$(dirname "$cache_file")"
    local tmpf
    tmpf=$(mktemp "$(dirname "$cache_file")/.tmp.XXXXXX")
    cat > "$tmpf"
    mv "$tmpf" "$cache_file"
}

# ============================================================
# PARALLEL JOB POOL — bash 3.2 compatible FIFO semaphore
# ============================================================
_JOB_POOL_FD=9

init_job_pool() {
    local max_jobs="$1"
    local fifo
    fifo=$(mktemp -u)
    mkfifo "$fifo"
    eval "exec ${_JOB_POOL_FD}<>'${fifo}'"
    rm -f "$fifo"
    local i
    for (( i=0; i<max_jobs; i++ )); do printf 'x\n' >&"$_JOB_POOL_FD"; done
}

acquire_slot() { local _t; read -r _t <&"$_JOB_POOL_FD"; }
release_slot() { printf 'x\n' >&"$_JOB_POOL_FD"; }

close_job_pool() {
    eval "exec ${_JOB_POOL_FD}>&-" 2>/dev/null || true
    eval "exec ${_JOB_POOL_FD}<&-" 2>/dev/null || true
}

# ============================================================
# CSV HELPER (bash 3.2 compatible parameter expansion)
# ============================================================
csv_escape() { printf '"%s"' "${1//\"/\"\"}"; }

# ============================================================
# FREE SUBDOMAIN SOURCES
# ============================================================

discover_certsh() {
    local domain="$1" outfile="$2"
    local response
    response=$(curl_with_retry "https://crt.sh/?q=%25.${domain}&output=json") || { > "$outfile"; return 0; }
    printf '%s\n' "$response" \
        | jq -r '.[].name_value' 2>/dev/null \
        | sed 's/\*\.//g' \
        | grep -E "^[a-zA-Z0-9._-]+$" \
        | sort -u > "$outfile" 2>/dev/null || true
    log_debug "crt.sh: $(wc -l < "$outfile" | tr -d ' ') entries"
}

discover_anubis() {
    local domain="$1" outfile="$2"
    local response
    response=$(curl_with_retry "https://anubisdb.com/anubis/subdomains/${domain}") || { > "$outfile"; return 0; }
    printf '%s\n' "$response" \
        | jq -r '.[]?' 2>/dev/null \
        | grep -E "^[a-zA-Z0-9._-]+$" \
        | sort -u > "$outfile" 2>/dev/null || true
    log_debug "AnubisDB: $(wc -l < "$outfile" | tr -d ' ') entries"
}

discover_hackertarget() {
    local domain="$1" outfile="$2"
    local response
    response=$(curl_with_retry "https://api.hackertarget.com/hostsearch/?q=${domain}") || { > "$outfile"; return 0; }
    printf '%s\n' "$response" \
        | grep -v "API count\|error\|<" \
        | awk -F',' '{print $1}' \
        | grep -E "^[a-zA-Z0-9._-]+$" \
        | sort -u > "$outfile" 2>/dev/null || true
    log_debug "HackerTarget: $(wc -l < "$outfile" | tr -d ' ') entries"
}

discover_alienvault() {
    local domain="$1" outfile="$2"
    local response
    response=$(curl_with_retry "https://otx.alienvault.com/api/v1/indicators/domain/${domain}/passive_dns") || { > "$outfile"; return 0; }
    printf '%s\n' "$response" \
        | jq -r '.passive_dns[]?.hostname' 2>/dev/null \
        | grep -E "^[a-zA-Z0-9._-]+$" \
        | sort -u > "$outfile" 2>/dev/null || true
    log_debug "AlienVault OTX: $(wc -l < "$outfile" | tr -d ' ') entries"
}

discover_bufferover() {
    local domain="$1" outfile="$2"
    local response
    response=$(curl_with_retry "https://tls.bufferover.run/dns?q=.${domain}") || { > "$outfile"; return 0; }
    printf '%s\n' "$response" \
        | jq -r '.Results[]?' 2>/dev/null \
        | awk -F',' '{print $NF}' \
        | sed 's/\.$//g' \
        | grep -E "^[a-zA-Z0-9._-]+$" \
        | sort -u > "$outfile" 2>/dev/null || true
    log_debug "BufferOver: $(wc -l < "$outfile" | tr -d ' ') entries"
}

discover_urlscan() {
    local domain="$1" outfile="$2"
    local response
    response=$(curl_with_retry "https://urlscan.io/api/v1/search/?q=domain:${domain}&size=10000") || { > "$outfile"; return 0; }
    printf '%s\n' "$response" \
        | jq -r '.results[]?.page.domain' 2>/dev/null \
        | grep -E "^[a-zA-Z0-9._-]+$" \
        | sort -u > "$outfile" 2>/dev/null || true
    log_debug "URLScan.io: $(wc -l < "$outfile" | tr -d ' ') entries"
}

discover_wayback() {
    local domain="$1" outfile="$2"
    local response
    response=$(curl_with_retry \
        "https://web.archive.org/cdx/search/cdx?url=*.${domain}&output=text&fl=original&collapse=urlkey&limit=50000") \
        || { > "$outfile"; return 0; }
    printf '%s\n' "$response" \
        | awk -F/ '{print $3}' \
        | awk -F: '{print $1}' \
        | grep -E "^[a-zA-Z0-9._-]+$" \
        | sort -u > "$outfile" 2>/dev/null || true
    log_debug "Wayback CDX: $(wc -l < "$outfile" | tr -d ' ') entries"
}

# ============================================================
# API-KEY-ENHANCED SUBDOMAIN SOURCES
# ============================================================

discover_securitytrails() {
    local domain="$1" outfile="$2"
    [[ -z "${SECURITYTRAILS_API_KEY:-}" ]] && { > "$outfile"; return 0; }
    local response
    response=$(curl_with_retry \
        "https://api.securitytrails.com/v1/domain/${domain}/subdomains?children_only=false&include_inactive=true" \
        -H "APIKEY: ${SECURITYTRAILS_API_KEY}" \
        -H "Accept: application/json") || { > "$outfile"; return 0; }
    printf '%s\n' "$response" \
        | jq -r '.subdomains[]?' 2>/dev/null \
        | sed "s/\$/.${domain}/" \
        | grep -E "^[a-zA-Z0-9._-]+$" \
        | sort -u > "$outfile" 2>/dev/null || true
    log_debug "SecurityTrails: $(wc -l < "$outfile" | tr -d ' ') entries"
}

discover_virustotal() {
    local domain="$1" outfile="$2"
    [[ -z "${VIRUSTOTAL_API_KEY:-}" ]] && { > "$outfile"; return 0; }
    > "$outfile"
    local cursor="" url response
    while true; do
        url="https://www.virustotal.com/api/v3/domains/${domain}/subdomains?limit=40"
        [[ -n "$cursor" ]] && url="${url}&cursor=${cursor}"
        response=$(curl_with_retry "$url" -H "x-apikey: ${VIRUSTOTAL_API_KEY}") || break
        printf '%s\n' "$response" \
            | jq -r '.data[]?.id' 2>/dev/null \
            | grep -E "^[a-zA-Z0-9._-]+$" >> "$outfile" 2>/dev/null || true
        cursor=$(printf '%s\n' "$response" | jq -r '.meta.cursor // empty' 2>/dev/null)
        [[ -z "$cursor" ]] && break
    done
    log_debug "VirusTotal: $(wc -l < "$outfile" | tr -d ' ') entries"
}

discover_censys() {
    local domain="$1" outfile="$2"
    [[ -z "${CENSYS_API_ID:-}" ]] || [[ -z "${CENSYS_API_SECRET:-}" ]] && { > "$outfile"; return 0; }
    local response
    response=$(curl_with_retry \
        "https://search.censys.io/api/v2/certificates/search?q=parsed.names%3A${domain}&per_page=100&fields=parsed.names" \
        -u "${CENSYS_API_ID}:${CENSYS_API_SECRET}") || { > "$outfile"; return 0; }
    printf '%s\n' "$response" \
        | jq -r '.result.hits[]?.parsed.names[]?' 2>/dev/null \
        | sed 's/\*\.//g' \
        | grep -E "^[a-zA-Z0-9._-]+$" \
        | sort -u > "$outfile" 2>/dev/null || true
    log_debug "Censys: $(wc -l < "$outfile" | tr -d ' ') entries"
}

discover_binaryedge() {
    local domain="$1" outfile="$2"
    [[ -z "${BINARYEDGE_API_KEY:-}" ]] && { > "$outfile"; return 0; }
    local response
    response=$(curl_with_retry \
        "https://api.binaryedge.io/v2/query/domains/subdomain/${domain}" \
        -H "X-Key: ${BINARYEDGE_API_KEY}") || { > "$outfile"; return 0; }
    printf '%s\n' "$response" \
        | jq -r '.events[]?' 2>/dev/null \
        | grep -E "^[a-zA-Z0-9._-]+$" \
        | sort -u > "$outfile" 2>/dev/null || true
    log_debug "BinaryEdge: $(wc -l < "$outfile" | tr -d ' ') entries"
}

# ============================================================
# DISCOVER SUBDOMAINS — orchestrator (all sources in parallel)
# ============================================================
discover_subdomains() {
    local domain="$1" output_file="$2"
    local tmpdir
    tmpdir=$(mktemp -d)

    log_info "Running subdomain discovery across all sources in parallel..."
    spinner_start "Querying sources"

    # Free sources — always run
    discover_certsh       "$domain" "${tmpdir}/certsh.txt"       &
    discover_anubis       "$domain" "${tmpdir}/anubis.txt"        &
    discover_hackertarget "$domain" "${tmpdir}/hackertarget.txt"  &
    discover_alienvault   "$domain" "${tmpdir}/alienvault.txt"    &
    discover_bufferover   "$domain" "${tmpdir}/bufferover.txt"    &
    discover_urlscan      "$domain" "${tmpdir}/urlscan.txt"       &
    discover_wayback      "$domain" "${tmpdir}/wayback.txt"       &

    # API-key-enhanced sources (each silently skips if no key set)
    discover_securitytrails "$domain" "${tmpdir}/securitytrails.txt" &
    discover_virustotal    "$domain"  "${tmpdir}/virustotal.txt"     &
    discover_censys        "$domain"  "${tmpdir}/censys.txt"         &
    discover_binaryedge    "$domain"  "${tmpdir}/binaryedge.txt"     &

    wait
    spinner_stop

    # Track which sources produced results
    local src
    for src in certsh anubis hackertarget alienvault bufferover urlscan wayback \
                securitytrails virustotal censys binaryedge; do
        local f="${tmpdir}/${src}.txt"
        if [[ -f "$f" ]] && [[ -s "$f" ]]; then
            SOURCES_USED+=("$src")
        fi
    done

    # Seed with root domain, then merge all source results
    printf '%s\n' "$domain" > "$output_file"
    cat "${tmpdir}"/*.txt >> "$output_file" 2>/dev/null || true

    # Keep only hostnames that end with .domain (or equal domain), deduplicate
    local DOMAIN_RE
    DOMAIN_RE="(^|\\.)(${domain//./\\.})$"
    grep -E "$DOMAIN_RE" "$output_file" 2>/dev/null | sort -u > "${output_file}.tmp" || true
    mv "${output_file}.tmp" "$output_file"

    rm -rf "$tmpdir"

    local total
    total=$(wc -l < "$output_file" | tr -d ' ')
    log_ok "Total unique subdomains: ${total} (sources used: ${SOURCES_USED[*]:-none})"
}

# ============================================================
# RESOLVE IPs — parallel with FIFO semaphore
# ============================================================
resolve_ips() {
    local subdomains_file="$1" output_file="$2"
    local tmpdir counter_file
    tmpdir=$(mktemp -d)
    counter_file=$(mktemp)

    local total
    total=$(wc -l < "$subdomains_file" | tr -d ' ')
    log_info "Resolving ${total} subdomains (${THREADS} threads)..."

    > "$output_file"
    init_job_pool "$THREADS"

    local idx=0
    while IFS= read -r subdomain; do
        [[ -z "$subdomain" ]] && continue
        local frag="${tmpdir}/r_${idx}"
        idx=$(( idx + 1 ))

        acquire_slot
        (
            local ip
            ip=$(resolve_hostname "$subdomain")
            local IP_RE='^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
            if [[ -n "$ip" ]] && [[ "$ip" =~ $IP_RE ]]; then
                printf '%s,%s\n' "$subdomain" "$ip" > "$frag"
                log_debug "  $subdomain -> $ip"
            fi
            printf 'x' >> "$counter_file"
            if [[ "$QUIET" -eq 0 ]] && [[ -t 2 ]]; then
                local done_n
                done_n=$(wc -c < "$counter_file" | tr -d ' ')
                printf '\r\033[K%b[INFO]%b Resolving: %d/%d' "$BLUE" "$NC" "$done_n" "$total" >&2
            fi
            release_slot
        ) &
    done < "$subdomains_file"

    wait
    close_job_pool
    [[ "$QUIET" -eq 0 ]] && [[ -t 2 ]] && printf '\r\033[K' >&2

    cat "${tmpdir}"/r_* 2>/dev/null | sort -u >> "$output_file" || true
    rm -rf "$tmpdir" "$counter_file"

    local count
    count=$(wc -l < "$output_file" | tr -d ' ')
    log_ok "Resolved ${count} subdomains to IP addresses"
}

# ============================================================
# INTERNETDB QUERY (free, with caching)
# ============================================================
query_internetdb() {
    local ip="$1"
    local cache_file
    cache_file=$(_cache_path_for_ip "$ip")

    local cached
    if cached=$(cache_get "$cache_file" 2>/dev/null) && [[ -n "$cached" ]]; then
        log_debug "Cache hit: $ip"
        printf '%s\n' "$cached"
        return 0
    fi

    local response
    response=$(curl_with_retry "https://internetdb.shodan.io/${ip}") || return 1

    if printf '%s\n' "$response" | jq -e . >/dev/null 2>&1; then
        printf '%s\n' "$response" | cache_set "$cache_file"
        printf '%s\n' "$response"
        return 0
    fi
    return 1
}

# ============================================================
# SHODAN FULL API (when SHODAN_API_KEY is set, else falls back to InternetDB)
# ============================================================
query_port_data() {
    local ip="$1"

    if [[ -n "${SHODAN_API_KEY:-}" ]]; then
        local cache_file="${CACHE_DIR}/shodan/${ip%%.*}/${ip}.json"
        local cached
        if cached=$(cache_get "$cache_file" 2>/dev/null) && [[ -n "$cached" ]]; then
            log_debug "Shodan cache hit: $ip"
            printf '%s\n' "$cached"
            return 0
        fi

        local response
        response=$(curl_with_retry \
            "https://api.shodan.io/shodan/host/${ip}?key=${SHODAN_API_KEY}") || true

        if [[ -n "${response:-}" ]] && \
           printf '%s\n' "$response" | jq -e . >/dev/null 2>&1 && \
           ! printf '%s\n' "$response" | jq -e '.error' >/dev/null 2>&1; then
            printf '%s\n' "$response" | cache_set "$cache_file"
            printf '%s\n' "$response"
            return 0
        fi
        log_debug "Shodan API error for $ip — falling back to InternetDB"
    fi

    query_internetdb "$ip"
}

# ============================================================
# PARSE PORT DATA — handles both InternetDB and Shodan full API response formats
# Outputs tab-separated: ports\thostnames\ttags\tvulns\tcpes
# ============================================================
parse_port_data() {
    local response="$1"

    local ports hostnames tags vulns cpes

    # Shodan full API has a 'data' array; InternetDB does not
    if printf '%s\n' "$response" | jq -e '.data' >/dev/null 2>&1; then
        ports=$(printf '%s\n' "$response"     | jq -r '.ports[]?'                         2>/dev/null | sort -n | tr '\n' ',' | sed 's/,$//')
        hostnames=$(printf '%s\n' "$response" | jq -r '.hostnames[]?'                     2>/dev/null | tr '\n' ',' | sed 's/,$//')
        tags=$(printf '%s\n' "$response"      | jq -r '.tags[]?'                          2>/dev/null | tr '\n' ',' | sed 's/,$//')
        vulns=$(printf '%s\n' "$response"     | jq -r '.vulns | if type=="object" then keys[] else .[]? end' 2>/dev/null | tr '\n' ',' | sed 's/,$//')
        cpes=$(printf '%s\n' "$response"      | jq -r '.data[]?.cpe[]?'                   2>/dev/null | sort -u | tr '\n' ',' | sed 's/,$//')
    else
        ports=$(printf '%s\n' "$response"     | jq -r '.ports[]?'     2>/dev/null | sort -n | tr '\n' ',' | sed 's/,$//')
        hostnames=$(printf '%s\n' "$response" | jq -r '.hostnames[]?' 2>/dev/null | tr '\n' ',' | sed 's/,$//')
        tags=$(printf '%s\n' "$response"      | jq -r '.tags[]?'      2>/dev/null | tr '\n' ',' | sed 's/,$//')
        vulns=$(printf '%s\n' "$response"     | jq -r '.vulns[]?'     2>/dev/null | tr '\n' ',' | sed 's/,$//')
        cpes=$(printf '%s\n' "$response"      | jq -r '.cpes[]?'      2>/dev/null | tr '\n' ',' | sed 's/,$//')
    fi

    printf '%s\t%s\t%s\t%s\t%s' \
        "${ports:-}" "${hostnames:-}" "${tags:-}" "${vulns:-}" "${cpes:-}"
}

# ============================================================
# GET PORT INFO — parallel with FIFO semaphore
# ============================================================
get_port_info() {
    local ips_file="$1" output_file="$2" json_tmpdir="$3"
    local tmpdir counter_file
    tmpdir=$(mktemp -d)
    counter_file=$(mktemp)

    local total
    total=$(wc -l < "$ips_file" | tr -d ' ')
    log_info "Querying port data for ${total} IPs (${THREADS} threads)..."

    printf 'Subdomain,IP,Ports,Hostnames,Tags,Vulns,CPEs\n' > "$output_file"

    init_job_pool "$THREADS"

    local idx=0
    while IFS=',' read -r subdomain ip; do
        [[ -z "$ip" ]] && continue
        local csv_frag="${tmpdir}/csv_${idx}"
        local json_frag="${json_tmpdir}/json_${idx}"
        idx=$(( idx + 1 ))

        acquire_slot
        (
            log_debug "Checking $ip ($subdomain)..."
            local data ports hostnames tags vulns cpes parsed

            if data=$(query_port_data "$ip") && [[ -n "$data" ]]; then
                parsed=$(parse_port_data "$data")
                ports=$(     printf '%s' "$parsed" | awk -F'\t' '{print $1}')
                hostnames=$( printf '%s' "$parsed" | awk -F'\t' '{print $2}')
                tags=$(      printf '%s' "$parsed" | awk -F'\t' '{print $3}')
                vulns=$(     printf '%s' "$parsed" | awk -F'\t' '{print $4}')
                cpes=$(      printf '%s' "$parsed" | awk -F'\t' '{print $5}')

                printf '%s,%s,%s,%s,%s,%s,%s\n' \
                    "$(csv_escape "$subdomain")" \
                    "$(csv_escape "$ip")" \
                    "$(csv_escape "${ports:-None}")" \
                    "$(csv_escape "${hostnames:-None}")" \
                    "$(csv_escape "${tags:-None}")" \
                    "$(csv_escape "${vulns:-None}")" \
                    "$(csv_escape "${cpes:-None}")" > "$csv_frag"

                # JSON fragment — build port/vuln arrays from raw response
                local ports_json hostnames_json tags_json vulns_json cpes_json
                ports_json=$(     printf '%s\n' "$data" | jq '.ports // []'      2>/dev/null || printf '[]')
                hostnames_json=$( printf '%s\n' "$data" | jq '.hostnames // []'  2>/dev/null || printf '[]')
                tags_json=$(      printf '%s\n' "$data" | jq '.tags // []'       2>/dev/null || printf '[]')
                vulns_json=$(     printf '%s\n' "$data" | jq \
                    'if .vulns then (.vulns | if type=="object" then keys else . end) else [] end' \
                    2>/dev/null || printf '[]')
                cpes_json=$(      printf '%s\n' "$data" | jq '.cpes // []'       2>/dev/null || printf '[]')

                jq -n \
                    --arg sub       "$subdomain" \
                    --arg ip        "$ip" \
                    --argjson ports     "$ports_json" \
                    --argjson hostnames "$hostnames_json" \
                    --argjson tags      "$tags_json" \
                    --argjson vulns     "$vulns_json" \
                    --argjson cpes      "$cpes_json" \
                    '{subdomain:$sub,ip:$ip,ports:$ports,hostnames:$hostnames,tags:$tags,vulns:$vulns,cpes:$cpes}' \
                    > "$json_frag" 2>/dev/null || true
            else
                printf '%s,%s,%s,%s,%s,%s,%s\n' \
                    "$(csv_escape "$subdomain")" \
                    "$(csv_escape "$ip")" \
                    '"No data"' '"No data"' '"No data"' '"No data"' '"No data"' > "$csv_frag"

                jq -n \
                    --arg sub "$subdomain" --arg ip "$ip" \
                    '{subdomain:$sub,ip:$ip,ports:[],hostnames:[],tags:[],vulns:[],cpes:[]}' \
                    > "$json_frag" 2>/dev/null || true
            fi

            printf 'x' >> "$counter_file"
            if [[ "$QUIET" -eq 0 ]] && [[ -t 2 ]]; then
                local done_n
                done_n=$(wc -c < "$counter_file" | tr -d ' ')
                printf '\r\033[K%b[INFO]%b Port data: %d/%d IPs' "$BLUE" "$NC" "$done_n" "$total" >&2
            fi
            sleep "$API_DELAY"
            release_slot
        ) &
    done < "$ips_file"

    wait
    close_job_pool
    [[ "$QUIET" -eq 0 ]] && [[ -t 2 ]] && printf '\r\033[K' >&2

    cat "${tmpdir}"/csv_* 2>/dev/null | sort -t',' -k1,1 >> "$output_file" || true
    rm -rf "$tmpdir" "$counter_file"

    log_ok "Port data saved to $(basename "$output_file")"
}

# ============================================================
# JSON OUTPUT
# ============================================================
generate_json_output() {
    local domain="$1" subdomains_file="$2" ips_file="$3"
    local json_tmpdir="$4" json_file="$5" scan_start="$6"

    local duration sub_count ip_count
    duration=$(( $(get_now) - scan_start ))
    sub_count=$(wc -l < "$subdomains_file" | tr -d ' ')
    ip_count=$(wc -l < "$ips_file" | tr -d ' ')

    local results_json
    if ls "${json_tmpdir}"/json_* >/dev/null 2>&1; then
        results_json=$(jq -s '.' "${json_tmpdir}"/json_* 2>/dev/null || printf '[]')
    else
        results_json='[]'
    fi

    local ip_with_data
    ip_with_data=$(printf '%s\n' "$results_json" \
        | jq '[.[] | select(.ports | length > 0)] | length' 2>/dev/null || printf '0')

    local sources_json="[]" keys_json="[]"
    if [[ ${#SOURCES_USED[@]} -gt 0 ]]; then
        sources_json=$(printf '%s\n' "${SOURCES_USED[@]}" | jq -R '.' | jq -s '.')
    fi
    if [[ ${#API_KEYS_ACTIVE[@]} -gt 0 ]]; then
        keys_json=$(printf '%s\n' "${API_KEYS_ACTIVE[@]}" | jq -R '.' | jq -s '.')
    fi

    jq -n \
        --arg domain    "$domain" \
        --arg timestamp "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
        --argjson duration     "$duration" \
        --argjson threads      "$THREADS" \
        --argjson sub_count    "$sub_count" \
        --argjson ip_count     "$ip_count" \
        --argjson ip_with_data "$ip_with_data" \
        --argjson sources      "$sources_json" \
        --argjson keys         "$keys_json" \
        --argjson results      "$results_json" \
        '{
            scan: {
                domain: $domain,
                timestamp: $timestamp,
                duration_seconds: $duration,
                threads: $threads,
                sources_used: $sources,
                api_keys_active: $keys,
                stats: {
                    subdomains_found: $sub_count,
                    ips_resolved: $ip_count,
                    ips_with_port_data: $ip_with_data
                }
            },
            results: $results
        }' > "$json_file"

    log_ok "JSON output: $(basename "$json_file")"
}

# ============================================================
# MARKDOWN SUMMARY
# ============================================================
create_summary() {
    local domain="$1" subdomains_file="$2" ips_file="$3"
    local ports_file="$4" summary_file="$5" scan_start="$6"

    local duration sub_count ip_count port_count
    duration=$(( $(get_now) - scan_start ))
    sub_count=$(wc -l < "$subdomains_file" | tr -d ' ')
    ip_count=$(wc -l < "$ips_file" | tr -d ' ')
    port_count=0
    if [[ -f "$ports_file" ]]; then
        port_count=$(tail -n +2 "$ports_file" | grep -vc '"No data"' | tr -d ' ' || printf '0')
    fi

    {
        printf '# Subdomain Discovery & Port Reconnaissance Report\n\n'
        printf '**Domain:** %s  \n' "$domain"
        printf '**Generated:** %s  \n' "$(date -u '+%Y-%m-%d %H:%M:%S UTC')"
        printf '**Duration:** %ds  \n' "$duration"
        printf '**Threads:** %d  \n' "$THREADS"
        printf '\n## Summary\n\n'
        printf '| Metric | Count |\n|--------|-------|\n'
        printf '| Subdomains discovered | %s |\n' "$sub_count"
        printf '| IPs resolved | %s |\n' "$ip_count"
        printf '| IPs with port data | %s |\n' "$port_count"
        printf '\n## Sources Used\n\n'
        if [[ ${#SOURCES_USED[@]} -gt 0 ]]; then
            local src
            for src in "${SOURCES_USED[@]}"; do printf '- %s\n' "$src"; done
        else
            printf '- (no sources returned results)\n'
        fi
        if [[ ${#API_KEYS_ACTIVE[@]} -gt 0 ]]; then
            printf '\n**API keys active:** %s\n' "${API_KEYS_ACTIVE[*]}"
        fi
        printf '\n## Subdomains\n\n'
        while IFS= read -r sub; do printf '- %s\n' "$sub"; done < "$subdomains_file"
        printf '\n## IP Addresses\n\n'
        if [[ -s "$ips_file" ]]; then
            while IFS=',' read -r sub ip; do
                printf '- **%s** → %s\n' "$sub" "$ip"
            done < "$ips_file"
        else
            printf '_No IPs resolved_\n'
        fi
        printf '\n## Port Data\n\n'
        if [[ -f "$ports_file" ]] && [[ -s "$ports_file" ]]; then
            cat "$ports_file"
        else
            printf '_No port data collected_\n'
        fi
    } > "$summary_file"

    log_ok "Summary: $(basename "$summary_file")"
}

# ============================================================
# USAGE
# ============================================================
usage() {
    cat << EOF
${BOLD}subdomain_scanner.sh${NC} — Passive Subdomain Discovery & Port Reconnaissance

${BOLD}Usage:${NC}
  $0 [OPTIONS] <domain>

${BOLD}Options:${NC}
  -o, --output DIR       Output directory (default: recon_DOMAIN_TIMESTAMP)
  -n, --threads N        Parallel worker threads (default: 5)
  -T, --timeout SECS     curl max-time per request in seconds (default: 30)
  -d, --delay SECS       Delay between port API requests (default: 0.5)
  -f, --format FORMAT    Output format: all | json | csv | md (default: all)
  -v, --verbose          Show debug/verbose output
  -q, --quiet            Suppress all non-error output
  -p, --proxy URL        HTTP/HTTPS proxy for all outbound requests
  -C, --no-cache         Disable result caching
  -k, --keys FILE        Path to API keys config file
  -h, --help             Show this help

${BOLD}Free subdomain sources (always active):${NC}
  crt.sh, AnubisDB, HackerTarget, AlienVault OTX,
  BufferOver, URLScan.io, Wayback Machine CDX

${BOLD}API-key-enhanced sources (optional):${NC}
  Shodan, SecurityTrails, VirusTotal, Censys, BinaryEdge
  Configure at: ~/.config/subdomain_scanner/keys.conf

${BOLD}Cache:${NC}    ~/.cache/subdomain_scanner/ (24h TTL, disable with -C)
${BOLD}Log file:${NC} <output_dir>/scan.log

${BOLD}Supported platforms:${NC}
  macOS 13+ (bash 3.2+), Debian 12, Ubuntu 22/24, Kali Linux

${BOLD}Examples:${NC}
  $0 example.com
  $0 -v -n 10 -f json example.com
  $0 -q -o /tmp/scan -f csv example.com
  $0 -k ~/.config/subdomain_scanner/keys.conf -f all example.com
  $0 -p http://127.0.0.1:8080 example.com
EOF
}

# ============================================================
# ARGUMENT PARSING — bash 3.2 compatible (getopts + long-option shim)
# ============================================================
parse_args() {
    # Pre-process GNU-style long options into their short equivalents
    local args=()
    for arg in "$@"; do
        case "$arg" in
            --output)   args+=("-o") ;;
            --threads)  args+=("-n") ;;
            --timeout)  args+=("-T") ;;
            --delay)    args+=("-d") ;;
            --format)   args+=("-f") ;;
            --verbose)  args+=("-v") ;;
            --quiet)    args+=("-q") ;;
            --proxy)    args+=("-p") ;;
            --no-cache) args+=("-C") ;;
            --keys)     args+=("-k") ;;
            --help)     args+=("-h") ;;
            *)          args+=("$arg") ;;
        esac
    done
    set -- "${args[@]}"

    while getopts ":o:n:T:d:f:vqp:Ck:h" opt; do
        case "$opt" in
            o) OUTPUT_DIR="$OPTARG" ;;
            n) THREADS="$OPTARG" ;;
            T) CURL_TIMEOUT="$OPTARG" ;;
            d) API_DELAY="$OPTARG" ;;
            f) OUTPUT_FORMAT="$OPTARG" ;;
            v) VERBOSE=1 ;;
            q) QUIET=1 ;;
            p) CURL_PROXY="$OPTARG" ;;
            C) NO_CACHE=1 ;;
            k) API_KEYS_FILE="$OPTARG" ;;
            h) usage; exit 0 ;;
            :) log_error "Option -$OPTARG requires an argument"; usage; exit 1 ;;
            ?) log_error "Unknown option: -$OPTARG"; usage; exit 1 ;;
        esac
    done
    shift $(( OPTIND - 1 ))

    if [[ $# -eq 0 ]]; then
        log_error "A domain argument is required"
        usage
        exit 1
    fi

    DOMAIN="$1"

    # Validate domain — ERE pattern stored in variable (bash 3.2 safe)
    local DOMAIN_RE='^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    if ! [[ "$DOMAIN" =~ $DOMAIN_RE ]]; then
        log_error "Invalid domain format: $DOMAIN"
        exit 1
    fi

    # Resolve OUTPUT_DIR to an absolute path (never cd into it)
    if [[ -z "$OUTPUT_DIR" ]]; then
        OUTPUT_DIR="$(pwd)/recon_${DOMAIN}_$(date +%Y%m%d_%H%M%S)"
    else
        case "$OUTPUT_DIR" in
            /*) ;;                              # already absolute
            *)  OUTPUT_DIR="$(pwd)/${OUTPUT_DIR}" ;;
        esac
    fi
}

# ============================================================
# MAIN
# ============================================================
main() {
    detect_os
    parse_args "$@"
    check_dependencies
    init_keys_config
    load_api_keys "$API_KEYS_FILE"

    SCAN_START_TIME=$(get_now)
    mkdir -p "$OUTPUT_DIR"
    LOG_FILE="${OUTPUT_DIR}/scan.log"

    local json_tmpdir
    json_tmpdir=$(mktemp -d)

    printf '\n'
    log_info "Starting passive reconnaissance for: ${BOLD}${DOMAIN}${NC}"
    log_info "Output directory : $OUTPUT_DIR"
    log_info "Threads          : $THREADS"
    log_info "Format           : $OUTPUT_FORMAT"
    [[ -n "$CURL_PROXY" ]] && log_info "Proxy: $CURL_PROXY"
    printf '\n'

    local subdomains_file="${OUTPUT_DIR}/subdomains.txt"
    local ips_file="${OUTPUT_DIR}/subdomains_with_ips.csv"
    local ports_file="${OUTPUT_DIR}/ports_and_services.csv"
    local summary_file="${OUTPUT_DIR}/summary.md"
    local json_file="${OUTPUT_DIR}/results.json"

    # Step 1 — Subdomain discovery
    discover_subdomains "$DOMAIN" "$subdomains_file"
    printf '\n'

    # Step 2 — IP resolution
    if [[ -s "$subdomains_file" ]]; then
        resolve_ips "$subdomains_file" "$ips_file"
        printf '\n'
    else
        log_warn "No subdomains found — skipping resolution"
        > "$ips_file"
    fi

    # Step 3 — Port data (skip for md-only format)
    if [[ -s "$ips_file" ]] && [[ "$OUTPUT_FORMAT" != "md" ]]; then
        get_port_info "$ips_file" "$ports_file" "$json_tmpdir"
        printf '\n'
    fi

    # Step 4 — Generate requested output formats
    case "$OUTPUT_FORMAT" in
        json)
            generate_json_output "$DOMAIN" "$subdomains_file" "$ips_file" \
                "$json_tmpdir" "$json_file" "$SCAN_START_TIME"
            ;;
        csv)
            : # ports_and_services.csv already written in step 3
            ;;
        md)
            create_summary "$DOMAIN" "$subdomains_file" "$ips_file" \
                "$ports_file" "$summary_file" "$SCAN_START_TIME"
            ;;
        all|*)
            create_summary "$DOMAIN" "$subdomains_file" "$ips_file" \
                "$ports_file" "$summary_file" "$SCAN_START_TIME"
            generate_json_output "$DOMAIN" "$subdomains_file" "$ips_file" \
                "$json_tmpdir" "$json_file" "$SCAN_START_TIME"
            ;;
    esac

    rm -rf "$json_tmpdir"

    # Final report
    local duration=$(( $(get_now) - SCAN_START_TIME ))
    printf '\n'
    log_ok "Reconnaissance complete in ${duration}s"
    printf '\n'
    printf '%bResults:%b %s\n' "$BOLD" "$NC" "$OUTPUT_DIR"
    [[ -f "$subdomains_file" ]] && printf '  %-30s (%s subdomains)\n' "subdomains.txt"          "$(wc -l < "$subdomains_file" | tr -d ' ')"
    [[ -f "$ips_file" ]]        && printf '  %-30s (%s resolved)\n'   "subdomains_with_ips.csv" "$(wc -l < "$ips_file" | tr -d ' ')"
    [[ -f "$ports_file" ]]      && printf '  %-30s\n' "ports_and_services.csv"
    [[ -f "$summary_file" ]]    && printf '  %-30s\n' "summary.md"
    [[ -f "$json_file" ]]       && printf '  %-30s\n' "results.json"
    printf '  %-30s\n' "scan.log"

    if [[ -f "$ports_file" ]]; then
        local vuln_count
        vuln_count=$(grep -c 'CVE-' "$ports_file" 2>/dev/null | tr -d ' ' || printf '0')
        if (( vuln_count > 0 )); then
            printf '\n'
            log_warn "Potential vulnerabilities detected in ${vuln_count} entries — review ports_and_services.csv"
        fi
    fi
}

# Clean up spinner on interrupt
trap 'spinner_stop; printf "\n"; log_error "Scan interrupted by user"; exit 130' INT TERM

main "$@"
