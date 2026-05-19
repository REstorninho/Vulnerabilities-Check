#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════╗
# ║  linux-full-audit.sh — Auditoria Completa + CVE/CWE Analyser   ║
# ║  Combina: linux-audit.sh + vuln-check.sh                        ║
# ║  Uso: sudo bash linux-full-audit.sh [OPÇÕES]                    ║
# ╚══════════════════════════════════════════════════════════════════╝
#
# FASES:
#   1  — Download de ferramentas (linPEAS, Lynis, Trivy, Grype,
#         OSV-Scanner, LES2, linux-exploit-suggester)
#   2  — Scans de segurança:
#          01_sysinfo      — sistema, rede, utilizadores
#          02_packages     — packages + actualizações pendentes
#          03_linpeas      — privesc automático (linPEAS)
#          04_lynis        — hardening audit (Lynis / manual)
#          05_trivy        — CVE scan filesystem (texto)
#          06_nvd_cve      — NVD API lookup básico
#          07_ssh_audit    — configuração SSH + CWE mapping
#          08_users_perms  — SUID, sudo, capabilities, permissões
#          09_services_net — serviços, portas, firewall, Docker
#          10_patch_gap    — kernel CVEs inline + LES2 + distro updates
#          11_app_vulns    — OSV-Scanner + Grype + PURL/NVD lookup
#   3  — Inventário estruturado (JSON) de todos os packages e apps
#   4  — CVE/CWE scan com output JSON (Trivy + Grype + NVD API)
#   5  — Updates de packages (apt/dnf/pacman/zypper/apk)
#   6  — Relatório HTML unificado com duas tabs:
#          "Audit"     — findings de segurança, privesc, hardening
#          "CVE Dashboard" — tabela CVE/CWE interactiva, inventário,
#                            updates com comandos clicáveis
#
# tools/ e reports/ ficam JUNTO DO SCRIPT — persistem entre execuções.
# Ferramentas só descarregam se não existirem (ou com --force).

set -uo pipefail

# ─── Cores ────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; MAGENTA='\033[0;35m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()    {
    echo -e "${YELLOW}[!]${NC} $*"
    log_jsonl "WARN" "$*"
    WARN_COUNT=$(( WARN_COUNT + 1 ))
}
err()     {
    echo -e "${RED}[X]${NC} $*"
    log_jsonl "ERROR" "$*"
    ERROR_COUNT=$(( ERROR_COUNT + 1 ))
}
step()    {
    CURRENT_PHASE="$*"
    echo -e "\n${CYAN}${BOLD}══════ $* ══════${NC}"
    log_jsonl "INFO" "Fase iniciada: $*"
}
section() {
    CURRENT_PHASE="$*"
    echo -e "\n${CYAN}─── $* ───${NC}"
}

# ─── Sistema de Logging Estruturado (JSON Lines) ──────────────────
# Escreve em audit_events.log (tudo) e audit_errors.log (só ERROR/WARN)
# Formato JSON Line — filtrável com jq:
#   jq 'select(.level=="ERROR")' audit_events.log
log_jsonl() {
    local level="$1" msg="$2" extra="${3:-}"
    # Só escreve se OUT já existe (mkdir feito mais tarde — durante init pode não estar)
    [[ -z "${ERROR_LOG:-}" ]] || [[ ! -d "$(dirname "$ERROR_LOG" 2>/dev/null)" ]] && return 0
    # Sanitizar para JSON
    local m="${msg//\\/\\\\}"; m="${m//\"/\\\"}"; m="${m//$'\n'/\\n}"; m="${m//$'\t'/\\t}"
    local p="${CURRENT_PHASE:-init}"; p="${p//\"/\\\"}"
    local ts; ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    local line="{\"timestamp\":\"${ts}\",\"level\":\"${level}\",\"phase\":\"${p}\",\"message\":\"${m}\""
    [[ -n "$extra" ]] && line="${line},${extra}"
    line="${line}}"
    echo "$line" >> "$EVENT_LOG" 2>/dev/null || true
    if [[ "$level" == "ERROR" ]] || [[ "$level" == "WARN" ]]; then
        echo "$line" >> "$ERROR_LOG" 2>/dev/null || true
    fi
}

# log_error — entrada manual com severidade explícita e dados extra
# Uso: log_error ERROR "msg" '"key":"value"'
log_error() {
    local sev="${1:-ERROR}"; shift
    local msg="$1"; shift
    local extra="${1:-}"
    log_jsonl "$sev" "$msg" "$extra"
    case "$sev" in
        ERROR) ERROR_COUNT=$(( ERROR_COUNT + 1 )) ;;
        WARN)  WARN_COUNT=$(( WARN_COUNT + 1 )) ;;
    esac
}

# trap para capturar erros não previstos
on_error() {
    local exit_code=$?
    local line_no=$1
    local cmd="${BASH_COMMAND:-?}"
    log_jsonl "ERROR" "Erro não-tratado" "\"line\":${line_no},\"exit_code\":${exit_code},\"command\":\"${cmd//\"/\\\"}\""
    ERROR_COUNT=$(( ERROR_COUNT + 1 ))
}
trap 'on_error $LINENO' ERR

# run_logged — executa comando e regista falha com stderr
# Uso: run_logged "label" cmd arg1 arg2
run_logged() {
    local label="$1"; shift
    local stderr_file; stderr_file=$(mktemp 2>/dev/null) || stderr_file="/tmp/run_logged_$$"
    local rc=0
    "$@" 2>"$stderr_file" || rc=$?
    if [[ $rc -ne 0 ]]; then
        local err_msg; err_msg=$(head -c 500 "$stderr_file" 2>/dev/null || echo "")
        log_jsonl "ERROR" "${label} falhou (exit=${rc})" "\"command\":\"${1//\"/\\\"}\",\"stderr\":\"${err_msg//\"/\\\"}\""
        ERROR_COUNT=$(( ERROR_COUNT + 1 ))
    fi
    rm -f "$stderr_file"
    return $rc
}

# py_check — verifica último bloco Python e regista erro se houver stderr não-vazio
# Uso: <python block> 2>/tmp/pyerr.log && py_check "label" "/tmp/pyerr.log"
py_check() {
    local label="$1" stderr_file="$2"
    if [[ -f "$stderr_file" ]] && [[ -s "$stderr_file" ]]; then
        # Filtrar tracebacks (multi-linha)
        local err_msg; err_msg=$(head -c 800 "$stderr_file" 2>/dev/null)
        # Só logar como ERROR se contém "Error" ou "Traceback" ou "Exception"
        if echo "$err_msg" | grep -qE "Error|Traceback|Exception|SyntaxError"; then
            log_jsonl "ERROR" "${label} — erro Python" "\"stderr\":\"${err_msg//\"/\\\"}\""
            ERROR_COUNT=$(( ERROR_COUNT + 1 ))
            warn "  ${label}: erro Python (ver ${ERROR_LOG})"
        fi
    fi
    rm -f "$stderr_file"
}

# ─── Defaults ─────────────────────────────────────────────────────
SKIP_DOWNLOAD=false
QUICK_MODE=false
NO_NVD=false
NO_BROWSER=false
FORCE=false
DEEP_SCAN=false
CUSTOM_OUT=""
NVD_API_KEY="${NVD_API_KEY:-}"
COMPARE_FILE=""
FAIL_ON=""

usage() {
cat <<'EOF'

  ╔══════════════════════════════════════════════════════════════════╗
  ║     linux-full-audit.sh — Auditoria Completa + CVE Analyser     ║
  ╚══════════════════════════════════════════════════════════════════╝

  USO:
    sudo bash linux-full-audit.sh [OPÇÕES]

  OPÇÕES:
    -h, --help            Esta mensagem
    -o, --output DIR      Output personalizado
                            (default: <script_dir>/reports/<host>_<date>/)
    -s, --skip-download   Usar ferramentas em cache (não descarregar)
    -q, --quick           Modo rápido — salta linPEAS e Lynis
    -n, --no-nvd          Salta consulta NVD (modo offline)
    --no-browser          Não abre relatório no browser
    --deep-scan           Activa Trivy secret+misconfig (mais lento)
    --force               Re-download de ferramentas mesmo que existam
    --nvd-api-key KEY     NVD API key (também via env var NVD_API_KEY)
                          Com key: rate limit passa de 5/30s para 50/30s (10× mais rápido)
                          Obter em: https://nvd.nist.gov/developers/request-an-api-key
    --compare FILE        Comparar com cve_results.json de run anterior
                          Output: novos CVEs, resolvidos, mudanças de severidade
    --fail-on LEVEL       Exit code != 0 quando há findings (para CI/CD)
                          Valores: critical, high, medium
                          Codes: 0=clean, 1=erro, 2=critical, 3=high, 4=medium

  EXIT CODES (sem --fail-on, sai sempre 0 excepto em erros):
    0  Sucesso, sem findings críticos
    1  Erro de execução (ficheiros, paths, etc)
    2  --fail-on critical com Critical CVEs encontrados
    3  --fail-on high com High CVEs encontrados
    4  --fail-on medium com Medium CVEs encontrados

  EXEMPLOS:
    sudo bash linux-full-audit.sh
    sudo bash linux-full-audit.sh --quick --no-nvd
    sudo bash linux-full-audit.sh --nvd-api-key abc123  # 10x mais rápido
    sudo bash linux-full-audit.sh --compare reports/host_20260515_1030/cve_results.json
    sudo bash linux-full-audit.sh --fail-on critical    # para CI/CD
    sudo bash linux-full-audit.sh -o /tmp/audit --no-browser

EOF
exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)          usage ;;
        -o|--output)        CUSTOM_OUT="$2"; shift 2 ;;
        -s|--skip-download) SKIP_DOWNLOAD=true; shift ;;
        -q|--quick)         QUICK_MODE=true; shift ;;
        -n|--no-nvd)        NO_NVD=true; shift ;;
        --no-browser)       NO_BROWSER=true; shift ;;
        --deep-scan)        DEEP_SCAN=true; shift ;;
        --force)            FORCE=true; shift ;;
        --nvd-api-key)      NVD_API_KEY="$2"; shift 2 ;;
        --compare)          COMPARE_FILE="$2"; shift 2 ;;
        --fail-on)          FAIL_ON="$2"; shift 2 ;;
        *)                  warn "Opção desconhecida: $1"; shift ;;
    esac
done

# Validar --fail-on
if [[ -n "$FAIL_ON" ]] && [[ ! "$FAIL_ON" =~ ^(critical|high|medium)$ ]]; then
    err "--fail-on deve ser: critical, high, ou medium"
    exit 1
fi

# Validar --compare
if [[ -n "$COMPARE_FILE" ]] && [[ ! -f "$COMPARE_FILE" ]]; then
    err "--compare: ficheiro não encontrado: $COMPARE_FILE"
    exit 1
fi

# ═══════════════════════════════════════════════════════════════════
# CONFIGURAÇÃO DE PATHS
# ═══════════════════════════════════════════════════════════════════
TARGET="$(hostname -s)"
DATE="$(date +%Y%m%d_%H%M)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLS="${SCRIPT_DIR}/tools"

if [[ -n "$CUSTOM_OUT" ]]; then
    OUT="$CUSTOM_OUT"
else
    OUT="${SCRIPT_DIR}/reports/${TARGET}_${DATE}"
fi

REPORT="${OUT}/REPORT_${TARGET}_${DATE}.html"
INV_FILE="${OUT}/inventory.json"
CVE_FILE="${OUT}/cve_results.json"
APP_UPD_JSON="${OUT}/app_updates.json"
OS_UPD_JSON="${OUT}/os_updates.json"
TRIVY_JSON="${OUT}/trivy_raw.json"
GRYPE_JSON="${OUT}/11_grype.json"
LES2_OUT="${OUT}/les2_raw.txt"
# Exports adicionais (#1 — CSV/SARIF)
CVE_CSV="${OUT}/cve_results.csv"
CVE_SARIF="${OUT}/cve_results.sarif"
DIFF_FILE="${OUT}/diff_vs_previous.json"
# Log estruturado (JSON Lines)
ERROR_LOG="${OUT}/audit_errors.log"
EVENT_LOG="${OUT}/audit_events.log"
# Error log
ERROR_LOG="${OUT}/audit_errors.log"
ERROR_COUNT=0
WARN_COUNT=0
CURRENT_PHASE="init"

mkdir -p "$OUT" "$TOOLS"

# Inicializar logs estruturados — após mkdir
echo "# audit_events.log — JSON Lines, todos os eventos. Filtrar com: jq 'select(.level==\"ERROR\")' $EVENT_LOG" > "$EVENT_LOG"
echo "# audit_errors.log — só ERROR e WARN" > "$ERROR_LOG"
log_jsonl "INFO" "Script iniciado" "\"version\":\"1.0\",\"args\":\"$*\",\"pid\":$$"

# Cache global de Trivy e Grype DBs — persiste entre runs (#4)
# Poupa ~600MB de download por run
export TRIVY_CACHE_DIR="${TOOLS}/trivy-cache"
export GRYPE_DB_CACHE_DIR="${TOOLS}/grype-cache"
mkdir -p "$TRIVY_CACHE_DIR" "$GRYPE_DB_CACHE_DIR"

# ─── Root check ───────────────────────────────────────────────────
IS_ROOT=0; [[ "$(id -u)" -eq 0 ]] && IS_ROOT=1
SUDO=""; [[ "$IS_ROOT" -eq 0 ]] && SUDO="sudo"

# ─── Detectar distro e package manager ───────────────────────────
DISTRO="$(grep -oP '(?<=^PRETTY_NAME=")[^"]+' /etc/os-release 2>/dev/null || uname -s)"
DISTRO_ID="$(grep -oP '(?<=^ID=)[^\n]+' /etc/os-release 2>/dev/null | tr -d '"' || echo 'unknown')"
OS_VER="$(grep -oP '(?<=^VERSION_ID=")[^"]+' /etc/os-release 2>/dev/null || uname -r)"
KERNEL="$(uname -r)"
ARCH="$(uname -m)"

detect_pkgmgr() {
    if   command -v apt-get &>/dev/null; then echo "apt"
    elif command -v dnf     &>/dev/null; then echo "dnf"
    elif command -v yum     &>/dev/null; then echo "yum"
    elif command -v pacman  &>/dev/null; then echo "pacman"
    elif command -v zypper  &>/dev/null; then echo "zypper"
    elif command -v apk     &>/dev/null; then echo "apk"
    else echo "unknown"
    fi
}
PKG_MGR="$(detect_pkgmgr)"

printf '\n\033[0;36m\033[1m'
cat <<EOF
╔══════════════════════════════════════════════════╗
║   linux-full-audit — Auditoria Completa          ║
╠══════════════════════════════════════════════════╣
║  Host    : ${TARGET}
║  OS      : ${DISTRO}
║  Kernel  : ${KERNEL}
║  PkgMgr  : ${PKG_MGR}
║  Date    : ${DATE}
║  Root    : ${IS_ROOT}
║  Tools   : ${TOOLS}
║  Output  : ${OUT}
╚══════════════════════════════════════════════════╝
EOF
printf '\033[0m\n'

[[ "$IS_ROOT" -eq 0 ]] && warn "Sem root — cobertura limitada. Recomendado: sudo bash $0"
[[ "$QUICK_MODE" == "true" ]] && warn "Modo rápido activo — linPEAS e Lynis serão saltados"
[[ "$NO_NVD"    == "true" ]] && warn "NVD lookup desactivado"

# ═══════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════

safe_count() {
    local f="$1" pat="$2" n
    n=$(grep -cE "$pat" "$f" 2>/dev/null || echo 0)
    n="${n//[[:space:]]/}"
    [[ "$n" =~ ^[0-9]+$ ]] || n=0
    echo "$n"
}

safe_download() {
    local url="$1" dest="$2" min_bytes="${3:-10240}"
    local curl_err; curl_err=$(mktemp 2>/dev/null) || curl_err="/tmp/curl_err_$$"
    local sz=0

    # Tentativa 1: curl com proxy do sistema (--proxy-negotiate honra $http_proxy/$https_proxy)
    if curl -fsSL --connect-timeout 30 --max-time 120 \
            --proxy-negotiate --anyauth \
            -o "$dest" "$url" 2>"$curl_err"; then
        sz=$(stat -c%s "$dest" 2>/dev/null || stat -f%z "$dest" 2>/dev/null || echo 0)
        if [[ "$sz" -ge "$min_bytes" ]]; then rm -f "$curl_err"; return 0; fi
        rm -f "$dest"
    fi

    # Tentativa 2: curl com --insecure (alguns proxies SSL inspection quebram o certificado)
    if curl -fsSL --connect-timeout 30 --max-time 120 --insecure \
            -o "$dest" "$url" 2>>"$curl_err"; then
        sz=$(stat -c%s "$dest" 2>/dev/null || echo 0)
        if [[ "$sz" -ge "$min_bytes" ]]; then rm -f "$curl_err"; return 0; fi
        rm -f "$dest"
    fi

    # Tentativa 3: wget como alternativa (stack HTTP diferente do curl)
    if command -v wget &>/dev/null; then
        if wget -q --timeout=120 --tries=2 -O "$dest" "$url" 2>>"$curl_err"; then
            sz=$(stat -c%s "$dest" 2>/dev/null || echo 0)
            if [[ "$sz" -ge "$min_bytes" ]]; then rm -f "$curl_err"; return 0; fi
            rm -f "$dest"
        fi
    fi

    local em; em=$(head -c 200 "$curl_err" 2>/dev/null)
    log_error WARN "Falha no download" "\"url\":\"${url//\"/\\\"}\",\"curl_error\":\"${em//\"/\\\"}\""
    echo -e "${YELLOW}[!]${NC}   Falha no download: $url"
    rm -f "$curl_err"
    return 1
}

# github_release_download — descarrega asset ZIP de release do GitHub
# Tenta múltiplos métodos porque objects.githubusercontent.com pode estar bloqueado
# Uso: github_release_download "owner/repo" "*linux*amd64*.zip" "/dest/file.zip" min_bytes fallback_ver fallback_url
# github_release_download — descarrega asset ZIP de release do GitHub
# Se objects.githubusercontent.com estiver bloqueado, mostra instruções manuais
# Uso: github_release_download repo filter dest min_bytes fallback_ver fallback_url [manual_dest]
github_release_download() {
    local repo="$1" asset_filter="$2" dest="$3" min_bytes="${4:-10240}"
    local fallback_ver="${5:-}" fallback_url="${6:-}" manual_dest="${7:-$3}"
    local ver="$fallback_ver" asset_url="$fallback_url"

    # 1. Obter metadados via API
    local api_resp
    api_resp=$(curl -fsSL --max-time 15 "https://api.github.com/repos/${repo}/releases/latest" 2>/dev/null) || api_resp=""
    if [[ -n "$api_resp" ]]; then
        ver=$(echo "$api_resp" | python3 -c "import sys,json; print(json.load(sys.stdin)['tag_name'].lstrip('v'))" 2>/dev/null || echo "$fallback_ver")
        local found_url
        found_url=$(echo "$api_resp" | python3 -c "
import sys,json,fnmatch
try:
    data=json.load(sys.stdin)
    for a in data.get('assets',[]):
        if fnmatch.fnmatch(a['name'], '${asset_filter}'):
            print(a['browser_download_url']); break
except: pass
" 2>/dev/null || echo "")
        [[ -n "$found_url" ]] && asset_url="$found_url"
        info "  v${ver} — $(basename "$asset_url")"
    else
        warn "  GitHub API inacessível — a usar fallback v${fallback_ver}"
    fi
    [[ -z "$asset_url" ]] && { warn "  Sem URL de download disponível"; return 1; }

    # 2. Teste rápido de conectividade ao host (5s) — evitar múltiplas tentativas inúteis
    local download_host
    download_host=$(python3 -c "from urllib.parse import urlparse; print(urlparse('${asset_url}').netloc)" 2>/dev/null                     || echo "objects.githubusercontent.com")
    if ! curl -fsSL --max-time 5 --head "https://${download_host}" -o /dev/null 2>/dev/null; then
        local tool_name; tool_name=$(basename "$repo")
        warn "  ${download_host} inacessível (firewall/proxy)"
        echo ""
        echo -e "${YELLOW}  ┌─ INSTALAÇÃO MANUAL ──────────────────────────────────────────┐${NC}"
        echo -e "${YELLOW}  │ 1. Descarregar numa máquina com acesso à internet:            │${NC}"
        echo -e "${CYAN}  │    ${asset_url}${NC}"
        echo -e "${YELLOW}  │ 2. Extrair o binário do ZIP                                   │${NC}"
        echo -e "${CYAN}  │ 3. Copiar para: ${manual_dest}${NC}"
        echo -e "${YELLOW}  │ 4. Re-executar o script (usará cache automaticamente)         │${NC}"
        echo -e "${YELLOW}  └───────────────────────────────────────────────────────────────┘${NC}"
        echo ""
        log_jsonl "WARN" "${tool_name}: host bloqueado (${download_host})"             "\"download_url\":\"${asset_url}\",\"manual_dest\":\"${manual_dest}\""
        return 1
    fi

    # 3. Host acessível — tentar descarregar
    if safe_download "$asset_url" "$dest" "$min_bytes"; then echo "$ver"; return 0; fi

    # 4. curl com Accept: application/octet-stream
    info "  A tentar com Accept: application/octet-stream..."
    if curl -fsSL --max-time 120 -H "Accept: application/octet-stream"             -o "$dest" "$asset_url" 2>/dev/null; then
        local sz; sz=$(stat -c%s "$dest" 2>/dev/null || echo 0)
        if [[ "$sz" -ge "$min_bytes" ]]; then echo "$ver"; return 0; fi
        rm -f "$dest"
    fi

    warn "  Todos os métodos falharam. Download manual: $asset_url"
    return 1
}
ensure_tool() {
    local name="$1" dest="$2" url="$3" min_bytes="${4:-10240}"
    if [[ -f "$dest" ]] && [[ "$FORCE" == "false" ]]; then
        local sz; sz=$(stat -c%s "$dest" 2>/dev/null || echo 0)
        info "${name} — cache OK ($(( sz / 1024 )) KB)"; return 0
    fi
    info "A descarregar ${name}..."
    if safe_download "$url" "$dest" "$min_bytes"; then
        chmod +x "$dest" 2>/dev/null || true
        info "  ${name} OK"; return 0
    fi
    warn "  ${name} — falhou"; return 1
}

install_pkg() {
    local pkg="$1"
    case "$PKG_MGR" in
        apt)    $SUDO apt-get install -y -q "$pkg" &>/dev/null ;;
        dnf)    $SUDO dnf install -y -q "$pkg" &>/dev/null ;;
        yum)    $SUDO yum install -y -q "$pkg" &>/dev/null ;;
        pacman) $SUDO pacman -S --noconfirm --quiet "$pkg" &>/dev/null ;;
        apk)    $SUDO apk add --quiet "$pkg" &>/dev/null ;;
    esac
}

html_escape() { sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g'; }

# NVD API helper com retry em 429 + suporte para API key (#2)
# Sem key: rate limit 5/30s — esperar 32s entre batches de 5
# Com key: rate limit 50/30s — esperar 6s entre batches de 50
# Uso: nvd_curl "keyword" [results_per_page]
nvd_curl() {
    local kw="$1" rpp="${2:-5}"
    local url="https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${kw}&resultsPerPage=${rpp}"
    local attempt
    local -a curl_args
    curl_args=(-fsSL --max-time 25 --write-out '\nHTTPCODE:%{http_code}')
    # Adicionar API key header se disponível
    if [[ -n "$NVD_API_KEY" ]]; then
        curl_args+=(-H "apiKey: $NVD_API_KEY")
    fi
    for attempt in 1 2; do
        local http_code body
        body=$(curl "${curl_args[@]}" "$url" 2>/dev/null) || return 1
        http_code=$(echo "$body" | tail -1 | grep -oE 'HTTPCODE:[0-9]+' | cut -d: -f2)
        body=$(echo "$body" | sed '$d')
        if [[ "$http_code" == "200" ]]; then
            echo "$body"
            return 0
        fi
        if [[ "$http_code" == "429" && "$attempt" -eq 1 ]]; then
            sleep 32
            continue
        fi
        return 1
    done
    return 1
}

# Sleep entre requests NVD ajustado pela presença de API key
nvd_sleep_short() {
    # Entre requests individuais
    if [[ -n "$NVD_API_KEY" ]]; then sleep 1; else sleep 7; fi
}
nvd_sleep_batch() {
    # Após N requests, esperar quota de 30s
    if [[ -n "$NVD_API_KEY" ]]; then sleep 6; else sleep 32; fi
}

colorize() {
    # IMPORTANTE: aplicar CVE/CWE PRIMEIRO (tags inline curtas).
    # Depois aplicar tags de linha inteira — non-greedy ($) para não engolir múltiplas linhas.
    # Sem .* no início porque sed já trabalha por linha.
    sed \
        -e 's/\(CVE-[0-9]\{4\}-[0-9]\+\)/<span class="cve-inline">\1<\/span>/g' \
        -e 's/\(CWE-[0-9]\+\)/<span class="cwe-inline">\1<\/span>/g' \
        -e 's/^\(.*CRÍTICO.*\)$/<span class="finding-line">\1<\/span>/' \
        -e 's/^\(.*CRITICAL.*\)$/<span class="finding-line">\1<\/span>/' \
        -e 's/^\(.*ALERTA.*\)$/<span class="alert-line">\1<\/span>/' \
        -e 's/^\(.*\[HIGH\].*\)$/<span class="alert-line">\1<\/span>/' \
        -e 's/^\(.*OK:.*\)$/<span class="ok-line">\1<\/span>/'
}

categorize() {
    case "$1" in
        01_sysinfo)                                          echo "system" ;;
        02_packages)                                         echo "system" ;;
        03_linpeas|03_privesc_manual|03_linpeas_skipped)     echo "privesc" ;;
        04_lynis|04_hardening_manual|04_lynis_skipped)       echo "hardening" ;;
        05_trivy|05_cve_manual)                              echo "cve" ;;
        06_nvd_cve|06_nvd_cve_skipped)                       echo "cve" ;;
        07_ssh_audit)                                        echo "hardening" ;;
        08_users_perms)                                      echo "privesc" ;;
        09_services_net)                                     echo "network" ;;
        10_patch_gap)                                        echo "cve" ;;
        11_app_vulns)                                        echo "cve" ;;
        *)                                                   echo "other" ;;
    esac
}

category_label() {
    case "$1" in
        system)    echo "&#x1F5A5; System" ;;
        network)   echo "&#x1F310; Network" ;;
        privesc)   echo "&#x1F510; Privilege Escalation" ;;
        hardening) echo "&#x1F6E1; Hardening" ;;
        cve)       echo "&#x1F41B; CVE / Vulnerabilities" ;;
        other)     echo "&#x1F4C4; Other" ;;
    esac
}

# ═══════════════════════════════════════════════════════════════════
# FASE 1 — DOWNLOAD DE FERRAMENTAS
# ═══════════════════════════════════════════════════════════════════
step "FASE 1 — Ferramentas"

for dep in curl python3; do
    command -v "$dep" &>/dev/null || { warn "A instalar $dep..."; install_pkg "$dep"; }
done

# ── linPEAS ───────────────────────────────────────────────────────
LINPEAS="${TOOLS}/linpeas.sh"
if [[ "$SKIP_DOWNLOAD" == "true" ]] && [[ -f "$LINPEAS" ]]; then
    info "linPEAS — cache OK (skip-download)"
elif [[ ! -f "$LINPEAS" ]] && [[ "$SKIP_DOWNLOAD" == "false" ]]; then
    ensure_tool "linPEAS" "$LINPEAS" \
        "https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh" 10000
elif [[ ! -f "$LINPEAS" ]]; then
    warn "linPEAS não encontrado e --skip-download activo"
else
    info "linPEAS — cache OK"
fi

# ── Lynis ─────────────────────────────────────────────────────────
HAS_LYNIS=false
LYNIS_BIN="lynis"
if command -v lynis &>/dev/null; then
    HAS_LYNIS=true
    info "Lynis — sistema OK ($(lynis --version 2>/dev/null | head -1))"
elif [[ -f "${TOOLS}/lynis/lynis" ]] && [[ "$FORCE" == "false" ]]; then
    HAS_LYNIS=true
    LYNIS_BIN="${TOOLS}/lynis/lynis"
    info "Lynis — cache OK"
elif [[ "$SKIP_DOWNLOAD" == "false" ]] || [[ "$FORCE" == "true" ]]; then
    info "A descarregar Lynis..."
    # Tentar API GitHub para versão mais recente (CISOfy/lynis); fallback hardcoded
    LYNIS_VER=$(curl -fsSL "https://api.github.com/repos/CISOfy/lynis/releases/latest" 2>/dev/null \
                | python3 -c "import sys,json; print(json.load(sys.stdin)['tag_name'].lstrip('v'))" \
                2>/dev/null || echo "3.1.4")
    LYNIS_TAR="${TOOLS}/lynis.tar.gz"
    LYNIS_URL="https://github.com/CISOfy/lynis/archive/refs/tags/${LYNIS_VER}.tar.gz"
    if safe_download "$LYNIS_URL" "$LYNIS_TAR" 100000; then
        # GitHub archive cria lynis-<ver>/, normalizar para lynis/
        tar -xzf "$LYNIS_TAR" -C "$TOOLS" 2>/dev/null
        if [[ -d "${TOOLS}/lynis-${LYNIS_VER}" ]]; then
            rm -rf "${TOOLS}/lynis"
            mv "${TOOLS}/lynis-${LYNIS_VER}" "${TOOLS}/lynis"
        fi
        if [[ -f "${TOOLS}/lynis/lynis" ]]; then
            chmod +x "${TOOLS}/lynis/lynis"
            HAS_LYNIS=true
            LYNIS_BIN="${TOOLS}/lynis/lynis"
            info "  Lynis v${LYNIS_VER} OK"
        else
            warn "  Lynis — extracção falhou"
        fi
    else
        # Fallback: CISOfy download server (versão hardcoded)
        if safe_download "https://downloads.cisofy.com/lynis/lynis-3.1.1.tar.gz" "$LYNIS_TAR" 100000; then
            tar -xzf "$LYNIS_TAR" -C "$TOOLS" 2>/dev/null
            if [[ -f "${TOOLS}/lynis/lynis" ]]; then
                HAS_LYNIS=true
                LYNIS_BIN="${TOOLS}/lynis/lynis"
                info "  Lynis 3.1.1 (fallback) OK"
            fi
        else
            warn "  Lynis — download falhou"
        fi
    fi
    rm -f "$LYNIS_TAR"
fi

# ── Trivy ─────────────────────────────────────────────────────────
TRIVY_BIN="${TOOLS}/trivy"
if command -v trivy &>/dev/null && [[ "$FORCE" == "false" ]]; then
    TRIVY_BIN="trivy"
    info "Trivy — sistema OK"
elif [[ ! -f "$TRIVY_BIN" ]] || [[ "$FORCE" == "true" ]]; then
    info "A determinar versão do Trivy..."
    TRIVY_VER=$(curl -fsSL "https://api.github.com/repos/aquasecurity/trivy/releases/latest" 2>/dev/null \
                | python3 -c "import sys,json; print(json.load(sys.stdin)['tag_name'].lstrip('v'))" \
                2>/dev/null || echo "0.51.0")
    case "$ARCH" in
        x86_64)  TA="Linux-64bit" ;;
        aarch64) TA="Linux-ARM64" ;;
        *)       TA="Linux-64bit" ;;
    esac
    TRIVY_URL="https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VER}/trivy_${TRIVY_VER}_${TA}.tar.gz"
    TRIVY_TAR="${TOOLS}/trivy.tar.gz"
    if safe_download "$TRIVY_URL" "$TRIVY_TAR" 5000000; then
        if tar -xzf "$TRIVY_TAR" -C "$TOOLS" trivy 2>/dev/null && [[ -f "$TRIVY_BIN" ]]; then
            chmod +x "$TRIVY_BIN"
            info "  Trivy v${TRIVY_VER} OK"
        else
            warn "  Trivy — extracção falhou"
        fi
    else
        warn "  Trivy — download falhou"
    fi
    rm -f "$TRIVY_TAR"
else
    sz=$(stat -c%s "$TRIVY_BIN" 2>/dev/null || echo 0)
    info "Trivy — cache OK ($(( sz / 1048576 )) MB)"
fi

# ── Grype ─────────────────────────────────────────────────────────
GRYPE_BIN="${TOOLS}/grype"
if [[ ! -f "$GRYPE_BIN" ]] || [[ "$FORCE" == "true" ]]; then
    info "A determinar versão do Grype..."
    GRYPE_VER=$(curl -fsSL "https://api.github.com/repos/anchore/grype/releases/latest" 2>/dev/null \
                | python3 -c "import sys,json; print(json.load(sys.stdin)['tag_name'].lstrip('v'))" \
                2>/dev/null || echo "0.78.0")
    case "$ARCH" in
        x86_64)  GA="linux_amd64" ;;
        aarch64) GA="linux_arm64" ;;
        armv7*)  GA="linux_arm" ;;
        *)       GA="linux_amd64" ;;
    esac
    GRYPE_URL="https://github.com/anchore/grype/releases/download/v${GRYPE_VER}/grype_${GRYPE_VER}_${GA}.tar.gz"
    GRYPE_TAR="${TOOLS}/grype.tar.gz"
    if safe_download "$GRYPE_URL" "$GRYPE_TAR" 20000000; then
        if tar -xzf "$GRYPE_TAR" -C "$TOOLS" grype 2>/dev/null && [[ -f "$GRYPE_BIN" ]]; then
            chmod +x "$GRYPE_BIN"
            info "  Grype v${GRYPE_VER} OK"
        else
            warn "  Grype — extracção falhou"
        fi
    else
        warn "  Grype — download falhou"
    fi
    rm -f "$GRYPE_TAR"
else
    sz=$(stat -c%s "$GRYPE_BIN" 2>/dev/null || echo 0)
    info "Grype — cache OK ($(( sz / 1048576 )) MB)"
fi

# ── OSV-Scanner ───────────────────────────────────────────────────
OSV_BIN="${TOOLS}/osv-scanner"
OSV_CMD=""

if [[ -f "$OSV_BIN" ]] && [[ "$FORCE" == "false" ]]; then
    OSV_CMD="$OSV_BIN"
    sz=$(stat -c%s "$OSV_BIN" 2>/dev/null || echo 0)
    info "OSV-Scanner — cache OK ($(( sz / 1048576 )) MB)"
elif command -v osv-scanner &>/dev/null && [[ "$FORCE" == "false" ]]; then
    OSV_CMD=$(command -v osv-scanner)
    info "OSV-Scanner — sistema OK ($OSV_CMD)"
elif [[ "$SKIP_DOWNLOAD" == "false" ]] || [[ "$FORCE" == "true" ]]; then
    info "A determinar versão mais recente do OSV-Scanner (google)..."
    OSV_ZIP="${TOOLS}/osv_tmp.zip"
    OSV_TMP="${TOOLS}/osv_extracted"

    # Determinar filtro de arquitectura para o asset
    case "$ARCH" in
        x86_64)  OSV_FILTER="*linux_amd64*.zip" ;;
        aarch64) OSV_FILTER="*linux_arm64*.zip" ;;
        armv7*)  OSV_FILTER="*linux_arm*.zip"   ;;
        *)       OSV_FILTER="*linux_amd64*.zip" ;;
    esac
    # Fallback URL com versão conhecida
    OSV_FALLBACK_URL="https://github.com/google/osv-scanner/releases/download/v2.3.8/osv-scanner_2.3.8_linux_amd64.zip"
    [[ "$ARCH" == "aarch64" ]] && OSV_FALLBACK_URL="https://github.com/google/osv-scanner/releases/download/v2.3.8/osv-scanner_2.3.8_linux_arm64.zip"

    OSV_VER=$(github_release_download \
        "google/osv-scanner" "$OSV_FILTER" "$OSV_ZIP" 5000000 \
        "2.3.8" "$OSV_FALLBACK_URL" "$OSV_BIN") && {
        mkdir -p "$OSV_TMP"
        if unzip -q "$OSV_ZIP" -d "$OSV_TMP" 2>/dev/null; then
            EXE_FOUND=$(find "$OSV_TMP" -type f \( -name "osv-scanner" -o -name "osv-scanner_*" \) \
                        ! -name "*.zip" ! -name "*.sha256" 2>/dev/null | head -1)
            if [[ -n "$EXE_FOUND" ]]; then
                cp "$EXE_FOUND" "$OSV_BIN"
                chmod +x "$OSV_BIN"
                OSV_CMD="$OSV_BIN"
                sz=$(stat -c%s "$OSV_BIN" 2>/dev/null || echo 0)
                info "  OSV-Scanner v${OSV_VER} extraído OK ($(( sz / 1048576 )) MB)"
            else
                warn "  OSV-Scanner: binário não encontrado dentro do ZIP"
            fi
        else
            warn "  OSV-Scanner: falha ao extrair ZIP"
        fi
    } || warn "  OSV-Scanner: download falhou"

    # Limpar temporários sempre
    rm -f "$OSV_ZIP"
    rm -rf "$OSV_TMP"

    [[ -z "$OSV_CMD" ]] && warn "  OSV-Scanner: não disponível — lock file scan será saltado"
fi

# ── linux-exploit-suggester-2 ─────────────────────────────────────
LES2="${TOOLS}/les2.pl"
LES_SH="${TOOLS}/linux-exploit-suggester.sh"
if [[ ! -f "$LES2" ]] || [[ "$FORCE" == "true" ]]; then
    ensure_tool "linux-exploit-suggester-2" "$LES2" \
        "https://raw.githubusercontent.com/jondonas/linux-exploit-suggester-2/master/linux-exploit-suggester-2.pl" 2000
else
    info "linux-exploit-suggester-2 — cache OK"
fi
if [[ ! -f "$LES_SH" ]] || [[ "$FORCE" == "true" ]]; then
    ensure_tool "linux-exploit-suggester" "$LES_SH" \
        "https://raw.githubusercontent.com/The-Z-Labs/linux-exploit-suggester/master/linux-exploit-suggester.sh" 5000
else
    info "linux-exploit-suggester — cache OK"
fi

# ═══════════════════════════════════════════════════════════════════
# FASE 2 — SCANS DE SEGURANÇA (herdados do linux-audit.sh)
# ═══════════════════════════════════════════════════════════════════
step "FASE 2 — Scans de Segurança"

# ─── 01: Sysinfo ──────────────────────────────────────────────────
section "01 — Sysinfo"
{
    echo "=== SISTEMA ==="; echo "Hostname : $(hostname)"; echo "OS       : ${DISTRO}"
    echo "Kernel   : $(uname -r)"; echo "Arch     : $(uname -m)"; echo "Uptime   : $(uptime 2>/dev/null)"
    echo ""; echo "=== CPU ==="; grep "model name\|cpu cores" /proc/cpuinfo 2>/dev/null | sort -u
    echo ""; echo "=== MEMÓRIA ==="; free -h 2>/dev/null
    echo ""; echo "=== DISCOS ==="; df -h 2>/dev/null
    echo ""; echo "=== INTERFACES DE REDE ==="; ip addr 2>/dev/null || ifconfig 2>/dev/null
    echo ""; echo "=== ROUTING TABLE ==="; ip route 2>/dev/null || route -n 2>/dev/null
    echo ""; echo "=== PORTAS EM ESCUTA ==="; ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null
    echo ""; echo "=== UTILIZADORES COM SHELL ==="; grep -v "nologin\|false\|sync\|halt\|shutdown" /etc/passwd 2>/dev/null
    echo ""; echo "=== GRUPOS ==="; grep -v "^#" /etc/group 2>/dev/null
} > "${OUT}/01_sysinfo.txt" 2>&1
info "01_sysinfo OK"

# ─── 02: Packages ─────────────────────────────────────────────────
section "02 — Packages"
{
    echo "=== PACKAGES INSTALADOS ==="
    case "$PKG_MGR" in
        apt)    dpkg -l 2>/dev/null ;;
        dnf|yum) rpm -qa 2>/dev/null ;;
        pacman) pacman -Q 2>/dev/null ;;
        apk)    apk list --installed 2>/dev/null ;;
        *)      echo "Package manager não identificado" ;;
    esac
    echo ""; echo "=== ACTUALIZAÇÕES PENDENTES ==="
    case "$PKG_MGR" in
        apt)    apt-get -s upgrade 2>/dev/null | grep "^Inst" || echo "Sem actualizações ou sem root" ;;
        dnf)    $SUDO dnf check-update 2>/dev/null || true ;;
        yum)    $SUDO yum check-update 2>/dev/null || true ;;
        pacman) pacman -Qu 2>/dev/null || true ;;
    esac
    echo ""; echo "=== VERSÕES CRÍTICAS ==="; uname -r
    command -v openssl &>/dev/null && openssl version 2>/dev/null
    command -v ssh     &>/dev/null && ssh -V 2>&1
    command -v python3 &>/dev/null && python3 --version 2>/dev/null
    command -v curl    &>/dev/null && curl --version 2>/dev/null | head -2
} > "${OUT}/02_packages.txt" 2>&1
info "02_packages OK"

# ─── 03: linPEAS / privesc manual ────────────────────────────────
section "03 — Privesc"
if [[ "$QUICK_MODE" == "true" ]]; then
    warn "03_linpeas saltado (--quick)"; echo "[saltado — modo rápido]" > "${OUT}/03_linpeas_skipped.txt"
elif [[ -f "$LINPEAS" ]]; then
    info "A correr linPEAS (2-5 min)..."
    timeout 300 bash "$LINPEAS" -a > "${OUT}/03_linpeas.txt" 2>&1 || true
    sz=$(stat -c%s "${OUT}/03_linpeas.txt" 2>/dev/null || echo 0)
    info "03_linpeas OK ($(( sz / 1024 )) KB)"
else
    warn "linPEAS não disponível — scan manual..."
    {
        echo "=== SUID BINARIES ==="; find / -perm -4000 -type f 2>/dev/null | sort
        echo ""; echo "=== SGID BINARIES ==="; find / -perm -2000 -type f 2>/dev/null | sort
        echo ""; echo "=== WORLD-WRITABLE DIRS ==="; find / -writable -type d 2>/dev/null | grep -v "^/proc\|^/sys\|^/dev" | sort
        echo ""; echo "=== SUDO RULES ==="; sudo -l 2>/dev/null || echo "N/A"
        echo ""; echo "=== CRONTABS ==="; crontab -l 2>/dev/null; ls -la /etc/cron* 2>/dev/null; cat /etc/crontab 2>/dev/null
        echo ""; echo "=== CAPABILITIES ==="; getcap -r / 2>/dev/null | grep -v "^getcap:" | sort
        echo ""; echo "=== PROCESSOS ==="; ps aux 2>/dev/null
        echo ""; echo "=== VARIÁVEIS DE AMBIENTE ==="; env 2>/dev/null | grep -v "LS_COLORS"
    } > "${OUT}/03_privesc_manual.txt" 2>&1; info "03_privesc_manual OK"
fi

# ─── 04: Lynis / hardening manual ────────────────────────────────
section "04 — Hardening"
if [[ "$QUICK_MODE" == "true" ]]; then
    warn "04_lynis saltado (--quick)"; echo "[saltado — modo rápido]" > "${OUT}/04_lynis_skipped.txt"
elif [[ "$HAS_LYNIS" == "true" ]]; then
    info "A correr Lynis..."
    $SUDO "$LYNIS_BIN" audit system --no-colors --quiet \
        --logfile "${OUT}/04_lynis.log" \
        --report-file "${OUT}/04_lynis_report.dat" \
        > "${OUT}/04_lynis.txt" 2>&1 || true
    info "04_lynis OK"
else
    warn "Lynis não disponível — hardening manual..."
    {
        echo "=== SSH CONFIG ==="; grep -v "^#\|^$" /etc/ssh/sshd_config 2>/dev/null
        echo ""; echo "=== FIREWALL ==="; $SUDO ufw status verbose 2>/dev/null || $SUDO iptables -L -n -v 2>/dev/null || $SUDO nft list ruleset 2>/dev/null || echo "N/A"
        echo ""; echo "=== SELINUX / APPARMOR ==="; getenforce 2>/dev/null; aa-status 2>/dev/null || echo "N/A"
        echo ""; echo "=== FSTAB ==="; cat /etc/fstab 2>/dev/null
        echo ""; echo "=== UID 0 (root duplicado) ==="; awk -F: '($3==0){print "ALERTA UID0:",$1}' /etc/passwd 2>/dev/null
        echo ""; echo "=== WORLD-READABLE /etc/ ==="; ls -la /etc/passwd /etc/shadow /etc/group 2>/dev/null
        echo ""; echo "=== AUTHORIZED_KEYS ==="; find /home /root -name "authorized_keys" 2>/dev/null -exec ls -la {} \;
    } > "${OUT}/04_hardening_manual.txt" 2>&1; info "04_hardening_manual OK"
fi

# ─── 05: Trivy (output texto para relatório de audit) ─────────────
section "05 — Trivy CVE Scan"
if [[ -x "$TRIVY_BIN" ]] || command -v trivy &>/dev/null; then
    TRIVY_CMD=$(command -v trivy 2>/dev/null || echo "$TRIVY_BIN")
    if [[ "$DEEP_SCAN" == "true" ]]; then
        SCANNERS="vuln,secret,misconfig"
        info "A correr Trivy (texto, deep scan: $SCANNERS)..."
    else
        SCANNERS="vuln"
        info "A correr Trivy (texto, scanners: $SCANNERS)..."
    fi
    timeout 600 "$TRIVY_CMD" fs / \
        --scanners "$SCANNERS" \
        --severity CRITICAL,HIGH,MEDIUM \
        --format table --no-progress --timeout 10m \
        --skip-dirs /proc,/sys,/dev,/run,/snap \
        > "${OUT}/05_trivy.txt" 2>&1 || true
    info "05_trivy OK"
else
    warn "Trivy não disponível — CVE check manual..."
    { echo "=== CVE CHECK MANUAL ==="
      command -v openssl &>/dev/null && { OSSL=$(openssl version 2>/dev/null); echo "OpenSSL: $OSSL"; }
      command -v ssh     &>/dev/null && echo "OpenSSH: $(ssh -V 2>&1)"
    } > "${OUT}/05_cve_manual.txt" 2>&1
fi

# ─── 06: NVD CVE Lookup básico ────────────────────────────────────
section "06 — NVD Lookup"
if [[ "$NO_NVD" == "true" ]]; then
    warn "06_nvd_cve saltado (--no-nvd)"; echo "[saltado]" > "${OUT}/06_nvd_cve_skipped.txt"
else
    {
        echo "=== NVD API CVE/CWE LOOKUP ==="; echo "Data: $(date)"; echo ""
        declare -A PKGS_TO_CHECK
        command -v openssl &>/dev/null && PKGS_TO_CHECK["openssl"]="$(openssl version 2>/dev/null | awk '{print $2}')"
        command -v ssh     &>/dev/null && PKGS_TO_CHECK["openssh"]="$(ssh -V 2>&1 | grep -oE 'OpenSSH_[0-9.p]+' | grep -oE '[0-9.p]+')"
        command -v python3 &>/dev/null && PKGS_TO_CHECK["python3"]="$(python3 --version 2>/dev/null | awk '{print $2}')"
        command -v nginx   &>/dev/null && PKGS_TO_CHECK["nginx"]="$(nginx -v 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')"
        for pkg in "${!PKGS_TO_CHECK[@]}"; do
            ver="${PKGS_TO_CHECK[$pkg]}"; [[ -z "$ver" ]] && continue
            echo "─── ${pkg} ${ver} ───"
            NVD_RESP=$(nvd_curl "$pkg" 5) || \
                { echo "  Falha API NVD"; nvd_sleep_short; continue; }
            echo "$NVD_RESP" | python3 -c "
import sys,json
try:
    d=json.load(sys.stdin)
    for v in d.get('vulnerabilities',[])[:5]:
        cve=v['cve']['id']; sev='N/A'
        for k in ('cvssMetricV31','cvssMetricV30','cvssMetricV2'):
            ms=v['cve'].get('metrics',{}).get(k,[])
            if ms: sev=ms[0].get('cvssData',{}).get('baseSeverity','N/A'); break
        desc=next((x['value'] for x in v['cve'].get('descriptions',[]) if x.get('lang')=='en'),'')[:120]
        cwes=[d2['value'] for w in v['cve'].get('weaknesses',[]) for d2 in w.get('description',[]) if d2.get('value','').startswith('CWE-')]
        cwes_str = ', '.join(cwes) if cwes else 'N/A'
        print(f'  {cve} [{sev}] CWE: {cwes_str} — {desc}')
except Exception as e: print(f'  Erro: {e}')
" 2>/dev/null
            echo ""; nvd_sleep_short
        done
    } > "${OUT}/06_nvd_cve.txt" 2>&1; info "06_nvd_cve OK"
fi

# ─── 07: SSH Audit ────────────────────────────────────────────────
section "07 — SSH Audit"
{
    echo "=== AUDIT SSH (CWE mapping) ==="
    SSHD_CFG="/etc/ssh/sshd_config"
    if [[ -f "$SSHD_CFG" ]]; then
        PRL=$(grep -i "^PermitRootLogin"       "$SSHD_CFG" 2>/dev/null | awk '{print $2}')
        PWDA=$(grep -i "^PasswordAuthentication" "$SSHD_CFG" 2>/dev/null | awk '{print $2}')
        MAT=$(grep -i "^MaxAuthTries"          "$SSHD_CFG" 2>/dev/null | awk '{print $2}')
        X11=$(grep -i "^X11Forwarding"         "$SSHD_CFG" 2>/dev/null | awk '{print $2}')
        ATF=$(grep -i "^AllowTcpForwarding"    "$SSHD_CFG" 2>/dev/null | awk '{print $2}')
        [[ -z "$PRL"  || "$PRL"  == "yes" ]] && echo "CRÍTICO: PermitRootLogin yes — CWE-250, CWE-269" || echo "OK: PermitRootLogin ${PRL}"
        [[ "$PWDA" == "yes" || -z "$PWDA" ]]  && echo "ALERTA: PasswordAuthentication yes — CWE-307"   || echo "OK: PasswordAuthentication ${PWDA}"
        [[ -n "$MAT"  && "$MAT" -gt 4 ]] 2>/dev/null && echo "ALERTA: MaxAuthTries=${MAT} — CWE-307"
        [[ "$X11" == "yes" ]] && echo "ALERTA: X11Forwarding yes — CWE-284"
        [[ "$ATF" == "yes" ]] && echo "ALERTA: AllowTcpForwarding yes — CWE-284"
        echo ""; echo "=== CONFIG COMPLETA ==="; grep -v "^#\|^$" "$SSHD_CFG" 2>/dev/null
    else
        echo "sshd_config não encontrado"
    fi
    echo ""; echo "=== AUTHORIZED_KEYS ==="
    for hd in /root /home/*; do
        ak="${hd}/.ssh/authorized_keys"
        [[ -f "$ak" ]] && { ls -la "$ak" 2>/dev/null; wc -l < "$ak" | xargs -I{} echo "  {} chaves"; }
    done
} > "${OUT}/07_ssh_audit.txt" 2>&1; info "07_ssh_audit OK"

# ─── 08: Utilizadores e permissões ───────────────────────────────
section "08 — Users & Perms"
{
    echo "=== UTILIZADORES COM UID 0 ==="; awk -F: '$3==0{print "CRÍTICO: UID0:",$1,"— CWE-269"}' /etc/passwd 2>/dev/null
    echo ""; echo "=== PASSWORDS VAZIAS ==="; awk -F: '($2==""||$2=="!!")' /etc/shadow 2>/dev/null || echo "Sem acesso a /etc/shadow"
    echo ""; echo "=== SUDO CONFIG ==="; $SUDO cat /etc/sudoers 2>/dev/null | grep -v "^#\|^$"
    echo ""; echo "=== LOGINS RECENTES ==="; last 2>/dev/null | head -30
    echo ""; echo "=== SESSÕES ACTIVAS ==="; who 2>/dev/null; w 2>/dev/null
    echo ""; echo "=== SUID NÃO-STANDARD ==="
    find / -perm -4000 -type f 2>/dev/null | \
        grep -vE "^/(usr/bin/(sudo|su|passwd|chsh|chfn|gpasswd|newgrp|mount|umount)|bin/(su|mount|umount))" | \
        while read -r f; do echo "ALERTA SUID: $f — CWE-250"; done
    echo ""; echo "=== WRITABLE /etc/ ==="; find /etc -writable -type f 2>/dev/null | while read -r f; do echo "ALERTA: $f — CWE-732"; done
    echo ""; echo "=== CAPABILITIES ==="; getcap -r / 2>/dev/null | grep -v "^getcap:" | while read -r l; do echo "ALERTA: $l — CWE-250"; done || echo "N/A"
} > "${OUT}/08_users_perms.txt" 2>&1; info "08_users_perms OK"

# ─── 09: Serviços e rede ─────────────────────────────────────────
section "09 — Services & Network"
{
    echo "=== SERVIÇOS ACTIVOS ==="
    command -v systemctl &>/dev/null && systemctl list-units --type=service --state=running 2>/dev/null || service --status-all 2>/dev/null
    echo ""; echo "=== PORTAS EM ESCUTA ==="; ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null
    echo ""; echo "=== CONEXÕES ESTABELECIDAS ==="; ss -tnp 2>/dev/null | grep "ESTAB" | head -30
    echo ""; echo "=== FIREWALL ==="
    command -v ufw      &>/dev/null && $SUDO ufw status verbose 2>/dev/null
    command -v iptables &>/dev/null && $SUDO iptables -L -n -v --line-numbers 2>/dev/null | head -60
    command -v nft      &>/dev/null && $SUDO nft list ruleset 2>/dev/null | head -60
    echo ""; echo "=== DOCKER ==="
    if command -v docker &>/dev/null; then
        docker ps -a 2>/dev/null; docker info 2>/dev/null | grep -E "Containers|Images|Server Version"
        ss -tlnp 2>/dev/null | grep -q ":2375\|:2376" && echo "CRÍTICO: Docker API TCP exposta — CWE-306, CWE-319"
    else echo "Docker não instalado"; fi
} > "${OUT}/09_services_net.txt" 2>&1; info "09_services_net OK"

# ─── 10: Patch Gap Analysis ──────────────────────────────────────
section "10 — Patch Gap"
PATCH_OUT="${OUT}/10_patch_gap.txt"
{
echo "=== PATCH GAP ANALYSIS ==="; echo "Data: $(date)"; echo ""
KERNEL_FULL=$(uname -r); KERNEL_VER=$(uname -r | grep -oE "^[0-9]+\.[0-9]+\.[0-9]+")
echo "Kernel  : ${KERNEL_FULL}"; echo "Distro  : ${DISTRO}"; echo ""

# ── Camada A: LES2 ──────────────────────────────────────────────
echo "══ CAMADA A — linux-exploit-suggester-2 ══"; echo ""
if [[ -f "$LES2" ]] && command -v perl &>/dev/null; then
    timeout 60 perl "$LES2" -k "$KERNEL_VER" 2>/dev/null > "$LES2_OUT" || \
    timeout 60 perl "$LES2" 2>/dev/null > "$LES2_OUT" || true
    cat "$LES2_OUT" 2>/dev/null || echo "[LES2 sem output]"
elif [[ -f "$LES_SH" ]]; then
    timeout 120 bash "$LES_SH" --kernelspace-only 2>/dev/null || timeout 120 bash "$LES_SH" 2>/dev/null || true
else
    echo "[!] linux-exploit-suggester não disponível (requer perl)"
fi

# ── Camada B: Package manager security updates ──────────────────
echo ""; echo "══ CAMADA B — Package manager security updates ══"; echo ""
case "$PKG_MGR" in
    apt)
        $SUDO apt-get update -qq 2>/dev/null || true
        apt-get --just-print upgrade 2>/dev/null | grep -i "security\|CVE" | grep "^Inst" | head -50 || echo "  Sem upgrades de segurança pendentes"
        dpkg -l unattended-upgrades 2>/dev/null | grep -q "^ii" && echo "OK: unattended-upgrades instalado" || echo "ALERTA: unattended-upgrades não instalado — CWE-1104"
        command -v debian-security-support &>/dev/null && $SUDO debian-security-support 2>/dev/null | grep -v "^$" | head -20
        ;;
    dnf)
        $SUDO dnf updateinfo list security 2>/dev/null | head -50 || echo "  N/A"
        $SUDO dnf updateinfo list cves 2>/dev/null | head -20 || true
        ;;
    yum)  $SUDO yum list-security 2>/dev/null | head -30 || echo "  N/A" ;;
    pacman)
        pacman -Qu 2>/dev/null | head -30 || echo "  Sem actualizações"
        command -v arch-audit &>/dev/null && arch-audit 2>/dev/null | head -30 || echo "  arch-audit não instalado"
        ;;
    apk)  apk version -l '<' 2>/dev/null | head -30 || echo "N/A" ;;
esac

# Kernel vs latest
echo ""; echo "══ Kernel vs. upstream ══"
KERNEL_SERIES=$(echo "$KERNEL_VER" | grep -oE "^[0-9]+\.[0-9]+")
LATEST_KERNEL=$(curl -fsSL --max-time 10 "https://www.kernel.org/releases.json" 2>/dev/null | \
    python3 -c "
import sys,json
try:
    d=json.load(sys.stdin)
    for r in d.get('releases',[]):
        v=r.get('version','')
        if v.startswith('${KERNEL_SERIES}.'):
            print(v); break
    else:
        for r in d.get('releases',[]):
            if r.get('moniker') in ('stable','longterm'):
                print(r.get('version','N/A')); break
except: print('N/A')
" 2>/dev/null) || LATEST_KERNEL="N/A"
echo "  Actual  : ${KERNEL_FULL}"
echo "  Latest ${KERNEL_SERIES}: ${LATEST_KERNEL}"
[[ "$LATEST_KERNEL" != "N/A" && "$LATEST_KERNEL" != "$KERNEL_VER" ]] && \
    echo "  ALERTA: Kernel desactualizado — CWE-1104" || \
    [[ "$LATEST_KERNEL" != "N/A" ]] && echo "  OK: Kernel actualizado"

# ── Camada C: CVEs inline ────────────────────────────────────────
echo ""; echo "══ CAMADA C — CVEs de kernel conhecidos (offline) ══"; echo ""
KV=$(echo "$KERNEL_FULL" | grep -oE "^[0-9]+\.[0-9]+\.[0-9]+")
[[ -z "$KV" ]] && KV=$(echo "$KERNEL_FULL" | grep -oE "^[0-9]+\.[0-9]+" | awk '{print $1".0"}')
FOUND_CVES=0

kernel_lt() {
    local v1 v2
    v1=$(echo "$1" | awk -F'[.-]' '{printf "%05d%05d%05d",$1,$2,$3}')
    v2=$(echo "$2" | awk -F'[.-]' '{printf "%05d%05d%05d",$1,$2,$3}')
    [ "$v1" -lt "$v2" ]
}
kernel_le() {
    local v1 v2
    v1=$(echo "$1" | awk -F'[.-]' '{printf "%05d%05d%05d",$1,$2,$3}')
    v2=$(echo "$2" | awk -F'[.-]' '{printf "%05d%05d%05d",$1,$2,$3}')
    [ "$v1" -le "$v2" ]
}

check_cve() {
    local cve="$1" sev="$2" name="$3" fixed_in="$4" note="$5"
    if kernel_lt "$KV" "$fixed_in"; then
        echo "  ${sev}: ${cve} — ${name}"; echo "  Corrigido em: ${fixed_in} | Actual: ${KV}"
        [[ -n "$note" ]] && echo "  Nota: ${note}"; echo ""
        FOUND_CVES=$(( FOUND_CVES + 1 ))
    fi
}

check_cve "CVE-2024-1086"  "CRÍTICO" "nf_tables use-after-free (LPE/container escape)" "6.6.15" "Exploited in-the-wild"
check_cve "CVE-2024-0646"  "CRÍTICO" "mremap() out-of-bounds write"                    "6.6.6"  "Kernel memory corruption LPE"
check_cve "CVE-2024-26581" "HIGH"    "nft_set_rbtree UAF"                               "6.7.3"  "netfilter UAF"
check_cve "CVE-2023-6931"  "HIGH"    "perf_group_detach out-of-bounds"                 "6.7.0"  "LPE via perf"
check_cve "CVE-2023-4623"  "CRÍTICO" "sch_hfsc UAF (net/sched)"                        "6.5.3"  "LPE — exploits activos"
check_cve "CVE-2023-3389"  "HIGH"    "io_uring UAF (IORING_OP_SPLICE)"                 "6.3.8"  "LPE via io_uring"
check_cve "CVE-2023-32629" "CRÍTICO" "overlayfs privesc (Ubuntu)"                      "6.2.0"  "Exploited in-the-wild Ubuntu"
check_cve "CVE-2023-2640"  "CRÍTICO" "overlayfs Ubuntu privesc"                        "6.2.0"  "Par com CVE-2023-32629"
check_cve "CVE-2022-3910"  "CRÍTICO" "cls_u32 UAF (net/sched)"                         "6.0.7"  "LPE"
check_cve "CVE-2022-0847"  "CRÍTICO" "Dirty Pipe"                                      "5.16.11" "Exploited in-the-wild"
check_cve "CVE-2022-0185"  "CRÍTICO" "fsconfig heap overflow"                          "5.16.2" "LPE com user namespace"
check_cve "CVE-2021-4034"  "CRÍTICO" "PwnKit — pkexec LPE"                             "0.0.0"  "pkexec (polkit), não kernel"
check_cve "CVE-2021-22555" "CRÍTICO" "netfilter heap OOB write"                        "5.12.13" "Exploited in-the-wild"
check_cve "CVE-2021-3156"  "CRÍTICO" "Baron Samedit — sudo heap overflow"              "0.0.0"  "sudo <1.9.5p2"
check_cve "CVE-2020-14386" "CRÍTICO" "raw socket heap overflow"                        "5.9.0"  "LPE com CAP_NET_RAW"
check_cve "CVE-2016-5195"  "CRÍTICO" "Dirty COW"                                       "4.8.3"  "Exploited — kernels antigos"

# Checks específicos de distro
command -v pkexec &>/dev/null && {
    PKEXEC_VER=$(pkexec --version 2>/dev/null | grep -oE "[0-9]+\.[0-9]+\.[0-9]+")
    [[ -n "$PKEXEC_VER" ]] && kernel_lt "$PKEXEC_VER" "0.120" && \
        echo "  CRÍTICO: CVE-2021-4034 (PwnKit) — pkexec ${PKEXEC_VER} < 0.120 — CWE-269"
}
echo "${DISTRO_ID}" | grep -qi "ubuntu" && kernel_lt "$KV" "6.2.0" && \
    echo "  CRÍTICO: CVE-2023-2640 + CVE-2023-32629 (overlayfs Ubuntu)"
command -v runc &>/dev/null && {
    RUNC_VER=$(runc --version 2>/dev/null | grep "runc version" | grep -oE "[0-9]+\.[0-9]+\.[0-9]+")
    [[ -n "$RUNC_VER" ]] && kernel_lt "$RUNC_VER" "1.1.12" && \
        echo "  CRÍTICO: CVE-2024-21626 (Leaky Vessels) — runc ${RUNC_VER} < 1.1.12"
}

[[ "$FOUND_CVES" -eq 0 ]] && echo "OK: Nenhum CVE inline detectado para kernel ${KV}" || \
    echo "TOTAL CVEs inline potencialmente afectados: ${FOUND_CVES}"
} > "$PATCH_OUT" 2>&1
sz=$(stat -c%s "$PATCH_OUT" 2>/dev/null || echo 0)
info "10_patch_gap OK ($(( sz / 1024 )) KB)"

# ─── 11: Application Vulnerability Scan ──────────────────────────
section "11 — App Vulns"
APP_OUT="${OUT}/11_app_vulns.txt"
{
echo "=== APPLICATION VULNERABILITY SCAN ==="; echo "Data: $(date)"; echo ""

# Inventário completo (texto para o relatório de audit)
echo "══ INVENTÁRIO ══"; echo ""
echo "--- System packages ---"
case "$PKG_MGR" in
    apt)    dpkg-query -W -f='${Package}==${Version}\n' 2>/dev/null | sort | head -200 ;;
    dnf|yum) rpm -qa --qf '%{NAME}==%{VERSION}-%{RELEASE}\n' 2>/dev/null | sort | head -200 ;;
    pacman) pacman -Q 2>/dev/null | tr ' ' '==' | head -200 ;;
    apk)    apk list --installed 2>/dev/null | head -200 ;;
esac
echo ""

echo "--- Runtimes ---"
for cmd in python3 python ruby node java go rustc php perl dotnet; do
    command -v "$cmd" &>/dev/null && echo "  ${cmd}: $("$cmd" --version 2>&1 | head -1)"
done
command -v java &>/dev/null && java -version 2>&1 | head -2 | sed 's/^/  /'

echo ""; echo "--- Browsers ---"
for b in google-chrome chromium chromium-browser firefox firefox-esr brave-browser microsoft-edge opera; do
    command -v "$b" &>/dev/null && echo "  ${b}: $("$b" --version 2>/dev/null || echo 'version unknown')"
done
command -v flatpak &>/dev/null && flatpak list 2>/dev/null | grep -iE "firefox|chrome|chromium|brave|edge" | awk '{print "  flatpak:",$1,$3}' | head -5

echo ""; echo "--- Servidores ---"
for svc in nginx apache2 httpd mysql mariadb postgres redis-server mongod docker containerd; do
    command -v "$svc" &>/dev/null && echo "  ${svc}: $("$svc" --version 2>/dev/null || "$svc" -v 2>/dev/null || echo 'installed'| head -1)"
done

echo ""; echo "--- DevOps / Security ---"
for t in git curl wget openssl ssh gpg docker kubectl helm terraform ansible vault; do
    command -v "$t" &>/dev/null && echo "  ${t}: $("$t" --version 2>/dev/null || "$t" -V 2>/dev/null || echo 'installed' | head -1)"
done

command -v snap    &>/dev/null && { echo ""; echo "--- Snap ---"; snap list 2>/dev/null | tail -n +2 | awk '{print "  "$1"=="$2}' | head -20; }
command -v flatpak &>/dev/null && { echo ""; echo "--- Flatpak ---"; flatpak list --columns=application,version 2>/dev/null | awk '{print "  "$1"=="$2}' | head -20; }
echo ""

# OSV-Scanner
echo "══ OSV-SCANNER ══"; echo ""
if [[ -n "$OSV_CMD" ]] && [[ -x "$OSV_CMD" ]]; then
    timeout 180 "$OSV_CMD" --format table --installed 2>/dev/null || \
        timeout 180 "$OSV_CMD" --format table --fs / 2>/dev/null || echo "  OSV --installed não suportado"
    echo ""
    echo "--- Lock files ---"
    # -xdev: não atravessar mountpoints (NFS, FUSE, etc — podem travar)
    # timeout 60s: limite total para o find não levar minutos
    LOCK_FILES=$(timeout 60 find / -xdev \( -name "package-lock.json" -o -name "yarn.lock" -o -name "requirements.txt" \
        -o -name "Pipfile.lock" -o -name "poetry.lock" -o -name "Gemfile.lock" \
        -o -name "go.sum" -o -name "Cargo.lock" -o -name "pom.xml" \) \
        -not -path "*/\.*" -not -path "*/node_modules/*" -not -path "/proc/*" -not -path "/sys/*" \
        2>/dev/null | head -20)
    [[ -n "$LOCK_FILES" ]] && echo "$LOCK_FILES" | while IFS= read -r lf; do
        echo "  Scanning: $lf"
        timeout 60 "$OSV_CMD" --format table --lockfile "$lf" 2>/dev/null || true
    done || echo "  Sem lock files encontrados"
    SBOM_OUT="${OUT}/11_sbom.cdx.json"
    timeout 180 "$OSV_CMD" scan --format cyclonedx-1-4 --installed --output "$SBOM_OUT" 2>/dev/null && \
        echo "SBOM gerado: ${SBOM_OUT}" || true
else
    echo "[!] OSV-Scanner não disponível (ver log para detalhes)"
fi
echo ""

# Grype
echo "══ GRYPE ══"; echo ""
if [[ -x "$GRYPE_BIN" ]]; then
    "$GRYPE_BIN" db update 2>/dev/null || true
    timeout 300 "$GRYPE_BIN" --output table --only-fixed dir:/ \
        --exclude "/proc" --exclude "/sys" --exclude "/dev" --exclude "/run" 2>/dev/null || true
    echo ""
    timeout 300 "$GRYPE_BIN" --output json dir:/ \
        --exclude "/proc" --exclude "/sys" --exclude "/dev" --exclude "/run" \
        --file "$GRYPE_JSON" 2>/dev/null || true
    [[ -f "$GRYPE_JSON" ]] && GRYPE_JSON="$GRYPE_JSON" python3 - <<'PYEOF'
import json,os,sys
gf=os.environ.get('GRYPE_JSON','')
try:
    d=json.load(open(gf))
    by_s={}
    for m in d.get('matches',[]):
        sev=m['vulnerability'].get('severity','Unknown').upper()
        by_s.setdefault(sev,[]).append((m['vulnerability']['id'],m['artifact']['name'],m['artifact'].get('version','')))
    for sev in ['CRITICAL','HIGH','MEDIUM','LOW']:
        items=by_s.get(sev,[])
        if not items: continue
        print(f"\n  {sev} ({len(items)}):")
        for cve,pkg,ver in items[:15]: print(f"    {cve:20s} {pkg}=={ver}")
    print(f"\n  TOTAL: {sum(len(v) for v in by_s.values())}")
except Exception as e: print(f"  Erro: {e}")
PYEOF
else
    echo "[!] Grype não disponível"
fi

# PURL / NVD lookup para apps críticas
if [[ "$NO_NVD" != "true" ]]; then
    echo ""; echo "══ PURL / NVD LOOKUP ══"; echo ""
    declare -A PURL_MAP
    command -v openssl &>/dev/null && PURL_MAP["openssl"]="$(openssl version 2>/dev/null | awk '{print $2}')"
    command -v ssh     &>/dev/null && PURL_MAP["openssh"]="$(ssh -V 2>&1 | grep -oE 'OpenSSH_[0-9.p]+' | grep -oE '[0-9.p]+')"
    command -v curl    &>/dev/null && PURL_MAP["curl"]="$(curl --version 2>/dev/null | head -1 | awk '{print $2}')"
    command -v git     &>/dev/null && PURL_MAP["git"]="$(git --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')"
    command -v python3 &>/dev/null && PURL_MAP["python"]="$(python3 --version 2>/dev/null | awk '{print $2}')"
    command -v nginx   &>/dev/null && PURL_MAP["nginx"]="$(nginx -v 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')"
    for b in google-chrome chromium firefox; do
        command -v "$b" &>/dev/null && PURL_MAP["$b"]="$("$b" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9.]+'| head -1)"
    done
    for app in "${!PURL_MAP[@]}"; do
        ver="${PURL_MAP[$app]}"; [[ -z "$ver" ]] && continue
        echo "─── ${app} ${ver} ───"
        NVD_RESP=$(nvd_curl "$app" 5) || \
            { echo "  API NVD indisponível"; nvd_sleep_short; continue; }
        echo "$NVD_RESP" | python3 -c "
import sys,json
try:
    d=json.load(sys.stdin)
    for v in d.get('vulnerabilities',[])[:5]:
        cve=v['cve']['id']; sev='N/A'
        for k in ('cvssMetricV31','cvssMetricV30','cvssMetricV2'):
            ms=v['cve'].get('metrics',{}).get(k,[])
            if ms: sev=ms[0].get('cvssData',{}).get('baseSeverity','N/A'); break
        label='CRÍTICO' if sev=='CRITICAL' else 'ALERTA' if sev=='HIGH' else sev
        desc=next((x['value'] for x in v['cve'].get('descriptions',[]) if x.get('lang')=='en'),'')[:100]
        print(f'  {label}: {cve} [{sev}] — {desc}')
except Exception as e: print(f'  Erro: {e}')
" 2>/dev/null
        echo ""; nvd_sleep_short
    done
fi

# Trivy detalhado (linguagens)
echo ""; echo "══ TRIVY — Apps ══"; echo ""
TRIVY_CMD=$(command -v trivy 2>/dev/null || echo "$TRIVY_BIN")
[[ -x "$TRIVY_CMD" ]] && \
    timeout 300 "$TRIVY_CMD" fs / --scanners vuln --severity CRITICAL,HIGH --format table \
        --no-progress --skip-dirs /proc,/sys,/dev,/run,/snap 2>/dev/null || \
    echo "[!] Trivy não disponível"

} > "$APP_OUT" 2>&1
sz=$(stat -c%s "$APP_OUT" 2>/dev/null || echo 0)
info "11_app_vulns OK ($(( sz / 1024 )) KB)"

# ═══════════════════════════════════════════════════════════════════
# FASE 3 — INVENTÁRIO ESTRUTURADO JSON (do vuln-check.sh)
# ═══════════════════════════════════════════════════════════════════
step "FASE 3 — Inventário JSON"

INV_TMP="${OUT}/inv_tmp.json"
printf '[\n' > "$INV_TMP"
INV_FIRST=1

add_inv() {
    local key="$1" name="$2" ver="$3" cat="$4" nvd="$5" src="$6"
    [[ -z "$ver" || "$ver" == "0" ]] && return
    name="${name//\"/\'}"; ver="${ver//\"/\'}"; key="${key//\//_}"
    [[ "$INV_FIRST" -eq 0 ]] && printf ',\n' >> "$INV_TMP"
    printf '{"key":"%s","name":"%s","version":"%s","category":"%s","nvd_keyword":"%s","source":"%s"}' \
        "$key" "$name" "$ver" "$cat" "$nvd" "$src" >> "$INV_TMP"
    INV_FIRST=0
}

# Apps conhecidas via binários
declare -A APP_BINS=(
    ["firefox"]="Firefox|firefox|--version|Browser|firefox"
    ["chromium"]="Chromium|chromium-browser|--version|Browser|chromium"
    ["google-chrome"]="Google Chrome|google-chrome|--version|Browser|google chrome"
    ["vscode"]="VS Code|code|--version|Editor|visual studio code"
    ["vim"]="Vim|vim|--version|Editor|vim"
    ["neovim"]="Neovim|nvim|--version|Editor|neovim"
    ["python3"]="Python 3|python3|--version|Runtime|python"
    ["node"]="Node.js|node|--version|Runtime|node.js"
    ["java"]="Java|java|-version|Runtime|java jdk"
    ["ruby"]="Ruby|ruby|--version|Runtime|ruby"
    ["php"]="PHP|php|--version|Runtime|php"
    ["go"]="Go|go|version|Runtime|go programming language"
    ["rust"]="Rust|rustc|--version|Runtime|rust programming language"
    ["openssh"]="OpenSSH|ssh|-V|Remote|openssh"
    ["openssl"]="OpenSSL|openssl|version|Security|openssl"
    ["nmap"]="Nmap|nmap|--version|Network|nmap"
    ["wireshark"]="Wireshark|wireshark|--version|Network|wireshark"
    ["curl"]="cURL|curl|--version|Network|curl"
    ["wget"]="Wget|wget|--version|Network|wget"
    ["openvpn"]="OpenVPN|openvpn|--version|Network|openvpn"
    ["docker"]="Docker|docker|--version|Virtualization|docker"
    ["git"]="Git|git|--version|DevTool|git"
    ["gpg"]="GnuPG|gpg|--version|Security|gnupg"
    ["vlc"]="VLC|vlc|--version|Media|vlc media player"
    ["nginx"]="nginx|nginx|-v|Server|nginx"
    ["apache2"]="Apache|apache2|-v|Server|apache http server"
    ["mysql"]="MySQL|mysql|--version|Database|mysql"
    ["psql"]="PostgreSQL|psql|--version|Database|postgresql"
    ["redis-server"]="Redis|redis-server|--version|Database|redis"
    ["ansible"]="Ansible|ansible|--version|DevTool|ansible"
)

for key in "${!APP_BINS[@]}"; do
    IFS='|' read -r display binary ver_flag category nvd_kw <<< "${APP_BINS[$key]}"
    binary_path=$(command -v "$binary" 2>/dev/null || true)
    [[ -z "$binary_path" ]] && continue
    ver=$("$binary" "$ver_flag" 2>&1 | grep -oP '\d+\.\d+[\.\d-p]*' | head -1 || true)
    [[ -z "$ver" ]] && continue
    add_inv "$key" "$display" "$ver" "$category" "$nvd_kw" "binary"
done

# System packages
case "$PKG_MGR" in
    apt)
        while IFS= read -r line; do
            pkg=$(echo "$line" | awk '{print $1}'); ver=$(echo "$line" | awk '{print $2}')
            [[ -z "$pkg" || -z "$ver" ]] && continue
            add_inv "pkg_${pkg}" "$pkg" "$ver" "Package" "$pkg" "dpkg"
        done < <(dpkg-query -W -f='${Package} ${Version}\n' 2>/dev/null | head -1500) ;;
    dnf|yum)
        while IFS= read -r line; do
            pkg=$(echo "$line" | awk '{print $1}'); ver=$(echo "$line" | awk '{print $2}')
            [[ -z "$pkg" || -z "$ver" ]] && continue
            add_inv "pkg_${pkg}" "$pkg" "$ver" "Package" "$pkg" "rpm"
        done < <(rpm -qa --queryformat '%{NAME} %{VERSION}-%{RELEASE}\n' 2>/dev/null | head -1500) ;;
    pacman)
        while IFS= read -r line; do
            pkg=$(echo "$line" | awk '{print $1}'); ver=$(echo "$line" | awk '{print $2}')
            [[ -z "$pkg" || -z "$ver" ]] && continue
            add_inv "pkg_${pkg}" "$pkg" "$ver" "Package" "$pkg" "pacman"
        done < <(pacman -Q 2>/dev/null | head -1500) ;;
    apk)
        while IFS= read -r line; do
            pkg=$(echo "$line" | grep -oP '^[a-z0-9_-]+' || true)
            ver=$(echo "$line" | grep -oP '\d+\.\d+[\.\d-r]*' | head -1 || true)
            [[ -z "$pkg" || -z "$ver" ]] && continue
            add_inv "pkg_${pkg}" "$pkg" "$ver" "Package" "$pkg" "apk"
        done < <(apk list --installed 2>/dev/null | head -1500) ;;
esac

printf '\n]\n' >> "$INV_TMP"

python3 -c "
import json,sys
try:
    data=json.load(open('${INV_TMP}'))
    seen={}
    for item in data:
        k=item.get('key','')
        if k not in seen: seen[k]=item
    out=list(seen.values())
    json.dump(out,open('${INV_FILE}','w'),indent=2)
    print(f'[+] Inventário: {len(out)} itens')
except Exception as e:
    print(f'[!] {e}',file=sys.stderr)
    import shutil; shutil.copy('${INV_TMP}','${INV_FILE}')
" 2>/dev/null || cp "$INV_TMP" "$INV_FILE"
rm -f "$INV_TMP"

INV_COUNT=$(python3 -c "import json; print(len(json.load(open('${INV_FILE}'))))" 2>/dev/null || echo "?")
info "Inventário: ${INV_COUNT} itens → ${INV_FILE}"

# ═══════════════════════════════════════════════════════════════════
# FASE 4 — CVE/CWE JSON ESTRUTURADO (Trivy + Grype + NVD API)
# ═══════════════════════════════════════════════════════════════════
step "FASE 4 — CVE JSON"

# Trivy em modo JSON
info "Trivy (JSON)..."
TRIVY_CMD=$(command -v trivy 2>/dev/null || echo "$TRIVY_BIN")
if [[ -x "$TRIVY_CMD" ]]; then
    export TRIVY_NO_PROGRESS=true
    timeout 600 "$TRIVY_CMD" fs / \
        --format json --output "$TRIVY_JSON" \
        --skip-dirs "/proc,/sys,/dev,/run,/snap" \
        2>/dev/null || true
fi

# Grype JSON já gerado na fase 11
[[ -f "$GRYPE_JSON" ]] && info "Grype JSON já disponível (fase 11)"

# Construir cve_results.json a partir de Trivy + Grype + NVD
TRIVY_JSON="$TRIVY_JSON" GRYPE_JSON="$GRYPE_JSON" INV_FILE="$INV_FILE" NO_NVD="$NO_NVD" \
NVD_API_KEY="$NVD_API_KEY" \
python3 - <<'PYEOF' > "$CVE_FILE" 2>/dev/null
import json, urllib.request, urllib.parse, time, sys, os

results = []
seen_pairs = set()

# ── Trivy ────────────────────────────────────────────────────────
trivy_file = os.environ.get('TRIVY_JSON','')
if os.path.exists(trivy_file):
    try:
        td = json.load(open(trivy_file))
        for res in td.get('Results', []):
            for v in res.get('Vulnerabilities') or []:
                cve_id = v.get('VulnerabilityID', '')
                app    = v.get('PkgName', '') or res.get('Target','').split('/')[-1]
                pair   = (cve_id, app)
                if pair in seen_pairs: continue
                seen_pairs.add(pair)
                cvss = None
                if v.get('CVSS'):
                    for src in v['CVSS'].values():
                        if src.get('V3Score'): cvss = src['V3Score']; break
                results.append({
                    "Source": "Trivy", "App": app, "Version": v.get('InstalledVersion',''),
                    "FixedIn": v.get('FixedVersion',''), "CveId": cve_id,
                    "Severity": v.get('Severity','UNKNOWN').upper(), "Cvss": cvss,
                    "Title": (v.get('Title') or '')[:80],
                    "Description": (v.get('Description') or '')[:200],
                    "Cwe": ', '.join(v.get('CweIDs') or []),
                    "References": (v.get('References') or [''])[0]
                })
        print(f'[+]   Trivy JSON: {len(results)} CVEs', file=sys.stderr)
    except Exception as e:
        print(f'[!]   Trivy JSON erro: {e}', file=sys.stderr)

# ── Grype ────────────────────────────────────────────────────────
grype_file = os.environ.get('GRYPE_JSON','')
grype_added = 0
if os.path.exists(grype_file):
    try:
        gd = json.load(open(grype_file))
        for m in gd.get('matches', []):
            cve_id = m['vulnerability']['id']
            app    = m['artifact']['name']
            pair   = (cve_id, app)
            if pair in seen_pairs: continue
            seen_pairs.add(pair)
            cvss = None
            for c in m['vulnerability'].get('cvss', []):
                if str(c.get('version','')).startswith('3'):
                    cvss = c.get('metrics',{}).get('baseScore'); break
            results.append({
                "Source": "Grype", "App": app, "Version": m['artifact'].get('version',''),
                "FixedIn": ', '.join(m['vulnerability'].get('fix',{}).get('versions',[])),
                "CveId": cve_id, "Severity": m['vulnerability'].get('severity','UNKNOWN').upper(),
                "Cvss": cvss, "Title": "", "Description": (m['vulnerability'].get('description') or '')[:200],
                "Cwe": "", "References": (m['vulnerability'].get('urls') or [''])[0]
            })
            grype_added += 1
        print(f'[+]   Grype JSON: {grype_added} CVEs novos', file=sys.stderr)
    except Exception as e:
        print(f'[!]   Grype JSON erro: {e}', file=sys.stderr)

# ── NVD API (apps conhecidas) ────────────────────────────────────
no_nvd = os.environ.get('NO_NVD','false')
inv_file = os.environ.get('INV_FILE','')
nvd_api_key = os.environ.get('NVD_API_KEY','')

# Rate limits — com API key são 10× maiores
if nvd_api_key:
    batch_size = 50    # 50 req per 30s window
    batch_sleep = 6    # seconds entre batches
    max_apps = 100     # mais apps possível com key
else:
    batch_size = 5     # 5 req per 30s window
    batch_sleep = 32   # 32s entre batches
    max_apps = 30      # limitar para não demorar uma hora

if no_nvd != "true":
    try:
        inv_data = json.load(open(inv_file))
    except: inv_data = []
    bin_apps = [x for x in inv_data if x.get('source') == 'binary' and x.get('nvd_keyword')][:max_apps]
    print(f'[+] NVD API: {len(bin_apps)} apps (API key: {"sim" if nvd_api_key else "não"})...', file=sys.stderr)

    def nvd_fetch(keyword, retries=1):
        kw = urllib.parse.quote(keyword)
        url = f'https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={kw}&resultsPerPage=10'
        for attempt in range(retries + 1):
            try:
                headers = {'User-Agent': 'linux-full-audit/1.0'}
                if nvd_api_key:
                    headers['apiKey'] = nvd_api_key
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=25) as r:
                    return json.loads(r.read())
            except urllib.error.HTTPError as e:
                if e.code == 429 and attempt < retries:
                    print(f'[!]   NVD 429 — retry em {batch_sleep}s...', file=sys.stderr)
                    time.sleep(batch_sleep); continue
                raise
        return None

    for i, app in enumerate(bin_apps):
        if i > 0 and i % batch_size == 0:
            print(f'[+]   NVD: rate limit pause ({batch_sleep}s)...', file=sys.stderr)
            time.sleep(batch_sleep)
        try:
            data = nvd_fetch(app.get('nvd_keyword',''), retries=1)
        except Exception as e:
            print(f'[!]   NVD [{app["key"]}]: {e}', file=sys.stderr); continue
        if not data: continue
        for v in data.get('vulnerabilities', []):
            cve = v['cve']; cve_id = cve['id']
            pair = (cve_id, app['key'])
            if pair in seen_pairs: continue
            seen_pairs.add(pair)
            desc = next((d['value'] for d in cve.get('descriptions',[]) if d['lang']=='en'), '')
            sev = 'UNKNOWN'; score = None; cwe = ''
            for mk in ['cvssMetricV31','cvssMetricV30','cvssMetricV2']:
                ms = cve.get('metrics',{}).get(mk)
                if ms:
                    sev = ms[0]['cvssData'].get('baseSeverity','UNKNOWN').upper()
                    score = ms[0]['cvssData'].get('baseScore'); break
            if cve.get('weaknesses'):
                cwes = [d2['value'] for w in cve['weaknesses'] for d2 in w.get('description',[])
                        if d2.get('value','').startswith('CWE-')]
                cwe = ', '.join(cwes)
            refs = (cve.get('references') or [{}])[0].get('url','')
            results.append({
                "Source": "NVD", "App": app['key'], "Version": app['version'],
                "FixedIn": "", "CveId": cve_id, "Severity": sev, "Cvss": score,
                "Title": "", "Description": desc[:200], "Cwe": cwe, "References": refs
            })
        print(f'[+]   {app["key"]} — {data.get("totalResults",0)} NVD', file=sys.stderr)

print(f'[+] CVE total: {len(results)}', file=sys.stderr)
json.dump(results, sys.stdout, indent=2)
PYEOF

CVE_TOTAL=$(python3 -c "import json; print(len(json.load(open('${CVE_FILE}'))))" 2>/dev/null || echo "?")
info "CVEs: ${CVE_TOTAL} total → ${CVE_FILE}"

# ═══════════════════════════════════════════════════════════════════
# FASE 4.5 — EXPORTS (CSV + SARIF) e COMPARAÇÃO (#1 + #3)
# ═══════════════════════════════════════════════════════════════════
step "FASE 4.5 — Exports CSV/SARIF + Compare"

# ── CSV Export ────────────────────────────────────────────────────
PY_ERR_CSV=$(mktemp 2>/dev/null) || PY_ERR_CSV="/tmp/pyerr_csv_$$"
CVE_FILE="$CVE_FILE" CSV_FILE="$CVE_CSV" python3 <<'PYEOF' 2>"$PY_ERR_CSV"
import json, csv, os, sys
try:
    data = json.load(open(os.environ['CVE_FILE']))
except Exception as e:
    print(f'CSV: erro a ler CVE file: {e}', file=sys.stderr)
    sys.exit(1)
try:
    with open(os.environ['CSV_FILE'], 'w', newline='', encoding='utf-8') as f:
        fields = ['Source','App','Version','FixedIn','CveId','Severity','Cvss','Cwe','Title','Description','References']
        w = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
        w.writeheader()
        for row in data: w.writerow(row)
    print(f'[+] CSV: {len(data)} CVEs exportados')
except Exception as e:
    print(f'CSV: erro a escrever: {e}', file=sys.stderr)
    sys.exit(2)
PYEOF
py_check "CSV export" "$PY_ERR_CSV"
[[ -f "$CVE_CSV" ]] && info "CSV export: $CVE_CSV"

# ── SARIF Export ──────────────────────────────────────────────────
# SARIF 2.1.0 — formato standard consumido por GitHub, Azure DevOps, GitLab
PY_ERR_SARIF=$(mktemp 2>/dev/null) || PY_ERR_SARIF="/tmp/pyerr_sarif_$$"
CVE_FILE="$CVE_FILE" SARIF_FILE="$CVE_SARIF" TARGET="$TARGET" python3 <<'PYEOF' 2>"$PY_ERR_SARIF"
import json, os, datetime, sys
try:
    data = json.load(open(os.environ['CVE_FILE']))
except Exception as e:
    print(f'SARIF: erro: {e}', file=sys.stderr); sys.exit(1)

sev_map = {'CRITICAL': 'error', 'HIGH': 'error', 'IMPORTANT': 'error',
           'MEDIUM': 'warning', 'MODERATE': 'warning',
           'LOW': 'note', 'NEGLIGIBLE': 'note', 'UNKNOWN': 'none'}

# Construir rules únicas e results
rules_dict = {}
results = []
for cve in data:
    cve_id = cve.get('CveId','')
    if not cve_id: continue
    if cve_id not in rules_dict:
        rules_dict[cve_id] = {
            "id": cve_id,
            "name": cve_id,
            "shortDescription": {"text": (cve.get('Title') or cve_id)[:120]},
            "fullDescription": {"text": (cve.get('Description') or '')[:500] or cve_id},
            "helpUri": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "properties": {
                "tags": ["security", "cve", cve.get('Cwe','').split(',')[0].strip() if cve.get('Cwe') else ''],
                "security-severity": str(cve.get('Cvss') or 0)
            }
        }
    sev = (cve.get('Severity') or 'UNKNOWN').upper()
    results.append({
        "ruleId": cve_id,
        "level": sev_map.get(sev, 'none'),
        "message": {
            "text": f"{cve.get('App','?')} {cve.get('Version','?')} → {cve_id} ({sev})" +
                    (f" — fixed in {cve['FixedIn']}" if cve.get('FixedIn') else "")
        },
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": cve.get('App','unknown')}
            }
        }],
        "properties": {
            "package": cve.get('App',''),
            "version": cve.get('Version',''),
            "fixedVersion": cve.get('FixedIn',''),
            "cwe": cve.get('Cwe',''),
            "source": cve.get('Source','')
        }
    })

sarif = {
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    "version": "2.1.0",
    "runs": [{
        "tool": {
            "driver": {
                "name": "linux-full-audit",
                "version": "1.0",
                "informationUri": "https://github.com/user/security-audit-scripts",
                "rules": list(rules_dict.values())
            }
        },
        "invocations": [{
            "executionSuccessful": True,
            "startTimeUtc": datetime.datetime.utcnow().isoformat() + 'Z',
            "machine": os.environ.get('TARGET','')
        }],
        "results": results
    }]
}
try:
    with open(os.environ['SARIF_FILE'], 'w', encoding='utf-8') as f:
        json.dump(sarif, f, indent=2)
    print(f'[+] SARIF: {len(results)} results, {len(rules_dict)} rules')
except Exception as e:
    print(f'SARIF: erro a escrever: {e}', file=sys.stderr); sys.exit(2)
PYEOF
py_check "SARIF export" "$PY_ERR_SARIF"
[[ -f "$CVE_SARIF" ]] && info "SARIF export: $CVE_SARIF"

# ── Compare com run anterior (#3) ─────────────────────────────────
if [[ -n "$COMPARE_FILE" ]]; then
    info "A comparar com: $COMPARE_FILE"
    PY_ERR_DIFF=$(mktemp 2>/dev/null) || PY_ERR_DIFF="/tmp/pyerr_diff_$$"
    CVE_FILE="$CVE_FILE" PREV_FILE="$COMPARE_FILE" DIFF_FILE="$DIFF_FILE" python3 <<'PYEOF' 2>"$PY_ERR_DIFF"
import json, os, sys
try:
    current = json.load(open(os.environ['CVE_FILE']))
    previous = json.load(open(os.environ['PREV_FILE']))
except Exception as e:
    print(f'Compare: erro a ler ficheiros: {e}', file=sys.stderr); sys.exit(1)

# Indexar por (CVE, App) para comparar
def index_by_key(data):
    return { (x.get('CveId',''), x.get('App','')): x for x in data if x.get('CveId') }

cur_idx = index_by_key(current)
prev_idx = index_by_key(previous)
cur_keys = set(cur_idx.keys())
prev_keys = set(prev_idx.keys())

new_cves      = [cur_idx[k] for k in (cur_keys - prev_keys)]
resolved_cves = [prev_idx[k] for k in (prev_keys - cur_keys)]

# Mudanças de severidade
sev_changes = []
for k in (cur_keys & prev_keys):
    cur_sev = (cur_idx[k].get('Severity') or '').upper()
    prev_sev = (prev_idx[k].get('Severity') or '').upper()
    if cur_sev != prev_sev:
        sev_changes.append({
            "CveId": k[0], "App": k[1],
            "Previous": prev_sev, "Current": cur_sev,
            "Cvss": cur_idx[k].get('Cvss')
        })

diff = {
    "previous_file": os.environ['PREV_FILE'],
    "current_file": os.environ['CVE_FILE'],
    "summary": {
        "total_previous": len(previous),
        "total_current": len(current),
        "new": len(new_cves),
        "resolved": len(resolved_cves),
        "severity_changed": len(sev_changes)
    },
    "new_cves": new_cves,
    "resolved_cves": resolved_cves,
    "severity_changes": sev_changes
}
try:
    with open(os.environ['DIFF_FILE'], 'w', encoding='utf-8') as f:
        json.dump(diff, f, indent=2)
    print(f'[+] Compare: {len(new_cves)} novos, {len(resolved_cves)} resolvidos, {len(sev_changes)} mudaram severidade')
except Exception as e:
    print(f'Compare: erro a escrever diff: {e}', file=sys.stderr); sys.exit(2)
PYEOF
    py_check "Compare diff" "$PY_ERR_DIFF"
    [[ -f "$DIFF_FILE" ]] && info "Diff: $DIFF_FILE"
fi

# ═══════════════════════════════════════════════════════════════════
# FASE 5 — APP UPDATES JSON
# ═══════════════════════════════════════════════════════════════════
step "FASE 5 — App Updates"

PKG_MGR="$PKG_MGR" SUDO="$SUDO" python3 - <<'PYEOF' > "$APP_UPD_JSON" 2>/dev/null
import json, subprocess, re, sys, os

updates = []
pkg_mgr = os.environ.get('PKG_MGR','unknown')
sudo    = os.environ.get('SUDO','')

def run(cmd, timeout=90):
    try: return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL, timeout=timeout, text=True)
    except: return ""

if pkg_mgr == "apt":
    # Update cache — apt-get update precisa de root; usar SUDO se script não está como root
    run(f"{sudo} apt-get update -qq 2>/dev/null")
    out = run("apt list --upgradable 2>/dev/null")
    for line in out.splitlines():
        m = re.match(r'^(\S+)/\S+\s+(\S+)\s+\S+\s+\[upgradable from:\s+(\S+)\]', line)
        if m:
            updates.append({"Source":"apt","Name":m.group(1),"Current":m.group(3),"Available":m.group(2),
                            "UpdateCmd":f"apt-get install --only-upgrade {m.group(1)}"})

elif pkg_mgr in ("dnf","yum"):
    out = run(f"{sudo} {pkg_mgr} check-update --quiet 2>/dev/null")
    for line in out.splitlines():
        m = re.match(r'^(\S+)\s+(\S+)\s+(\S+)', line)
        if m and m.group(1) not in ('Last','Loaded','Updated','Security'):
            updates.append({"Source":pkg_mgr,"Name":m.group(1),"Current":"","Available":m.group(2),
                            "UpdateCmd":f"{pkg_mgr} update -y {m.group(1)}"})

elif pkg_mgr == "pacman":
    out = run("pacman -Qu 2>/dev/null")
    for line in out.splitlines():
        m = re.match(r'^(\S+)\s+(\S+)\s+->\s+(\S+)', line)
        if m:
            updates.append({"Source":"pacman","Name":m.group(1),"Current":m.group(2),"Available":m.group(3),
                            "UpdateCmd":f"pacman -S --noconfirm {m.group(1)}"})

elif pkg_mgr == "zypper":
    out = run("zypper list-updates 2>/dev/null")
    for line in out.splitlines():
        parts = [p.strip() for p in line.split('|')]
        if len(parts) >= 5 and parts[0] == 'v':
            updates.append({"Source":"zypper","Name":parts[2],"Current":parts[4] if len(parts)>4 else "","Available":parts[3],
                            "UpdateCmd":f"zypper update {parts[2]}"})

elif pkg_mgr == "apk":
    out = run("apk version -l '<' 2>/dev/null")
    for line in out.splitlines():
        m = re.match(r'^(\S+)-(\S+)\s+<\s+(\S+)', line)
        if m:
            updates.append({"Source":"apk","Name":m.group(1),"Current":m.group(2),"Available":m.group(3),
                            "UpdateCmd":f"apk add --upgrade {m.group(1)}"})

json.dump(updates, sys.stdout, indent=2)
print(f'[+] App updates: {len(updates)}', file=sys.stderr)
PYEOF

APP_UPD_COUNT=$(python3 -c "import json; print(len(json.load(open('${APP_UPD_JSON}'))))" 2>/dev/null || echo "?")
info "App updates: ${APP_UPD_COUNT} disponíveis"

# ═══════════════════════════════════════════════════════════════════
# FASE 6 — RELATÓRIO HTML UNIFICADO
# ═══════════════════════════════════════════════════════════════════
step "FASE 6 — Relatório HTML"

sleep 1  # flush a disco

# ── Estatísticas para o relatório de audit ─────────────────────────
mapfile -t TXT_FILES < <(find "$OUT" -maxdepth 1 -name "*.txt" -type f | sort)

# Cache: contagens crit/high por ficheiro — calculado UMA vez, reusado em TOC,
# Executive Summary, secções por categoria e categoria-level totals
declare -A CRIT_CACHE HIGH_CACHE
TOTAL_CRIT=0; TOTAL_HIGH=0; ALL_CVES=""; ALL_CWES=""
for f in "${TXT_FILES[@]}"; do
    [[ -f "$f" && -s "$f" ]] || { CRIT_CACHE[$f]=0; HIGH_CACHE[$f]=0; continue; }
    c=$(safe_count "$f" "CRÍTICO\|CRITICAL")
    h=$(safe_count "$f" "\[HIGH\]\|HIGH\b\|ALERTA")
    CRIT_CACHE[$f]=$c
    HIGH_CACHE[$f]=$h
    TOTAL_CRIT=$(( TOTAL_CRIT + c ))
    TOTAL_HIGH=$(( TOTAL_HIGH + h ))
    cves_found=$(grep -oE "CVE-[0-9]{4}-[0-9]+" "$f" 2>/dev/null | sort -u | tr '\n' ' ') || true
    cwes_found=$(grep -oE "CWE-[0-9]+"            "$f" 2>/dev/null | sort -u | tr '\n' ' ') || true
    ALL_CVES="${ALL_CVES} ${cves_found}"; ALL_CWES="${ALL_CWES} ${cwes_found}"
done

UNIQ_CVES=0; UNIQ_CWES=0
[[ -n "${ALL_CVES// /}" ]] && UNIQ_CVES=$(echo "$ALL_CVES" | tr ' ' '\n' | grep -c "CVE-" 2>/dev/null) || UNIQ_CVES=0
[[ -n "${ALL_CWES// /}" ]] && UNIQ_CWES=$(echo "$ALL_CWES" | tr ' ' '\n' | sort -u | grep -c "CWE-" 2>/dev/null) || UNIQ_CWES=0
UNIQ_CVES="${UNIQ_CVES//[[:space:]]/}"; [[ "$UNIQ_CVES" =~ ^[0-9]+$ ]] || UNIQ_CVES=0
UNIQ_CWES="${UNIQ_CWES//[[:space:]]/}"; [[ "$UNIQ_CWES" =~ ^[0-9]+$ ]] || UNIQ_CWES=0

CVES_SORTED=$(echo "$ALL_CVES" | tr ' ' '\n' | grep "CVE-" | sort -u 2>/dev/null) || CVES_SORTED=""

TOP_FINDINGS=$(
    for f in "${TXT_FILES[@]}"; do
        [[ -s "$f" ]] || continue; base=$(basename "$f" .txt)
        grep -E "^.{0,200}(CRÍTICO|CRITICAL|ALERTA)" "$f" 2>/dev/null | head -3 | while IFS= read -r line; do
            sev="high"; echo "$line" | grep -qE "CRÍTICO|CRITICAL" && sev="critical"
            short=$(echo "$line" | cut -c1-180 | html_escape)
            echo "${sev}|${base}|${short}"
        done
    done | head -20
)

build_cve_table() {
    # Para cada CVE: procurar em todos os .txt, tentar encontrar severity dentro de 80 chars
    # do CVE (à direita ou à esquerda) — heurística melhor do que apenas "context"
    for cve in $CVES_SORTED; do
        [[ -z "$cve" ]] && continue
        local sev="UNKNOWN" desc="" found_in="" sev_prefix="5"
        for f in "${TXT_FILES[@]}"; do
            [[ -s "$f" ]] || continue
            # Procurar o CVE no ficheiro
            if grep -q "$cve" "$f" 2>/dev/null; then
                found_in=$(basename "$f" .txt)
                # Pegar a linha do CVE + 1 antes e 1 depois
                local raw_ctx
                raw_ctx=$(grep -B1 -A1 -m1 "$cve" "$f" 2>/dev/null)
                # Procurar severity próximo do CVE (mesma linha tem prioridade)
                local cve_line
                cve_line=$(echo "$raw_ctx" | grep -m1 "$cve")
                # Prioridade: severity NA MESMA LINHA do CVE
                if echo "$cve_line" | grep -qE "\bCRITICAL\b|CRÍTICO"; then
                    sev="CRITICAL"; sev_prefix="1"
                elif echo "$cve_line" | grep -qE "\bHIGH\b|ALERTA"; then
                    sev="HIGH"; sev_prefix="2"
                elif echo "$cve_line" | grep -qE "\bMEDIUM\b"; then
                    sev="MEDIUM"; sev_prefix="3"
                elif echo "$cve_line" | grep -qE "\bLOW\b"; then
                    sev="LOW"; sev_prefix="4"
                else
                    # Fallback: severity nas linhas adjacentes (mesma ordem)
                    if echo "$raw_ctx" | grep -qE "\bCRITICAL\b|CRÍTICO"; then
                        sev="CRITICAL"; sev_prefix="1"
                    elif echo "$raw_ctx" | grep -qE "\bHIGH\b|ALERTA"; then
                        sev="HIGH"; sev_prefix="2"
                    elif echo "$raw_ctx" | grep -qE "\bMEDIUM\b"; then
                        sev="MEDIUM"; sev_prefix="3"
                    elif echo "$raw_ctx" | grep -qE "\bLOW\b"; then
                        sev="LOW"; sev_prefix="4"
                    fi
                fi
                desc=$(grep -A1 "$cve" "$f" 2>/dev/null | grep -oE "Desc: .{0,150}" | head -1 | sed 's/^Desc: //' | html_escape)
                [[ -z "$desc" ]] && desc="(ver ${found_in})"
                break
            fi
        done
        # Prefixo numérico para ordenação semântica (1=CRITICAL ... 5=UNKNOWN)
        echo "${sev_prefix}|${sev}|${cve}|${found_in}|${desc}"
    done | sort -t'|' -k1,1n -k3,3 | cut -d'|' -f2-
}
CVE_TABLE_DATA=$(build_cve_table)

# Organizar ficheiros por categoria para TOC
declare -A CAT_FILES
for f in "${TXT_FILES[@]}"; do
    [[ -f "$f" ]] || continue
    base=$(basename "$f" .txt); cat=$(categorize "$base")
    CAT_FILES[$cat]="${CAT_FILES[$cat]:-} ${base}"
done
TOC_ORDER="system network privesc hardening cve other"

# ── Ler JSON para o CVE Dashboard ─────────────────────────────────
CVE_JSON=$(cat "$CVE_FILE" 2>/dev/null || echo "[]")
INV_JSON=$(python3 -c "
import json
data=json.load(open('${INV_FILE}'))
# Apenas apps binárias + sample de packages para não explodir o HTML
out=[x for x in data if x.get('source')=='binary']
out+=[x for x in data if x.get('source')!='binary'][:300]
print(json.dumps(out))
" 2>/dev/null || echo "[]")
UPD_JSON=$(cat "$APP_UPD_JSON" 2>/dev/null || echo "[]")

# ── CVE stats para o Dashboard ─────────────────────────────────────
CVE_CRIT=$(python3 -c "import json; d=json.load(open('${CVE_FILE}')); print(sum(1 for x in d if (x.get('Severity') or '').upper()=='CRITICAL'))" 2>/dev/null || echo 0)
CVE_HIGH=$(python3 -c "import json; d=json.load(open('${CVE_FILE}')); print(sum(1 for x in d if (x.get('Severity') or '').upper() in ('HIGH','IMPORTANT')))" 2>/dev/null || echo 0)
CVE_MED=$(python3 -c "import json; d=json.load(open('${CVE_FILE}')); print(sum(1 for x in d if (x.get('Severity') or '').upper() in ('MEDIUM','MODERATE')))" 2>/dev/null || echo 0)
CWE_UNIQ=$(python3 -c "
import json; d=json.load(open('${CVE_FILE}'))
cwes=set()
for x in d:
    for c in (x.get('Cwe') or '').split(','):
        c=c.strip()
        if c.startswith('CWE-'): cwes.add(c)
print(len(cwes))
" 2>/dev/null || echo 0)

info "Stats audit: Critical=${TOTAL_CRIT} High=${TOTAL_HIGH} CVEs=${UNIQ_CVES} CWEs=${UNIQ_CWES}"
info "Stats CVE dashboard: Critical=${CVE_CRIT} High=${CVE_HIGH} Total=${CVE_TOTAL}"

# ─── Gerar HTML ───────────────────────────────────────────────────
{
cat <<HTMLHEAD
<!DOCTYPE html>
<html lang="pt">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Full Audit — ${TARGET} — ${DATE}</title>
<style>
:root{
  --bg:#0d1117; --bg2:#161b22; --bg3:#21262d; --bg4:#2d333b;
  --text:#c9d1d9; --dim:#8b949e; --border:#30363d;
  --cyan:#58a6ff; --green:#3fb950; --yellow:#d29922;
  --red:#f85149; --magenta:#bc8cff; --orange:#ff7b00;
  --red-bg:rgba(248,81,73,.12); --orange-bg:rgba(255,123,0,.10);
  --yellow-bg:rgba(210,153,34,.08); --green-bg:rgba(63,185,80,.08);
  --sidebar-w:260px;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:'Consolas','Monaco','Courier New',monospace;font-size:13px;line-height:1.5;display:flex;min-height:100vh}

/* ── Sidebar ── */
.sidebar{width:var(--sidebar-w);background:var(--bg2);border-right:1px solid var(--border);position:fixed;top:0;left:0;bottom:0;overflow-y:auto;padding:20px 0;z-index:50}
.sb-head{padding:0 20px 15px;border-bottom:1px solid var(--border);margin-bottom:10px}
.sb-head h2{color:var(--cyan);font-size:1em;margin-bottom:4px}
.sb-head .host{font-size:.78em;color:var(--dim)}
.toc-cat{padding:8px 20px 4px;font-size:.7em;color:var(--dim);text-transform:uppercase;letter-spacing:1px;margin-top:6px}
.toc-item{display:flex;justify-content:space-between;align-items:center;padding:5px 20px;cursor:pointer;color:var(--text);text-decoration:none;font-size:.83em;border-left:3px solid transparent;transition:.12s}
.toc-item:hover{background:var(--bg3);border-left-color:var(--cyan)}
.toc-item.active{background:var(--bg3);border-left-color:var(--cyan);color:var(--cyan)}
.toc-badges{display:flex;gap:3px}
.toc-mini{padding:1px 5px;border-radius:2px;font-size:.7em;font-weight:bold}
.tm-c{background:#3d0000;color:var(--red)}
.tm-h{background:#2d1800;color:var(--yellow)}
.tm-o{background:#001a10;color:var(--green)}

/* ── Tab switcher ── */
.tabs{display:flex;gap:0;padding:0 20px;margin-top:10px;border-bottom:1px solid var(--border);margin-bottom:8px}
.tab-btn{padding:6px 14px;font-size:.82em;cursor:pointer;color:var(--dim);background:none;border:none;border-bottom:2px solid transparent;transition:.12s;font-family:inherit}
.tab-btn:hover{color:var(--text)}
.tab-btn.active{color:var(--cyan);border-bottom-color:var(--cyan)}

/* ── Main ── */
.main{margin-left:var(--sidebar-w);flex:1;display:flex;flex-direction:column;min-width:0}
.header{background:linear-gradient(135deg,#0d1117,#161b22);border-bottom:2px solid var(--cyan);padding:15px 28px;position:sticky;top:0;z-index:40}
.header h1{color:var(--cyan);font-size:1.15em;margin-bottom:6px}
.meta{display:flex;flex-wrap:wrap;gap:12px;font-size:.79em;opacity:.85}
.stats{display:flex;gap:6px;margin-top:8px;flex-wrap:wrap;align-items:center}
.stat-badge{padding:2px 10px;border-radius:3px;font-weight:bold;font-size:.82em;border:1px solid}
.stat-crit{background:var(--red-bg);color:var(--red);border-color:var(--red)}
.stat-high{background:var(--orange-bg);color:var(--orange);border-color:var(--orange)}
.stat-med{background:var(--yellow-bg);color:var(--yellow);border-color:var(--yellow)}
.stat-cve{background:rgba(188,140,255,.1);color:var(--magenta);border-color:var(--magenta)}
.stat-cwe{background:var(--green-bg);color:var(--green);border-color:var(--green)}
.stat-info{background:rgba(88,166,255,.1);color:var(--cyan);border-color:var(--cyan)}
.filters{margin-left:auto;display:flex;gap:5px}
.filter-btn{padding:2px 9px;border-radius:3px;font-size:.78em;cursor:pointer;background:var(--bg3);color:var(--dim);border:1px solid var(--border);transition:.12s}
.filter-btn:hover{color:var(--text);border-color:var(--cyan)}
.filter-btn.active{color:var(--cyan);border-color:var(--cyan)}

/* ── Container ── */
.container{padding:18px 28px;flex:1}
.tab-panel{display:none}
.tab-panel.active{display:block}

/* ── Audit sections ── */
.exec-summary{background:linear-gradient(135deg,rgba(248,81,73,.07),rgba(210,153,34,.04));border:1px solid var(--red);border-left:4px solid var(--red);border-radius:6px;padding:16px 20px;margin-bottom:16px}
.exec-summary h2{color:var(--red);margin-bottom:10px;font-size:1em}
.finding-row{display:flex;gap:10px;padding:5px 0;border-bottom:1px dashed rgba(255,255,255,.05);font-size:.83em}
.finding-row:last-child{border-bottom:none}
.fr-sev{padding:2px 7px;border-radius:3px;font-weight:bold;font-size:.73em;min-width:65px;text-align:center;flex-shrink:0}
.fr-sev.critical{background:#3d0000;color:var(--red)}
.fr-sev.high{background:#2d1800;color:var(--yellow)}
.fr-src{color:var(--cyan);flex-shrink:0;min-width:130px;font-size:.79em}
.fr-msg{color:var(--text);flex:1;word-break:break-word}
.category{margin-bottom:16px}
.category-h{padding:6px 0;margin-bottom:6px;border-bottom:1px solid var(--border);color:var(--dim);font-size:.9em;letter-spacing:1px;text-transform:uppercase}
.sec{background:var(--bg2);border:1px solid var(--border);border-radius:6px;margin-bottom:8px;scroll-margin-top:120px}
.sec-h{display:flex;justify-content:space-between;align-items:center;padding:8px 14px;cursor:pointer;border-radius:6px 6px 0 0;background:var(--bg3);user-select:none}
.sec-h:hover{background:#2a2f3a}
.sec-t{font-weight:bold;color:var(--cyan);font-size:.88em}
.sec-c{max-height:0;overflow:hidden;transition:max-height .3s}
.sec-c.open{max-height:9999px}
pre{padding:14px;overflow-x:auto;font-size:12px;white-space:pre-wrap;word-break:break-all}
.badge{padding:2px 6px;border-radius:3px;font-size:.73em;font-weight:bold;margin-left:3px}
.b-crit{background:#3d0000;color:var(--red)}
.b-high{background:#2d1800;color:var(--yellow)}
.b-ok{background:#001a10;color:var(--green)}
.finding-line{color:var(--red);font-weight:bold}
.alert-line{color:var(--yellow);font-weight:bold}
.ok-line{color:var(--green)}
.cve-inline{color:var(--magenta);font-weight:bold}
.cwe-inline{color:var(--green);font-weight:bold}

/* ── CVE Dashboard ── */
.dash-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:10px;margin-bottom:18px}
.dash-card{background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:14px 16px;text-align:center}
.dash-card .num{font-size:2em;font-weight:700;line-height:1}
.dash-card .lbl{font-size:.72em;color:var(--dim);margin-top:3px;text-transform:uppercase;letter-spacing:.5px}
.section2{background:var(--bg2);border:1px solid var(--border);border-radius:6px;margin-bottom:12px}
.sec2-hdr{display:flex;justify-content:space-between;align-items:center;padding:9px 15px;cursor:pointer;background:var(--bg3);border-radius:6px 6px 0 0;user-select:none}
.sec2-hdr:hover{background:var(--bg4)}
.sec2-title{font-weight:700;color:var(--cyan);font-size:.88em}
.sec2-body{padding:14px;display:none}
.sec2-body.open{display:block}
.vtable{width:100%;border-collapse:collapse;font-size:.81em}
.vtable th{background:var(--bg3);color:var(--cyan);padding:6px 10px;text-align:left;font-size:.77em;text-transform:uppercase;letter-spacing:.5px;border-bottom:1px solid var(--border)}
.vtable td{padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top;word-break:break-word;max-width:300px}
.vtable tr:hover{background:rgba(88,166,255,.04)}
.vtable tr:last-child td{border-bottom:none}
.sev{display:inline-block;padding:1px 7px;border-radius:2px;font-size:.74em;font-weight:700;min-width:62px;text-align:center}
.sev-CRITICAL{background:var(--red-bg);color:var(--red)}
.sev-HIGH,.sev-IMPORTANT{background:var(--orange-bg);color:var(--orange)}
.sev-MEDIUM,.sev-MODERATE{background:var(--yellow-bg);color:var(--yellow)}
.sev-LOW,.sev-NEGLIGIBLE{background:var(--green-bg);color:var(--green)}
.sev-UNKNOWN,.sev-INFO{background:var(--bg4);color:var(--dim)}
.cve-id{color:var(--magenta);font-weight:700}
.cwe-id{color:var(--green);font-size:.79em}
.fixed{color:var(--green);font-size:.77em}
.upd-cmd{font-family:monospace;background:var(--bg4);padding:2px 7px;border-radius:3px;font-size:.79em;color:var(--cyan);cursor:pointer}
.upd-cmd:hover{background:var(--bg3)}
.inv-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:8px}
.inv-card{background:var(--bg3);border:1px solid var(--border);border-radius:5px;padding:10px 12px}
.inv-card h4{color:var(--text);font-size:.83em;margin-bottom:3px}
.inv-ver{color:var(--cyan);font-size:.8em}
.inv-cat{display:inline-block;font-size:.69em;padding:1px 6px;border-radius:10px;background:var(--bg4);color:var(--dim);margin-top:3px}
.search-box{width:100%;padding:6px 11px;background:var(--bg4);border:1px solid var(--border);border-radius:4px;color:var(--text);font-family:monospace;font-size:.83em;margin-bottom:10px;outline:none}
.search-box:focus{border-color:var(--cyan)}
::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:var(--bg4);border-radius:3px}
.footer{text-align:center;padding:14px;opacity:.35;font-size:.74em;border-top:1px solid var(--border);margin-top:16px}
body.filter-critical .sec:not(.has-crit){display:none}
body.filter-critical .category:not(.has-crit){display:none}
body.filter-high .sec:not(.has-high):not(.has-crit){display:none}
body.filter-high .category:not(.has-high):not(.has-crit){display:none}
</style>
</head>
<body>
HTMLHEAD

# ── Sidebar ────────────────────────────────────────────────────────
cat <<SIDEBAR
<aside class="sidebar">
  <div class="sb-head">
    <h2>&#128269; linux-full-audit</h2>
    <div class="host">${TARGET} &middot; ${DATE}</div>
  </div>

  <div class="tabs">
    <button class="tab-btn active" onclick="switchTab('audit',this)">Audit</button>
    <button class="tab-btn"        onclick="switchTab('dashboard',this)">CVE Dashboard</button>
  </div>

  <!-- TOC para o tab Audit -->
  <nav id="toc-audit">
SIDEBAR

for cat in $TOC_ORDER; do
    files="${CAT_FILES[$cat]:-}"; [[ -z "$files" ]] && continue
    label=$(category_label "$cat"); echo "<div class=\"toc-cat\">${label}</div>"
    for base in $files; do
        f="${OUT}/${base}.txt"; [[ -f "$f" ]] || continue
        fc="${CRIT_CACHE[$f]:-0}"; fh="${HIGH_CACHE[$f]:-0}"
        badges=""
        [[ "$fc" -gt 0 ]] 2>/dev/null && badges="${badges}<span class=\"toc-mini tm-c\">${fc}</span>"
        [[ "$fh" -gt 0 ]] 2>/dev/null && badges="${badges}<span class=\"toc-mini tm-h\">${fh}</span>"
        [[ -z "$badges" ]] && badges='<span class="toc-mini tm-o">OK</span>'
        echo "<a class=\"toc-item\" href=\"#${base}\" onclick=\"switchTab('audit',document.querySelector('.tab-btn'))\"><span>${base}</span><span class=\"toc-badges\">${badges}</span></a>"
    done
done

cat <<SIDEBAR2
  </nav>

  <!-- TOC para o tab CVE Dashboard -->
  <nav id="toc-dash" style="display:none">
    <div class="toc-cat">Visão Geral</div>
    <div class="toc-item active" onclick="showDashSection('summary',this)">&#128202; Dashboard</div>
    <div class="toc-cat">Vulnerabilidades</div>
    <div class="toc-item" onclick="showDashSection('cve',this)">&#128308; CVEs / CWEs <span class="toc-mini tm-c">${CVE_TOTAL}</span></div>
    <div class="toc-cat">Updates</div>
    <div class="toc-item" onclick="showDashSection('app-upd',this)">&#128230; App Updates <span class="toc-mini $([ "${APP_UPD_COUNT}" != "0" ] && echo "tm-h" || echo "tm-o")">${APP_UPD_COUNT}</span></div>
    <div class="toc-cat">Inventário</div>
    <div class="toc-item" onclick="showDashSection('inventory',this)">&#128203; Packages <span class="toc-mini tm-o">${INV_COUNT}</span></div>
  </nav>
</aside>
SIDEBAR2

# ── Header ─────────────────────────────────────────────────────────
cat <<HTMLHDR
<main class="main">
<div class="header">
  <h1>&#128269; linux-full-audit &mdash; ${TARGET}</h1>
  <div class="meta">
    <span>&#128187; <b>${TARGET}</b></span>
    <span>&#128039; <b>${DISTRO}</b></span>
    <span>&#9881; <b>kernel ${KERNEL}</b></span>
    <span>&#128197; <b>${DATE}</b></span>
    <span>&#128272; root: <b>${IS_ROOT}</b></span>
  </div>
  <div class="stats">
    <span class="stat-badge stat-crit">&#128308; Critical: ${TOTAL_CRIT}</span>
    <span class="stat-badge stat-high">&#128992; High: ${TOTAL_HIGH}</span>
    <span class="stat-badge stat-cve">&#128995; CVEs: ${CVE_TOTAL}</span>
    <span class="stat-badge stat-cwe">&#128994; CWEs: ${CWE_UNIQ}</span>
    <span class="stat-badge stat-info">&#128230; Updates: ${APP_UPD_COUNT}</span>
    <div class="filters">
      <span class="filter-btn active" onclick="setFilter('all',this)">All</span>
      <span class="filter-btn" onclick="setFilter('critical',this)">Critical</span>
      <span class="filter-btn" onclick="setFilter('high',this)">+High</span>
    </div>
  </div>
</div>
<div class="container">
HTMLHDR

# ══════════════════════════════════════════════════════════════════
# TAB 1 — AUDIT (output dos scans .txt)
# ══════════════════════════════════════════════════════════════════
echo '<div id="tab-audit" class="tab-panel active">'

# Executive Summary
if [[ -n "$TOP_FINDINGS" ]]; then
    echo '<div class="exec-summary"><h2>&#9888; Executive Summary — Top Findings</h2>'
    echo "$TOP_FINDINGS" | while IFS='|' read -r sev src msg; do
        [[ -z "$msg" ]] && continue
        echo "<div class=\"finding-row\"><span class=\"fr-sev ${sev}\">${sev^^}</span>"
        echo "<span class=\"fr-src\"><a href=\"#${src}\" style=\"color:inherit\">${src}</a></span>"
        echo "<span class=\"fr-msg\">${msg}</span></div>"
    done
    echo '</div>'
fi

# Execution errors / warnings block — só aparece se houver
if [[ "$ERROR_COUNT" -gt 0 ]] 2>/dev/null || [[ "$WARN_COUNT" -gt 0 ]] 2>/dev/null; then
    err_color=$([ "$ERROR_COUNT" -gt 0 ] && echo "var(--red)" || echo "var(--yellow)")
    err_bg=$([ "$ERROR_COUNT" -gt 0 ] && echo "rgba(248,81,73,.05)" || echo "rgba(210,153,34,.05)")
    echo "<div style=\"background:${err_bg};border:1px solid ${err_color};border-left:4px solid ${err_color};border-radius:6px;padding:14px 18px;margin-bottom:14px\">"
    echo "<h2 style=\"color:${err_color};font-size:.95em;margin-bottom:10px\">&#9888; Execution Issues — ${ERROR_COUNT} errors, ${WARN_COUNT} warnings</h2>"
    echo "<div style=\"font-size:.82em;color:var(--dim);margin-bottom:8px\">Log estruturado: <code style=\"color:var(--cyan)\">${ERROR_LOG}</code></div>"
    if [[ -f "$ERROR_LOG" ]]; then
        echo "<details><summary style=\"cursor:pointer;color:var(--cyan);font-size:.85em\">Ver últimos 15 eventos</summary>"
        echo "<table class=\"vtable\" style=\"margin-top:8px\"><thead><tr><th>Hora</th><th>Nível</th><th>Fase</th><th>Mensagem</th></tr></thead><tbody>"
        # Parsear JSON Lines do error log — últimos 15
        tail -15 "$ERROR_LOG" 2>/dev/null | grep -v "^#" | python3 -c "
import sys, json
for line in sys.stdin:
    line = line.strip()
    if not line or line.startswith('#'): continue
    try:
        e = json.loads(line)
        ts = e.get('timestamp','').replace('T',' ').replace('Z','')
        lvl = e.get('level','')
        phase = e.get('message','').replace('<','&lt;').replace('>','&gt;')[:80]
        ph = e.get('phase','').replace('<','&lt;').replace('>','&gt;')[:30]
        lvl_color = '#f85149' if lvl == 'ERROR' else '#d29922'
        print(f'<tr><td style=\"font-size:.75em;color:var(--dim)\">{ts}</td><td><span style=\"color:{lvl_color};font-weight:bold\">{lvl}</span></td><td style=\"color:var(--cyan);font-size:.78em\">{ph}</td><td style=\"font-size:.8em\">{phase}</td></tr>')
    except: pass
" 2>/dev/null
        echo "</tbody></table></details>"
    fi
    echo "</div>"
fi

# CVE Summary Table
if [[ -n "$CVE_TABLE_DATA" ]]; then
    echo "<div class=\"category\"><div class=\"category-h\">&#128027; CVE Summary (${UNIQ_CVES} únicos nos scans de texto)</div>"
    echo "<div class=\"sec\"><div class=\"sec-h\" onclick=\"toggle('cve-table')\"><span class=\"sec-t\">&#128202; CVE Table</span></div>"
    echo "<div class=\"sec-c open\" id=\"cve-table-content\"><table class=\"vtable\">"
    echo "<thead><tr><th>Severity</th><th>CVE ID</th><th>Source</th><th>Desc</th></tr></thead><tbody>"
    echo "$CVE_TABLE_DATA" | while IFS='|' read -r sev cve src desc; do
        [[ -z "$cve" ]] && continue
        case "$sev" in CRITICAL|HIGH|MEDIUM|LOW|UNKNOWN) ;; *) sev="UNKNOWN" ;; esac
        [[ -z "$desc" ]] && desc="(ver ${src})"
        echo "<tr><td><span class=\"sev sev-${sev}\">${sev}</span></td>"
        echo "<td><span class=\"cve-id\">${cve}</span></td>"
        echo "<td><a href=\"#${src}\" style=\"color:var(--cyan)\">${src}</a></td>"
        echo "<td style=\"font-size:.8em;color:var(--dim)\">${desc}</td></tr>"
    done
    echo '</tbody></table></div></div></div>'
fi

# Secções por categoria
for cat in $TOC_ORDER; do
    files="${CAT_FILES[$cat]:-}"; [[ -z "$files" ]] && continue
    label=$(category_label "$cat")
    cat_crit=0; cat_high=0
    for base in $files; do
        f="${OUT}/${base}.txt"; [[ -f "$f" ]] || continue
        cat_crit=$(( cat_crit + ${CRIT_CACHE[$f]:-0} ))
        cat_high=$(( cat_high + ${HIGH_CACHE[$f]:-0} ))
    done
    cat_cls="category"
    [[ "$cat_crit" -gt 0 ]] 2>/dev/null && cat_cls="${cat_cls} has-crit"
    [[ "$cat_high" -gt 0 ]] 2>/dev/null && cat_cls="${cat_cls} has-high"
    echo "<div class=\"${cat_cls}\"><div class=\"category-h\">${label}</div>"
    for base in $files; do
        f="${OUT}/${base}.txt"; [[ -f "$f" ]] || continue
        fc="${CRIT_CACHE[$f]:-0}"; fh="${HIGH_CACHE[$f]:-0}"
        badges=""
        [[ "$fc" -gt 0 ]] 2>/dev/null && badges="${badges}<span class=\"badge b-crit\">${fc} CRITICAL</span>"
        [[ "$fh" -gt 0 ]] 2>/dev/null && badges="${badges}<span class=\"badge b-high\">${fh} HIGH</span>"
        [[ -z "$badges" ]] && badges='<span class="badge b-ok">OK</span>'
        sec_cls="sec"; auto_open=""
        [[ "$fc" -gt 0 ]] 2>/dev/null && { sec_cls="${sec_cls} has-crit"; auto_open=" open"; }
        [[ "$fh" -gt 0 ]] 2>/dev/null && { sec_cls="${sec_cls} has-high"; [[ -z "$auto_open" ]] && auto_open=" open"; }
        # LC_ALL=C para tratar bytes literais (linPEAS pode ter chars não-UTF8)
        content=$(LC_ALL=C head -3000 "$f" | html_escape | colorize)
        sz=$(stat -c%s "$f" 2>/dev/null || echo 0)
        [[ "${sz//[[:space:]]/}" -gt 500000 ]] 2>/dev/null && content="${content}
<span style='color:var(--yellow)'>[... truncado a 3000 linhas — ver ficheiro completo ...]</span>"
        echo "<div class=\"${sec_cls}\" id=\"${base}\"><div class=\"sec-h\" onclick=\"toggle('${base}')\">"
        echo "<span class=\"sec-t\">&#128196; ${base}</span><span>${badges}</span></div>"
        echo "<div class=\"sec-c${auto_open}\" id=\"${base}-content\"><pre>${content}</pre></div></div>"
    done
    echo "</div>"
done

echo '</div>' # end tab-audit

# ══════════════════════════════════════════════════════════════════
# TAB 2 — CVE DASHBOARD (interactivo, do vuln-check.sh)
# ══════════════════════════════════════════════════════════════════
echo '<div id="tab-dashboard" class="tab-panel">'

# Dashboard sections
cat <<DASHSECTIONS
<div id="dash-summary">
<div class="dash-grid">
  <div class="dash-card"><div class="num" style="color:var(--red)">${CVE_CRIT}</div><div class="lbl">Critical CVEs</div></div>
  <div class="dash-card"><div class="num" style="color:var(--orange)">${CVE_HIGH}</div><div class="lbl">High CVEs</div></div>
  <div class="dash-card"><div class="num" style="color:var(--yellow)">${CVE_MED}</div><div class="lbl">Medium CVEs</div></div>
  <div class="dash-card"><div class="num" style="color:var(--green)">${CWE_UNIQ}</div><div class="lbl">CWEs Únicos</div></div>
  <div class="dash-card"><div class="num" style="color:var(--cyan)">${APP_UPD_COUNT}</div><div class="lbl">App Updates</div></div>
  <div class="dash-card"><div class="num" style="color:var(--text)">${CVE_TOTAL}</div><div class="lbl">CVEs Total</div></div>
  <div class="dash-card"><div class="num" style="color:var(--text)">${INV_COUNT}</div><div class="lbl">Packages</div></div>
</div>
<div class="section2"><div class="sec2-hdr" onclick="toggleSec2('top-apps')"><span class="sec2-title">&#127942; Apps/Packages com mais CVEs</span><span style="color:var(--dim)">&#9660;</span></div><div class="sec2-body open" id="top-apps-body"><div id="top-apps-content"></div></div></div>
<div class="section2"><div class="sec2-hdr" onclick="toggleSec2('top-cwes')"><span class="sec2-title">&#128278; CWEs mais frequentes</span><span style="color:var(--dim)">&#9660;</span></div><div class="sec2-body" id="top-cwes-body"><div id="top-cwes-content"></div></div></div>
</div>
<div id="dash-cve" style="display:none">
  <input class="search-box" id="cve-search" placeholder="&#128269; Filtrar CVE, app, CWE, descrição..." oninput="renderCves()">
  <div id="cve-table-wrap"></div>
</div>
<div id="dash-app-upd" style="display:none">
  <div class="section2"><div class="sec2-hdr" onclick="toggleSec2('app-upd-sec')"><span class="sec2-title">&#128230; App Updates Disponíveis</span><span style="color:var(--dim)">&#9660;</span></div><div class="sec2-body open" id="app-upd-sec-body"><div id="app-upd-content"></div></div></div>
</div>
<div id="dash-inventory" style="display:none">
  <input class="search-box" id="inv-search" placeholder="&#128269; Filtrar packages/apps..." oninput="renderInventory()">
  <div id="inv-grid-wrap"></div>
</div>
DASHSECTIONS

echo '</div>' # end tab-dashboard

# ── Footer + JS ────────────────────────────────────────────────────
cat <<HTMLFOOT
</div> <!-- /container -->
<div class="footer">linux-full-audit &mdash; ${TARGET} &mdash; ${DATE} &mdash; ${DISTRO}</div>
</main>

<script>
const DATA_CVE = ${CVE_JSON};
const DATA_INV = ${INV_JSON};
const DATA_UPD = ${UPD_JSON};

let cveFilter = 'all';

// ── Tab switcher ──────────────────────────────────────────────────
function switchTab(id, el) {
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  document.getElementById('tab-'+id).classList.add('active');
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  if(el) el.classList.add('active'); else document.querySelectorAll('.tab-btn')[id==='audit'?0:1].classList.add('active');
  document.getElementById('toc-audit').style.display = id==='audit' ? '' : 'none';
  document.getElementById('toc-dash').style.display  = id==='audit' ? 'none' : '';
  if(id==='dashboard') { renderSummary(); renderCves(); }
}

// ── Audit helpers ─────────────────────────────────────────────────
function toggle(id) { var c=document.getElementById(id+'-content'); if(c) c.classList.toggle('open'); }
function setFilter(mode,el) {
  document.body.classList.remove('filter-critical','filter-high');
  if(mode!=='all') document.body.classList.add('filter-'+mode);
  document.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));
  if(el) el.classList.add('active');
}

// ── Dashboard helpers ─────────────────────────────────────────────
function toggleSec2(id) { var b=document.getElementById(id+'-body'); if(b) b.classList.toggle('open'); }
function showDashSection(id,el) {
  document.querySelectorAll('#tab-dashboard > div').forEach(d=>d.style.display='none');
  var sec=document.getElementById('dash-'+id);
  if(sec) sec.style.display='block';
  document.querySelectorAll('#toc-dash .toc-item').forEach(i=>i.classList.remove('active'));
  if(el) el.classList.add('active');
  if(id==='cve') renderCves();
  if(id==='inventory') renderInventory();
  if(id==='app-upd') renderAppUpd();
  if(id==='summary') renderSummary();
}

function sevBadge(s) {
  var sn=(s||'UNKNOWN').toUpperCase();
  return '<span class="sev sev-'+sn+'">'+sn+'</span>';
}

function renderCves() {
  var q=(document.getElementById('cve-search')?.value||'').toLowerCase();
  var rows=DATA_CVE;
  if(cveFilter!=='all') rows=rows.filter(r=>(r.Severity||'').toUpperCase()===cveFilter);
  if(q) rows=rows.filter(r=>
    (r.CveId||'').toLowerCase().includes(q)||(r.App||'').toLowerCase().includes(q)||
    (r.Cwe||'').toLowerCase().includes(q)||(r.Description||'').toLowerCase().includes(q));
  var ord={'CRITICAL':0,'HIGH':1,'IMPORTANT':1,'MEDIUM':2,'MODERATE':2,'LOW':3,'NEGLIGIBLE':3};
  rows.sort((a,b)=>{
    var sa=ord[(a.Severity||'').toUpperCase()]??9, sb=ord[(b.Severity||'').toUpperCase()]??9;
    return sa!==sb ? sa-sb : (parseFloat(b.Cvss)||0)-(parseFloat(a.Cvss)||0);
  });
  var h='<p style="color:var(--dim);font-size:.79em;margin-bottom:8px">'+rows.length+' CVEs</p>';
  h+='<div style="display:flex;gap:5px;margin-bottom:10px">';
  ['all','CRITICAL','HIGH','MEDIUM'].forEach(f=>{
    h+='<span style="padding:2px 9px;border-radius:3px;font-size:.77em;cursor:pointer;border:1px solid var(--border);'+(cveFilter===f?'color:var(--cyan);border-color:var(--cyan)':'color:var(--dim)')+'" onclick="cveFilter=\''+f+'\';renderCves()">'+f+'</span>';
  });
  h+='</div>';
  h+='<table class="vtable"><thead><tr><th>Sev</th><th>CVSS</th><th>CVE ID</th><th>App/Versão</th><th>Fix</th><th>CWE</th><th>Fonte</th><th>Desc</th></tr></thead><tbody>';
  rows.forEach(r=>{
    var fix=r.FixedIn?'<span class="fixed">&#10003; '+r.FixedIn+'</span>':'<span style="color:var(--dim);font-size:.77em">&#8211;</span>';
    var cwe=r.Cwe?'<span class="cwe-id">'+r.Cwe+'</span>':'&#8211;';
    var cveLink=r.CveId?'<a class="cve-id" href="https://nvd.nist.gov/vuln/detail/'+r.CveId+'" target="_blank" style="text-decoration:none">'+r.CveId+'</a>':'&#8211;';
    var desc=(r.Title||r.Description||'').substring(0,130);
    h+='<tr><td>'+sevBadge(r.Severity)+'</td><td style="color:var(--yellow)">'+(r.Cvss!=null?r.Cvss:'&#8211;')+'</td><td>'+cveLink+'</td><td><b>'+(r.App||'')+'</b><br><span style="color:var(--dim)">'+(r.Version||'')+'</span></td><td>'+fix+'</td><td>'+cwe+'</td><td style="color:var(--dim);font-size:.77em">'+(r.Source||'')+'</td><td style="font-size:.79em;color:var(--dim)">'+desc+'</td></tr>';
  });
  h+='</tbody></table>';
  document.getElementById('cve-table-wrap').innerHTML=h;
}

function renderInventory() {
  var q=(document.getElementById('inv-search')?.value||'').toLowerCase();
  var rows=q?DATA_INV.filter(r=>(r.name||'').toLowerCase().includes(q)||(r.category||'').toLowerCase().includes(q)):DATA_INV;
  var h='<p style="color:var(--dim);font-size:.79em;margin-bottom:10px">'+rows.length+' items</p><div class="inv-grid">';
  rows.forEach(r=>{
    var key=r.key||r.name;
    var cveC=DATA_CVE.filter(c=>c.App===key).length;
    var crit=DATA_CVE.filter(c=>c.App===key&&(c.Severity||'').toUpperCase()==='CRITICAL').length;
    var hi=DATA_CVE.filter(c=>c.App===key&&['HIGH','IMPORTANT'].includes((c.Severity||'').toUpperCase())).length;
    var badge=crit>0?'<span style="color:var(--red);font-size:.73em">&#128308; '+crit+' Critical</span>':
              hi>0?'<span style="color:var(--orange);font-size:.73em">&#128992; '+hi+' High</span>':
              cveC>0?'<span style="color:var(--yellow);font-size:.73em">&#9888; '+cveC+' CVEs</span>':
              '<span style="color:var(--green);font-size:.73em">&#10003; OK</span>';
    h+='<div class="inv-card"><h4>'+(r.name||key)+'</h4><div class="inv-ver">'+(r.version||'&#8211;')+'</div><div style="margin-top:3px">'+badge+'</div><span class="inv-cat">'+(r.category||'')+'</span></div>';
  });
  h+='</div>';
  document.getElementById('inv-grid-wrap').innerHTML=h;
}

function renderAppUpd() {
  if(!DATA_UPD||!DATA_UPD.length){document.getElementById('app-upd-content').innerHTML='<p style="color:var(--green)">&#10003; Sem updates encontrados</p>';return;}
  var h='<p style="color:var(--dim);font-size:.79em;margin-bottom:8px">'+DATA_UPD.length+' updates</p>';
  h+='<table class="vtable"><thead><tr><th>Fonte</th><th>Package</th><th>Atual</th><th>Disponível</th><th>Comando</th></tr></thead><tbody>';
  DATA_UPD.forEach(u=>{
    h+='<tr style="border-left:3px solid var(--orange)"><td style="color:var(--dim)">'+(u.Source||'')+'</td><td><b>'+(u.Name||'')+'</b></td><td style="color:var(--dim)">'+(u.Current||'')+'</td><td style="color:var(--green)">'+(u.Available||'')+'</td><td><span class="upd-cmd" onclick="navigator.clipboard.writeText(this.dataset.cmd)" data-cmd="'+(u.UpdateCmd||'').replace(/"/g,"&quot;")+'" title="Copiar">'+(u.UpdateCmd||'')+'</span></td></tr>';
  });
  h+='</tbody></table>';
  document.getElementById('app-upd-content').innerHTML=h;
}

function renderSummary() {
  var appC={};
  DATA_CVE.forEach(c=>{
    var a=c.App||'unknown';
    if(!appC[a]) appC[a]={total:0,crit:0,high:0};
    appC[a].total++;
    var s=(c.Severity||'').toUpperCase();
    if(s==='CRITICAL') appC[a].crit++; else if(['HIGH','IMPORTANT'].includes(s)) appC[a].high++;
  });
  var top=Object.entries(appC).sort((a,b)=>(b[1].crit*100+b[1].high*10+b[1].total)-(a[1].crit*100+a[1].high*10+a[1].total)).slice(0,15);
  var h='<table class="vtable"><thead><tr><th>App/Package</th><th>Total</th><th>Critical</th><th>High</th></tr></thead><tbody>';
  top.forEach(([app,c])=>{h+='<tr><td><b>'+app+'</b></td><td>'+c.total+'</td><td>'+(c.crit>0?'<span style="color:var(--red)">'+c.crit+'</span>':'&#8211;')+'</td><td>'+(c.high>0?'<span style="color:var(--orange)">'+c.high+'</span>':'&#8211;')+'</td></tr>';});
  h+='</tbody></table>';
  document.getElementById('top-apps-content').innerHTML=h;

  var cweC={};
  DATA_CVE.forEach(c=>{(c.Cwe||'').split(/,\s*/).forEach(cw=>{cw=cw.trim();if(cw.match(/^CWE-\d+/)) cweC[cw]=(cweC[cw]||0)+1;});});
  var topCwe=Object.entries(cweC).sort((a,b)=>b[1]-a[1]).slice(0,10);
  var ch=topCwe.length===0?'<p style="color:var(--dim)">Sem dados CWE (Trivy/NVD)</p>':'<table class="vtable"><thead><tr><th>CWE</th><th>Ocorrências</th><th>Ref</th></tr></thead><tbody>';
  topCwe.forEach(([cwe,n])=>{var num=cwe.replace('CWE-','');ch+='<tr><td><span class="cwe-id">'+cwe+'</span></td><td>'+n+'</td><td><a href="https://cwe.mitre.org/data/definitions/'+num+'.html" target="_blank" style="color:var(--cyan);font-size:.79em">cwe.mitre.org &#8599;</a></td></tr>';});
  if(topCwe.length>0) ch+='</tbody></table>';
  document.getElementById('top-cwes-content').innerHTML=ch;
}

// ── Scrollspy ────────────────────────────────────────────────────
function initScrollSpy(){
  var items=document.querySelectorAll('#toc-audit .toc-item');
  var sections=document.querySelectorAll('#tab-audit .sec[id]');
  var obs=new IntersectionObserver(function(entries){entries.forEach(function(e){if(e.isIntersecting){var id=e.target.id;items.forEach(function(i){i.classList.toggle('active',i.getAttribute('href')==='#'+id);});}});},{rootMargin:'-120px 0px -60% 0px'});
  sections.forEach(function(s){obs.observe(s);});
}

document.addEventListener('DOMContentLoaded',function(){
  document.querySelectorAll('.sec-c.open').forEach(function(el){el.style.maxHeight='none';});
  initScrollSpy();
  renderSummary();
  renderCves();
});
</script>
</body>
</html>
HTMLFOOT

} > "$REPORT" 2>&1

# ═══════════════════════════════════════════════════════════════════
# SUMÁRIO FINAL
# ═══════════════════════════════════════════════════════════════════
if [[ -f "$REPORT" && -s "$REPORT" ]]; then
    sz=$(stat -c%s "$REPORT" 2>/dev/null || echo 0)
    info "&#10004; Relatório: ${REPORT} ($(( sz / 1024 )) KB)"
else
    err "Falha ao gerar relatório HTML"
fi

printf '\n\033[0;36m\033[1m'
cat <<EOF
╔══════════════════════════════════════════════════╗
║   AUDIT COMPLETO                                 ║
╠══════════════════════════════════════════════════╣
║  [Audit]  Critical  : ${TOTAL_CRIT}
║  [Audit]  High      : ${TOTAL_HIGH}
║  [Audit]  CVEs txt  : ${UNIQ_CVES}
║  [Dash]   CVEs JSON : ${CVE_TOTAL}
║  [Dash]   CWEs      : ${CWE_UNIQ}
║  [Dash]   App upd   : ${APP_UPD_COUNT}
║  Inventário         : ${INV_COUNT} items
╠══════════════════════════════════════════════════╣
║  Execução  errors   : ${ERROR_COUNT}
║  Execução  warnings : ${WARN_COUNT}
╠══════════════════════════════════════════════════╣
║  Relatório HTML : ${REPORT}
║  Inventory JSON : ${INV_FILE}
║  CVEs JSON      : ${CVE_FILE}
║  CVEs CSV       : ${CVE_CSV}
║  CVEs SARIF     : ${CVE_SARIF}
║  Event log      : ${EVENT_LOG}
║  Error log      : ${ERROR_LOG}
EOF
if [[ -f "$DIFF_FILE" ]]; then
    NEW_C=$(python3 -c "import json; print(json.load(open('$DIFF_FILE'))['summary']['new'])" 2>/dev/null || echo "?")
    RES_C=$(python3 -c "import json; print(json.load(open('$DIFF_FILE'))['summary']['resolved'])" 2>/dev/null || echo "?")
    echo "║  Diff vs prev   : +${NEW_C} novos, -${RES_C} resolvidos"
    echo "║                   ${DIFF_FILE}"
fi
echo "╚══════════════════════════════════════════════════╝"
printf '\033[0m\n'

# Log final do script
log_jsonl "INFO" "Script terminado" "\"errors\":${ERROR_COUNT},\"warnings\":${WARN_COUNT},\"cves_total\":${CVE_TOTAL:-0}"

# Mensagem destacada se houve erros
if [[ "$ERROR_COUNT" -gt 0 ]] 2>/dev/null; then
    printf '\033[0;31m\033[1m[!]\033[0m '
    echo "Ocorreram ${ERROR_COUNT} erros e ${WARN_COUNT} avisos durante a execução."
    echo "    Ver: ${ERROR_LOG}"
    echo "    Filtrar: jq 'select(.level==\"ERROR\")' ${EVENT_LOG}"
elif [[ "$WARN_COUNT" -gt 0 ]] 2>/dev/null; then
    printf '\033[1;33m\033[1m[!]\033[0m '
    echo "Execução com ${WARN_COUNT} avisos. Ver: ${ERROR_LOG}"
fi

if [[ "$NO_BROWSER" == "false" ]] && [[ -f "$REPORT" ]]; then
    if command -v xdg-open &>/dev/null; then
        xdg-open "$REPORT" &>/dev/null &
    elif command -v firefox &>/dev/null; then
        firefox "$REPORT" &>/dev/null &
    fi
fi

# ═══════════════════════════════════════════════════════════════════
# EXIT CODE SEMÂNTICO (#5)
# ═══════════════════════════════════════════════════════════════════
EXIT_CODE=0
if [[ -n "$FAIL_ON" ]]; then
    case "$FAIL_ON" in
        critical)
            if [[ "$CVE_CRIT" -gt 0 ]] 2>/dev/null || [[ "$TOTAL_CRIT" -gt 0 ]] 2>/dev/null; then
                err "FAIL-ON CRITICAL: ${CVE_CRIT} CVEs Critical (JSON), ${TOTAL_CRIT} findings Critical (audit)"
                EXIT_CODE=2
            fi
            ;;
        high)
            if [[ "$CVE_CRIT" -gt 0 ]] 2>/dev/null || [[ "$TOTAL_CRIT" -gt 0 ]] 2>/dev/null; then
                err "FAIL-ON HIGH: ${CVE_CRIT} Critical detectados"
                EXIT_CODE=2
            elif [[ "$CVE_HIGH" -gt 0 ]] 2>/dev/null || [[ "$TOTAL_HIGH" -gt 0 ]] 2>/dev/null; then
                err "FAIL-ON HIGH: ${CVE_HIGH} CVEs High (JSON), ${TOTAL_HIGH} findings High (audit)"
                EXIT_CODE=3
            fi
            ;;
        medium)
            if [[ "$CVE_CRIT" -gt 0 ]] 2>/dev/null; then
                err "FAIL-ON MEDIUM: ${CVE_CRIT} Critical detectados"; EXIT_CODE=2
            elif [[ "$CVE_HIGH" -gt 0 ]] 2>/dev/null; then
                err "FAIL-ON MEDIUM: ${CVE_HIGH} High detectados"; EXIT_CODE=3
            elif [[ "$CVE_MED" -gt 0 ]] 2>/dev/null; then
                err "FAIL-ON MEDIUM: ${CVE_MED} CVEs Medium"
                EXIT_CODE=4
            fi
            ;;
    esac
fi

exit $EXIT_CODE
