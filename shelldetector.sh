#!/bin/bash
# Copyright (C) 2026 sigithdteam-lab
# GNU General Public License v3.0
# =============================================================================
# WebShell Detector Pro v2.0 (Upgraded with sgtcop.py patterns)
# Advanced webshell detection with logging only (no deletion)
# =============================================================================

set -euo pipefail

# =============================================================================
# KONFIGURASI
# =============================================================================

VERSION="2.0"
SCAN_DIR=""
LOG_DIR="/var/log/webshell_detector"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="${LOG_DIR}/scan_${TIMESTAMP}.log"
REPORT_FILE="${LOG_DIR}/report_${TIMESTAMP}.txt"
ALERT_FILE="${LOG_DIR}/alerts_${TIMESTAMP}.txt"
JSON_FILE="${LOG_DIR}/scan_${TIMESTAMP}.json"

# Warna output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Counter
TOTAL_SCANNED=0
SUSPICIOUS_FOUND=0
CRITICAL_FOUND=0

# Opsi
OUTPUT_JSON=false

# =============================================================================
# KONFIGURASI DETEKSI (dari sgtcop.py)
# =============================================================================

SKIP_DIRS=(
    "/proc" "/sys" "/dev" "/run" "/tmp" "/var/tmp"
    "/var/log" "/var/cache" "/usr/share/doc" "/usr/share/man"
)

SCAN_EXTS=(
    ".php" ".php3" ".php4" ".php5" ".php7" ".phtml" ".phps"
    ".inc" ".module" ".theme" ".engine" ".cgi" ".pl" ".py"
)

MAX_FILE_SIZE=2097152  # 2 MB

# Pola berbahaya (gabungan dari sgtcop.py)
DANGEROUS_PATTERNS=(
    # Command Execution
    "shell_exec\s*\(" "system\s*\(" "exec\s*\(" "passthru\s*\("
    "popen\s*\(" "proc_open\s*\(" "pcntl_exec\s*\("
    # Code Execution
    "eval\s*\(" "assert\s*\(" "create_function\s*\("
    "call_user_func\s*\(" "call_user_func_array\s*\("
    # Obfuscation + Execution
    "base64_decode\s*\(.*eval" "gzinflate\s*\(.*eval"
    "gzuncompress\s*\(.*eval" "str_rot13\s*\(.*eval" "hex2bin\s*\(.*eval"
    # Remote Access
    "curl_exec\s*\(" "curl_multi_exec\s*\(" "fsockopen\s*\("
    "pfsockopen\s*\(" "stream_socket_client\s*\(" "socket_create\s*\("
    # File Ops with base64
    "file_put_contents\s*\(.*base64" "fopen\s*\(.*w.*base64"
    # Dynamic execution
    "system\s*\(\s*\$_(GET|POST|REQUEST)"
    "exec\s*\(\s*\$_(GET|POST|REQUEST)"
    "shell_exec\s*\(\s*\$_(GET|POST|REQUEST)"
    "passthru\s*\(\s*\$_(GET|POST|REQUEST)"
    "popen\s*\(\s*\$_(GET|POST|REQUEST)"
    "proc_open\s*\(\s*\$_(GET|POST|REQUEST)"
    "assert\s*\(\s*\$_(GET|POST|REQUEST)"
    "include\s*\(\s*\$_(GET|POST|REQUEST)"
    "require\s*\(\s*\$_(GET|POST|REQUEST)"
    "file_get_contents\s*\(\s*\$_(GET|POST|REQUEST)"
    "base64_decode\s*\(\s*\$_(GET|POST|REQUEST)"
    # Obfuscation short patterns
    "\\x[0-9a-f]{2}" "chr\s*\(\d+\)\s*\."
)

DANGEROUS_FUNCTIONS=(
    "eval" "system" "exec" "shell_exec" "passthru" "popen" "proc_open"
    "curl_exec" "phpinfo" "dl" "fsockopen" "pfsockopen" "posix_kill"
    "gzinflate" "gzuncompress" "highlight_file" "ini_alter" "ini_set"
    "set_time_limit" "php_uname" "php_version" "readlink" "symlink" "link"
    "mail" "mb_send_mail" "pcntl_exec" "create_function" "call_user_func"
    "call_user_func_array" "curl_multi_exec" "stream_socket_client"
    "socket_create"
)

SUSPICIOUS_NAMES=(
    "shell" "cmd" "c99" "r57" "backdoor" "webshell" "eval" "system"
    "exec" "phpshell" "phpcmd" "adminer" "hack" "exploit" "inject"
    "malware" "virus" "c99shell" "r57shell" "wso" "b374k" "ninja-shell"
    "ecws" "cmd.php" "admin.php"
)

CRITICAL_PATTERNS=(
    "c99shell" "r57shell" "wso" "b374k" "ninja-shell" "ecws filemanager"
    "webshell" "backdoor" "cmd.php" "admin.php"
)

# =============================================================================
# FUNGSI UTILITY
# =============================================================================

init() {
    mkdir -p "$LOG_DIR"
    {
        echo "╔════════════════════════════════════════════════════════════╗"
        echo "║     WebShell Detector Pro v${VERSION} (sgtcop enhanced)   ║"
        echo "║     Scan started: $(date)                                  ║"
        echo "║     Scan directory: ${SCAN_DIR}                           ║"
        echo "╚════════════════════════════════════════════════════════════╝"
    } > "$LOG_FILE"
}

log() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%H:%M:%S')
    case "$level" in
        "INFO")    echo -e "${GREEN}[${timestamp}] [INFO]${NC} $message" | tee -a "$LOG_FILE" ;;
        "WARN")    echo -e "${YELLOW}[${timestamp}] [WARN]${NC} $message" | tee -a "$LOG_FILE" ;;
        "ERROR")   echo -e "${RED}[${timestamp}] [ERROR]${NC} $message" | tee -a "$LOG_FILE" ;;
        "FOUND")   echo -e "${YELLOW}[${timestamp}] [⚠️]${NC} $message" | tee -a "$LOG_FILE" ;;
        "CRITICAL") echo -e "${RED}[${timestamp}] [💀]${NC} $message" | tee -a "$LOG_FILE" ;;
        *)         echo "$message" | tee -a "$LOG_FILE" ;;
    esac
}

show_banner() {
    cat << "EOF"
╔══════════════════════════════════════════════════════════════╗
║           WebShell Detector Pro v${VERSION}                  ║
║           Enhanced with sgtcop.py patterns                  ║
║           LOG ONLY - No files are deleted                   ║
╚══════════════════════════════════════════════════════════════╝
EOF
    echo ""
}

show_help() {
    cat << EOF
${BLUE}WebShell Detector Pro v${VERSION}${NC}

${BOLD}USAGE:${NC}
    $0 [OPTIONS] DIRECTORY

${BOLD}OPTIONS:${NC}
    -j, --json      Output results in JSON format (saved to ${JSON_FILE})
    -h, --help      Show this help

${BOLD}DESCRIPTION:${NC}
    Scans for webshells and backdoors using enhanced patterns from sgtcop.py.
    All findings are logged for manual review. No files are deleted.

${BOLD}EXAMPLES:${NC}
    # Scan web root directory
    $0 /var/www/html

    # Scan with JSON output
    $0 --json /var/www/html

${BOLD}OUTPUT FILES:${NC}
    ${LOG_DIR}/scan_TIMESTAMP.log    - Full scan log
    ${LOG_DIR}/report_TIMESTAMP.txt  - Summary report
    ${LOG_DIR}/alerts_TIMESTAMP.txt  - Critical alerts
    ${LOG_DIR}/scan_TIMESTAMP.json   - JSON output (if --json used)

EOF
    exit 0
}

# =============================================================================
# FUNGSI SCAN
# =============================================================================

is_skip_dir() {
    local dir="$1"
    for skip in "${SKIP_DIRS[@]}"; do
        if [[ "$dir" == "$skip" ]] || [[ "$dir" == "$skip"/* ]]; then
            return 0
        fi
    done
    return 1
}

should_scan_file() {
    local file="$1"
    local ext="${file##*.}"
    for scan_ext in "${SCAN_EXTS[@]}"; do
        if [[ "$ext" == "${scan_ext#.}" ]]; then
            return 0
        fi
    done
    return 1
}

check_file() {
    local file="$1"
    local found_patterns=()
    local is_critical=false
    local file_content=""
    local file_hash=""

    # Skip if not readable
    [[ -r "$file" ]] || return 0

    # Skip if too large
    local filesize=$(stat -c%s "$file" 2>/dev/null || stat -f%z "$file" 2>/dev/null || echo 0)
    [[ $filesize -gt $MAX_FILE_SIZE ]] && return 0

    file_content=$(cat "$file" 2>/dev/null || echo "")
    [[ -z "$file_content" ]] && return 0

    # Hash
    if command -v md5sum &>/dev/null; then
        file_hash=$(md5sum "$file" | cut -d' ' -f1)
    elif command -v md5 &>/dev/null; then
        file_hash=$(md5 -q "$file" 2>/dev/null || echo "")
    fi

    local filename=$(basename "$file")

    # Critical patterns
    for pattern in "${CRITICAL_PATTERNS[@]}"; do
        if grep -qi "$pattern" <<< "$filename" || grep -qi "$pattern" <<< "$file_content"; then
            found_patterns+=("CRITICAL: $pattern")
            is_critical=true
        fi
    done

    # Suspicious names
    for name in "${SUSPICIOUS_NAMES[@]}"; do
        if grep -qi "$name" <<< "$filename"; then
            found_patterns+=("SUSPICIOUS_NAME: $name")
            is_critical=true
        fi
    done

    # Dangerous patterns (gabungan untuk efisiensi)
    local combined_pattern=$(printf "|%s" "${DANGEROUS_PATTERNS[@]}")
    combined_pattern="${combined_pattern:1}"
    if grep -Eiq "$combined_pattern" "$file"; then
        for pattern in "${DANGEROUS_PATTERNS[@]}"; do
            if grep -Eiq "$pattern" "$file"; then
                found_patterns+=("DANGEROUS: $pattern")
                is_critical=true
            fi
        done
    fi

    # Dangerous functions
    for func in "${DANGEROUS_FUNCTIONS[@]}"; do
        if grep -Eiq "${func}\s*\(" "$file"; then
            found_patterns+=("FUNCTION: $func()")
            is_critical=true
        fi
    done

    # Obfuscation detection
    if grep -qE 'base64_decode.*[A-Za-z0-9+/]{50,}' "$file"; then
        found_patterns+=("OBFUSCATED: Long base64 string")
        is_critical=true
    fi
    if grep -qE 'gzinflate.*base64_decode' "$file"; then
        found_patterns+=("OBFUSCATED: Gzip + Base64 combo")
        is_critical=true
    fi
    if grep -qE 'echo.*base64_decode.*[A-Za-z0-9+/]{20,}' "$file"; then
        found_patterns+=("WEBSHELL: echo + base64 pattern")
        is_critical=true
    fi
    if grep -qE 'str_rot13\s*\(|hex2bin\s*\(' "$file"; then
        found_patterns+=("OBFUSCATED: str_rot13/hex2bin used")
        is_critical=true
    fi

    # If findings exist
    if [[ ${#found_patterns[@]} -gt 0 ]]; then
        TOTAL_SCANNED=$((TOTAL_SCANNED + 1))
        SUSPICIOUS_FOUND=$((SUSPICIOUS_FOUND + 1))

        local filepath=$(realpath "$file" 2>/dev/null || echo "$file")

        if [[ "$is_critical" == true ]]; then
            CRITICAL_FOUND=$((CRITICAL_FOUND + 1))
            log "CRITICAL" "💀 FILE: $filepath"
            {
                echo "[$(date)] CRITICAL: $filepath"
                echo "Patterns found:"
                for p in "${found_patterns[@]}"; do
                    echo "  - $p"
                done
                echo ""
            } >> "$ALERT_FILE"
        else
            log "FOUND" "⚠️  FILE: $filepath"
        fi

        # Log detail ke report
        {
            echo "─────────────────────────────────────────────────"
            echo "File: $filepath"
            echo "Size: $(du -h "$file" 2>/dev/null | cut -f1 || echo "N/A")"
            echo "Permissions: $(stat -c %a "$file" 2>/dev/null || stat -f %Lp "$file" 2>/dev/null || echo "N/A")"
            echo "Owner: $(stat -c %U:%G "$file" 2>/dev/null || stat -f %Su:%Sg "$file" 2>/dev/null || echo "N/A")"
            echo "Hash (MD5): ${file_hash:-N/A}"
            echo "Patterns:"
            for p in "${found_patterns[@]}"; do
                echo "  - $p"
            done
            echo ""
        } >> "$REPORT_FILE"

        # Context for critical
        if [[ "$is_critical" == true ]]; then
            echo -e "${RED}Context:${NC}"
            grep -B2 -A2 -n -E 'eval|base64_decode|gzinflate|system|shell_exec|exec' "$file" 2>/dev/null | head -10 || true
            echo ""
        fi

        # Save for JSON
        if [[ "$OUTPUT_JSON" == true ]]; then
            # Escape patterns for JSON
            local patterns_json=$(printf '%s\n' "${found_patterns[@]}" | jq -R . | jq -s .)
            echo "{\"file\":\"$filepath\",\"critical\":$is_critical,\"patterns\":$patterns_json}" >> "$JSON_FILE.tmp"
        fi
    fi
}

scan_directory() {
    local dir="$1"
    log "INFO" "Scanning directory: $dir"
    while IFS= read -r -d '' file; do
        is_skip_dir "$(dirname "$file")" && continue
        should_scan_file "$file" && check_file "$file"
    done < <(find "$dir" -type f -print0 2>/dev/null)
}

# =============================================================================
# GENERATE REPORT
# =============================================================================

generate_report() {
    {
        echo "╔═══════════════════════════════════════════════════════════════╗"
        echo "║                    SCAN REPORT                                ║"
        echo "╚═══════════════════════════════════════════════════════════════╝"
        echo ""
        echo "Scan Details:"
        echo "  Directory: $SCAN_DIR"
        echo "  Date: $(date)"
        echo "  Scan Type: LOG ONLY (No files deleted)"
        echo ""
        echo "Statistics:"
        echo "  Files Scanned: $TOTAL_SCANNED"
        echo "  Suspicious Files: $SUSPICIOUS_FOUND"
        echo "  Critical Files: $CRITICAL_FOUND"
        echo ""
        echo "─────────────────────────────────────────────────────────────────"
        echo ""
        echo "⚠️  IMPORTANT:"
        echo "  - No files were deleted or moved"
        echo "  - All suspicious files are logged for manual review"
        echo "  - Please review each file before taking action"
        echo ""
        echo "─────────────────────────────────────────────────────────────────"
        echo ""

        if [[ $CRITICAL_FOUND -gt 0 ]]; then
            echo "💀 CRITICAL FILES FOUND:"
            echo "─────────────────────────────────────────────────────────────────"
            cat "$ALERT_FILE" 2>/dev/null || echo "  (No alerts recorded)"
        fi

        if [[ $SUSPICIOUS_FOUND -gt 0 ]]; then
            echo ""
            echo "⚠️  ALL SUSPICIOUS FILES:"
            echo "─────────────────────────────────────────────────────────────────"
            grep -E "^File: " "$REPORT_FILE" 2>/dev/null || echo "  (No suspicious files)"
        fi

        echo ""
        echo "─────────────────────────────────────────────────────────────────"
        echo ""
        echo "Log file: $LOG_FILE"
        echo "Report: $REPORT_FILE"
        echo "Alerts: $ALERT_FILE"
        if [[ "$OUTPUT_JSON" == true ]]; then
            echo "JSON output: $JSON_FILE"
        fi
    } | tee -a "$LOG_FILE"
}

# =============================================================================
# GENERATE JSON
# =============================================================================

generate_json() {
    if [[ "$OUTPUT_JSON" == true && -f "$JSON_FILE.tmp" ]]; then
        {
            echo "{"
            echo "  \"scan\": {"
            echo "    \"directory\": \"$SCAN_DIR\","
            echo "    \"timestamp\": \"$(date -Iseconds)\","
            echo "    \"total_scanned\": $TOTAL_SCANNED,"
            echo "    \"suspicious_found\": $SUSPICIOUS_FOUND,"
            echo "    \"critical_found\": $CRITICAL_FOUND"
            echo "  },"
            echo "  \"files\": ["
            paste -sd, "$JSON_FILE.tmp"
            echo "  ]"
            echo "}"
        } > "$JSON_FILE"
        rm -f "$JSON_FILE.tmp"
        log "INFO" "JSON output saved to $JSON_FILE"
    fi
}

# =============================================================================
# MAIN
# =============================================================================

main() {
    show_banner

    # Parse options with getopts (supports long options via -:)
    while getopts ":jh-:" opt; do
        case $opt in
            j) OUTPUT_JSON=true ;;
            h) show_help; exit 0 ;;
            -) case "${OPTARG}" in
                   json) OUTPUT_JSON=true ;;
                   help) show_help; exit 0 ;;
                   *) echo -e "${RED}Unknown option --${OPTARG}${NC}" >&2; exit 1 ;;
               esac ;;
            :) echo -e "${RED}Option -$OPTARG requires an argument${NC}" >&2; exit 1 ;;
            ?) echo -e "${RED}Unknown option -$OPTARG${NC}" >&2; exit 1 ;;
        esac
    done
    shift $((OPTIND-1))

    # Now $@ contains positional arguments (directories)
    if [[ $# -eq 0 ]]; then
        echo -e "${RED}Error: No directory specified.${NC}" >&2
        show_help
        exit 1
    elif [[ $# -gt 1 ]]; then
        echo -e "${RED}Error: Multiple directories specified. Only one allowed.${NC}" >&2
        exit 1
    else
        SCAN_DIR="$1"
    fi

    # Validate directory
    if [[ ! -d "$SCAN_DIR" ]]; then
        echo -e "${RED}Error: Directory '$SCAN_DIR' not found!${NC}" >&2
        exit 1
    fi
    if [[ ! -r "$SCAN_DIR" ]]; then
        echo -e "${RED}Error: Cannot read directory '$SCAN_DIR'${NC}" >&2
        exit 1
    fi

    # Initialize
    init

    # Scan
    echo -e "${BLUE}Starting scan...${NC}"
    echo ""
    scan_directory "$SCAN_DIR"

    # Generate JSON if needed
    if [[ "$OUTPUT_JSON" == true ]]; then
        generate_json
    fi

    # Report
    echo ""
    generate_report

    # Summary
    echo ""
    if [[ $CRITICAL_FOUND -gt 0 ]]; then
        echo -e "${RED}💀 CRITICAL: Found $CRITICAL_FOUND critical webshell(s)${NC}"
    fi
    if [[ $SUSPICIOUS_FOUND -gt 0 ]]; then
        echo -e "${YELLOW}⚠️  Found $SUSPICIOUS_FOUND suspicious file(s)${NC}"
    fi
    if [[ $SUSPICIOUS_FOUND -eq 0 ]]; then
        echo -e "${GREEN}✅ No suspicious files found!${NC}"
    fi

    echo -e "${BLUE}Logs saved to: $LOG_DIR${NC}"
}

# =============================================================================
# EKSEKUSI
# =============================================================================

main "$@"
