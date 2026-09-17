#!/usr/bin/env bash
# probe.sh — paladin-probe live-probe wrapper (version from VERSION)
#
# Enforces the Live Probe Protocol mechanically so the agent doesn't have to:
# consent gates, route skip-lists, throttling, 429 backoff, 5xx circuit
# breaker, traceability header, idempotency keys, evidence capture with a
# sha256 manifest. Treat this script like tests/grader.py — execute it,
# never read it.
#
# Exit codes:
#   0  ok
#   2  consent.live_requests denied
#   3  URL matches skip_routes
#   4  mutating verb blocked (destructive_tests: false)
#   5  429 retries exhausted (endpoint aborted)
#   6  transport failure (connect error / timeout)
#   7  5xx circuit breaker tripped
#   8  usage / config error
#   9  evidence write failure
#  10  manifest drift (verify subcommand)

set -euo pipefail

PROBE_VERSION="v$(cat "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/VERSION")"
STATE_DIR_NAME=".probe-state"
HISTORY_LOG="history.log"
DEFAULT_IGNORE_HEADERS="Date|Set-Cookie|X-Request-Id|ETag|Server|Content-Length"

usage() {
    cat <<'EOF'
probe.sh — paladin-probe live-probe wrapper

Usage:
  probe.sh send --rt RT-003 --method POST --url URL [options]
  probe.sh diff --rt RT-003 --method GET --url URL [--var K=V]... [options]
  probe.sh capture --rt RT-003 --kind KIND -- <command...>
  probe.sh verify [--root PATH]
  probe.sh check  [--root PATH]

send options:
  --rt RT-NNN           Finding/evidence id (required, ^RT-[0-9]{3}$)
  --method VERB         GET|HEAD|POST|PUT|DELETE|PATCH (required)
  --url URL             Target URL (required)
  --data STRING         Request body as a string
  --data-file PATH      Request body from file (sent byte-exact)
  --json                Add Content-Type: application/json (with --data*)
  --header 'K: V'       Extra header (repeatable). X-Paladin-Probe and
                        User-Agent overrides are rejected (exit 8).
  --idempotency-key K   Reuse an idempotency key across retries of one probe
  --label NAME          Infix in evidence filenames: <ts>-<label>-request.http
  --dry-run             Print the request and evidence paths; send nothing
  --json-out            Emit the result line as JSON instead of k=v pairs

capture options (instrumented evidence — no HTTP involved):
  --rt RT-NNN           Finding the capture supports (required, ^RT-[0-9]{3}$)
  --kind KIND           serverlog | dbstate | test-oracle (required)
  --                    Everything after -- is the command to run (through
                        bash -c, so env vars and pipes work). Each kind is
                        gated on its own consent key (absent = denied, exit 2):
                        serverlog    log_access.method + log_access.target
                                     — command must reference the target
                        dbstate      db_read_access.kind + db_read_access.dsn_env
                                     — command must reference the env var name
                        test-oracle  test_suite_oracle.command
                                     — command must match it exactly
                        Output goes to evidence/<RT>/<ts>-<kind>.instrumented.md
                        with a provenance header, secrets masked, first 8192
                        bytes, hashed into manifest.sha256. The command's own
                        exit code is recorded (a failing oracle is a result);
                        capture itself exits 0.

diff options (differential oracle — sends baseline then follow-up):
  --var KEY=VALUE       Substitutes {{KEY}} in url/data/headers of the
                        follow-up request (repeatable)
  --var-base KEY=VALUE  Substitution values for the baseline request
                        (repeatable); any {{KEY}} without a --var-base value
                        is stripped, so the baseline is always sendable
  --ignore-header H     Header excluded from normalization (repeatable;
                        default set: Date, Set-Cookie, X-Request-Id, ETag,
                        Server, Content-Length)
  --raw                 Do not collapse whitespace in bodies before diffing

Root resolution (--root wins, then $PALADIN_PROBE_ROOT, then walk up from
$PWD until a directory containing .red-team/config.yaml is found):
  --root PATH           Project dir containing .red-team/

Config keys read from .red-team/config.yaml:
  consent.live_requests     bool, default false — gate for everything HTTP
  consent.destructive_tests bool, default false — gates POST/PUT/DELETE/PATCH
  log_access.method/.target consent for capture --kind serverlog
  db_read_access.kind/.dsn_env  consent for capture --kind dbstate
  test_suite_oracle.command consent for capture --kind test-oracle
  skip_routes               list of glob or substring patterns
  throttle_seconds          default 1, per-host minimum gap between requests
  connect_timeout           default 5 (seconds)
  max_time                  default 30 (seconds)
EOF
}

die() { echo "probe.sh: $*" >&2; exit 8; }

# ---------------------------------------------------------------- root/config

resolve_root() {
    local dir="${OPT_ROOT:-${PALADIN_PROBE_ROOT:-}}"
    if [[ -n "$dir" ]]; then
        [[ -f "$dir/.red-team/config.yaml" ]] || die "--root: no .red-team/config.yaml under $dir"
        ROOT="$dir"; return
    fi
    dir="$PWD"
    while [[ "$dir" != "/" ]]; do
        if [[ -f "$dir/.red-team/config.yaml" ]]; then ROOT="$dir"; return; fi
        dir="$(dirname "$dir")"
    done
    die "no .red-team/config.yaml found upward from $PWD (pass --root or set PALADIN_PROBE_ROOT)"
}

# cfg_get <dotted.key> — one-level-nested YAML scalar reader; echoes value.
cfg_get() {
    local key="$1" top skey
    top="${key%%.*}"; skey="${key#*.}"
    [[ "$top" == "$skey" ]] && skey=""
    awk -v tkey="$top" -v skey="$skey" '
        /^[[:space:]]*(#|$)/ { next }
        {
            match($0, /^ */); ind = RLENGTH
            l = $0; sub(/^ */, "", l)
            if (ind == 0) {
                cur = l; sub(/:.*/, "", cur)
                inblock = (cur == tkey)
                if (inblock && skey == "") {
                    v = l; sub(/^[^:]*:[[:space:]]*/, "", v)
                    gsub(/^["'"'"']|["'"'"']$/, "", v)
                    print v; exit
                }
                next
            }
            if (inblock && skey != "") {
                k = l; sub(/:.*/, "", k)
                if (k == skey) {
                    v = l; sub(/^[^:]*:[[:space:]]*/, "", v)
                    gsub(/^["'"'"']|["'"'"']$/, "", v)
                    print v; exit
                }
            }
        }' "$ROOT/.red-team/config.yaml" 2>/dev/null || true
}

cfg_val() { # cfg_val <key> <default>
    local v; v="$(cfg_get "$1")"
    [[ -n "$v" ]] && echo "$v" || echo "$2"
}

cfg_bool() { # cfg_bool <key> — true only if value is true/yes/1
    local v; v="$(cfg_get "$1")"
    case "${v,,}" in true|yes|1) return 0 ;; *) return 1 ;; esac
}

skip_routes() { # echoes one pattern per line
    awk '
        /^[[:space:]]*(#|$)/ { next }
        {
            match($0, /^ */); ind = RLENGTH
            l = $0; sub(/^ */, "", l)
            if (ind == 0) { cur = l; sub(/:.*/, "", cur); inblock = (cur == "skip_routes"); next }
            if (inblock && l ~ /^-/) {
                v = l; sub(/^-[[:space:]]*/, "", v)
                gsub(/^["'"'"']|["'"'"']$/, "", v)
                print v
            }
        }' "$ROOT/.red-team/config.yaml" 2>/dev/null || true
}

# ---------------------------------------------------------------- url helpers

url_host() { # scheme://user:pw@host:port/p?q -> host[:port]
    local u="${1#*://}" hp
    hp="${u%%/*}"; hp="${hp%%\?*}"
    hp="${hp##*@}"
    echo "$hp"
}

url_path() { # -> /path?query (at least "/")
    local u="${1#*://}" hp rest
    hp="${u%%/*}"; hp="${hp%%\?*}"
    rest="${u#"$hp"}"
    [[ -n "$rest" ]] || rest="/"
    echo "$rest"
}

url_skip_match() { # url_skip_match <url> — 0 if any skip pattern matches
    local url="$1" p path
    path="$(url_path "$url")"
    while IFS= read -r p; do
        [[ -z "$p" ]] && continue
        # shellcheck disable=SC2053  # unquoted RHS is intentional (glob match)
        [[ "$path" == $p ]] && return 0
        [[ "$path" == *"$p"* ]] && return 0
    done < <(skip_routes)
    return 1
}

# ---------------------------------------------------------------- throttle/breaker

state_dir() { mkdir -p "$ROOT/.red-team/$STATE_DIR_NAME"; echo "$ROOT/.red-team/$STATE_DIR_NAME"; }

throttle_wait() { # per-host minimum gap: throttle_wait <host> <seconds>
    local host="$1" secs="$2" f last now gap
    f="$(state_dir)/$HISTORY_LOG"
    if [[ -f "$f" ]]; then
        last="$(awk -v h="$host" '$2 == h { l = $1 } END { print l }' "$f")"
        if [[ -n "${last:-}" ]]; then
            now="$(date +%s)"; gap=$(( now - last ))
            if (( gap < secs )); then sleep $(( secs - gap )); fi
        fi
    fi
    return 0
}

history_record() { # history_record <host> <status>; prunes >10min old entries
    local f; f="$(state_dir)/$HISTORY_LOG"
    echo "$(date +%s) $1 $2" >> "$f"
    local cutoff=$(( $(date +%s) - 600 ))
    awk -v c="$cutoff" '$1 >= c' "$f" > "$f.tmp" && mv "$f.tmp" "$f"
}

breaker_marker() { echo "$(state_dir)/$1.aborted"; }

breaker_refuses() { # marker present and younger than 10 min
    local m; m="$(breaker_marker "$1")"
    [[ -f "$m" ]] || return 1
    local age=$(( $(date +%s) - $(stat -c %Y "$m") ))
    (( age < 600 )) && return 0
    rm -f "$m"; return 1
}

breaker_trip() { # >30% 5xx over >=4 requests to host in rolling 60s
    local host="$1" f
    f="$(state_dir)/$HISTORY_LOG"
    [[ -f "$f" ]] || return 1
    awk -v h="$host" -v now="$(date +%s)" '
        $2 == h && (now - $1) <= 60 { n++; if ($3 >= 500) fives++ }
        END { exit !((n >= 4) && (fives > 0) && (fives / n > 0.30)) }' "$f"
}

abort_write() { # abort_write <host> <url> <status>
    local f="$ROOT/.red-team/sessions/$(date -u +%F)_abort.md"
    mkdir -p "$ROOT/.red-team/sessions"
    {
        echo "# Probe Session Aborted — circuit breaker"
        echo ""
        echo "- time: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "- host: $1"
        echo "- url:  $2"
        echo "- trigger status: $3"
        echo ""
        echo "Last requests:"
        tail -5 "$(state_dir)/$HISTORY_LOG" 2>/dev/null | sed 's/^/    /' || true
    } >> "$f"
    touch "$(breaker_marker "$1")"
}

# ---------------------------------------------------------------- evidence

now_ts() { date -u +%Y-%m-%dT%H-%M-%SZ; }

hash_append() { # hash_append <evidence-dir> <file>
    local dir="$1" f="$2" h
    h="$(sha256sum "$f" | awk '{print $1}')"
    printf '%s  %s\n' "$h" "$(basename "$f")" >> "$dir/manifest.sha256"
}

# write_evidence_pair — writes <ts>[-label]-{request,response}.http + manifest.
# Uses globals set by do_send; sets REQFILE/RESPFILE.
write_evidence_pair() {
    local rt="$1" ts="$2" label="$3" method="$4" url="$5" host="$6"
    local status="$7" ttime="$8" retries="$9"
    local dir="$ROOT/.red-team/evidence/$rt" infix=""
    [[ -n "$label" ]] && infix="-$label"
    mkdir -p "$dir" || { echo "probe.sh: cannot mkdir $dir" >&2; exit 9; }
    # sub-second sends must not collide on the second-granularity timestamp
    local base="$ts$infix" n=1
    while [[ -e "$dir/$base-request.http" || -e "$dir/$base-response.http" ]]; do
        n=$(( n + 1 )); base="$ts$infix-$n"
    done
    local req="$dir/$base-request.http" resp="$dir/$base-response.http"

    {
        echo "$method $(url_path "$url") HTTP/1.1"
        echo "Host: $host"
        cat "$SENT_HDRS"
        echo ""
        head -c 4096 "$BODY_TMP" 2>/dev/null || true
        echo ""
        echo "# sent-at: $ts"
        echo "# curl-argv: $(cat "$ARGV_TMP" 2>/dev/null || true)"
    } > "$req"

    {
        if [[ "$status" == "0" ]]; then
            echo "HTTP/1.1 TRANSPORT-ERROR"
        else
            echo "HTTP/1.1 $status"
        fi
        cat "$RESP_HDRS" 2>/dev/null || true
        echo ""
        head -c 1000 "$RESP_BODY" 2>/dev/null || true
        echo ""
        echo "# time_total: $ttime"
        echo "# retries: $retries"
    } > "$resp"

    hash_append "$dir" "$req"
    hash_append "$dir" "$resp"
    REQFILE="$req"; RESPFILE="$resp"
}

# ---------------------------------------------------------------- arg parsing

parse_opts() {
    SUB=""; OPT_RT=""; OPT_METHOD=""; OPT_URL=""; OPT_DATA=""; OPT_DATAFILE=""
    OPT_JSON=false; HEADERS=(); OPT_IDEM=""; OPT_LABEL=""; OPT_DRYRUN=false
    OPT_JSONOUT=false; OPT_ROOT=""; VARS=(); BASE_VARS=(); IGN=(); OPT_RAW=false
    OPT_KIND=""; CMD=()
    PENDING=""
    local args=("$@") arg i
    for (( i=0; i<${#args[@]}; i++ )); do
        arg="${args[$i]}"
        if (( i == 0 )); then SUB="$arg"; continue; fi
        case "$arg" in
            --) # everything after -- is the capture command, verbatim
                CMD=("${args[@]:$((i + 1))}")
                break ;;
            --rt) PENDING=rt; continue ;;
            --method) PENDING=method; continue ;;
            --url) PENDING=url; continue ;;
            --data) PENDING=data; continue ;;
            --data-file) PENDING=datafile; continue ;;
            --header) PENDING=header; continue ;;
            --idempotency-key) PENDING=idem; continue ;;
            --label) PENDING=label; continue ;;
            --var) PENDING=var; continue ;;
            --var-base) PENDING=varbase; continue ;;
            --ignore-header) PENDING=ign; continue ;;
            --kind) PENDING=kind; continue ;;
            --root) PENDING=root; continue ;;
            --json) OPT_JSON=true; continue ;;
            --dry-run) OPT_DRYRUN=true; continue ;;
            --json-out) OPT_JSONOUT=true; continue ;;
            --raw) OPT_RAW=true; continue ;;
            -h|--help) usage; exit 0 ;;
            *) : ;;
        esac
        if [[ -n "$PENDING" ]]; then
            case "$PENDING" in
                rt) OPT_RT="$arg" ;;
                method) OPT_METHOD="${arg^^}" ;;
                url) OPT_URL="$arg" ;;
                data) OPT_DATA="$arg" ;;
                datafile) OPT_DATAFILE="$arg" ;;
                idem) OPT_IDEM="$arg" ;;
                label) OPT_LABEL="$arg" ;;
                root) OPT_ROOT="$arg" ;;
                header) HEADERS+=("$arg") ;;
                var) VARS+=("$arg") ;;
                varbase) BASE_VARS+=("$arg") ;;
                ign) IGN+=("$arg") ;;
                kind) OPT_KIND="$arg" ;;
            esac
            PENDING=""
        else
            die "unknown argument: $arg (see --help)"
        fi
    done
    if [[ -n "$PENDING" ]]; then die "--$PENDING requires a value"; fi
    return 0
}

substitute_vars() { # substitute_vars <string> <base|follow>
    # "follow": apply --var K=V substitutions, leave unknown {{K}} intact.
    # "base":   apply --var-base K=V, then strip any remaining {{K}} tokens
    #           so the baseline URL is always sendable.
    local s="$1" which="$2" kv k v
    local -a use=()
    if [[ "$which" == "base" ]]; then use=("${BASE_VARS[@]:-}"); else use=("${VARS[@]:-}"); fi
    for kv in "${use[@]:-}"; do
        [[ -z "$kv" ]] && continue
        k="{{${kv%%=*}}}"; v="${kv#*=}"
        s="${s//"$k"/$v}"
    done
    if [[ "$which" == "base" ]]; then
        s="$(printf '%s' "$s" | sed -E 's/\{\{[A-Za-z0-9_-]+\}\}//g')"
    fi
    printf '%s' "$s"
}

# ---------------------------------------------------------------- cmd: check

cmd_check() {
    resolve_root
    local live dex effort routes="" aborted="" m host
    if cfg_bool consent.live_requests; then live=true; else live=false; fi
    if cfg_bool consent.destructive_tests; then dex=true; else dex=false; fi
    effort="$(cfg_val effort standard)"
    routes="$(skip_routes | tr '\n' ' ')"
    for m in "$(state_dir)"/*.aborted; do
        [[ -e "$m" ]] || continue
        host="$(basename "$m" .aborted)"
        breaker_refuses "$host" || continue
        aborted="$aborted $host"
    done
    echo "root=$ROOT"
    echo "live_requests=$live"
    echo "destructive_tests=$dex"
    echo "effort=$effort"
    echo "throttle_seconds=$(cfg_val throttle_seconds 1)"
    echo "skip_routes=${routes:-<none>}"
    echo "aborted_hosts=${aborted:- <none>}"
    local logm logt dbk dbe tsc
    logm="$(cfg_get log_access.method)"; logt="$(cfg_get log_access.target)"
    dbk="$(cfg_get db_read_access.kind)"; dbe="$(cfg_get db_read_access.dsn_env)"
    tsc="$(cfg_get test_suite_oracle.command)"
    if [[ -n "$logm" && -n "$logt" ]]; then
        echo "log_access=granted (method=$logm, target=$logt)"
    else
        echo "log_access=denied"
    fi
    if [[ -n "$dbk" && -n "$dbe" ]]; then
        echo "db_read_access=granted (kind=$dbk, dsn_env=\$${dbe})"
    else
        echo "db_read_access=denied"
    fi
    if [[ -n "$tsc" ]]; then
        echo "test_suite_oracle=granted"
    else
        echo "test_suite_oracle=denied"
    fi
    $live || exit 2
    exit 0
}

# ---------------------------------------------------------------- cmd: verify

cmd_verify() {
    resolve_root
    local any_drift=false found=0 mf dir hash base actual
    for mf in "$ROOT"/.red-team/evidence/*/manifest.sha256; do
        [[ -f "$mf" ]] || continue
        found=1; dir="$(dirname "$mf")"
        while read -r hash base; do
            [[ -z "${hash:-}" ]] && continue
            if [[ ! -e "$dir/$base" ]]; then
                echo "DRIFT $dir/$base missing"
                any_drift=true; continue
            fi
            actual="$(sha256sum "$dir/$base" | awk '{print $1}')"
            if [[ "$actual" != "$hash" ]]; then
                echo "DRIFT $dir/$base expected=$hash actual=$actual"
                any_drift=true
            fi
        done < "$mf"
    done
    if (( ! found )); then echo "no manifests found"; exit 0; fi
    if $any_drift; then exit 10; fi
    echo "OK all evidence hashes verified"
    exit 0
}

# ---------------------------------------------------------------- cmd: send

do_send() { # one consented, throttled, evidence-captured request
    local label="${1:-$OPT_LABEL}"
    local rt="$OPT_RT" method="$OPT_METHOD" url="$OPT_URL" host path h

    [[ "$rt" =~ ^RT-[0-9]{3}$ ]] || die "--rt must match RT-NNN (e.g. RT-003), got '$rt'"
    case "$method" in
        GET|HEAD|POST|PUT|DELETE|PATCH) ;;
        *) die "--method must be one of GET|HEAD|POST|PUT|DELETE|PATCH, got '$method'" ;;
    esac
    [[ "$url" =~ ^https?:// ]] || die "--url must be http(s), got '$url'"
    if $OPT_JSON && [[ -z "$OPT_DATA" && -z "$OPT_DATAFILE" ]]; then
        die "--json requires --data or --data-file"
    fi

    resolve_root
    cfg_bool consent.live_requests || {
        echo "probe.sh: consent.live_requests is not true — refusing to send (edit .red-team/config.yaml to consent)" >&2
        exit 2
    }
    if url_skip_match "$url"; then
        echo "probe.sh: $url matches skip_routes — refusing" >&2
        exit 3
    fi
    case "$method" in
        POST|PUT|DELETE|PATCH)
            cfg_bool consent.destructive_tests || {
                echo "probe.sh: $method is state-mutating and consent.destructive_tests is not true — refusing" >&2
                exit 4
            } ;;
    esac

    host="$(url_host "$url")"

    # probe headers are non-overridable
    for h in "${HEADERS[@]:-}"; do
        [[ -z "$h" ]] && continue
        case "${h,,}" in
            x-paladin-probe:*) die "refusing to override X-Paladin-Probe header" ;;
            user-agent:*) die "refusing to override User-Agent header" ;;
        esac
    done

    local hdr_args=()
    for h in "${HEADERS[@]:-}"; do [[ -n "$h" ]] && hdr_args+=(-H "$h"); done
    hdr_args+=(-H "User-Agent: paladin-probe/$PROBE_VERSION")
    hdr_args+=(-H "X-Paladin-Probe: $PROBE_VERSION")

    local idem=""
    case "$method" in
        POST|PUT|DELETE|PATCH)
            if [[ -n "$OPT_IDEM" ]]; then
                idem="$OPT_IDEM"
            else
                idem="$(cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen 2>/dev/null || echo "probe-$(date +%s)")"
            fi
            hdr_args+=(-H "X-Paladin-Probe-Idempotency: $idem") ;;
    esac
    if $OPT_JSON; then hdr_args+=(-H "Content-Type: application/json"); fi

    BODY_TMP="$(mktemp)"
    local data_args=()
    if [[ -n "$OPT_DATAFILE" ]]; then
        [[ -f "$OPT_DATAFILE" ]] || die "--data-file not found: $OPT_DATAFILE"
        data_args=(--data-binary "@$OPT_DATAFILE")
        cp "$OPT_DATAFILE" "$BODY_TMP"
    elif [[ -n "$OPT_DATA" ]]; then
        data_args=(--data "$OPT_DATA")
        printf '%s' "$OPT_DATA" > "$BODY_TMP"
    fi

    SENT_HDRS="$(mktemp)"
    for h in "${HEADERS[@]:-}"; do [[ -n "$h" ]] && echo "$h"; done > "$SENT_HDRS"
    echo "User-Agent: paladin-probe/$PROBE_VERSION" >> "$SENT_HDRS"
    echo "X-Paladin-Probe: $PROBE_VERSION" >> "$SENT_HDRS"
    [[ -n "$idem" ]] && echo "X-Paladin-Probe-Idempotency: $idem" >> "$SENT_HDRS"
    if $OPT_JSON; then echo "Content-Type: application/json" >> "$SENT_HDRS"; fi

    ARGV_TMP="$(mktemp)"
    {
        printf 'curl -sS -X %s %s' "$method" "$url"
        local a
        for a in "${hdr_args[@]}"; do
            if [[ "$a" == "-H" ]]; then printf ' -H'; else printf ' "%s"' "$a"; fi
        done
        if (( ${#data_args[@]} )); then printf ' %s' "${data_args[*]}"; fi
        printf '\n'
    } > "$ARGV_TMP"

    local ts; ts="$(now_ts)"

    if $OPT_DRYRUN; then
        echo "dry-run: nothing sent, nothing written"
        echo "  method: $method"
        echo "  url:    $url"
        echo "  headers:"; sed 's/^/    /' "$SENT_HDRS"
        if [[ -s "$BODY_TMP" ]]; then
            echo "  body (first 200 chars): $(head -c 200 "$BODY_TMP")"
        fi
        echo "  would write: $ROOT/.red-team/evidence/$rt/$ts${label:+-$label}-request.http"
        echo "               $ROOT/.red-team/evidence/$rt/$ts${label:+-$label}-response.http"
        cleanup_send_tmps
        exit 0
    fi

    if breaker_refuses "$host"; then
        echo "probe.sh: circuit breaker active for $host (recent abort) — refusing" >&2
        cleanup_send_tmps
        exit 7
    fi

    throttle_wait "$host" "$(cfg_val throttle_seconds 1)"

    local ct mt
    ct="$(cfg_val connect_timeout 5)"
    mt="$(cfg_val max_time 30)"
    RESP_HDRS="$(mktemp)"; RESP_BODY="$(mktemp)"
    local rerr; rerr="$(mktemp)"
    local status=0 elapsed=0 attempt retries=0 wout rc
    local backoff=(0 2 4 8)
    for attempt in 1 2 3 4; do
        set +e
        wout="$(curl -sS --compressed -X "$method" "$url" "${hdr_args[@]}" \
            ${data_args[@]+"${data_args[@]}"} \
            --connect-timeout "$ct" --max-time "$mt" \
            -o "$RESP_BODY" -D "$RESP_HDRS" -w '%{http_code} %{time_total}' 2>"$rerr")"
        rc=$?
        set -e
        if (( rc != 0 )); then
            echo "probe.sh: transport error (curl exit $rc): $(head -c 200 "$rerr")" >&2
            write_evidence_pair "$rt" "$ts" "$label" "$method" "$url" "$host" 0 "$elapsed" "$retries"
            history_record "$host" 0
            cleanup_send_tmps
            exit 6
        fi
        read -r status elapsed <<< "$wout"
        if [[ -z "$status" || "$status" == "000" ]]; then
            echo "probe.sh: transport error (no status returned)" >&2
            write_evidence_pair "$rt" "$ts" "$label" "$method" "$url" "$host" 0 "$elapsed" "$retries"
            history_record "$host" 0
            cleanup_send_tmps
            exit 6
        fi
        if [[ "$status" == "429" && "$attempt" -lt 4 ]]; then
            retries="$attempt"
            sleep "${backoff[$attempt]}"
            continue
        fi
        break
    done

    if [[ "$status" == "429" ]]; then
        write_evidence_pair "$rt" "$ts" "$label" "$method" "$url" "$host" "$status" "$elapsed" "$retries"
        history_record "$host" "$status"
        touch "$(breaker_marker "$host")"
        echo "probe.sh: 429 persisted after 3 retries — aborting endpoint $host" >&2
        cleanup_send_tmps
        exit 5
    fi

    history_record "$host" "$status"

    if breaker_trip "$host"; then
        write_evidence_pair "$rt" "$ts" "$label" "$method" "$url" "$host" "$status" "$elapsed" "$retries"
        abort_write "$host" "$url" "$status"
        echo "probe.sh: circuit breaker tripped for $host (>30% 5xx over >=4 requests/60s) — session aborted" >&2
        cleanup_send_tmps
        exit 7
    fi

    write_evidence_pair "$rt" "$ts" "$label" "$method" "$url" "$host" "$status" "$elapsed" "$retries"
    cleanup_send_tmps
    SEND_STATUS="$status"; SEND_ELAPSED="$elapsed"; SEND_RETRIES="$retries"
    SEND_REQ="$REQFILE"; SEND_RESP="$RESPFILE"; SEND_IDEM="$idem"
}

cleanup_send_tmps() {
    rm -f "${SENT_HDRS:-}" "${BODY_TMP:-}" "${ARGV_TMP:-}" "${RESP_HDRS:-}" "${RESP_BODY:-}"
}

emit_result() {
    if $OPT_JSONOUT; then
        printf '{"rt":"%s","status":"%s","elapsed":"%s","retries":"%s","request":"%s","response":"%s","idempotency":"%s"}\n' \
            "$OPT_RT" "${SEND_STATUS:-}" "${SEND_ELAPSED:-}" "${SEND_RETRIES:-}" "${SEND_REQ:-}" "${SEND_RESP:-}" "${SEND_IDEM:--}"
    else
        echo "rt=$OPT_RT status=${SEND_STATUS:-} elapsed=${SEND_ELAPSED:-} retries=${SEND_RETRIES:-} request=${SEND_REQ:-} response=${SEND_RESP:-} idempotency=${SEND_IDEM:--}"
    fi
}

cmd_send() {
    do_send
    emit_result
}

# ---------------------------------------------------------------- cmd: diff

skip_header_regex() { # builds header-filter regex from IGN + defaults
    local re="$DEFAULT_IGNORE_HEADERS" h
    for h in "${IGN[@]:-}"; do
        [[ -n "$h" ]] && re="$re|${h}"
    done
    echo "$re"
}

extract_response() { # extract_response <response.http> — normalized view
    local f="$1" tmp_clean tmp_hdr re
    tmp_clean="$(mktemp)"; tmp_hdr="$(mktemp)"
    sed '/^#/d' "$f" > "$tmp_clean"
    awk 'NR==1 { next } /^$/ { exit } { print }' "$tmp_clean" > "$tmp_hdr"
    re="$(skip_header_regex)"
    awk -v re="^(${re}):" 'tolower($0) ~ tolower(re) { next } { print }' "$tmp_hdr" | sort
    echo "---body---"
    if $OPT_RAW; then
        awk '/^$/ { b = 1; next } b { print }' "$tmp_clean"
    else
        awk '/^$/ { b = 1; next } b { print }' "$tmp_clean" | tr -s '[:space:]' ' '; echo
    fi
    rm -f "$tmp_clean" "$tmp_hdr"
}

apply_substitution() { # apply_substitution <base|follow> — rewrites OPT_* in place
    local which="$1" url2 data2 h headers2=()
    url2="$(substitute_vars "$OPT_URL" "$which")"
    data2="$(substitute_vars "$OPT_DATA" "$which")"
    if [[ -n "$OPT_DATAFILE" ]]; then
        local sub_file; sub_file="$(mktemp)"
        substitute_vars "$(cat "$OPT_DATAFILE")" "$which" > "$sub_file"
        OPT_DATAFILE="$sub_file"
    fi
    for h in "${HEADERS[@]:-}"; do
        [[ -n "$h" ]] && headers2+=("$(substitute_vars "$h" "$which")")
    done
    OPT_URL="$url2"; OPT_DATA="$data2"
    HEADERS=("${headers2[@]:-}")
}

cmd_diff() {
    # preserve the template so both legs substitute from the same original
    local tpl_url="$OPT_URL" tpl_data="$OPT_DATA" tpl_datafile="$OPT_DATAFILE"
    local -a tpl_headers=("${HEADERS[@]:-}")

    apply_substitution base
    do_send "baseline"
    local b_resp="$SEND_RESP"

    # restore template, then apply the follow-up substitution set
    OPT_URL="$tpl_url"; OPT_DATA="$tpl_data"; OPT_DATAFILE="$tpl_datafile"
    HEADERS=("${tpl_headers[@]:-}")
    apply_substitution follow
    do_send "followup"
    local f_resp="$SEND_RESP"

    local b_norm f_norm difff ts lines
    b_norm="$(mktemp)"; f_norm="$(mktemp)"
    extract_response "$b_resp" > "$b_norm"
    extract_response "$f_resp" > "$f_norm"
    ts="$(now_ts)"
    local ddir="$(dirname "$f_resp")" dbase="$ts" dn=1
    while [[ -e "$ddir/$dbase-diff.txt" ]]; do dn=$(( dn + 1 )); dbase="$ts-$dn"; done
    difff="$ddir/$dbase-diff.txt"
    if diff -u "$b_norm" "$f_norm" > "$difff"; then
        lines=0
        hash_append "$(dirname "$f_resp")" "$difff"
        rm -f "$b_norm" "$f_norm"
        echo "delta=identical changed_lines=0 diff=$difff"
        exit 0
    fi
    lines="$(grep -cE '^[+-][^+-]' "$difff" || true)"
    hash_append "$(dirname "$f_resp")" "$difff"
    rm -f "$b_norm" "$f_norm"
    echo "delta=different changed_lines=$lines diff=$difff"
    exit 0
}

# ---------------------------------------------------------------- cmd: capture

mask_secrets() { # stdin -> stdout, obvious secrets redacted (conservative)
    sed -E \
        -e 's/AKIA[0-9A-Z]{16}/AKIA[REDACTED]/g' \
        -e 's/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/eyJ[REDACTED-JWT]/g' \
        -e 's#(://[^/@:]+):([^/@]+)@#\1:[REDACTED]@#g' \
        -e 's/([Bb]earer )[A-Za-z0-9._-]{8,}/\1[REDACTED]/g' \
        -e 's/([Pp]assword|[Ss]ecret|[Tt]oken|[Aa]pi[_-]?[Kk]ey)(["'"'"' ]?[=:][ ]?)[A-Za-z0-9._/+=-]{6,}/\1\2[REDACTED]/g' \
        -e 's/-----BEGIN [A-Z ]*PRIVATE KEY-----.* -----END [A-Z ]*PRIVATE KEY-----/[REDACTED PRIVATE KEY BLOCK]/g' \
        -e 's/[A-Za-z0-9+/]{40,}/[REDACTED-LONG-TOKEN]/g'
}

cmd_capture() {
    local rt="$OPT_RT" kind="$OPT_KIND" cmd_str consent_ref
    [[ "$rt" =~ ^RT-[0-9]{3}$ ]] || die "--rt must match RT-NNN (e.g. RT-003), got '$rt'"
    case "$kind" in
        serverlog|dbstate|test-oracle) ;;
        *) die "--kind must be serverlog | dbstate | test-oracle, got '$kind'" ;;
    esac
    (( ${#CMD[@]} )) || die "capture requires a command after -- (see --help)"
    resolve_root
    cmd_str="${CMD[*]}"

    case "$kind" in
        serverlog)
            local m t
            m="$(cfg_get log_access.method)"; t="$(cfg_get log_access.target)"
            if [[ -z "$m" || -z "$t" ]]; then
                echo "probe.sh: log_access (method+target) not consented — refusing capture" >&2
                exit 2
            fi
            consent_ref="log_access (method=$m, target=$t)"
            [[ "$cmd_str" == *"$t"* ]] || die "capture command does not reference consented log_access.target '$t'"
            ;;
        dbstate)
            local k e
            k="$(cfg_get db_read_access.kind)"; e="$(cfg_get db_read_access.dsn_env)"
            if [[ -z "$k" || -z "$e" ]]; then
                echo "probe.sh: db_read_access (kind+dsn_env) not consented — refusing capture" >&2
                exit 2
            fi
            consent_ref="db_read_access (kind=$k, dsn_env=\$${e} — value never read by the wrapper)"
            [[ "$cmd_str" == *"$e"* ]] || die "capture command does not reference consented db_read_access.dsn_env '$e'"
            ;;
        test-oracle)
            local c
            c="$(cfg_get test_suite_oracle.command)"
            if [[ -z "$c" ]]; then
                echo "probe.sh: test_suite_oracle.command not consented — refusing capture" >&2
                exit 2
            fi
            consent_ref="test_suite_oracle.command"
            [[ "$cmd_str" == "$c" ]] || die "capture command must exactly match consented test_suite_oracle.command"
            ;;
    esac

    local dir="$ROOT/.red-team/evidence/$rt" ts base n=1 out raw cmd_exit
    mkdir -p "$dir" || { echo "probe.sh: cannot mkdir $dir" >&2; exit 9; }
    ts="$(now_ts)"; base="$ts-$kind"
    while [[ -e "$dir/$base.instrumented.md" ]]; do n=$(( n + 1 )); base="$ts-$kind-$n"; done
    out="$dir/$base.instrumented.md"
    raw="$(mktemp)"

    # consent gates matched the command string; run it through bash so env
    # vars, pipes, and redirections in the consented command work as written
    set +e
    bash -c "$cmd_str" > "$raw" 2>&1
    cmd_exit=$?
    set -e

    {
        echo "# instrumented capture — $kind"
        echo ""
        echo "- rt: $rt"
        echo "- kind: $kind"
        echo "- captured_at: $ts"
        echo "- command: $cmd_str"
        echo "- consent: $consent_ref"
        echo "- cmd_exit: $cmd_exit"
        echo "- output_bytes: $(wc -c < "$raw") (first 8192 shown)"
        echo "- masking: AKIA keys, JWTs, URL credentials, bearer tokens, labeled"
        echo "  secrets, private key blocks, opaque runs >=40 chars are redacted"
        echo ""
        echo "## output (masked)"
        echo ""
        echo '```'
        mask_secrets < "$raw" | head -c 8192
        echo ""
        echo '```'
    } > "$out" || { rm -f "$raw"; echo "probe.sh: cannot write $out" >&2; exit 9; }

    hash_append "$dir" "$out"
    echo "rt=$rt kind=$kind cmd_exit=$cmd_exit bytes=$(wc -c < "$raw") capture=$out"
    rm -f "$raw"
}

# ---------------------------------------------------------------- main

[[ $# -eq 0 ]] && { usage; exit 8; }
parse_opts "$@"
case "$SUB" in
    send) cmd_send ;;
    diff) cmd_diff ;;
    capture) cmd_capture ;;
    verify) cmd_verify ;;
    check) cmd_check ;;
    -h|--help|help) usage; exit 0 ;;
    *) die "unknown subcommand: $SUB (send | diff | capture | verify | check)" ;;
esac
