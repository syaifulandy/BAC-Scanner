#!/bin/bash

INPUT_FILE=""
ROLE_FILE="roles.json"
OUTPUT_DIR="bac_output"
THREADS=4
DELAY=0.2
API_PREFIX=""
EXCLUDE_PATTERN=""


# =========================
# ARG
# =========================
while [[ "$#" -gt 0 ]]; do
  case $1 in
    -i|--input) INPUT_FILE="$2"; shift ;;
    -r|--roles) ROLE_FILE="$2"; shift ;;
    -p|--prefix) API_PREFIX="$2"; shift ;;
    -x|--exclude) EXCLUDE_PATTERN="$2"; shift ;;
    -t|--threads) THREADS="$2"; shift ;;
    --gen-roles)
      cat <<EOF > roles.json
{
  "baseline_role": "admin",
  "roles": [
    { "name": "admin", "cookie": "SESSION=admin", "enabled": true },
    { "name": "user", "cookie": "SESSION=user", "enabled": true }
  ]
}
EOF
      echo "[OK] roles.json created"
      exit 0 ;;

      -h|--help)
        cat << EOF

      🔥 UNIVERSAL BAC SCANNER (SPA + API + IDOR)

      Usage:
        $0 -i targets.txt [options]

      Options:
        -i, --input FILE         Target list (required)
        -r, --roles FILE         Roles JSON file (default: roles.json)
        -p, --prefix PATH        API prefix (e.g: /app.php)
        -x, --exclude STR        Skip endpoint (comma-separated)
                                 Example: logout,signout,revoke
        -t, --threads NUM        Concurrent requests (default: 4)

      Extra:
        --gen-roles              Generate roles.json template

      Examples:
        $0 -i targets.txt
        $0 -i targets.txt -p /app.php
        $0 -i targets.txt -p /app.php -x logout,signout,revoke
        $0 -i targets.txt -r custom_roles.json -t 10

      Notes:
        - Prefix will be prepended to all discovered API paths
        - Exclude helps avoid breaking session (e.g. logout endpoint)

EOF
  exit 0 ;;

  esac
  shift
done

[[ -z "$INPUT_FILE" ]] && { echo "use -h for help"; exit 1; }
mkdir -p "$OUTPUT_DIR"

# =========================
# ROLE
# =========================
BASELINE_ROLE=$(jq -r '.baseline_role' "$ROLE_FILE")

get_cookie() {
  jq -r --arg r "$1" '.roles[] | select(.name==$r) | .cookie' "$ROLE_FILE"
}

BASELINE_COOKIE=$(get_cookie "$BASELINE_ROLE")

# =========================
# HASH
# =========================
hash_body() { md5sum | cut -d' ' -f1; }

# =========================
# JS RECURSIVE
# =========================
discover_js_recursive() {

  base=$1
  seed=$2
  out=$3

  mkdir -p "$out"
  cp "$seed" "$out/queue.txt"
  > "$out/visited.txt"

  while true; do
    new=0

    while read -r js; do
      grep -qx "$js" "$out/visited.txt" && continue

      echo "$js" >> "$out/visited.txt"
      f="$out/$(basename "$js")"

      curl -s "$js" -o "$f"

      grep -rhoE '\.\./(nodes|chunks)/[a-zA-Z0-9._-]+\.js' "$f" \
      | sed 's|\.\./||' \
      | while read dep; do
          full="$base/$dep"
          if ! grep -qx "$full" "$out/visited.txt"; then
            echo "$full" >> "$out/queue.txt"
            new=1
          fi
        done

    done < "$out/queue.txt"

    [[ $new -eq 0 ]] && break
  done
}

# =========================
# API EXTRACTOR (FIXED)
# =========================
extract_api() {

  dir=$1
  out=$2

  echo "[STEP] Extracting API..."

  (
  grep -rEho '\$\{[^}]+\}/[a-zA-Z0-9/_-]+' "$dir" | sed 's/.*}//'

  grep -rEho '\/[a-zA-Z0-9/_-]+' "$dir" \
  | grep -Ei 'api|auth|user|admin|data|report|dashboard|login|notification|gbo'

  ) | sort -u > "$out"

  echo "[OK] found: $(wc -l < "$out") endpoints"
}

# =========================
# IDOR CHECK 🔥
# =========================
idor_test() {

  url=$1
  cookie=$2

  # hanya path, bukan domain
  path=$(echo "$url" | cut -d/ -f4-)

  if [[ "$path" =~ /([0-9]+) ]]; then
    id=${BASH_REMATCH[1]}
    next=$((id + 1))

    new_path=$(echo "$path" | sed "s/$id/$next/")
    base=$(echo "$url" | cut -d/ -f1-3)

    test_url="$base/$new_path"

    r1=$(curl -s -H "Cookie: $cookie" "$url")
    r2=$(curl -s -H "Cookie: $cookie" "$test_url")

    h1=$(echo "$r1" | hash_body)
    h2=$(echo "$r2" | hash_body)

    if [[ "$h1" != "$h2" ]]; then
      echo "[IDOR] $url -> $test_url"
    fi
  fi
}

# =========================
# TEST
# =========================
test_url() {

  url=$1
  OUT=$2

  echo "[CHECK] $url"

  # no auth
  BODY=$(mktemp)
  code=$(curl -s -o "$BODY" -w "%{http_code}" "$url")

  if [[ "$code" == "200" ]] && ! grep -qi 'login' "$BODY"; then
    echo "[CRITICAL] $url" >> "$OUT"
  fi

  ADM_BODY=$(mktemp)
  ADM_CODE=$(curl -s -H "Cookie: $BASELINE_COOKIE" "$url" -o "$ADM_BODY" -w "%{http_code}")
  ADM_HASH=$(cat "$ADM_BODY" | hash_body)

  for role in $(jq -r '.roles[].name' roles.json); do

    [[ "$role" == "$BASELINE_ROLE" ]] && continue

    cookie=$(get_cookie "$role")

    R_BODY=$(mktemp)
    R_CODE=$(curl -s -H "Cookie: $cookie" "$url" -o "$R_BODY" -w "%{http_code}")
    R_HASH=$(cat "$R_BODY" | hash_body)

    if [[ "$ADM_CODE" =~ 403|401 && "$R_CODE" == "200" ]]; then
      echo "[PRIV_ESC][$role] $url" >> "$OUT"
    fi

    if [[ "$ADM_CODE" == "200" && "$R_CODE" == "200" && "$ADM_HASH" != "$R_HASH" ]]; then
      echo "[DATA_DIFF][$role] $url" >> "$OUT"
    fi

    # 🔥 IDOR test
    idor_test "$url" "$cookie" >> "$OUT"

    rm -f "$R_BODY"
  done

  rm -f "$ADM_BODY" "$BODY"
}

# =========================
# SCAN
# =========================
scan_target() {

  URL=$1
  DOMAIN=$(echo "$URL" | sed 's|https\?://||' | cut -d/ -f1)
  BASE="https://$DOMAIN"

  DIR="$OUTPUT_DIR/$DOMAIN"
  mkdir -p "$DIR/js"

  echo "[TARGET] $DOMAIN"

  katana -u "$URL" -H "Cookie: $BASELINE_COOKIE" -jc -xhr -silent -j -o "$DIR/admin.jsonl"

  jq -r '.request.endpoint?' "$DIR/admin.jsonl" | grep "$DOMAIN" > "$DIR/admin.txt"

  grep '\.js' "$DIR/admin.txt" > "$DIR/js_seed.txt"

  discover_js_recursive "$BASE/app/immutable" "$DIR/js_seed.txt" "$DIR/js"

  extract_api "$DIR/js" "$DIR/api.txt"

  # 🔥 CLEAN FORMAT
  sed -i 's|.*:||' "$DIR/api.txt"

  
  # 🔥 BUILD FINAL
  > "$DIR/final.txt"

  while read -r ep; do
    [[ -z "$ep" ]] && continue

    if [[ "$ep" =~ ^/ ]]; then
      echo "$BASE$API_PREFIX$ep" >> "$DIR/final.txt"
    fi

  done < "$DIR/api.txt"

  # hapus duplicate
  sort -u "$DIR/final.txt" -o "$DIR/final.txt"

  # ✅ FILTER EXCLUDE (FIXED POSITION)
  DEFAULT_EXCLUDE="logout|signout|revoke|csrf|token"

  if [[ -n "$EXCLUDE_PATTERN" ]]; then
    USER_EXCLUDE=$(echo "$EXCLUDE_PATTERN" | sed 's/,/|/g')
    PATTERN="$DEFAULT_EXCLUDE|$USER_EXCLUDE"
  else
    PATTERN="$DEFAULT_EXCLUDE"
  fi

  grep -Ev "$PATTERN" "$DIR/final.txt" > "$DIR/tmp.txt"
  mv "$DIR/tmp.txt" "$DIR/final.txt"

  echo "[OK] testing: $(wc -l < "$DIR/final.txt")"

  # ✅ RESET FINDINGS
  > "$DIR/findings.txt"

  # ✅ TESTING
  while read -r url; do
    test_url "$url" "$DIR/findings.txt" &

    if (( $(jobs -r | wc -l) >= THREADS )); then
      wait -n
    fi

  done < "$DIR/final.txt"

  wait


  echo "[DONE]"
}

# =========================
# MAIN
# =========================

while read -r t; do
  scan_target "$t"
done < "$INPUT_FILE"
