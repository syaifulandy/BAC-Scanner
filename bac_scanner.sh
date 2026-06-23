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
# HASH & PREVIEW
# =========================
hash_body() { md5sum | cut -d' ' -f1; }

RESP_PREVIEW=200

preview_body() {
  head -c "$RESP_PREVIEW" \
  | tr '\r\n' '  ' \
  | sed 's/|/ /g' \
  | sed 's/"/'\''/g' \
  | sed 's/  */ /g'
}

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

      curl -s --max-time 10 "$js" -o "$f"

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
  role=$3
  DIR=$4
  OUT=$5

  path=$(echo "$url" | cut -d/ -f4-)

  if [[ "$path" =~ /([0-9]+) ]]; then
    id=${BASH_REMATCH[1]}
    next=$((id + 1))

    new_path=$(echo "$path" | sed "0,/$id/{s/$id/$next/}")
    base=$(echo "$url" | cut -d/ -f1-3)
    test_url="$base/$new_path"

    # ambil response target
    TMP=$(mktemp)
    CODE2=$(curl -s --max-time 10 -H "Cookie: $cookie" "$test_url" -o "$TMP" -w "%{http_code}")
    r2=$(cat "$TMP")
    rm -f "$TMP"

    # ambil original
    r1=$(curl -s --max-time 10 -H "Cookie: $cookie" "$url")

    h1=$(echo "$r1" | hash_body)
    h2=$(echo "$r2" | hash_body)


    LEN1=$(echo -n "$r1" | wc -c)
    LEN2=$(echo -n "$r2" | wc -c)

    DIFF=$(( LEN1 - LEN2 ))
    DIFF=${DIFF#-}

    if [[ "$CODE2" == "200" && ( "$DIFF" -gt 20 || "$h1" != "$h2" ) ]]; then
      fname=$(gen_resp_file "$test_url-$cookie")
      resp_path="responses/$fname.txt"
      echo "$r2" > "$DIR/$resp_path"

      preview=$(echo "$r2" | preview_body)
      echo "IDOR|$role|$url->$test_url|$CODE2|$LEN2|$preview|$resp_path" >> "$OUT"

    fi
  fi
}

# =========================
# TEST
# =========================
test_url() {
  url=$1
  OUT=$2
  DIR=$3

  echo "[CHECK] $url"

  # no auth
  BODY=$(mktemp)
  code=$(curl -s --max-time 10 -o "$BODY" -w "%{http_code}" "$url")

  if [[ "$code" == "200" ]] && ! grep -qi 'login' "$BODY"; then
    body_preview=$(cat "$BODY" | preview_body)
    len=$(wc -c <"$BODY")

    fname=$(gen_resp_file "$url")
    resp_path="responses/$fname.txt"
    cp "$BODY" "$DIR/$resp_path"
    echo "CRITICAL|unauth|$url|$code|$len|$body_preview|$resp_path" >> "$OUT"

  fi

  ADM_BODY=$(mktemp)
  ADM_CODE=$(curl -s --max-time 10 -H "Cookie: $BASELINE_COOKIE" "$url" -o "$ADM_BODY" -w "%{http_code}")
  ADM_HASH=$(cat "$ADM_BODY" | hash_body)

  for role in $(jq -r '.roles[].name' "$ROLE_FILE"); do

    [[ "$role" == "$BASELINE_ROLE" ]] && continue

    cookie=$(get_cookie "$role")

    R_BODY=$(mktemp)
    R_CODE=$(curl -s --max-time 10 -H "Cookie: $cookie" "$url" -o "$R_BODY" -w "%{http_code}")
    R_HASH=$(cat "$R_BODY" | hash_body)
    if [[ ( "$ADM_CODE" == "403" || "$ADM_CODE" == "401" ) && "$R_CODE" == "200" ]]; then
      echo "PRIV_ESC|$role|$url|$R_CODE|0|-|-" >> "$OUT"
    fi

    sleep 0.3

    # refresh admin
    ADM_BODY2=$(mktemp)
    ADM_CODE2=$(curl -s --max-time 10 -H "Cookie: $BASELINE_COOKIE" "$url" -o "$ADM_BODY2" -w "%{http_code}")
    ADM_HASH2=$(cat "$ADM_BODY2" | hash_body)

    if [[ "$ADM_CODE2" == "200" && "$R_CODE" == "200" ]]; then
      if [[ "$ADM_HASH2" != "$R_HASH" ]] || ! diff -q "$ADM_BODY2" "$R_BODY" >/dev/null; then

        R_PREVIEW=$(cat "$R_BODY" | preview_body)
        R_LEN=$(wc -c <"$R_BODY")

        fname=$(gen_resp_file "$url-$role")
        resp_path="responses/$fname.txt"
        cp "$R_BODY" "$DIR/$resp_path"
        echo "DATA_DIFF|$role|$url|$R_CODE|$R_LEN|$R_PREVIEW|$resp_path" >> "$OUT"
      fi
    fi

    rm -f "$ADM_BODY2"


    # 🔥 IDOR test
    idor_test "$url" "$cookie" "$role" "$DIR" "$OUT"

    rm -f "$R_BODY"
  done

  rm -f "$ADM_BODY" "$BODY"
}


gen_resp_file() {
  echo "$1" | md5sum | cut -d' ' -f1
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
  mkdir -p "$DIR/responses"

  echo "[TARGET] $DOMAIN"

  katana -u "$URL" -H "Cookie: $BASELINE_COOKIE" -jc -xhr -silent -j -o "$DIR/admin.jsonl"

  if [[ ! -s "$DIR/admin.jsonl" ]]; then
    echo "[WARN] katana empty for $DOMAIN"
    return
  fi

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
      echo "$BASE$API_PREFIX$ep" | sed 's|//|/|g' | sed 's|https:/|https://|' >> "$DIR/final.txt"
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

  echo "TYPE|ROLE|URL|STATUS|LENGTH|PREVIEW|RESP_FILE" > "$DIR/findings.txt"

  # ✅ TESTING
  while read -r url; do
    test_url "$url" "$DIR/findings.txt" "$DIR" &
    sleep "$DELAY"
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
