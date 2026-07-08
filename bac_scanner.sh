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
    {
      "name":"admin",
      "cookie":"SESSION=admin"
    },
    {
      "name":"user",
      "bearer":"eyJ..."
    }
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

get_auth_header() {

    jq -r --arg r "$1" '
        .roles[]
        | select(.name==$r)
        | if .cookie then
            "Cookie: \(.cookie)"
          elif .bearer then
            "Authorization: Bearer \(.bearer)"
          else
            ""
          end
    ' "$ROLE_FILE"

}

BASELINE_HEADER=$(get_auth_header "$BASELINE_ROLE")

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
  header=$2
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
    CODE2=$(curl -s --max-time 10 -H "$header" "$test_url" -o "$TMP" -w "%{http_code}")
    r2=$(cat "$TMP")
    rm -f "$TMP"

    # ambil original
    r1=$(curl -s --max-time 10 -H "$header" "$url")

    h1=$(echo "$r1" | hash_body)
    h2=$(echo "$r2" | hash_body)


    LEN1=$(echo -n "$r1" | wc -c)
    LEN2=$(echo -n "$r2" | wc -c)

    DIFF=$(( LEN1 - LEN2 ))
    DIFF=${DIFF#-}

    if [[ "$CODE2" == "200" && ( "$DIFF" -gt 20 || "$h1" != "$h2" ) ]]; then
      fname=$(gen_resp_file "$test_url-$role")
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

  # ADMIN
  ADM_BODY=$(mktemp)
  ADM_CODE=$(curl -s --max-time 10 -H "$BASELINE_HEADER" "$url" -o "$ADM_BODY" -w "%{http_code}")
  ADM_HASH=$(cat "$ADM_BODY" | hash_body)

  # NO AUTH
  BODY=$(mktemp)
  N_CODE=$(curl -s --max-time 10 -o "$BODY" -w "%{http_code}" "$url")

  ROLES=$(jq -r '.roles[].name' "$ROLE_FILE")
  # LOOP ROLES
  for role in $ROLES; do
    header=$(get_auth_header "$role")

    R_BODY=$(mktemp)
    R_CODE=$(curl -s --max-time 10 -H "$header" "$url" -o "$R_BODY" -w "%{http_code}")
    R_HASH=$(cat "$R_BODY" | hash_body)

    # skip baseline
    if [[ "$role" == "$BASELINE_ROLE" ]]; then
      rm -f "$R_BODY"
      continue
    fi


    # 🔥 SHARED ACCESS (hanya kalau response SAMA)
    if [[ "$ADM_CODE" == "200" && "$R_CODE" == "200" ]]; then

      if [[ "$ADM_HASH" == "$R_HASH" ]] && diff -q "$ADM_BODY" "$R_BODY" >/dev/null; then
        
        LEN=$(wc -c < "$R_BODY")
        PREVIEW=$(cat "$R_BODY" | preview_body)
        fname=$(gen_resp_file "$url-$role")
        cp "$R_BODY" "$DIR/responses/$fname.txt"

        echo "POTENTIAL_BAC|$role|$url|$R_CODE|$LEN|$PREVIEW|responses/$fname.txt" >> "$OUT"
      fi

    fi

    # 🔥 PRIV ESC
    if [[ ( "$ADM_CODE" == "403" || "$ADM_CODE" == "401" ) && "$R_CODE" == "200" ]]; then
      
      LEN=$(wc -c < "$R_BODY")
      PREVIEW=$(cat "$R_BODY" | preview_body)
      fname=$(gen_resp_file "$url-$role")

      cp "$R_BODY" "$DIR/responses/$fname.txt"

      echo "PRIV_ESC|$role|$url|$R_CODE|$LEN|$PREVIEW|responses/$fname.txt" >> "$OUT"
    fi

    # 🔥 DATA DIFF
    if [[ "$ADM_CODE" == "200" && "$R_CODE" == "200" ]]; then
      if [[ "$ADM_HASH" != "$R_HASH" ]] || ! diff -q "$ADM_BODY" "$R_BODY" >/dev/null; then

        PREVIEW=$(cat "$R_BODY" | preview_body)
        LEN=$(wc -c < "$R_BODY")

        fname=$(gen_resp_file "$url-$role")
        cp "$R_BODY" "$DIR/responses/$fname.txt"

        echo "DATA_DIFF|$role|$url|$R_CODE|$LEN|$PREVIEW|responses/$fname.txt" >> "$OUT"
      fi
    fi

    # 🔥 IDOR
    idor_test "$url" "$header" "$role" "$DIR" "$OUT"

    rm -f "$R_BODY"
  done

  # 🔥 UNAUTH SAVE

  if [[ "$N_CODE" == "200" ]] && ! grep -qi 'login' "$BODY"; then
    PREVIEW=$(cat "$BODY" | preview_body)
    LEN=$(wc -c < "$BODY")

    fname=$(gen_resp_file "$url-noauth")
    cp "$BODY" "$DIR/responses/$fname.txt"

    echo "CRITICAL|unauth|$url|$N_CODE|$LEN|$PREVIEW|responses/$fname.txt" >> "$OUT"
  fi

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
  mkdir -p "$DIR/raw"
  mkdir -p "$DIR/processed"
  mkdir -p "$DIR/analysis"
  mkdir -p "$DIR/findings"
  mkdir -p "$DIR/responses"
  mkdir -p "$DIR/js"

  echo "[TARGET] $DOMAIN"

  # ADMIN
  katana -u "$URL" -H "$BASELINE_HEADER" -jc -jsl -aff -xhr -hl -pls domcontentloaded -system-chrome -system-chrome-path /usr/bin/chromium -no-sandbox -silent -j -o "$DIR/raw/admin.jsonl" > /dev/null 2>&1

  # USER
  USER_ROLE=$(
    jq -r \
      --arg base "$BASELINE_ROLE" \
      '.roles[] | select(.name != $base) | .name' \
      "$ROLE_FILE" | head -1
    )
  USER_HEADER=$(get_auth_header "$USER_ROLE")
  katana -u "$URL" -H "$USER_HEADER" -jc -jsl -aff -xhr -hl -pls domcontentloaded -system-chrome -system-chrome-path /usr/bin/chromium -no-sandbox -silent -j -o "$DIR/raw/user.jsonl" > /dev/null 2>&1

  # NO AUTH
  katana -u "$URL" -jc -jsl -aff -xhr -hl -pls domcontentloaded -system-chrome -system-chrome-path /usr/bin/chromium -no-sandbox -silent -j -o "$DIR/raw/noauth.jsonl" > /dev/null 2>&1


  if [[ ! -s "$DIR/raw/admin.jsonl" ]]; then
    echo "[WARN] katana empty for $DOMAIN"
    return
  fi

  jq -r '.request.endpoint?' "$DIR/raw/admin.jsonl" | grep "$DOMAIN" > "$DIR/raw/admin.txt"
  jq -r '.request.endpoint?' "$DIR/raw/user.jsonl"  | grep "$DOMAIN" > "$DIR/raw/user.txt"
  jq -r '.request.endpoint?' "$DIR/raw/noauth.jsonl" | grep "$DOMAIN" > "$DIR/raw/noauth.txt"

  # normalize dulu
  sort -u "$DIR/raw/admin.txt" -o "$DIR/raw/admin.txt"
  sort -u "$DIR/raw/user.txt" -o "$DIR/raw/user.txt"
  sort -u "$DIR/raw/noauth.txt" -o "$DIR/raw/noauth.txt"


  # =========================
  # ACCESS SURFACE ANALYSIS
  # =========================


  # admin only
  comm -23 "$DIR/raw/admin.txt" "$DIR/raw/user.txt" > "$DIR/analysis/admin_only.txt"

  # shared admin-user
  comm -12 "$DIR/raw/admin.txt" "$DIR/raw/user.txt" > "$DIR/analysis/shared_user.txt"

  # public exposure
  comm -12 "$DIR/raw/admin.txt" "$DIR/raw/noauth.txt" > "$DIR/analysis/public.txt"

  # user only
  comm -23 "$DIR/raw/user.txt" "$DIR/raw/admin.txt" > "$DIR/analysis/user_only.txt"


  cat "$DIR/raw/admin.txt" "$DIR/raw/user.txt" "$DIR/raw/noauth.txt" > "$DIR/raw/all.txt"
  sort -u "$DIR/raw/all.txt" -o "$DIR/raw/all.txt"


  cat "$DIR/raw/admin.txt" "$DIR/raw/user.txt" "$DIR/raw/noauth.txt" \
  | grep '\.js' > "$DIR/processed/js_seed.txt"


  discover_js_recursive "$BASE/app/immutable" "$DIR/processed/js_seed.txt" "$DIR/js"

  extract_api "$DIR/js" "$DIR/processed/api.txt"

  # 🔥 CLEAN FORMAT
  sed -i 's|.*:||' "$DIR/processed/api.txt"

  
  # 🔥 BUILD FINAL
  > "$DIR/processed/final.txt"

  # API
  while read -r ep; do
    [[ -z "$ep" ]] && continue

    if [[ "$ep" =~ ^/ ]]; then
      echo "$BASE$API_PREFIX$ep" | sed 's|//|/|g' | sed 's|https:/|https://|' >> "$DIR/processed/final.txt"
    fi
  done < "$DIR/processed/api.txt"

  # TAMBAH KATANA ENDPOINT
  cat "$DIR/raw/all.txt" >> "$DIR/processed/final.txt"

  # dedupe
  sort -u "$DIR/processed/final.txt" -o "$DIR/processed/final.txt"

  
  # 🔥 FILTER STATIC FILE
  grep -Ev '\.(js|css|png|jpg|jpeg|svg|woff|woff2|ttf|map|ico|gif)$' "$DIR/processed/final.txt" > "$DIR/processed/final_clean.txt"
  mv "$DIR/processed/final_clean.txt" "$DIR/processed/final.txt"



  # ✅ FILTER EXCLUDE (FIXED POSITION)
  DEFAULT_EXCLUDE="logout|signout|revoke|csrf|token"

  if [[ -n "$EXCLUDE_PATTERN" ]]; then
    USER_EXCLUDE=$(echo "$EXCLUDE_PATTERN" | sed 's/,/|/g')
    PATTERN="$DEFAULT_EXCLUDE|$USER_EXCLUDE"
  else
    PATTERN="$DEFAULT_EXCLUDE"
  fi

  grep -Ev "$PATTERN" "$DIR/processed/final.txt" > "$DIR/processed/tmp.txt"
  mv "$DIR/processed/tmp.txt" "$DIR/processed/final.txt"

  echo "[OK] testing: $(wc -l < "$DIR/processed/final.txt")"
  echo "TYPE|ROLE|URL|STATUS|LENGTH|PREVIEW|RESP_FILE" > "$DIR/findings/raw_finding.txt"

  # ✅ TESTING
  while read -r url; do
    test_url "$url" "$DIR/findings/raw_finding.txt" "$DIR" &

    sleep "$DELAY"
    if (( $(jobs -r | wc -l) >= THREADS )); then
      wait -n
    fi

  done < "$DIR/processed/final.txt"

  wait

  
  # simpan header, sort isi tanpa header, gabung lagi
  head -n 1 "$DIR/findings/raw_finding.txt" > "$DIR/processed/tmp_header.txt"

  tail -n +2 "$DIR/findings/raw_finding.txt" | sort -u > "$DIR/processed/tmp_body.txt"

  cat "$DIR/processed/tmp_header.txt" "$DIR/processed/tmp_body.txt" > "$DIR/findings/raw_finding.txt"


  echo "[STEP] signal analysis"

  RAW="$DIR/findings/raw_finding.txt"
  HIGH="$DIR/findings/high_signal.txt"
  LOW="$DIR/findings/low_signal.txt"

  # extract preview frequency
  cut -d'|' -f6 "$RAW" \
  | tail -n +2 \
  | sort \
  | uniq -c \
  | sort -nr > "$DIR/processed/preview_freq.txt"

  # ambil yang sering muncul (threshold = >5)
  awk '$1 > 5 { $1=""; sub(/^ /,""); print }' "$DIR/processed/preview_freq.txt" \
  > "$DIR/processed/preview_noise.txt"

  # buat header
  head -n 1 "$RAW" > "$HIGH"
  head -n 1 "$RAW" > "$LOW"


  # skip header saat isi
  tail -n +2 "$RAW" | grep -vFf "$DIR/processed/preview_noise.txt" >> "$HIGH"
  tail -n +2 "$RAW" | grep -Ff "$DIR/processed/preview_noise.txt" >> "$LOW"


  echo "[OK] high signal: $(($(wc -l < "$HIGH") - 1))"
  echo "[OK] low signal: $(($(wc -l < "$LOW") - 1))"

  echo "[STEP] grouping high signal"

  GROUPED="$DIR/findings/high_signal_grouped.txt"

  # header baru
  echo "TYPE|ROLES|URLS|STATUS|COUNT|PREVIEW" > "$GROUPED"

  tail -n +2 "$HIGH" | awk -F'|' '
  {
    key = $6    # preview
    type[key] = $1
    status[key] = $4

    if (!(key in roles)) {
      roles[key] = $2
      urls[key] = $3
      count[key] = 1
    } else {
      roles[key] = roles[key] "," $2
      urls[key] = urls[key] "," $3
      count[key]++
    }
  }
  END {
    for (k in roles) {
      print type[k] "|" roles[k] "|" urls[k] "|" status[k] "|" count[k] "|" k
    }
  }
  ' >> "$GROUPED"

  echo "[OK] grouped entries: $(($(wc -l < "$GROUPED") - 1))"


  echo "[DONE]"
}

# =========================
# MAIN
# =========================

while read -r t; do
  scan_target "$t"
done < "$INPUT_FILE"
