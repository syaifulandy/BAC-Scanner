===============================================
🔥 UNIVERSAL BAC SCANNER (SPA + API + IDOR)
===============================================

DESCRIPTION
-----------
Universal BAC Scanner adalah tool berbasis Bash untuk:
- Discover API endpoint dari modern SPA (React, Vue, Svelte)
- Rekonstruksi endpoint backend dari file JavaScript
- Deteksi Broken Access Control (BAC)
- Deteksi potensi IDOR (Insecure Direct Object Reference)

Tool ini dirancang untuk bekerja pada aplikasi modern yang:
- Tidak expose API via crawler tradisional
- Menggunakan dynamic JS bundle (Vite/Webpack)


-----------------------------------------------
MAIN FEATURES
-----------------------------------------------
- ✅ Recursive JavaScript discovery
- ✅ Template string API extraction (${VAR}/endpoint)
- ✅ Backend API reconstruction
- ✅ Optional prefix support (e.g: /app.php)
- ✅ Multi-role access control testing
- ✅ IDOR detection (numeric-based)
- ✅ Exclude dangerous endpoint (logout, revoke, dll)
- ✅ Parallel request execution


-----------------------------------------------
HOW IT WORKS (FLOW)
-----------------------------------------------
1. Crawl target menggunakan Katana
2. Extract semua JS file dari crawling result
3. Recursive discover JS dependencies (chunks/nodes)
4. Parse JS untuk menemukan endpoint API:
   - Template string: ${base}/endpoint
   - Hardcoded path: /api, /user, dll
5. Normalize endpoint → inject prefix (optional)
6. Filter endpoint berbahaya (logout, revoke, dll)
7. Test access control:
   - No Auth (unauthorized access)
   - Privilege Escalation (role bypass)
   - Data Exposure (response berbeda)
8. Jalankan IDOR test:
   - Identify numeric ID
   - Modify parameter (e.g: /1 → /2)
   - Compare response


-----------------------------------------------
DETECTED VULNERABILITIES
-----------------------------------------------

[CRITICAL]
 - Endpoint bisa diakses tanpa authentication

[PRIV_ESC]
 - Role lebih rendah bisa akses endpoint privileged

[DATA_DIFF]
 - Response berbeda antar role (potensi data leak)

[IDOR]
 - Resource dapat diakses dengan memodifikasi ID


-----------------------------------------------
DEPENDENCIES
-----------------------------------------------
Pastikan tool berikut terinstall:

- bash
- curl
- jq
- katana (https://github.com/projectdiscovery/katana)

Install jq:
  apt install jq

Install katana:
  go install github.com/projectdiscovery/katana/cmd/katana@latest


-----------------------------------------------
USAGE
-----------------------------------------------

Basic:
  ./bac_scanner.sh -i targets.txt

With API prefix:
  ./bac_scanner.sh -i targets.txt -p /app.php

Exclude endpoint:
  ./bac_scanner.sh -i targets.txt -x logout,signout,revoke

Custom roles:
  ./bac_scanner.sh -i targets.txt -r myroles.json

Increase threads:
  ./bac_scanner.sh -i targets.txt -t 10


-----------------------------------------------
ROLES CONFIGURATION
-----------------------------------------------

Generate template:
  ./bac_scanner.sh --gen-roles

Example roles.json:

{
  "baseline_role": "admin",
  "roles": [
    {
      "name": "admin",
      "cookie": "SESSION=admin_cookie",
      "enabled": true
    },
    {
      "name": "user",
      "cookie": "SESSION=user_cookie",
      "enabled": true
    }
  ]
}


-----------------------------------------------
OUTPUT STRUCTURE
-----------------------------------------------

bac_output/
  target-domain/
    ├── admin.jsonl      (katana crawl result)
    ├── admin.txt        (all discovered URLs)
    ├── js_seed.txt      (initial JS list)
    ├── js/              (downloaded JS files)
    ├── api.txt          (extracted endpoints)
    ├── final.txt        (normalized endpoints)
    ├── findings.txt     (vulnerability findings)


-----------------------------------------------
NOTES
-----------------------------------------------

- Prefix digunakan jika backend API tidak root (e.g: /app.php)
- Exclude endpoint penting untuk menghindari logout/session drop
- Tool ini lebih efektif untuk SPA modern dibanding crawler biasa
- IDOR detection saat ini berbasis numeric ID


-----------------------------------------------
LIMITATIONS
-----------------------------------------------

- Tidak parse deeply obfuscated JavaScript
- IDOR hanya basic (numeric-based)
- False positive bisa terjadi (perlu validasi manual)
- Hanya support Cookie Based Authentication
- Tidak support Decoupled Architecture / Microservices (Front end dan backend berbeda domain)

-----------------------------------------------
DISCLAIMER
-----------------------------------------------

Tool ini hanya untuk:
- Security testing
- Authorized penetration testing
- Internal assessment

Dilarang digunakan tanpa izin target.


===============================================
🔥 Built for modern web app testing
===============================================
