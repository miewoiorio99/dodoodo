#!/usr/bin/env bash

set -e

LIST_URL="https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_BASE64.txt"
RAW_FILE="/tmp/v2ray_raw.txt"
DECODED_FILE="/tmp/v2ray_decoded.txt"
CONFIG="/usr/local/etc/v2ray/config.json"

echo "[+] Downloading Base64 list..."
curl -s "$LIST_URL" -o "$RAW_FILE"

echo "[+] Decoding entire file from Base64..."
base64 -d "$RAW_FILE" > "$DECODED_FILE" 2>/dev/null || {
  echo "[-] ERROR: The file is not valid Base64 or decoding failed."
  exit 1
}

echo "[+] Extracting protocol lines..."
grep -E "^(vmess|vless|ss|trojan)://" "$DECODED_FILE" > /tmp/proxies.txt || {
  echo "[-] No protocol-prefixed lines found after decoding."
  exit 1
}

echo "[+] Found $(wc -l < /tmp/proxies.txt) proxies"

test_proxy() {
  curl --socks5 127.0.0.1:1080 -m 6 https://www.google.com >/dev/null 2>&1
}

i=0
while read -r line; do
  i=$((i+1))
  echo ""
  echo "=============================="
  echo "[+] Trying proxy #$i"
  echo "$line"
  echo "=============================="

  proto=$(echo "$line" | cut -d: -f1)

  # -----------------------------
  # SHADOWSOCKS SPECIAL HANDLING
  # -----------------------------
  if [[ "$proto" == "ss" ]]; then
    echo "[+] Parsing Shadowsocks link..."

    ss_payload=$(echo "$line" | sed 's#ss://##')

    base64_part=$(echo "$ss_payload" | cut -d@ -f1)
    server_part=$(echo "$ss_payload" | cut -d@ -f2 | cut -d# -f1)

    decoded=$(echo "$base64_part" | base64 -d 2>/dev/null)
    method=$(echo "$decoded" | cut -d: -f1)
    password=$(echo "$decoded" | cut -d: -f2)

    addr=$(echo "$server_part" | cut -d: -f1)
    port=$(echo "$server_part" | cut -d: -f2)

    if [[ -z "$method" || -z "$password" || -z "$addr" || -z "$port" ]]; then
      echo "[-] Invalid Shadowsocks format, skipping..."
      continue
    fi

    echo "[+] SS method: $method"
    echo "[+] SS password: $password"
    echo "[+] SS address: $addr"
    echo "[+] SS port: $port"

    cat > "$CONFIG" <<EOF
{
  "inbounds": [
    { "port": 1080, "listen": "127.0.0.1", "protocol": "socks", "settings": { "udp": true } }
  ],
  "outbounds": [
    {
      "protocol": "shadowsocks",
      "settings": {
        "servers": [
          { "address": "$addr", "port": $port, "method": "$method", "password": "$password" }
        ]
      }
    }
  ]
}
EOF

    echo "[+] Restarting V2Ray..."
    systemctl restart v2ray || continue
    sleep 2

    if test_proxy; then
      echo "[+] SUCCESS! Proxy #$i works."
      exit 0
    else
      echo "[-] Proxy #$i failed, trying next..."
      continue
    fi
  fi

  # -----------------------------
  # VMESS / VLESS / TROJAN NORMAL HANDLING
  # -----------------------------

  encoded=$(echo "$line" | sed "s#${proto}://##")
  json=$(echo "$encoded" | base64 -d 2>/dev/null || true)

  if [[ -z "$json" ]]; then
    echo "[-] Failed to decode Base64 payload, skipping..."
    continue
  fi

  echo "[+] Decoded JSON:"
  echo "$json"

  addr=$(echo "$json" | jq -r '.add // .address // empty')
  port=$(echo "$json" | jq -r '.port // empty')
  id=$(echo "$json" | jq -r '.id // .uuid // empty')
  method=$(echo "$json" | jq -r '.method // empty')
  password=$(echo "$json" | jq -r '.password // empty')
  net=$(echo "$json" | jq -r '.net // "tcp"')
  path=$(echo "$json" | jq -r '.path // "/"')
  tls=$(echo "$json" | jq -r '.tls // empty')

  echo "[+] Building config for protocol: $proto"

  case "$proto" in
    vmess)
      cat > "$CONFIG" <<EOF
{
  "inbounds": [
    { "port": 1080, "listen": "127.0.0.1", "protocol": "socks", "settings": { "udp": true } }
  ],
  "outbounds": [
    {
      "protocol": "vmess",
      "settings": {
        "vnext": [
          {
            "address": "$addr",
            "port": $port,
            "users": [
              { "id": "$id", "alterId": 0, "security": "auto" }
            ]
          }
        ]
      },
      "streamSettings": {
        "network": "$net",
        "security": "$( [[ "$tls" == "tls" ]] && echo tls || echo none )",
        "wsSettings": { "path": "$path" }
      }
    }
  ]
}
EOF
      ;;
    vless)
      cat > "$CONFIG" <<EOF
{
  "inbounds": [
    { "port": 1080, "listen": "127.0.0.1", "protocol": "socks", "settings": { "udp": true } }
  ],
  "outbounds": [
    {
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "$addr",
            "port": $port,
            "users": [
              { "id": "$id", "encryption": "none" }
            ]
          }
        ]
      },
      "streamSettings": {
        "network": "$net",
        "security": "$( [[ "$tls" == "tls" ]] && echo tls || echo none )",
        "wsSettings": { "path": "$path" }
      }
    }
  ]
}
EOF
      ;;
    trojan)
      cat > "$CONFIG" <<EOF
{
  "inbounds": [
    { "port": 1080, "listen": "127.0.0.1", "protocol": "socks", "settings": { "udp": true } }
  ],
  "outbounds": [
    {
      "protocol": "trojan",
      "settings": {
        "servers": [
          { "address": "$addr", "port": $port, "password": "$password" }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "$( [[ "$tls" == "tls" ]] && echo tls || echo none )"
      }
    }
  ]
}
EOF
      ;;
  esac

  echo "[+] Restarting V2Ray..."
  systemctl restart v2ray || continue
  sleep 2

  if test_proxy; then
    echo "[+] SUCCESS! Proxy #$i works."
    exit 0
  else
    echo "[-] Proxy #$i failed, trying next..."
  fi

done < /tmp/proxies.txt

echo "[-] No working proxies found."
exit 1
