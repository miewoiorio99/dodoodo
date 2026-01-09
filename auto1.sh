#!/usr/bin/env bash

set -euo pipefail

LIST_URL="https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_BASE64.txt"
RAW_FILE="/tmp/v2ray_raw.txt"
DECODED_FILE="/tmp/v2ray_decoded.txt"
CONFIG="/root/v2ray/config.json"
LOG_FILE="/tmp/v2ray.log"
PROXY_LIST="/tmp/proxies.txt"

mkdir -p /root/v2ray

echo "[+] Downloading Base64 list..."
curl -fsSL "$LIST_URL" -o "$RAW_FILE"

echo "[+] Decoding entire file from Base64..."
if ! base64 -d "$RAW_FILE" > "$DECODED_FILE" 2>/dev/null; then
  echo "[-] ERROR: The file is not valid Base64 or decoding failed."
  exit 1
fi

echo "[+] Extracting protocol lines..."
if ! grep -E "^(vmess|vless|ss|trojan)://" "$DECODED_FILE" > "$PROXY_LIST"; then
  echo "[-] No protocol-prefixed lines found after decoding."
  exit 1
fi

echo "[+] Found $(wc -l < "$PROXY_LIST") proxies"

test_proxy() {
  curl --socks5 127.0.0.1:9079 -m 6 -sS https://www.google.com >/dev/null 2>&1
}

restart_v2ray() {
  echo "[+] Restarting V2Ray..."
  systemctl restart v2ray || continue
  sleep 2
}

url_decode() {
  # very simple URL decoder for common cases (%XX)
  local input="${1//+/ }"
  printf '%b' "${input//%/\\x}"
}

i=0
while read -r line; do
  i=$((i+1))
  echo ""
  echo "=============================="
  echo "[+] Trying proxy #$i"
  echo "$line"
  echo "=============================="

  proto="${line%%://*}"

  # -----------------------------
  # SHADOWSOCKS HANDLING (ss://)
  # -----------------------------
  if [[ "$proto" == "ss" ]]; then
    echo "[+] Parsing Shadowsocks link..."

    ss_payload="${line#ss://}"

    base64_part="${ss_payload%@*}"
    server_part="${ss_payload#*@}"
    server_part="${server_part%%#*}"

    decoded="$(echo "$base64_part" | base64 -d 2>/dev/null || true)"
    method="${decoded%%:*}"
    password="${decoded#*:}"

    addr="${server_part%%:*}"
    port="${server_part##*:}"

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
    { "port": 9079, "listen": "127.0.0.1", "protocol": "socks", "settings": { "udp": true } }
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

    restart_v2ray

    if test_proxy; then
      echo "[+] SUCCESS! Proxy #$i works."
      exit 0
    else
      echo "[-] Proxy #$i failed, trying next..."
      continue
    fi
  fi

  # -----------------------------
  # VMESS / VLESS / TROJAN
  # -----------------------------

  case "$proto" in
    vmess)
      echo "[+] Parsing vmess link..."

      encoded="${line#vmess://}"
      json="$(echo "$encoded" | base64 -d 2>/dev/null || true)"

      if [[ -z "$json" ]]; then
        echo "[-] Invalid vmess Base64 payload, skipping..."
        continue
      fi

      # validate JSON once
      if ! echo "$json" | jq -e . >/dev/null 2>&1; then
        echo "[-] Invalid JSON in vmess payload, skipping..."
        continue
      fi

      echo "[+] Decoded JSON:"
      echo "$json"

      addr="$(echo "$json" | jq -r '.add // .address // empty')"
      port="$(echo "$json" | jq -r '.port // empty')"
      id="$(echo "$json"  | jq -r '.id // .uuid // empty')"
      net="$(echo "$json" | jq -r '.net // "tcp"')"
      path="$(echo "$json" | jq -r '.path // "/"')"
      tls="$(echo "$json"  | jq -r '.tls // empty')"

      if [[ -z "$addr" || -z "$port" || -z "$id" ]]; then
        echo "[-] Missing required vmess fields, skipping..."
        continue
      fi

      security="none"
      if [[ "$tls" == "tls" ]]; then
        security="tls"
      fi

      cat > "$CONFIG" <<EOF
{
  "inbounds": [
    { "port": 9079, "listen": "127.0.0.1", "protocol": "socks", "settings": { "udp": true } }
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
        "security": "$security",
        "wsSettings": {
          "path": "$path"
        }
      }
    }
  ]
}
EOF
      ;;

    vless)
      echo "[+] Parsing vless link..."

      # Strip scheme
      vless_body="${line#vless://}"

      # Remove fragment (#tag)
      main_part="${vless_body%%#*}"

      # Split user@host:port and query
      user_host="${main_part%%\?*}"
      query=""
      if [[ "$main_part" == *"?"* ]]; then
        query="${main_part#*\?}"
      fi

      user="${user_host%@*}"
      hostport="${user_host#*@}"

      addr="${hostport%%:*}"
      port="${hostport##*:}"

      id="$user"

      net="tcp"
      security="none"
      path="/"

      if [[ -n "$query" ]]; then
        IFS='&' read -ra kvs <<< "$query"
        for kv in "${kvs[@]}"; do
          key="${kv%%=*}"
          val="${kv#*=}"
          val_decoded="$(url_decode "$val")"
          case "$key" in
            type) net="$val_decoded" ;;
            security) security="$val_decoded" ;;
            path) path="$val_decoded" ;;
          esac
        done
      fi

      if [[ -z "$addr" || -z "$port" || -z "$id" ]]; then
        echo "[-] Missing required vless fields, skipping..."
        continue
      fi

      # Normalize security
      if [[ "$security" != "tls" ]]; then
        security="none"
      fi

      # Build streamSettings conditionally
      if [[ "$net" == "ws" ]]; then
        stream_settings=$(cat <<JSON
{
  "network": "ws",
  "security": "$security",
  "wsSettings": {
    "path": "$path"
  }
}
JSON
)
      else
        stream_settings=$(cat <<JSON
{
  "network": "$net",
  "security": "$security"
}
JSON
)
      fi

      cat > "$CONFIG" <<EOF
{
  "inbounds": [
    { "port": 9079, "listen": "127.0.0.1", "protocol": "socks", "settings": { "udp": true } }
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
      "streamSettings": $stream_settings
    }
  ]
}
EOF
      ;;

    trojan)
      echo "[+] Parsing trojan link..."

      trojan_body="${line#trojan://}"
      main_part="${trojan_body%%#*}"

      user_host="${main_part%%\?*}"
      query=""
      if [[ "$main_part" == *"?"* ]]; then
        query="${main_part#*\?}"
      fi

      password="${user_host%@*}"
      hostport="${user_host#*@}"

      addr="${hostport%%:*}"
      port="${hostport##*:}"

      net="tcp"
      security="tls"
      path="/"

      if [[ -n "$query" ]]; then
        IFS='&' read -ra kvs <<< "$query"
        for kv in "${kvs[@]}"; do
          key="${kv%%=*}"
          val="${kv#*=}"
          val_decoded="$(url_decode "$val")"
          case "$key" in
            type) net="$val_decoded" ;;
            security) security="$val_decoded" ;;
            path) path="$val_decoded" ;;
          esac
        done
      fi

      if [[ -z "$addr" || -z "$port" || -z "$password" ]]; then
        echo "[-] Missing required trojan fields, skipping..."
        continue
      fi

      if [[ "$security" != "tls" ]]; then
        security="none"
      fi

      if [[ "$net" == "ws" ]]; then
        stream_settings=$(cat <<JSON
{
  "network": "ws",
  "security": "$security",
  "wsSettings": {
    "path": "$path"
  }
}
JSON
)
      else
        stream_settings=$(cat <<JSON
{
  "network": "$net",
  "security": "$security"
}
JSON
)
      fi

      cat > "$CONFIG" <<EOF
{
  "inbounds": [
    { "port": 9079, "listen": "127.0.0.1", "protocol": "socks", "settings": { "udp": true } }
  ],
  "outbounds": [
    {
      "protocol": "trojan",
      "settings": {
        "servers": [
          { "address": "$addr", "port": $port, "password": "$password" }
        ]
      },
      "streamSettings": $stream_settings
    }
  ]
}
EOF
      ;;

    *)
      echo "[-] Unknown protocol: $proto, skipping..."
      continue
      ;;
  esac

  restart_v2ray

  if test_proxy; then
    echo "[+] SUCCESS! Proxy #$i works."
    exit 0
  else
    echo "[-] Proxy #$i failed, trying next..."
  fi

done < "$PROXY_LIST"

echo "[-] No working proxies found."
exit 1
