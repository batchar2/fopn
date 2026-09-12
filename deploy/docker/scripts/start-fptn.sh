#!/bin/bash

export OUT_NETWORK_INTERFACE=$(ip -o -4 route show to default | awk '{print $5}')
echo "[FPTN] Using network interface: $OUT_NETWORK_INTERFACE"

exec /usr/local/bin/fptn-server \
    --server-key=/etc/fptn/server.key \
    --server-crt=/etc/fptn/server.crt \
    --out-network-interface="${OUT_NETWORK_INTERFACE}" \
    --server-port=4430 \
    --enable-detect-probing="${ENABLE_DETECT_PROBING}" \
    --allowed-sni-list="${ALLOWED_SNI_LIST}" \
    --tun-interface-name=fptn0 \
    --enable-domain-blacklist-filter="$ENABLE_DOMAIN_BLACKLIST_FILTER" \
    --domain-blacklist-urls="$DOMAIN_BLACKLIST_URLS" \
    --enable-ads-filter="$ENABLE_ADS_FILTER" \
    --ads-blocklist-urls="$ADS_BLOCKLIST_URLS" \
    --data-dir="$DATA_DIR" \
    --enable-torrent-filter="$ENABLE_TORRENT_FILTER" \
    --enable-spam-filter="$ENABLE_SPAM_FILTER" \
    --prometheus-access-key="$PROMETHEUS_SECRET_ACCESS_KEY" \
    --use-remote-server-auth="$USE_REMOTE_SERVER_AUTH" \
    --remote-server-auth-host="$REMOTE_SERVER_AUTH_HOST" \
    --remote-server-auth-port="$REMOTE_SERVER_AUTH_PORT" \
    --max-active-sessions-per-user="$MAX_ACTIVE_SESSIONS_PER_USER" \
    --server-external-ips="${SERVER_EXTERNAL_IPS}" \
    --mtu-size="${MTU_SIZE}"
