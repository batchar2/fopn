#!/bin/sh
# Разбор аргументов: до подключения. Успех = дошли до выбора сервера или
# внятной ошибки конфига, провал = падение разбора (usage/Unknown/Duplicate).
BIN=/tmp/fc
DIR=/tmp/fcases
mkdir -p $DIR
pass=0; fail=0

run() {
  name="$1"; shift
  out=$($BIN "$@" 2>&1 | head -40)
  if echo "$out" | grep -qE "Unknown argument|Duplicate argument|Zero positional|Usage: fptn-client"; then
    echo "ПРОВАЛ  $name"
    echo "$out" | grep -E "Unknown|Duplicate|Zero positional" | head -1 | sed 's/^/          /'
    fail=$((fail+1))
  else
    echo "ок      $name"
    pass=$((pass+1))
  fi
}

# --- конфиги ---
cat > $DIR/base.json <<J
{"socks_listen":"127.0.0.9:20991","tun_interface_name":"zbt0","disable_routing":true,
 "tun_interface_ip":"192.0.2.9","access_token":["TOKEN"]}
J
cat > $DIR/dashes.json <<J
{"socks-listen":"127.0.0.9:20992","tun-interface-name":"zbt0","disable-routing":"true",
 "tun-interface-ip":"192.0.2.9","access-token":["TOKEN"]}
J
cat > $DIR/boolfalse.json <<J
{"socks_listen":"127.0.0.9:20993","disable_routing":false,"access_token":["TOKEN"]}
J
cat > $DIR/nulls.json <<J
{"socks_listen":"127.0.0.9:20994","preferred_server":null,"max_ping":null,"access_token":["TOKEN"]}
J
cat > $DIR/numbers.json <<J
{"socks_listen":"127.0.0.9:20995","socks_route_table":1099,"mtu_size":1400,"max_ping":900,
 "disable_routing":true,"access_token":["TOKEN"]}
J
cat > $DIR/twotokens.json <<J
{"socks_listen":"127.0.0.9:20996","disable_routing":true,"access_token":["TOKEN","TOKEN"]}
J
cat > $DIR/allflags.json <<J
{"socks_listen":"127.0.0.9:20997","socks_route_table":1098,"disable_routing":true,
 "routing_mark":"0x40000000","tun_interface_name":"zbt0","tun_interface_ip":"192.0.2.9",
 "tun_interface_ipv6":"fd00:5a42:9::1","mtu_size":1400,"sni":"google.com",
 "bypass_method":"obfuscation","connection_strategy":"rolling-tunnel",
 "exclude_tunnel_networks":"10.0.0.0/8,192.168.0.0/16","include_tunnel_networks":"",
 "enable_split_tunnel":false,"split_tunnel_mode":"exclude","split_tunnel_domains":"ru,su",
 "blacklist_domains":"ria.ru","exclude_servers":"Russia|Vietnam",
 "max_ping":900,"preferred_server":"","out_network_interface":"",
 "access_token":["TOKEN"]}
J
cat > $DIR/badjson.json <<J
{ этонеджейсон
J
cat > $DIR/notobject.json <<J
["массив, а не объект"]
J

for f in $DIR/*.json; do sed -i "s|TOKEN|$1|g" "$f"; done

run "конфиг с подчёркиваниями"        -c $DIR/base.json
run "конфиг с дефисами"                -c $DIR/dashes.json
run "disable_routing=false"            -c $DIR/boolfalse.json
run "null-значения пропускаются"       -c $DIR/nulls.json
run "числовые значения"                -c $DIR/numbers.json
run "два токена массивом"              -c $DIR/twotokens.json
run "все флаги разом"                  -c $DIR/allflags.json
run "перекрытие: порт из cmdline"      --socks-listen 127.0.0.9:20981 -c $DIR/base.json
run "перекрытие через подчёркивание"   --socks_listen 127.0.0.9:20982 -c $DIR/base.json
run "перекрытие токена из cmdline"     --access-token "$1" -c $DIR/base.json
run "длинная форма --config"           --config $DIR/base.json
run "только флаги, без конфига"        --socks-listen 127.0.0.9:20983 --disable-routing --access-token "$1"

echo "--- ожидаемые ошибки (не падение разбора) ---"
for t in "битый JSON:$DIR/badjson.json" "не объект:$DIR/notobject.json" "нет файла:/tmp/fcases/нет.json"; do
  n=${t%%:*}; f=${t#*:}
  out=$($BIN -c "$f" 2>&1 | head -5)
  if echo "$out" | grep -qE "Cannot open config file|must contain a JSON object|parse error|Config file"; then
    echo "ок      $n — внятная ошибка"; pass=$((pass+1))
  else
    echo "ПРОВАЛ  $n"; echo "$out" | head -2 | sed 's/^/          /'; fail=$((fail+1))
  fi
done

out=$($BIN --help 2>&1 | head -3); echo "$out" | grep -q "Usage: fptn-client" && { echo "ок      --help"; pass=$((pass+1)); } || { echo "ПРОВАЛ  --help"; fail=$((fail+1)); }
out=$($BIN --version 2>&1 | tail -1); echo "$out" | grep -qE "^[0-9]+\.[0-9]+" && { echo "ок      --version ($out)"; pass=$((pass+1)); } || { echo "ПРОВАЛ  --version"; fail=$((fail+1)); }

echo
echo "ИТОГО: успешно $pass, провалов $fail"
