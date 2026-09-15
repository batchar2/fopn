#!/bin/sh
# Живые проверки: клиент реально поднимает туннель и гоняет трафик через SOCKS.
# Маршруты роутера не трогаются (--disable-routing), порт свой.
BIN=/tmp/fc
TOK="$1"
DIR=/tmp/fcases
mkdir -p $DIR
pass=0; fail=0

start() {          # start <файл-конфига> <секунд ожидания>
  $BIN -c "$1" > /tmp/live.log 2>&1 &
  PID=$!
  i=0
  while [ $i -lt "$2" ]; do
    grep -q "SOCKS5 proxy listening" /tmp/live.log && return 0
    grep -qE "Config error|All servers unavailable|No servers left" /tmp/live.log && return 1
    sleep 2; i=$((i+2))
  done
  return 1
}
stop() { kill $PID 2>/dev/null; sleep 2; kill -9 $PID 2>/dev/null; }

check() {          # check <имя> <условие-успеха 0/1>
  if [ "$2" -eq 0 ]; then echo "ок      $1"; pass=$((pass+1));
  else echo "ПРОВАЛ  $1"; fail=$((fail+1)); fi
}

mk() {             # mk <файл> <доп-поля>
  cat > "$1" <<J
{"socks_listen":"127.0.0.9:20990","disable_routing":true,"tun_interface_name":"zbt0",
 "tun_interface_ip":"192.0.2.9","tun_interface_ipv6":"fd00:5a42:9::1",
 "bypass_method":"obfuscation","routing_mark":"0x40000000"$2,
 "access_token":["$TOK"]}
J
}

echo "=== 1. базовое подключение и трафик через SOCKS ==="
mk $DIR/live.json ""
if start $DIR/live.json 90; then
  check "туннель поднялся" 0
  code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 25 --socks5 127.0.0.9:20990 https://api.ipify.org)
  [ "$code" = "200" ] && check "TCP через SOCKS (curl 200)" 0 || { check "TCP через SOCKS (код $code)" 1; }
  ip=$(curl -s --max-time 25 --socks5 127.0.0.9:20990 https://api.ipify.org)
  echo "        внешний IP через туннель: $ip"
  code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 25 --socks5-hostname 127.0.0.9:20990 https://api.ipify.org)
  [ "$code" = "200" ] && check "резолв имени внутри туннеля" 0 || check "резолв имени внутри туннеля (код $code)" 1
  echo "        дескрипторов у клиента: $(ls /proc/$PID/fd 2>/dev/null | wc -l), RSS: $(awk '/VmRSS/{print $2}' /proc/$PID/status 2>/dev/null)kB"
else
  check "туннель поднялся" 1; tail -3 /tmp/live.log | sed 's/^/        /'
fi
stop

echo "=== 2. preferred_server по имени ==="
mk $DIR/pref.json ',"preferred_server":"Server-1"'
if start $DIR/pref.json 60; then
  grep -q "SELECTED SERVER" /tmp/live.log && echo "        $(grep -m1 'SELECTED SERVER' /tmp/live.log | sed 's/.*SELECTED SERVER: *//')"
  check "preferred_server принят" 0
else check "preferred_server принят" 1; tail -2 /tmp/live.log | sed 's/^/        /'; fi
stop

echo "=== 3. exclude_servers регуляркой выбрасывает всё ==="
mk $DIR/excl.json ',"exclude_servers":".*"'
$BIN -c $DIR/excl.json > /tmp/live.log 2>&1 &
PID=$!; sleep 12; stop
grep -q "No servers left" /tmp/live.log && check "пустой пул — внятная ошибка" 0 || { check "пустой пул" 1; tail -2 /tmp/live.log | sed 's/^/        /'; }

echo "=== 4. max_ping недостижимый ==="
mk $DIR/ping.json ',"max_ping":1'
$BIN -c $DIR/ping.json > /tmp/live.log 2>&1 &
PID=$!; sleep 60; stop
grep -qE "over the 1 ms limit|did not answer the latency check" /tmp/live.log && check "max_ping отрабатывает" 0 || { check "max_ping отрабатывает" 1; tail -2 /tmp/live.log | sed 's/^/        /'; }

echo "=== 5. неизвестный bypass_method ==="
mk $DIR/bad.json ',"bypass_method":"такого-нет"'
$BIN -c $DIR/bad.json > /tmp/live.log 2>&1 &
PID=$!; sleep 10; stop
grep -qiE "bypass|method|Unknown|error" /tmp/live.log && check "внятная реакция на плохой bypass_method" 0 || { check "плохой bypass_method" 1; tail -2 /tmp/live.log | sed 's/^/        /'; }

echo
echo "ИТОГО: успешно $pass, провалов $fail"
