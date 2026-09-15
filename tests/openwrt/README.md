# Checking the client on a router

Two scripts that run straight on OpenWrt. They cover what unit tests cannot:
argument parsing of the built binary and a live tunnel.

```sh
scp fptn-client-cli root@router:/tmp/fc     # or cat | ssh with dropbear
cat cases-parse.sh | ssh root@router 'cat > /tmp/cases-parse.sh'
ssh root@router 'sh /tmp/cases-parse.sh "<token>"'
ssh root@router 'sh /tmp/cases-live.sh  "<token>"'
```

`cases-parse.sh` — argument parsing, no connection needed: a config written
with underscores and with dashes, a boolean switch in three spellings, `null`,
numbers, an array of tokens, the command line overriding the file (including
through an underscored key), the long and short form of `--config`, running
with no file at all, plus how clear the errors are on broken JSON, on an array
instead of an object, and on a missing file.

`cases-live.sh` — a real tunnel: bringing it up, TCP through SOCKS, resolving a
name inside the tunnel (`--socks5-hostname`), pinning a server by name, an
empty pool after `exclude_servers`, an unreachable `max_ping`, an unknown
`bypass_method`. Router routes are left alone: the client runs with
`disable_routing` and its own port.

Use a token of your own for the run: the server allows one active session per
user, so the account of a production router cannot be used — the test would
take its connectivity away.

Русская версия — [README.ru.md](README.ru.md).
