#!/usr/bin/env bash

print_usage() {
    echo "Usage: $0 <fptn-client-cli-path> <version> <arch> <strip-tool> <openwrt-version>"
    exit 1
}

if [ "$#" -ne 5 ]; then
    print_usage
fi

CLIENT_CLI="$1"
VERSION="$2"
ARCH="$3"
STRIP_TOOL="$4"
OPENWRT_VERSION="$5"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SHARED_DIR="$(dirname "$SCRIPT_DIR")"

APK_TOOL="${APK_TOOL:-apk}"

if ! command -v "$APK_TOOL" >/dev/null 2>&1; then
    echo "apk tool not found: $APK_TOOL"
    exit 1
fi

CLIENT_TMP_DIR=$(mktemp -d -t fptn-client-cli-XXXXXX)

mkdir -p "$CLIENT_TMP_DIR/usr/bin"

cp "$CLIENT_CLI" "$CLIENT_TMP_DIR/usr/bin/"
chmod 755 "$CLIENT_TMP_DIR/usr/bin/$(basename "$CLIENT_CLI")"
"$STRIP_TOOL" "$CLIENT_TMP_DIR/usr/bin/$(basename "$CLIENT_CLI")"

cp -a "$SHARED_DIR/files/etc" "$CLIENT_TMP_DIR/"
chmod 755 "$CLIENT_TMP_DIR/etc/init.d/fptn"
chmod 755 "$CLIENT_TMP_DIR/etc/uci-defaults/99-fptn"
chmod 644 "$CLIENT_TMP_DIR/etc/config/fptn"

cp -a "$SHARED_DIR/luci/." "$CLIENT_TMP_DIR/"
sed -i "s/@FPTN_VERSION@/${VERSION}/" "$CLIENT_TMP_DIR/www/luci-static/resources/view/fptn/main.js"
find "$CLIENT_TMP_DIR/usr/share/luci" "$CLIENT_TMP_DIR/usr/share/rpcd" "$CLIENT_TMP_DIR/www" -type d -exec chmod 755 {} +
find "$CLIENT_TMP_DIR/usr/share/luci" "$CLIENT_TMP_DIR/usr/share/rpcd" "$CLIENT_TMP_DIR/www" -type f -exec chmod 644 {} +

mkdir -p "$CLIENT_TMP_DIR/usr/lib/lua/luci/i18n"
for po in "$SHARED_DIR"/po/*/fptn.po; do
    po2lmo "$po" "$CLIENT_TMP_DIR/usr/lib/lua/luci/i18n/fptn.$(basename "$(dirname "$po")").lmo"
done

"$APK_TOOL" mkpkg \
    --info "name:fptn-client" \
    --info "version:${VERSION}-r1" \
    --info "arch:${ARCH}" \
    --info "description:FPTN client" \
    --info "license:MIT" \
    --info "url:https://github.com/fptn-project/fptn" \
    --info "depends:libstdcpp6 libatomic kmod-tun ip-full" \
    --script "post-install:$SCRIPT_DIR/post-install" \
    --script "pre-deinstall:$SCRIPT_DIR/pre-deinstall" \
    --files "$CLIENT_TMP_DIR" \
    --output "fptn-client-${VERSION}-openwrt-${OPENWRT_VERSION}-${ARCH}.apk"

rm -rf "$CLIENT_TMP_DIR"

echo "Client apk package created successfully."
