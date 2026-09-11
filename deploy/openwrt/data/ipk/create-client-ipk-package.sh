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

IPKG_BUILD="${IPKG_BUILD:-/builder/scripts/ipkg-build}"

if [ ! -x "$IPKG_BUILD" ]; then
    echo "ipkg-build tool not found: $IPKG_BUILD"
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

mkdir -p "$CLIENT_TMP_DIR/CONTROL"

cat > "$CLIENT_TMP_DIR/CONTROL/control" <<EOF
Package: fptn-client
Version: ${VERSION}-r1
Architecture: ${ARCH}
Maintainer: FPTN Project <https://github.com/fptn-project/fptn>
Section: net
Priority: optional
License: MIT
Depends: libstdcpp6, libatomic, kmod-tun, ip-full
Description: FPTN client
EOF

cp "$SCRIPT_DIR/conffiles" "$CLIENT_TMP_DIR/CONTROL/conffiles"
cp "$SCRIPT_DIR/postinst" "$CLIENT_TMP_DIR/CONTROL/postinst"
cp "$SCRIPT_DIR/prerm" "$CLIENT_TMP_DIR/CONTROL/prerm"
chmod 755 "$CLIENT_TMP_DIR/CONTROL/postinst" "$CLIENT_TMP_DIR/CONTROL/prerm"
chmod 644 "$CLIENT_TMP_DIR/CONTROL/control" "$CLIENT_TMP_DIR/CONTROL/conffiles"

OUTPUT_DIR=$(mktemp -d -t fptn-client-ipk-XXXXXX)

"$IPKG_BUILD" -c "$CLIENT_TMP_DIR" "$OUTPUT_DIR"

mv "$OUTPUT_DIR"/fptn-client_*.ipk \
    "fptn-client-${VERSION}-openwrt-${OPENWRT_VERSION}-${ARCH}.ipk"

rm -rf "$CLIENT_TMP_DIR" "$OUTPUT_DIR"

echo "Client ipk package created successfully."
