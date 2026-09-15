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

# <staging dir> <package name> <output file>
build_ipk() {
    local output_dir
    output_dir=$(mktemp -d -t fptn-ipk-XXXXXX)
    "$IPKG_BUILD" -c "$1" "$output_dir"
    mv "$output_dir/$2"_*.ipk "$3"
    rm -rf "$1" "$output_dir"
}

# fptn-client: the binary, the procd service and the UCI config. The LuCI page
# is a package of its own below: when ZeroBlock runs the client, a second
# settings page that nothing reads only confuses people.

CLIENT_TMP_DIR=$(mktemp -d -t fptn-client-cli-XXXXXX)

mkdir -p "$CLIENT_TMP_DIR/usr/bin"

cp "$CLIENT_CLI" "$CLIENT_TMP_DIR/usr/bin/"
chmod 755 "$CLIENT_TMP_DIR/usr/bin/$(basename "$CLIENT_CLI")"
"$STRIP_TOOL" "$CLIENT_TMP_DIR/usr/bin/$(basename "$CLIENT_CLI")"

cp -a "$SHARED_DIR/files/etc" "$CLIENT_TMP_DIR/"
chmod 755 "$CLIENT_TMP_DIR/etc/init.d/fptn"
chmod 755 "$CLIENT_TMP_DIR/etc/uci-defaults/99-fptn"
chmod 644 "$CLIENT_TMP_DIR/etc/config/fptn"

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

build_ipk "$CLIENT_TMP_DIR" fptn-client \
    "fptn-client-${VERSION}-openwrt-${OPENWRT_VERSION}-${ARCH}.ipk"

echo "Client ipk package created successfully."

# luci-app-fptn: the web page, its translations and the rpcd ACL. Nothing in it
# depends on the CPU, so it is built as "all" and the name stays clear of the
# fptn-client-*-<arch>.ipk pattern ZeroBlock looks for in a release.

LUCI_TMP_DIR=$(mktemp -d -t luci-app-fptn-XXXXXX)

cp -a "$SHARED_DIR/luci/." "$LUCI_TMP_DIR/"
sed -i "s/@FPTN_VERSION@/${VERSION}/" "$LUCI_TMP_DIR/www/luci-static/resources/view/fptn/main.js"
find "$LUCI_TMP_DIR/usr/share/luci" "$LUCI_TMP_DIR/usr/share/rpcd" "$LUCI_TMP_DIR/www" -type d -exec chmod 755 {} +
find "$LUCI_TMP_DIR/usr/share/luci" "$LUCI_TMP_DIR/usr/share/rpcd" "$LUCI_TMP_DIR/www" -type f -exec chmod 644 {} +

mkdir -p "$LUCI_TMP_DIR/usr/lib/lua/luci/i18n"
for po in "$SHARED_DIR"/po/*/fptn.po; do
    po2lmo "$po" "$LUCI_TMP_DIR/usr/lib/lua/luci/i18n/fptn.$(basename "$(dirname "$po")").lmo"
done

mkdir -p "$LUCI_TMP_DIR/CONTROL"

cat > "$LUCI_TMP_DIR/CONTROL/control" <<EOF
Package: luci-app-fptn
Version: ${VERSION}-r1
Architecture: all
Maintainer: FPTN Project <https://github.com/fptn-project/fptn>
Section: luci
Priority: optional
License: MIT
Depends: luci-base, fptn-client
Description: LuCI page for the FPTN client
EOF

cp "$SCRIPT_DIR/luci-postinst" "$LUCI_TMP_DIR/CONTROL/postinst"
cp "$SCRIPT_DIR/luci-postrm" "$LUCI_TMP_DIR/CONTROL/postrm"
chmod 755 "$LUCI_TMP_DIR/CONTROL/postinst" "$LUCI_TMP_DIR/CONTROL/postrm"
chmod 644 "$LUCI_TMP_DIR/CONTROL/control"

build_ipk "$LUCI_TMP_DIR" luci-app-fptn \
    "luci-app-fptn-${VERSION}-openwrt-${OPENWRT_VERSION}-all.ipk"

echo "LuCI ipk package created successfully."
