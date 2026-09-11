FROM --platform=linux/amd64 openwrt/sdk:armsr-armv8-24.10.7 AS sdk

FROM --platform=linux/amd64 ubuntu:24.04 AS builder

ARG TOOLCHAIN_DIR=toolchain-aarch64_generic_gcc-13.3.0_musl
ARG CROSS_PREFIX=aarch64-openwrt-linux-musl
ARG CONAN_ARCH=armv8
ARG CONAN_GCC_VERSION=13
ARG JOBS=8
ARG PKG_ARCH=aarch64_generic

ENV DEBIAN_FRONTEND=noninteractive
ENV STAGING_DIR=/builder/staging_dir/${TOOLCHAIN_DIR}
ENV PATH=${STAGING_DIR}/bin:${PATH}

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential git wget curl ca-certificates file perl \
        autoconf automake libtool pkg-config python3-pip && \
    rm -rf /var/lib/apt/lists/*

RUN pip3 install --no-cache-dir --break-system-packages conan cmake ninja

COPY --from=sdk /builder/staging_dir/${TOOLCHAIN_DIR} /builder/staging_dir/${TOOLCHAIN_DIR}
COPY --from=sdk /builder/staging_dir/host /builder/staging_dir/host
COPY --from=sdk /builder/scripts /builder/scripts

ENV PATH=/builder/staging_dir/host/bin:${PATH}

RUN cat > /tmp/openwrt.profile <<EOF
[settings]
os=Linux
arch=${CONAN_ARCH}
compiler=gcc
compiler.version=${CONAN_GCC_VERSION}
compiler.libcxx=libstdc++11
compiler.cppstd=20
build_type=Release

[buildenv]
STAGING_DIR=${STAGING_DIR}
CC=${STAGING_DIR}/bin/${CROSS_PREFIX}-gcc
CXX=${STAGING_DIR}/bin/${CROSS_PREFIX}-g++
AR=${STAGING_DIR}/bin/${CROSS_PREFIX}-ar
RANLIB=${STAGING_DIR}/bin/${CROSS_PREFIX}-ranlib
STRIP=${STAGING_DIR}/bin/${CROSS_PREFIX}-strip
NM=${STAGING_DIR}/bin/${CROSS_PREFIX}-nm
LD=${STAGING_DIR}/bin/${CROSS_PREFIX}-ld

[conf]
tools.build:compiler_executables={"c": "${STAGING_DIR}/bin/${CROSS_PREFIX}-gcc", "cpp": "${STAGING_DIR}/bin/${CROSS_PREFIX}-g++"}
tools.cmake.cmaketoolchain:system_name=Linux
tools.cmake.cmaketoolchain:system_processor=aarch64
tools.build:jobs=${JOBS}
EOF

RUN conan profile detect --force

WORKDIR /app

COPY conanfile.py ./
COPY .conan .conan

RUN conan install . \
      --output-folder=/build \
      --build=missing \
      --profile:build=default \
      --profile:host=/tmp/openwrt.profile \
      -s:b compiler.cppstd=20 \
      -o with_gui_client=False \
      -o openwrt=True

RUN mkdir -p /tmp/po2lmo/lib /tmp/po2lmo/contrib && cd /tmp/po2lmo \
    && for f in Makefile po2lmo.c lib/lmo.c lib/lmo.h lib/plural_formula.y contrib/lemon.c contrib/lempar.c; do \
         wget -q -O "$f" "https://raw.githubusercontent.com/openwrt/luci/openwrt-24.10/modules/luci-base/src/$f"; \
       done \
    && make po2lmo \
    && cp po2lmo /usr/local/bin/po2lmo \
    && rm -rf /tmp/po2lmo

RUN mkdir -p /app/deploy/openwrt/data/luci/www/luci-static/resources/fptn \
    && wget -q -O /app/deploy/openwrt/data/luci/www/luci-static/resources/fptn/brotli.js \
         "https://raw.githubusercontent.com/google/brotli/v1.2.0/js/decode.min.js"

COPY . /app

RUN find /app/deploy/openwrt -type f -exec sed -i 's/\r$//' {} + \
    && chmod 755 /app/deploy/openwrt/data/ipk/create-client-ipk-package.sh

ARG OPENWRT_VERSION=24.10.x
ARG PKG_VERSION=0.0.0

RUN /usr/local/bin/cmake -S /app -B /build \
      -DCMAKE_TOOLCHAIN_FILE=/build/conan_toolchain.cmake \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_COMPILE_WARNING_AS_ERROR=OFF \
      -DCMAKE_STRIP=${STAGING_DIR}/bin/${CROSS_PREFIX}-strip \
      -DFPTN_OPENWRT_ARCH=${PKG_ARCH} \
      -DFPTN_OPENWRT_VERSION=${OPENWRT_VERSION} \
      -DFPTN_VERSION=${PKG_VERSION}

RUN /usr/local/bin/cmake --build /build --target fptn-client-cli -j${JOBS}

RUN /usr/local/bin/cmake --build /build --target build-openwrt-ipk

FROM ubuntu:24.04 AS artifact
WORKDIR /out
COPY --from=builder /app/*.ipk /out/
