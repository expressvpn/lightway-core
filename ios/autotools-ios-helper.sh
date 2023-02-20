#! /bin/sh

set -e

#
# Build for iOS device (arm64) and simulator (x86_64 only)
# - macOS 10.15.4
# - iOS 15.4
# - Xcode 13.2.1
#
# Build for tvOS device (arm64) and simulator (x86_64 only)
# - macOS 12.0
# - tvOS 17.0
# - Xcode 15.0 beta
#
# Usage:
# - Place/copy the script at wolfSSL root
# - Customize MIN_IOS_VERSION and other flags as needed
#
export MIN_IOS_VERSION=12.0
export MIN_TVOS_VERSION=17.0

build() {
    # Compiler options
    export OPT_FLAGS="-O3 -fembed-bitcode"
    export MAKE_JOBS="$(/usr/sbin/sysctl -n hw.ncpu)"

    # WolfSSL + Helium
    export WOLF_FLAGS="-fPIC -D_FORTIFY_SOURCE=2 -DWOLFSSL_DTLS_ALLOW_FUTURE -DWOLFSSL_MIN_RSA_BITS=2048 -DWOLFSSL_MIN_ECC_BITS=256"

    # Get the correct toolchain for target platforms
    export CC="$(xcrun --find --sdk ${SDK} clang)"
    export CXX="$(xcrun --find --sdk ${SDK} clang++)"
    export CPP="$(xcrun --find --sdk ${SDK} cpp)"
    export CFLAGS="${HOST_FLAGS} ${OPT_FLAGS}"
    export CXXFLAGS="${HOST_FLAGS} ${OPT_FLAGS}"
    export LDFLAGS="${HOST_FLAGS}"

    echo "Debug C_EXTRA_FLAGS=${WOLF_FLAGS}"

    export EXEC_PREFIX="${PREFIX}/${CONFIG}-${PLATFORM}"
    echo "PLATFORM: ${PLATFORM}"
    echo "EXEC_PREFIX: ${EXEC_PREFIX}"
    ./configure $ARCH_OPTS \
        C_EXTRA_FLAGS="$WOLF_FLAGS" \
        --host="${CHOST}" \
        --exec-prefix="${EXEC_PREFIX}" \
        --enable-static \
        --enable-tls13 \
        --disable-oldtls \
        --prefix="${PREFIX}" \
        --enable-singlethreaded \
        --enable-dtls \
        --enable-dtls13 \
        --enable-dtls-mtu \
        --enable-sp=yes,4096 \
        --disable-sha3 \
        --disable-dh \
        --enable-curve25519 \
        --enable-secure-renegotiation \
        --disable-shared \
        --disable-examples \
        --disable-sys-ca-certs \
        --enable-sni

    make clean
    mkdir -p "${EXEC_PREFIX}"
    make V=1 -j"${MAKE_JOBS}" --debug=j
    make install
}

build_iphoneos() {
    export SDK="iphoneos"
    export PLATFORM="iphoneos"
    export EFFECTIVE_PLATFORM_NAME="-iphoneos"
    export ARCH_OPTS="--enable-armasm --enable-sp-asm"
    export ARCH_FLAGS="-arch arm64"
    export HOST_FLAGS="${ARCH_FLAGS} -miphoneos-version-min=${MIN_IOS_VERSION} -isysroot $(xcrun --sdk ${SDK} --show-sdk-path)"
    export CHOST="arm64-apple-ios"
    build
}

build_iphonesimulator() {
    export SDK="iphonesimulator"
    export PLATFORM="iphonesimulator"
    export EFFECTIVE_PLATFORM_NAME="-iphonesimulator"
    export ARCH_OPTS=""
    export ARCH_FLAGS="-arch x86_64"
    export HOST_FLAGS="${ARCH_FLAGS} -mios-simulator-version-min=${MIN_IOS_VERSION} -isysroot $(xcrun --sdk ${SDK} --show-sdk-path)"
    export CHOST="x86_64-apple-darwin"
    build
}

build_tvos() {
    export SDK="appletvos"
    export PLATFORM="appletvos"
    export EFFECTIVE_PLATFORM_NAME="-appletvos"
    export ARCH_OPTS="--enable-armasm --enable-sp-asm"
    export ARCH_FLAGS="-arch arm64"
    export HOST_FLAGS="${ARCH_FLAGS} -mtvos-version-min=${MIN_TVOS_VERSION} -isysroot $(xcrun --sdk ${SDK} --show-sdk-path)"
    export CHOST="arm64-apple-ios"
    build
}

build_tvsimulator() {
    export SDK="appletvsimulator"
    export PLATFORM="appletvsimulator"
    export EFFECTIVE_PLATFORM_NAME="-appletvsimulator"
    export ARCH_OPTS=""
    export ARCH_FLAGS="-arch x86_64"
    export HOST_FLAGS="${ARCH_FLAGS} -mtvos-simulator-version-min=${MIN_TVOS_VERSION} -isysroot $(xcrun --sdk ${SDK} --show-sdk-path)"
    export CHOST="x86_64-apple-darwin"
    build
}

build_ios_universal_binary() {
    # Create ios universal binary
    LIB_NAME="libwolfssl.a"
    mkdir -p "${PREFIX}/${CONFIG}-ios-universal/lib"
    lipo -create -output "${PREFIX}/${CONFIG}-ios-universal/lib/${LIB_NAME}" \
        "${PREFIX}/${CONFIG}-iphoneos/lib/${LIB_NAME}" \
        "${PREFIX}/${CONFIG}-iphonesimulator/lib/${LIB_NAME}"
}

build_tvos_universal_binary() {
    # Create ios universal binary
    LIB_NAME="libwolfssl.a"
    mkdir -p "${PREFIX}/${CONFIG}-tvos-universal/lib"
    lipo -create -output "${PREFIX}/${CONFIG}-tvos-universal/lib/${LIB_NAME}" \
        "${PREFIX}/${CONFIG}-appletvos/lib/${LIB_NAME}" \
        "${PREFIX}/${CONFIG}-appletvsimulator/lib/${LIB_NAME}"
}
# Locations
PREFIX=${PREFIX:-"$(pwd)/../builds/wolfssl_ios"}
CONFIG=${CONFIG:-"Release"}
PLATFORMS="${PREFIX}"/platforms
UNIVERSAL="${PREFIX}"/universal

mkdir -p "${PLATFORMS}"
mkdir -p "${UNIVERSAL}"

TARGET=${1:-"-all"}
echo "Building wolfSSL for ${TARGET}..."

case "${TARGET}" in
-iphoneos)
    build_iphoneos
    ;;
-iphonesimulator)
    build_iphonesimulator
    ;;
-appletvos)
    build_tvos
    ;;
-appletvsimulator)
    build_tvsimulator
    ;;
-all)
    build_iphoneos
    build_iphonesimulator
    build_ios_universal_binary
    build_tvos
    build_tvsimulator
    build_tvos_universal_binary
    ;;
*)
    echo "Unsupport target: ${TARGET}"
    exit 64
    ;;
esac

echo "Building wolfSSL for ${TARGET}... Done."
