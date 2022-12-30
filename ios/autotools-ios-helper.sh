#! /bin/sh

set -e

#
# Build for iOS 64bit-ARM variants and iOS Simulator
# - Place/copy the script at wolfSSL root
# - Customize MIN_IOS_VERSION and other flags as needed
#
# Local Environment
# - macOS 10.15.4
# - iOS 15.4
# - Xcode 13.2.1
#
export MIN_IOS_VERSION=12.0

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
    SDK="iphoneos"
    PLATFORM="iphoneos"
    ARCH_OPTS="--enable-armasm --enable-sp-asm"
    ARCH_FLAGS="-arch arm64"
    HOST_FLAGS="${ARCH_FLAGS} -miphoneos-version-min=${MIN_IOS_VERSION} -isysroot $(xcrun --sdk ${SDK} --show-sdk-path)"
    CHOST="arm64-apple-ios"
    build
}

build_iphonesimulator() {
    SDK="iphonesimulator"
    PLATFORM="iphonesimulator"
    ARCH_OPTS=""
    ARCH_FLAGS="-arch x86_64"
    HOST_FLAGS="${ARCH_FLAGS} -mios-simulator-version-min=${MIN_IOS_VERSION} -isysroot $(xcrun --sdk ${SDK} --show-sdk-path)"
    CHOST="x86_64-apple-darwin"
    build
}

build_universal_binary() {
    # Create ios universal binary
    LIB_NAME="libwolfssl.a"
    mkdir -p "${PREFIX}/${CONFIG}-universal/lib"
    lipo -create -output "${PREFIX}/${CONFIG}-universal/lib/${LIB_NAME}" \
        "${PREFIX}/${CONFIG}-iphoneos/lib/${LIB_NAME}" \
        "${PREFIX}/${CONFIG}-iphonesimulator/lib/${LIB_NAME}"
}

echo "Building wolfSSL for iOS..."

# Locations
PREFIX=${PREFIX:-"$(pwd)/../builds/wolfssl_ios"}
CONFIG=${CONFIG:-"Release"}
PLATFORMS="${PREFIX}"/platforms
UNIVERSAL="${PREFIX}"/universal

mkdir -p "${PLATFORMS}"
mkdir -p "${UNIVERSAL}"

EFFECTIVE_PLATFORM_NAME=${1:-"universal"}
case "${EFFECTIVE_PLATFORM_NAME}" in
-iphoneos)
    build_iphoneos
    ;;
-iphonesimulator)
    build_iphonesimulator
    ;;
*)
    build_iphoneos
    build_iphonesimulator
    build_universal_binary
    ;;
esac

echo "Building wolfSSL for iOS... Done."
