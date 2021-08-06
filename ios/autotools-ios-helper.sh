#! /bin/sh

#
# Build for iOS 64bit-ARM variants and iOS Simulator
# - Place/copy the script at wolfSSL root
# - Customize MIN_IOS_VERSION and other flags as needed
#
# Local Environment
# - macOS 10.15.4
# - iOS 13.4
# - Xcode 11.4
#

Build() {
    # Ensure -fembed-bitcode builds, as workaround for libtool macOS bug
    export MACOSX_DEPLOYMENT_TARGET="10.4"
    # Get the correct toolchain for target platforms
    export CC=$(xcrun --find --sdk "${SDK}" clang)
    export CXX=$(xcrun --find --sdk "${SDK}" clang++)
    export CPP=$(xcrun --find --sdk "${SDK}" cpp)
    export CFLAGS="${HOST_FLAGS} ${OPT_FLAGS}"
    export CXXFLAGS="${HOST_FLAGS} ${OPT_FLAGS}"
    export LDFLAGS="${HOST_FLAGS}"

    echo "Debug C_EXTRA_FLAGS= ${WOLF_FLAGS}"

    EXEC_PREFIX="${PLATFORMS}/${PLATFORM}"
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
        --enable-sp \
        --disable-sha3 \
        --disable-dh \
        --enable-curve25519 \
        --enable-secure-renegotiation \
        --disable-shared  # Avoid Xcode loading dylibs even when staticlibs exist

    make clean
    mkdir -p "${PLATFORMS}" &> /dev/null
    make V=1 -j"${MAKE_JOBS}" --debug=j
    make install
}

BuildIntel() {
    # Ensure -fembed-bitcode builds, as workaround for libtool macOS bug
    export MACOSX_DEPLOYMENT_TARGET="10.10"
    # Get the correct toolchain for target platforms
    export CC=$(xcrun --find --sdk "${SDK}" clang)
    export CXX=$(xcrun --find --sdk "${SDK}" clang++)
    export CPP=$(xcrun --find --sdk "${SDK}" cpp)
    export CFLAGS="${HOST_FLAGS} ${OPT_FLAGS}"
    export CXXFLAGS="${HOST_FLAGS} ${OPT_FLAGS}"
    export LDFLAGS="${HOST_FLAGS}"

    echo "Debug C_EXTRA_FLAGS= ${WOLF_FLAGS}"

    EXEC_PREFIX="${PLATFORMS}/${PLATFORM}"
    ./configure $ARCH_OPTS \
        C_EXTRA_FLAGS="$WOLF_FLAGS" \
        --host="${CHOST}" \
        --exec-prefix="${EXEC_PREFIX}" \
        --enable-static \
        --enable-tls13 \
        --disable-oldtls \
        --enable-aesni \
        --prefix="${PREFIX}" \
        --enable-singlethreaded \
        --enable-dtls \
        --enable-dtls-mtu \
        --enable-sp \
        --enable-sp-asm \
        --enable-intelasm \
        --disable-sha3 \
        --disable-dh \
        --enable-curve25519 \
        --enable-secure-renegotiation \
        --disable-shared  # Avoid Xcode loading dylibs even when staticlibs exist

    make clean
    mkdir -p "${PLATFORMS}" &> /dev/null
    make V=1 -j"${MAKE_JOBS}" --debug=j
    make install
}

echo "Building wolfSSL for iOS..."

# Locations
ScriptDir="$( cd "$( dirname "$0" )" && pwd )"
cd - &> /dev/null
PREFIX="$(pwd)/../builds/wolfssl_ios"
PLATFORMS="${PREFIX}"/platforms
UNIVERSAL="${PREFIX}"/universal

# Compiler options
OPT_FLAGS="-O3 -g3 -fembed-bitcode"
MAKE_JOBS=8
MIN_IOS_VERSION=12.0

# WolfSSL + Helium
WOLF_FLAGS="-fPIC -DWOLFSSL_DTLS_ALLOW_FUTURE -DWOLFSSL_MIN_RSA_BITS=2048 -DWOLFSSL_MIN_ECC_BITS=256"

# Build for platforms
SDK="iphoneos"
PLATFORM="iphoneos"
PLATFORM_IPHONEOS=${PLATFORM}
ARCH_OPTS="--enable-armasm"
ARCH_FLAGS="-arch arm64 -arch arm64e"
HOST_FLAGS="${ARCH_FLAGS} -mfpu=auto -miphoneos-version-min=${MIN_IOS_VERSION} -isysroot $(xcrun --sdk ${SDK} --show-sdk-path)"
CHOST="arm-apple-darwin"
Build | tee "${PLATFORM}.log"

SDK="iphonesimulator"
PLATFORM="iphonesimulator"
PLATFORM_IPHONESIMULATOR=${PLATFORM}
ARCH_OPTS=""
ARCH_FLAGS="-arch x86_64"
HOST_FLAGS="${ARCH_FLAGS} -mios-simulator-version-min=${MIN_IOS_VERSION} -isysroot $(xcrun --sdk ${SDK} --show-sdk-path)"
CHOST="x86_64-apple-darwin"
Build | tee "${PLATFORM}.log"

SDK="iphonesimulator"
PLATFORM="iphonesimulator"
PLATFORM_IPHONESIMULATOR=${PLATFORM}
ARCH_OPTS=""
ARCH_FLAGS="-arch arm64"
HOST_FLAGS="${ARCH_FLAGS} -mios-simulator-version-min=${MIN_IOS_VERSION} -isysroot $(xcrun --sdk ${SDK} --show-sdk-path)"
CHOST="x86_64-apple-darwin"
Build | tee "${PLATFORM}.log"

# Create ios universal binary
cd "${PLATFORMS}/${PLATFORM_IPHONEOS}/lib"
LIB_NAME=`find . -iname *.a`
cd -
mkdir -p "${PLATFORMS}/universal/lib" &> /dev/null
lipo -create -output "${PLATFORMS}/universal/lib/${LIB_NAME}" \
    "${PLATFORMS}/${PLATFORM_IPHONEOS}/lib/${LIB_NAME}" \
    "${PLATFORMS}/${PLATFORM_IPHONESIMULATOR}/lib/${LIB_NAME}"

echo "Building wolfSSL for iOS... Done."

SDK="macosx"
PLATFORM="macos-x86_64"
PLATFORM_MACOS_INTEL=${PLATFORM}
ARCH_OPTS=""
ARCH_FLAGS="-arch x86_64"
HOST_FLAGS="${ARCH_FLAGS} -isysroot $(xcrun --sdk ${SDK} --show-sdk-path)"
CHOST="x86_64-apple-darwin"
BuildIntel | tee "${PLATFORM}.log"

SDK="macosx"
PLATFORM="macos-arm64"
PLATFORM_MACOS_ARM64=${PLATFORM}
ARCH_OPTS=""
ARCH_FLAGS="-target arm64-apple-darwin"
HOST_FLAGS="${ARCH_FLAGS} -isysroot $(xcrun --sdk ${SDK} --show-sdk-path)"
CHOST="aarch64-apple-darwin"
Build | tee "${PLATFORM}.log"

# Create macOS universal binary
cd "${PLATFORMS}/${PLATFORM_MACOS_ARM64}/lib"
LIB_NAME=`find . -iname *.a`
cd -
mkdir -p "${PLATFORMS}/macos/lib" &> /dev/null
lipo -create -output "${PLATFORMS}/macos/lib/${LIB_NAME}" \
    "${PLATFORMS}/${PLATFORM_MACOS_INTEL}/lib/${LIB_NAME}" \
    "${PLATFORMS}/${PLATFORM_MACOS_ARM64}/lib/${LIB_NAME}"
