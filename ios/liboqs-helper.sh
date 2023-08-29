export MIN_IOS_VERSION=12.0
export MIN_TVOS_VERSION=17.0

PREFIX=${PREFIX:-"$(pwd)"}

build_iphoneos() {
    LIB_NAME="liboqs.a"
    cmake -G Xcode -B ${PREFIX}/build-iphoneos -DPLATFORM=OS64 -DDEPLOYMENT_TARGET=$MIN_IOS_VERSION -DCMAKE_TOOLCHAIN_FILE=apple.cmake -DOQS_BUILD_ONLY_LIB=ON -DOQS_USE_OPENSSL=OFF -DOQS_MINIMAL_BUILD='KEM_kyber_512;KEM_kyber_768;KEM_kyber_1024;SIG_dilithium_2;SIG_dilithium_3;SIG_dilithium_5;SIG_falcon_512;SIG_falcon_1024' .
    cmake --build ${PREFIX}/build-iphoneos --config Release --target oqs -- -j $(/usr/sbin/sysctl -n hw.ncpu) -sdk iphoneos
    cp ${PREFIX}/build-iphoneos/lib/Release/${LIB_NAME} ${PREFIX}/build-iphoneos/lib
}

build_iphonesimulator() {
    LIB_NAME="liboqs.a"
    cmake -G Xcode -B ${PREFIX}/build-iphonesimulator -DPLATFORM=SIMULATOR64 -DDEPLOYMENT_TARGET=$MIN_IOS_VERSION -DCMAKE_TOOLCHAIN_FILE=apple.cmake -DOQS_BUILD_ONLY_LIB=ON -DOQS_USE_OPENSSL=OFF -DOQS_MINIMAL_BUILD='KEM_kyber_512;KEM_kyber_768;KEM_kyber_1024;SIG_dilithium_2;SIG_dilithium_3;SIG_dilithium_5;SIG_falcon_512;SIG_falcon_1024' .
    cmake --build ${PREFIX}/build-iphonesimulator --config Release --target oqs -- -j $(/usr/sbin/sysctl -n hw.ncpu) -sdk iphonesimulator
    cp ${PREFIX}/build-iphonesimulator/lib/Release/${LIB_NAME} ${PREFIX}/build-iphonesimulator/lib
}

build_tvos() {
    LIB_NAME="liboqs.a"
    cmake -G Xcode -B ${PREFIX}/build-appletvos -DPLATFORM=TVOS -DDEPLOYMENT_TARGET=$MIN_TVOS_VERSION -DCMAKE_TOOLCHAIN_FILE=apple.cmake -DOQS_BUILD_ONLY_LIB=ON -DOQS_USE_OPENSSL=OFF -DOQS_MINIMAL_BUILD='KEM_kyber_512;KEM_kyber_768;KEM_kyber_1024;SIG_dilithium_2;SIG_dilithium_3;SIG_dilithium_5;SIG_falcon_512;SIG_falcon_1024' .
    cmake --build ${PREFIX}/build-appletvos --config Release --target oqs -- -j $(/usr/sbin/sysctl -n hw.ncpu) -sdk appletvos
    cp ${PREFIX}/build-appletvos/lib/Release/${LIB_NAME} ${PREFIX}/build-appletvos/lib
}

build_tvsimulator() {
    LIB_NAME="liboqs.a"
    cmake -G Xcode -B ${PREFIX}/build-appletvsimulator -DPLATFORM=SIMULATOR_TVOS -DDEPLOYMENT_TARGET=$MIN_TVOS_VERSION -DCMAKE_TOOLCHAIN_FILE=apple.cmake -DOQS_BUILD_ONLY_LIB=ON -DOQS_USE_OPENSSL=OFF -DOQS_MINIMAL_BUILD='KEM_kyber_512;KEM_kyber_768;KEM_kyber_1024;SIG_dilithium_2;SIG_dilithium_3;SIG_dilithium_5;SIG_falcon_512;SIG_falcon_1024' .
    cmake --build ${PREFIX}/build-appletvsimulator --config Release --target oqs -- -j $(/usr/sbin/sysctl -n hw.ncpu) -sdk appletvsimulator
    cp ${PREFIX}/build-appletvsimulator/lib/Release/${LIB_NAME} ${PREFIX}/build-appletvsimulator/lib
}

build_ios_universal_binary() {
    # Create ios universal binary
    LIB_NAME="liboqs.a"
    mkdir -p ${PREFIX}/build_universal/lib
    cp -r ${PREFIX}/build-iphoneos/include ${PREFIX}/build_universal
    lipo -create -output "${PREFIX}/build_universal/lib/${LIB_NAME}" \
        "${PREFIX}/build-iphoneos/lib/Release/${LIB_NAME}" \
        "${PREFIX}/build-iphonesimulator/lib/Release/${LIB_NAME}"
}

build_tvos_universal_binary() {
    # Create ios universal binary
    LIB_NAME="liboqs.a"
    mkdir -p ${PREFIX}/build_universal/lib
    cp -r ${PREFIX}/build-appletvos/include build_universal
    lipo -create -output "${PREFIX}/build_universal/lib/${LIB_NAME}" \
        "${PREFIX}/build-appletvos/lib/Release/${LIB_NAME}" \
        "${PREFIX}/build-appletvsimulator/lib/Release/${LIB_NAME}"
}

TARGET=${1:-"-all"}
echo "Building liboqs for ${TARGET}..."

case "${TARGET}" in
-iphoneos)
    build_iphoneos
    ;;
-iphonesimulator)
    build_iphonesimulator
    ;;
-iphoneuniversal)
    build_iphoneos
    build_iphonesimulator
    build_ios_universal_binary
    ;;
-appletvos)
    build_tvos
    ;;
-appletvsimulator)
    build_tvsimulator
    ;;
-appletvuniversal)
    build_tvos
    build_tvsimulator
    build_tvos_universal_binary
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

echo "Building liboqs for ${TARGET}... Done."
