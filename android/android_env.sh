export APILEVEL=21
export ANDROID_NDK_VERSION=${ANDROID_NDK_VERSION:-"23.2.8568313"}
export ANDROID_SDK_ROOT=${ANDROID_SDK_ROOT:-"${HOME}/Library/Android/sdk"}
export ANDROID_NDK_HOME=${ANDROID_NDK_HOME:-"${ANDROID_SDK_ROOT}/ndk/${ANDROID_NDK_VERSION}"}
export DEFAULT_CPP_FLAGS="-DANDROID -D_ANDROID -D__ANDROID__"
export DEFAULT_FLAGS="-fPIC"

case $OSTYPE in
 darwin*)
   export TOOLCHAIN="${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/darwin-x86_64/bin/"
   ;;
 linux*)
   export TOOLCHAIN="${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/linux-x86_64/bin/"
   ;;
esac

if [ -z "$1" ]; then
  echo "Android arch not provided!"
  exit 1
fi

case $1 in
 armeabi-v7a )
  export CHOST=armv7a-linux-androideabi
  export ARCH_FLAGS="-march=armv7-a -mfloat-abi=softfp -mfpu=vfpv3-d16 -O3"
  export ARCH=armeabi-v7a
  export CONFIGURE_PLATFORM="android-arm"
  ARCH_OPTS="--enable-sp-asm"
  ;;
 arm64-v8a )
  export CHOST=aarch64-linux-android
  export ARCH_FLAGS="-march=armv8-a+crypto -O3"
  export ARCH=arm64-v8a
  export CONFIGURE_PLATFORM="android-arm64"
  ARCH_OPTS="--enable-armasm"
  ;;
 x86 )
  export CHOST=i686-linux-android
  export ARCH_FLAGS="-march=i686 -msse3 -m32 -O3"
  export ARCH=x86
  export CONFIGURE_PLATFORM="android-x86"
  ARCH_OPTS=""
  ;;
 x86_64 )
  export CHOST=x86_64-linux-android
  export ARCH_FLAGS="-march=x86-64 -msse4.2 -mpopcnt -m64 -O3"
  export ARCH=x86_64
  export CONFIGURE_PLATFORM="android64-x86_64"
  ARCH_OPTS="--enable-sp-asm"
  ;;
esac

export API_PREFIX=${TOOLCHAIN}${CHOST}${APILEVEL}
export SYSROOT="${ANDROID_NDK_HOME}/sysroot/"

export CFLAGS="-isystem ${SYSROOT} ${ARCH_FLAGS} ${DEFAULT_FLAGS}"
export CXXFLAGS="-isystem ${SYSROOT} ${ARCH_FLAGS} ${DEFAULT_FLAGS}"
export CPPFLAGS="${DEFAULT_CPP_FLAGS}"

export CPP="${API_PREFIX}-clang -E"
export CC="${API_PREFIX}-clang"
export CXX="${API_PREFIX}-clang++"
export LD="${TOOLCHAIN}ld"
export AS="${API_PREFIX}-as"
export AR="${TOOLCHAIN}llvm-ar"
export RANLIB="${TOOLCHAIN}llvm-ranlib"
export STRIP="${TOOLCHAIN}llvm-strip"
export OBJDUMP="${TOOLCHAIN}llvm-objdump"

CONFIG_OPTS=()
CONFIG_OPTS+=("--host=${CHOST}")
CONFIG_OPTS+=($ARCH_OPTS)

export PATH=${TOOLCHAIN}:$PATH

export CROSS_OPTS=${CONFIG_OPTS[@]}
