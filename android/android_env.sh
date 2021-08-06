export APILEVEL=21
export TOOLCHAIN="${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/linux-x86_64/bin/"
export DEFAULT_CPP_FLAGS="-DANDROID -D_ANDROID -D__ANDROID__ -D__ANDROID_API__=${APILEVEL}"
export DEFAULT_FLAGS="-fPIC"

if [ -z "$1" ]; then
  echo "Android arch not provided!"
  exit 1
fi

case $1 in
 armeabi-v7a )
  export CHOST=armv7a-linux-androideabi
  export NOAPI_PREFIX=${TOOLCHAIN}arm-linux-androideabi
  export ARCH_FLAGS="-march=armv7-a -mfloat-abi=softfp -mfpu=vfpv3-d16 -O2"
  export ARCH=armeabi-v7a
  export CONFIGURE_PLATFORM="android-arm"
  ARCH_OPTS="--enable-sp-asm"
  ;;
 arm64-v8a )
  export CHOST=aarch64-linux-android
  export NOAPI_PREFIX=${TOOLCHAIN}aarch64-linux-android
  export ARCH_FLAGS="-march=armv8-a+crypto -O2"
  export ARCH=arm64-v8a
  export CONFIGURE_PLATFORM="android-arm64"
  ARCH_OPTS="--enable-armasm"
  ;;
 x86 )
  export CHOST=i686-linux-android
  export NOAPI_PREFIX=${TOOLCHAIN}i686-linux-android
  export ARCH_FLAGS="-march=i686 -mtune=intel -mssse3 -mfpmath=sse -m32 -O2"
  export ARCH=x86
  export CONFIGURE_PLATFORM="android-x86"
  ARCH_OPTS=""
  ;;
 x86_64 )
  export CHOST=x86_64-linux-android
  export NOAPI_PREFIX=${TOOLCHAIN}x86_64-linux-android
  export ARCH_FLAGS="-march=x86-64 -msse4.2 -mpopcnt -m64 -mtune=intel -O2"
  export ARCH=x86_64
  export CONFIGURE_PLATFORM="android64-x86_64"
  ARCH_OPTS="--enable-sp-asm"
  ;;
esac

export API_PREFIX=${TOOLCHAIN}${CHOST}${APILEVEL}
export SYSROOT="${ANDROID_NDK_HOME}/sysroot/"

export CFLAGS="-isystem ${SYSROOT} ${ARCH_FLAGS} ${DEFAULT_FLAGS} -D__ANDROID_API__=21"
export CXXFLAGS="-isystem ${SYSROOT} ${ARCH_FLAGS} ${DEFAULT_FLAGS}"
export CPPFLAGS="${DEFAULT_CPP_FLAGS}"

export CPP="${API_PREFIX}-clang -E"
export CC="${API_PREFIX}-clang"
export CXX="${API_PREFIX}-clang++"
export LD="${NOAPI_PREFIX}-ld"
export AS="${NOAPI_PREFIX}-as"
export AR="${NOAPI_PREFIX}-ar"
export RANLIB="${NOAPI_PREFIX}-ranlib"
export STRIP="${NOAPI_PREFIX}-strip"
export OBJDUMP="${NOAPI_PREFIX}-objdump"

CONFIG_OPTS=()
CONFIG_OPTS+=("--host=${CHOST}")
CONFIG_OPTS+=($ARCH_OPTS)

export CROSS_OPTS=${CONFIG_OPTS[@]}
