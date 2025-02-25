#ifndef _WIN_USER_SETTINGS_H_
#define _WIN_USER_SETTINGS_H_

#undef WOLFSSL_AESNI
#define WOLFSSL_AESNI

#undef HAVE_INTEL_RDSEED
#define HAVE_INTEL_RDSEED

#undef USE_INTEL_SPEEDUP
// #define USE_INTEL_SPEEDUP // Needs ASM stubs which are not included in the vxproj

#undef WOLFSSL_X86_64_BUILD
#define WOLFSSL_X86_64_BUILD

#endif /* _WIN_USER_SETTINGS_H_ */
