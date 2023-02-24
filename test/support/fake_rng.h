#ifndef _HE_FAKE_RNG
#define _HE_FAKE_RNG

#include "he.h"
#include "he_internal.h"

/**
 *  This function should NEVER be defined and only used in test files by
 *  #include "mock_fake_rng.h"
 */
int wc_InitRng(RNG *rng);

/**
 *  This function should NEVER be defined and only used in test files by
 *  #include "mock_fake_rng.h"
 */
int wc_RNG_GenerateBlock(RNG *rng, byte *bytes, uint32_t sz);

#endif
