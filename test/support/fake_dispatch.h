#ifndef _HE_FAKE_DISPATCH
#define _HE_FAKE_DISPATCH

#include <stdarg.h>
#include "he.h"
#include "conn_internal.h"

/**
 *  This function should NEVER be defined and only used in test files by
 *  #include "mock_fake_dispatch.h"
 */
int dispatch(char *func, ...);

/**
 *  This function should NEVER be defined and only used in test files by
 *  #include "mock_fake_dispatch.h"
 */
int dispatch_conn(char *func, he_conn_t *client);

#endif
