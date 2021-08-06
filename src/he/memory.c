/* *
 * Lightway Core
 * Copyright (C) 2021 Express VPN International Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include "memory.h"

static he_malloc_t internal_malloc = 0;
static he_calloc_t internal_calloc = 0;
static he_realloc_t internal_realloc = 0;
static he_free_t internal_free = 0;

he_return_code_t he_set_allocators(he_malloc_t new_malloc, he_calloc_t new_calloc,
                                   he_realloc_t new_realloc, he_free_t new_free) {
  int res = wolfSSL_SetAllocators(new_malloc, new_free, new_realloc);

  // Currently this function is hardcoded to return 0 but just-in-case :-)
  // https://github.com/wolfSSL/wolfssl/blob/f15450f63e440d5ef64ceac1a6fe79296e2cec7a/wolfcrypt/src/memory.c#L109
  if(res != 0) {
    return HE_ERR_INIT_FAILED;
  }

  internal_malloc = new_malloc;
  internal_calloc = new_calloc;
  internal_realloc = new_realloc;
  internal_free = new_free;

  return HE_SUCCESS;
}

void *he_internal_malloc(size_t size) {
  if(internal_malloc) {
    return internal_malloc(size);
  } else {
    return malloc(size);
  }
}
void *he_internal_calloc(size_t nmemb, size_t size) {
  if(internal_calloc) {
    return internal_calloc(nmemb, size);
  } else {
    return calloc(nmemb, size);
  }
}

void *he_internal_realloc(void *ptr, size_t size) {
  if(internal_realloc) {
    return internal_realloc(ptr, size);
  } else {
    return realloc(ptr, size);
  }
}

void he_internal_free(void *ptr) {
  if(internal_free) {
    internal_free(ptr);
  } else {
    free(ptr);
  }
}
