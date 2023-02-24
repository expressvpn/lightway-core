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

#include "he.h"
#include "he_internal.h"

#include <unity.h>
#include "test_defs.h"

// Unit under test
#include "memory.h"

static int malloc_calls = 0;
static int calloc_calls = 0;
static int realloc_calls = 0;
static int free_calls = 0;

void setUp(void) {
  malloc_calls = 0;
  calloc_calls = 0;
  realloc_calls = 0;
  free_calls = 0;
}

void tearDown(void) {
}

void *malloc_for_test(size_t size) {
  malloc_calls++;
  return NULL;
}

void *calloc_for_test(size_t nmemb, size_t size) {
  calloc_calls++;
  return NULL;
}

void *realloc_for_test(void *ptr, size_t size) {
  realloc_calls++;
  return NULL;
}

void free_for_test(void *ptr) {
  free_calls++;
}

void test_default_malloc_calloc_free(void) {
  int *malloced = he_malloc(sizeof(int));
  TEST_ASSERT_NOT_NULL(malloced);

  int *calloced = he_calloc(1, sizeof(int));
  TEST_ASSERT_NOT_NULL(calloced);
  TEST_ASSERT_EQUAL(0, *calloced);

  calloced = he_realloc(calloced, 2 * sizeof(int));
  TEST_ASSERT_NOT_NULL(calloced);
  TEST_ASSERT_EQUAL(0, *calloced);

  he_free(malloced);
  he_free(calloced);
}

void test_custom_malloc_calloc_free(void) {
  he_set_allocators(malloc_for_test, calloc_for_test, realloc_for_test, free_for_test);

  int *malloced = he_malloc(sizeof(int));
  TEST_ASSERT_NULL(malloced);
  TEST_ASSERT_EQUAL(1, malloc_calls);

  int *calloced = he_calloc(1, sizeof(int));
  TEST_ASSERT_NULL(calloced);
  TEST_ASSERT_EQUAL(1, calloc_calls);

  calloced = he_realloc(calloced, sizeof(int));
  TEST_ASSERT_NULL(calloced);
  TEST_ASSERT_EQUAL(1, realloc_calls);

  he_free(malloced);
  TEST_ASSERT_EQUAL(1, free_calls);
}
