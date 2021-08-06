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

#include <he.h>
#include "unity.h"
#include "test_defs.h"

// Unit under test
#include "config.h"

he_conn_t *conn;

// 50
char *max_string = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

void setUp(void) {
  conn = calloc(1, sizeof(he_conn_t));
}

void tearDown(void) {
  free(conn);
}

void test_he_config_set_string_okay(void) {
  TEST_ASSERT_EQUAL_STRING("", conn->username);

  int res1 = he_internal_set_config_string(conn->username, good_username);

  TEST_ASSERT_EQUAL_STRING(good_username, conn->username);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res1);
}

void test_he_config_set_string_too_long(void) {
  TEST_ASSERT_EQUAL_STRING("", conn->username);

  int res1 = he_internal_set_config_string(conn->username, bad_string_too_long);

  TEST_ASSERT_EQUAL_STRING("", conn->username);
  TEST_ASSERT_EQUAL(HE_ERR_STRING_TOO_LONG, res1);
}

void test_he_config_set_string_empty(void) {
  TEST_ASSERT_EQUAL_STRING("", conn->username);

  int res1 = he_internal_set_config_string(conn->username, "");

  TEST_ASSERT_EQUAL_STRING("", conn->username);
  TEST_ASSERT_EQUAL(HE_ERR_EMPTY_STRING, res1);
}

void test_set_integer(void) {
  int res1 = he_internal_set_config_int(&conn->outside_mtu, 10);
  TEST_ASSERT_EQUAL(10, conn->outside_mtu);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res1);
}

void test_set_integer_with_negative(void) {
  int res1 = he_internal_set_config_int(&conn->outside_mtu, -10);
  TEST_ASSERT_EQUAL(0, conn->outside_mtu);
  TEST_ASSERT_EQUAL(HE_ERR_NEGATIVE_NUMBER, res1);
}

void test_config_string_too_long(void) {
  bool res = he_internal_config_is_string_length_okay(bad_string_too_long);
  TEST_ASSERT_FALSE(res);
}

void test_config_string_okay_length(void) {
  bool res = he_internal_config_is_string_length_okay(max_string);
  TEST_ASSERT_TRUE(res);
}

void test_config_string_is_empty(void) {
  bool res = he_internal_config_is_empty_string("");
  TEST_ASSERT_TRUE(res);
}

void test_config_string_is_not_empty(void) {
  bool res = he_internal_config_is_empty_string("123");
  TEST_ASSERT_FALSE(res);
}
