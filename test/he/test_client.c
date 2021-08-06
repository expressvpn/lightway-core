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

#include "client.h"

#include "mock_ssl_ctx.h"
#include "mock_conn.h"
#include "mock_plugin_chain.h"

#include "mock_memory.h"

he_ssl_ctx_t ssl_ctx = {0};
he_conn_t conn = {0};
he_plugin_chain_t inside_plugins = {0};
he_plugin_chain_t outside_plugins = {0};
he_client_t *client = {0};

void setUp(void) {
  client = calloc(1, sizeof(he_client_t));
}

void tearDown(void) {
  free(client);
}

void test_client_create_fails_initial_calloc(void) {
  he_internal_calloc_ExpectAnyArgsAndReturn(NULL);
  he_client_t *test_client = he_client_create();

  TEST_ASSERT_NULL(test_client);
}

void setup_create_expectations(he_ssl_ctx_t *ctx1, he_conn_t *conn1,
                               he_plugin_chain_t *inside_plugins1,
                               he_plugin_chain_t *outside_plugins1) {
  he_internal_calloc_ExpectAnyArgsAndReturn(client);

  he_ssl_ctx_create_ExpectAndReturn(ctx1);
  he_conn_create_ExpectAndReturn(conn1);
  he_plugin_create_chain_ExpectAndReturn(inside_plugins1);
  he_plugin_create_chain_ExpectAndReturn(outside_plugins1);

  if(ctx1 == NULL || conn1 == NULL || inside_plugins1 == NULL || outside_plugins1 == NULL) {
    he_conn_destroy_ExpectAnyArgs();
    he_ssl_ctx_destroy_ExpectAnyArgs();
    he_plugin_destroy_chain_ExpectAnyArgs();
    he_plugin_destroy_chain_ExpectAnyArgs();
    he_internal_free_ExpectAnyArgs();
  }
}

void test_client_create_failures(void) {
  setup_create_expectations(NULL, &conn, &inside_plugins, &outside_plugins);
  he_client_t *test_client = he_client_create();
  TEST_ASSERT_EQUAL(NULL, test_client);

  setup_create_expectations(&ssl_ctx, NULL, &inside_plugins, &outside_plugins);
  test_client = he_client_create();
  TEST_ASSERT_EQUAL(NULL, test_client);

  setup_create_expectations(&ssl_ctx, &conn, NULL, &outside_plugins);
  test_client = he_client_create();
  TEST_ASSERT_EQUAL(NULL, test_client);

  setup_create_expectations(&ssl_ctx, &conn, &inside_plugins, NULL);
  test_client = he_client_create();
  TEST_ASSERT_EQUAL(NULL, test_client);
}

void test_client_create_succeeds(void) {
  setup_create_expectations(&ssl_ctx, &conn, &inside_plugins, &outside_plugins);

  he_client_t *test_client = he_client_create();

  TEST_ASSERT_EQUAL(client, test_client);
}

void test_client_destroy_nullsafe(void) {
  he_client_destroy(NULL);
}

void test_client_destroy_destroys_it_all(void) {
  he_client_t *client = calloc(1, sizeof(he_client_t));
  client->ssl_ctx = &ssl_ctx;
  client->conn = &conn;
  client->inside_plugins = &inside_plugins;
  client->outside_plugins = &outside_plugins;

  he_conn_destroy_Expect(&conn);
  he_ssl_ctx_destroy_Expect(&ssl_ctx);
  he_plugin_destroy_chain_Expect(&inside_plugins);
  he_plugin_destroy_chain_Expect(&outside_plugins);
  he_internal_free_Expect(client);

  he_client_destroy(client);
}

void test_connect_disconnect_valid_nulls(void) {
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, he_client_connect(NULL));
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, he_client_disconnect(NULL));
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, he_client_is_config_valid(NULL));
}

void test_connect_bad_ssl_ctx(void) {
  he_ssl_ctx_start_ExpectAnyArgsAndReturn(HE_ERR_FAILED);

  int res = he_client_connect(client);

  TEST_ASSERT_EQUAL(HE_ERR_FAILED, res);
}

void test_connect_bad_conn(void) {
  he_ssl_ctx_start_ExpectAnyArgsAndReturn(HE_SUCCESS);
  he_conn_client_connect_ExpectAnyArgsAndReturn(HE_ERR_FAILED);

  int res = he_client_connect(client);

  TEST_ASSERT_EQUAL(HE_ERR_FAILED, res);
}

void test_connect_succeeds(void) {
  he_ssl_ctx_start_ExpectAnyArgsAndReturn(HE_SUCCESS);
  he_conn_client_connect_ExpectAnyArgsAndReturn(HE_SUCCESS);

  int res = he_client_connect(client);

  TEST_ASSERT_EQUAL(HE_SUCCESS, res);
}

void test_disconnect_bad_ssl_ctx(void) {
  he_ssl_ctx_stop_ExpectAnyArgsAndReturn(HE_ERR_FAILED);

  int res = he_client_disconnect(client);

  TEST_ASSERT_EQUAL(HE_ERR_FAILED, res);
}

void test_disconnect_bad_conn(void) {
  he_ssl_ctx_stop_ExpectAnyArgsAndReturn(HE_SUCCESS);
  he_conn_disconnect_ExpectAnyArgsAndReturn(HE_ERR_FAILED);

  int res = he_client_disconnect(client);

  TEST_ASSERT_EQUAL(HE_ERR_FAILED, res);
}

void test_disconnect_succeeds(void) {
  he_ssl_ctx_stop_ExpectAnyArgsAndReturn(HE_SUCCESS);
  he_conn_disconnect_ExpectAnyArgsAndReturn(HE_SUCCESS);

  int res = he_client_disconnect(client);

  TEST_ASSERT_EQUAL(HE_SUCCESS, res);
}

void test_is_valid_bad_ssl_ctx(void) {
  he_ssl_ctx_is_valid_client_ExpectAnyArgsAndReturn(HE_ERR_CONF_CA_NOT_SET);

  int res = he_client_is_config_valid(client);

  TEST_ASSERT_EQUAL(HE_ERR_CONF_CA_NOT_SET, res);
}

void test_is_valid_bad_conn(void) {
  he_ssl_ctx_is_valid_client_ExpectAnyArgsAndReturn(HE_SUCCESS);
  he_conn_is_valid_client_ExpectAnyArgsAndReturn(HE_ERR_CONF_USERNAME_NOT_SET);

  int res = he_client_is_config_valid(client);

  TEST_ASSERT_EQUAL(HE_ERR_CONF_USERNAME_NOT_SET, res);
}

void test_is_valid_succeeds(void) {
  he_ssl_ctx_is_valid_client_ExpectAnyArgsAndReturn(HE_SUCCESS);
  he_conn_is_valid_client_ExpectAnyArgsAndReturn(HE_SUCCESS);

  int res = he_client_is_config_valid(client);

  TEST_ASSERT_EQUAL(HE_SUCCESS, res);
}
