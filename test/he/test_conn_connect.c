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

/// Why do we have this file here? Instead of a "clean" connection and SSL CTX we use a fully
/// configured one here to be able to test the "conn_connect" functions specifically.

#include "he.h"
#include "he_internal.h"

#include <unity.h>
#include "test_defs.h"

// Unit under test
#include "conn.h"

// Direct Includes for Utility Functions
#include "config.h"
#include "core.h"
#include "memory.h"

// Internal Mocks
#include "mock_wolf.h"
#include "mock_ssl_ctx.h"
#include "mock_fake_dispatch.h"

// External Mocks
#include "mock_ssl.h"
#include "mock_wolfio.h"

he_ssl_ctx_t *ctx;
he_conn_t *conn;
WOLFSSL_CTX *test_wolf_ctx;
WOLFSSL *test_wolf_ssl;

void setUp(void) {
  test_wolf_ctx = (WOLFSSL_CTX *)calloc(1, sizeof(WOLFSSL_CTX));
  test_wolf_ssl = (WOLFSSL *)calloc(1, sizeof(WOLFSSL));

  /* Full featured client config */
  ctx = calloc(1, sizeof(he_ssl_ctx_t));
  ctx->wolf_ctx = test_wolf_ctx;
  ctx->maximum_supported_version.major_version = HE_WIRE_MAXIMUM_PROTOCOL_MAJOR_VERSION;
  ctx->maximum_supported_version.minor_version = HE_WIRE_MAXIMUM_PROTOCOL_MINOR_VERSION;

  conn = he_conn_create();
  he_conn_set_username(conn, "myuser");
  he_conn_set_password(conn, "mypassword");
  he_conn_set_outside_mtu(conn, 1500);
  he_conn_set_sni_hostname(conn, good_hostname);

  call_counter = 0;
}

void tearDown(void) {
  free(test_wolf_ctx);
  free(test_wolf_ssl);
  free(ctx);
  free(conn);
}

static void setup_dtls_expectations(void) {
  // Wolf set up
  wolfSSL_new_ExpectAndReturn(test_wolf_ctx, test_wolf_ssl);

  wolfSSL_dtls_set_using_nonblock_Expect(test_wolf_ssl, 1);
  wolfSSL_dtls_set_mtu_ExpectAndReturn(test_wolf_ssl, calculate_wolf_mtu(conn->outside_mtu),
                                       SSL_SUCCESS);

  wolfSSL_SetIOWriteCtx_Expect(test_wolf_ssl, conn);
  wolfSSL_SetIOReadCtx_Expect(test_wolf_ssl, conn);

  he_ssl_ctx_is_server_dn_set_ExpectAndReturn(ctx, false);
}

static void setup_tls_expectations(void) {
  // Wolf set up
  wolfSSL_new_ExpectAndReturn(test_wolf_ctx, test_wolf_ssl);

  wolfSSL_UseSNI_ExpectAndReturn(test_wolf_ssl, WOLFSSL_SNI_HOST_NAME, conn->sni_hostname,
                                 strlen(conn->sni_hostname), WOLFSSL_SUCCESS);
  wolfSSL_SetIOWriteCtx_Expect(test_wolf_ssl, conn);
  wolfSSL_SetIOReadCtx_Expect(test_wolf_ssl, conn);

  he_ssl_ctx_is_server_dn_set_ExpectAndReturn(ctx, false);
}

void test_he_client_connect_wolf_new_fail(void) {
  wolfSSL_new_ExpectAndReturn(test_wolf_ctx, NULL);

  int res2 = he_conn_client_connect(conn, ctx, NULL, NULL);
  TEST_ASSERT_EQUAL(HE_ERR_INIT_FAILED, res2);
}

void test_he_client_connect_wolf_connect_want_read(void) {
  // WolfSSL Setup
  setup_dtls_expectations();

  wolfSSL_negotiate_ExpectAndReturn(test_wolf_ssl, SSL_FAILURE);

  wolfSSL_get_error_ExpectAndReturn(test_wolf_ssl, SSL_FAILURE, SSL_ERROR_WANT_READ);

  wolfSSL_dtls_get_current_timeout_ExpectAndReturn(test_wolf_ssl, 1);
  wolfSSL_version_ExpectAndReturn(test_wolf_ssl, DTLS1_2_VERSION);

  int res2 = he_conn_client_connect(conn, ctx, NULL, NULL);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res2);
}

void test_he_client_connect_wolf_connect_want_write(void) {
  setup_dtls_expectations();

  wolfSSL_negotiate_ExpectAndReturn(test_wolf_ssl, SSL_FAILURE);

  wolfSSL_get_error_ExpectAndReturn(test_wolf_ssl, SSL_FAILURE, SSL_ERROR_WANT_WRITE);

  wolfSSL_dtls_get_current_timeout_ExpectAndReturn(test_wolf_ssl, 1);
  wolfSSL_version_ExpectAndReturn(test_wolf_ssl, DTLS1_2_VERSION);

  int res2 = he_conn_client_connect(conn, ctx, NULL, NULL);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res2);
}

void test_he_client_connect_wolf_connect_other_error(void) {
  // Wolf set up
  setup_dtls_expectations();

  wolfSSL_negotiate_ExpectAndReturn(test_wolf_ssl, SSL_FAILURE);
  wolfSSL_get_error_ExpectAndReturn(test_wolf_ssl, SSL_FAILURE, SSL_FAILURE);

  int res2 = he_conn_client_connect(conn, ctx, NULL, NULL);
  TEST_ASSERT_EQUAL(HE_ERR_CONNECT_FAILED, res2);
}

void test_he_client_connect_with_bad_mtu(void) {
  // Wolf set up
  wolfSSL_new_ExpectAndReturn(test_wolf_ctx, test_wolf_ssl);

  // This will be checked for explicitly later
  wolfSSL_CTX_set_cipher_list_IgnoreAndReturn(SSL_SUCCESS);

  wolfSSL_dtls_set_using_nonblock_Expect(test_wolf_ssl, 1);

  // Force a failure (will happen if the MTU is too large)
  wolfSSL_dtls_set_mtu_ExpectAndReturn(test_wolf_ssl, calculate_wolf_mtu(conn->outside_mtu),
                                       WOLFSSL_FAILURE);

  int res = he_conn_client_connect(conn, ctx, NULL, NULL);
  TEST_ASSERT_EQUAL(HE_ERR_INVALID_MTU_SIZE, res);
}

void test_he_client_connect_wolf_dtls_connect_success(void) {
  // Wolf set up
  setup_dtls_expectations();

  wolfSSL_negotiate_ExpectAndReturn(test_wolf_ssl, SSL_SUCCESS);
  // For this test it doesn't matter what it's called with as long as it's called
  // Revisit this as part of the audit
  wolfSSL_write_IgnoreAndReturn(100);
  wolfSSL_dtls_get_current_timeout_ExpectAndReturn(test_wolf_ssl, 1);
  wolfSSL_version_ExpectAndReturn(test_wolf_ssl, DTLS1_2_VERSION);

  int res2 = he_conn_client_connect(conn, ctx, NULL, NULL);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res2);
}

void test_he_client_connect_wolf_tls_connect_success(void) {
  ctx->connection_type = HE_CONNECTION_TYPE_STREAM;

  // Wolf set up
  setup_tls_expectations();

  wolfSSL_negotiate_ExpectAndReturn(test_wolf_ssl, SSL_SUCCESS);
  // For this test it doesn't matter what it's called with as long as it's called
  // Revisit this as part of the audit
  wolfSSL_write_IgnoreAndReturn(100);

  // TODO: no need to call wolfSSL_dtls_get_current_timeout if the connection type is stream
  wolfSSL_dtls_get_current_timeout_ExpectAndReturn(test_wolf_ssl, 1);
  wolfSSL_version_ExpectAndReturn(test_wolf_ssl, DTLS1_2_VERSION);

  int res2 = he_conn_client_connect(conn, ctx, NULL, NULL);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res2);
}

#ifndef HE_NO_PQC
void test_he_client_connect_pqc_keyshare_udp(void) {
  ctx->use_pqc = true;

  // Wolf set up
  setup_dtls_expectations();
  wolfSSL_UseKeyShare_ExpectAndReturn(test_wolf_ssl, WOLFSSL_P256_KYBER_LEVEL1, SSL_SUCCESS);

  wolfSSL_negotiate_ExpectAndReturn(test_wolf_ssl, SSL_SUCCESS);
  // For this test it doesn't matter what it's called with as long as it's called
  // Revisit this as part of the audit
  wolfSSL_write_IgnoreAndReturn(100);
  wolfSSL_dtls_get_current_timeout_ExpectAndReturn(test_wolf_ssl, 1);
  wolfSSL_version_ExpectAndReturn(test_wolf_ssl, DTLS1_3_VERSION);
  wolfSSL_dtls13_use_quick_timeout_ExpectAndReturn(test_wolf_ssl, true);

  int res2 = he_conn_client_connect(conn, ctx, NULL, NULL);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res2);
}

void test_he_client_connect_pqc_keyshare_tcp(void) {
  ctx->use_pqc = true;
  ctx->connection_type = HE_CONNECTION_TYPE_STREAM;

  // Wolf set up
  setup_tls_expectations();
  wolfSSL_UseKeyShare_ExpectAndReturn(test_wolf_ssl, WOLFSSL_P521_KYBER_LEVEL5, SSL_SUCCESS);

  wolfSSL_negotiate_ExpectAndReturn(test_wolf_ssl, SSL_SUCCESS);
  // For this test it doesn't matter what it's called with as long as it's called
  // Revisit this as part of the audit
  wolfSSL_write_IgnoreAndReturn(100);

  // TODO: no need to call wolfSSL_dtls_get_current_timeout if the connection type is stream
  wolfSSL_dtls_get_current_timeout_ExpectAndReturn(test_wolf_ssl, 1);
  wolfSSL_version_ExpectAndReturn(test_wolf_ssl, TLS1_3_VERSION);
  wolfSSL_dtls13_use_quick_timeout_ExpectAndReturn(test_wolf_ssl, true);

  int res2 = he_conn_client_connect(conn, ctx, NULL, NULL);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res2);
}
#endif
