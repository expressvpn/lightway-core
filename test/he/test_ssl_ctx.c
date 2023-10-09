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
#include "ssl_ctx.h"

// Direct Includes for Utility Functions
#include "config.h"
#include "memory.h"
#include <wolfssl/error-ssl.h>

// Internal Mocks
#include "mock_wolf.h"

// External Mocks
#include "mock_ssl.h"
#include "mock_wolfio.h"

// "Empty" ctx
he_ssl_ctx_t *ctx;

// "Properly configured" ctx
he_ssl_ctx_t *ctx2;

// "Properly configured" ctx for server
he_ssl_ctx_t *ctx3;

WOLFSSL_CTX *wolf_ctx;

void setUp(void) {
  ctx = he_ssl_ctx_create();
  wolf_ctx = (WOLFSSL_CTX *)calloc(1, sizeof(WOLFSSL_CTX));

  ctx2 = he_ssl_ctx_create();
  he_ssl_ctx_set_ca(ctx2, fake_cert, sizeof(fake_cert));
  he_ssl_ctx_set_outside_write_cb(ctx2, write_cb);

  ctx3 = he_ssl_ctx_create();
  he_ssl_ctx_set_server_cert_key_files(ctx3, good_username, good_password);
  he_ssl_ctx_set_outside_write_cb(ctx3, write_cb);
  he_ssl_ctx_set_auth_cb(ctx3, auth_cb);
}

void tearDown(void) {
  if(ctx) {
    free(ctx);
  }
  if(ctx2) {
    free(ctx2);
  }
  if(wolf_ctx) {
    free(wolf_ctx);
  }
}

void test_he_init(void) {
  wolfSSL_Init_ExpectAndReturn(SSL_SUCCESS);
  he_return_code_t res = he_init();
  TEST_ASSERT_EQUAL(HE_SUCCESS, res);
}

void test_he_init_fail(void) {
  wolfSSL_Init_ExpectAndReturn(BAD_MUTEX_E);
  he_return_code_t res = he_init();
  TEST_ASSERT_EQUAL(HE_ERR_INIT_FAILED, res);
}

void test_he_cleanup(void) {
  wolfSSL_Cleanup_ExpectAndReturn(SSL_SUCCESS);
  he_return_code_t res = he_cleanup();
  TEST_ASSERT_EQUAL(HE_SUCCESS, res);
}

void test_he_client_cleanup_fail(void) {
  wolfSSL_Cleanup_ExpectAndReturn(BAD_MUTEX_E);
  he_return_code_t res = he_cleanup();
  TEST_ASSERT_EQUAL(HE_ERR_CLEANUP_FAILED, res);
}

void test_valid_to_connect_not_null(void) {
  he_ssl_ctx_t *test = NULL;
  int res1 = he_ssl_ctx_is_valid_client(test);
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, res1);
}

void test_valid_to_connect_no_ca(void) {
  he_ssl_ctx_t *test = he_ssl_ctx_create();

  he_ssl_ctx_set_outside_write_cb(test, write_cb);

  int res = he_ssl_ctx_is_valid_client(test);
  TEST_ASSERT_EQUAL(HE_ERR_CONF_CA_NOT_SET, res);

  free(test);
}

void test_valid_to_connect_no_outside_write_cb(void) {
  he_ssl_ctx_t *test = he_ssl_ctx_create();

  int res3 = he_ssl_ctx_set_ca(test, fake_cert, sizeof(fake_cert));
  TEST_ASSERT_EQUAL(HE_SUCCESS, res3);

  int res5 = he_ssl_ctx_is_valid_client(test);
  TEST_ASSERT_EQUAL(HE_ERR_CONF_OUTSIDE_WRITE_CB_NOT_SET, res5);

  free(test);
}

void test_valid_to_connect_server_null(void) {
  int res = he_ssl_ctx_is_valid_server(NULL);
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, res);
}

void test_valid_to_connect_server_no_server_key(void) {
  he_ssl_ctx_t *test = he_ssl_ctx_create();

  he_ssl_ctx_set_outside_write_cb(ctx, write_cb);

  int res = he_ssl_ctx_is_valid_server(ctx);
  TEST_ASSERT_EQUAL(HE_ERR_CONF_CA_NOT_SET, res);
}

void test_valid_to_connect_server_no_auth_cb(void) {
  he_ssl_ctx_t *test = he_ssl_ctx_create();

  he_ssl_ctx_set_outside_write_cb(ctx, write_cb);

  int res = he_ssl_ctx_set_server_cert_key_files(ctx, good_username, good_password);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res);

  res = he_ssl_ctx_is_valid_server(ctx);
  TEST_ASSERT_EQUAL(HE_ERR_CONF_AUTH_CB_NOT_SET, res);
}

void test_valid_to_connect_server_only_auth_buf_cb(void) {
  he_ssl_ctx_t *test = he_ssl_ctx_create();

  he_ssl_ctx_set_outside_write_cb(ctx, write_cb);

  int res = he_ssl_ctx_set_server_cert_key_files(ctx, good_username, good_password);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res);

  he_ssl_ctx_set_auth_buf_cb(ctx, auth_buf_cb);

  res = he_ssl_ctx_is_valid_server(ctx);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res);
}

void test_valid_to_connect_server(void) {
  he_ssl_ctx_t *test = he_ssl_ctx_create();

  he_ssl_ctx_set_outside_write_cb(ctx, write_cb);

  int res = he_ssl_ctx_set_server_cert_key_files(ctx, good_username, good_password);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res);

  he_ssl_ctx_set_auth_cb(ctx, auth_cb);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res);

  res = he_ssl_ctx_is_valid_server(ctx);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res);
}

void test_ctx_create_destroy(void) {
  he_ssl_ctx_t *test_ctx = NULL;

  test_ctx = he_ssl_ctx_create();
  TEST_ASSERT_NOT_NULL(test_ctx);

  test_ctx->wolf_ctx = wolf_ctx;
  wolfSSL_CTX_free_Expect(wolf_ctx);

  he_ssl_ctx_destroy(test_ctx);

  // Should be a no-op
  he_ssl_ctx_destroy(NULL);
}

void test_he_ssl_ctx_stop(void) {
  TEST_ASSERT_EQUAL(HE_SUCCESS, he_ssl_ctx_stop(ctx));
}

void test_he_client_connect_bad_client_config(void) {
  int res1 = he_ssl_ctx_start(ctx);
  TEST_ASSERT_EQUAL(HE_ERR_CONF_OUTSIDE_WRITE_CB_NOT_SET, res1);
}

void test_he_client_connect_fails_bad_connection_type(void) {
  // Wolf set up
  ctx2->connection_type = 99;
  int res1 = he_ssl_ctx_start(ctx2);
  TEST_ASSERT_EQUAL(HE_ERR_INIT_FAILED, res1);
}

void test_he_client_connect_wolf_ctx_new_fails(void) {
  // Wolf set up
  WOLFSSL_METHOD *my_method = (WOLFSSL_METHOD *)0xdeadbeef;
  WOLFSSL_CTX *my_ctx = (WOLFSSL_CTX *)0xdeadbeef;
  wolfDTLS_client_method_ExpectAndReturn(my_method);
  wolfSSL_CTX_new_ExpectAndReturn(my_method, NULL);
  int res1 = he_ssl_ctx_start(ctx2);
  TEST_ASSERT_EQUAL(HE_ERR_INIT_FAILED, res1);
}

void test_he_client_connect_wolf_ctx_load_verify_fails_bad_file(void) {
  // Wolf set up
  WOLFSSL_METHOD *my_method = (WOLFSSL_METHOD *)0xdeadbeef;
  WOLFSSL_CTX *my_ctx = (WOLFSSL_CTX *)0xdeadbeef;
  wolfDTLS_client_method_ExpectAndReturn(my_method);
  wolfSSL_CTX_new_ExpectAndReturn(my_method, my_ctx);

  // This will be checked for explicitly later
  wolfSSL_CTX_set_cipher_list_IgnoreAndReturn(SSL_SUCCESS);

  wolfSSL_CTX_load_verify_buffer_ExpectAndReturn(my_ctx, fake_cert, sizeof(fake_cert),
                                                 SSL_FILETYPE_PEM, SSL_BAD_FILE);

  int res2 = he_ssl_ctx_start(ctx2);
  TEST_ASSERT_EQUAL(HE_ERR_SSL_BAD_FILE, res2);
}

void test_he_client_connect_wolf_ctx_load_verify_fails_bad_file_type(void) {
  // Wolf set up
  WOLFSSL_METHOD *my_method = (WOLFSSL_METHOD *)0xdeadbeef;
  WOLFSSL_CTX *my_ctx = (WOLFSSL_CTX *)0xdeadbeef;
  wolfDTLS_client_method_ExpectAndReturn(my_method);
  wolfSSL_CTX_new_ExpectAndReturn(my_method, my_ctx);

  // This will be checked for explicitly later
  wolfSSL_CTX_set_cipher_list_IgnoreAndReturn(SSL_SUCCESS);

  wolfSSL_CTX_load_verify_buffer_ExpectAndReturn(my_ctx, fake_cert, sizeof(fake_cert),
                                                 SSL_FILETYPE_PEM, SSL_BAD_FILETYPE);

  int res2 = he_ssl_ctx_start(ctx2);
  TEST_ASSERT_EQUAL(HE_ERR_SSL_BAD_FILETYPE, res2);
}

void test_he_client_connect_wolf_ctx_load_verify_fails_memory_e(void) {
  // Wolf set up
  WOLFSSL_METHOD *my_method = (WOLFSSL_METHOD *)0xdeadbeef;
  WOLFSSL_CTX *my_ctx = (WOLFSSL_CTX *)0xdeadbeef;
  wolfDTLS_client_method_ExpectAndReturn(my_method);
  wolfSSL_CTX_new_ExpectAndReturn(my_method, my_ctx);

  // This will be checked for explicitly later
  wolfSSL_CTX_set_cipher_list_IgnoreAndReturn(SSL_SUCCESS);

  wolfSSL_CTX_load_verify_buffer_ExpectAndReturn(my_ctx, fake_cert, sizeof(fake_cert),
                                                 SSL_FILETYPE_PEM, MEMORY_E);

  int res2 = he_ssl_ctx_start(ctx2);
  TEST_ASSERT_EQUAL(HE_ERR_SSL_OUT_OF_MEMORY, res2);
}

void test_he_client_connect_wolf_ctx_load_verify_fails_asn_input_e(void) {
  // Wolf set up
  WOLFSSL_METHOD *my_method = (WOLFSSL_METHOD *)0xdeadbeef;
  WOLFSSL_CTX *my_ctx = (WOLFSSL_CTX *)0xdeadbeef;
  wolfDTLS_client_method_ExpectAndReturn(my_method);
  wolfSSL_CTX_new_ExpectAndReturn(my_method, my_ctx);

  // This will be checked for explicitly later
  wolfSSL_CTX_set_cipher_list_IgnoreAndReturn(SSL_SUCCESS);

  wolfSSL_CTX_load_verify_buffer_ExpectAndReturn(my_ctx, fake_cert, sizeof(fake_cert),
                                                 SSL_FILETYPE_PEM, ASN_INPUT_E);

  int res2 = he_ssl_ctx_start(ctx2);
  TEST_ASSERT_EQUAL(HE_ERR_SSL_ASN_INPUT, res2);
}
void test_he_client_connect_wolf_ctx_load_verify_fails_buffer_e(void) {
  // Wolf set up
  WOLFSSL_METHOD *my_method = (WOLFSSL_METHOD *)0xdeadbeef;
  WOLFSSL_CTX *my_ctx = (WOLFSSL_CTX *)0xdeadbeef;
  wolfDTLS_client_method_ExpectAndReturn(my_method);
  wolfSSL_CTX_new_ExpectAndReturn(my_method, my_ctx);

  // This will be checked for explicitly later
  wolfSSL_CTX_set_cipher_list_IgnoreAndReturn(SSL_SUCCESS);

  wolfSSL_CTX_load_verify_buffer_ExpectAndReturn(my_ctx, fake_cert, sizeof(fake_cert),
                                                 SSL_FILETYPE_PEM, BUFFER_E);

  int res2 = he_ssl_ctx_start(ctx2);
  TEST_ASSERT_EQUAL(HE_ERR_SSL_BUFFER, res2);
}

void test_he_client_connect_wolf_ctx_load_verify_unknown_error(void) {
  // Wolf set up
  WOLFSSL_METHOD *my_method = (WOLFSSL_METHOD *)0xdeadbeef;
  WOLFSSL_CTX *my_ctx = (WOLFSSL_CTX *)0xdeadbeef;
  wolfDTLS_client_method_ExpectAndReturn(my_method);
  wolfSSL_CTX_new_ExpectAndReturn(my_method, my_ctx);

  // This will be checked for explicitly later
  wolfSSL_CTX_set_cipher_list_IgnoreAndReturn(SSL_SUCCESS);

  wolfSSL_CTX_load_verify_buffer_ExpectAndReturn(my_ctx, fake_cert, sizeof(fake_cert),
                                                 SSL_FILETYPE_PEM, -2);

  int res2 = he_ssl_ctx_start(ctx2);
  TEST_ASSERT_EQUAL(HE_ERR_SSL_CERT, res2);
}

void test_he_client_connect_fails_if_set_min_version_fails(void) {
  // Wolf set up
  WOLFSSL_METHOD *my_method = (WOLFSSL_METHOD *)0xdeadbeef;
  WOLFSSL_CTX *my_ctx = (WOLFSSL_CTX *)0xdeadbeef;
  wolfDTLS_client_method_ExpectAndReturn(my_method);
  wolfSSL_CTX_new_ExpectAndReturn(my_method, my_ctx);

  wolfSSL_CTX_load_verify_buffer_ExpectAndReturn(my_ctx, fake_cert, sizeof(fake_cert),
                                                 SSL_FILETYPE_PEM, SSL_SUCCESS);

  wolfSSL_CTX_SetMinVersion_ExpectAndReturn(my_ctx, WOLFSSL_DTLSV1_2, BAD_FUNC_ARG);

  int res2 = he_ssl_ctx_start(ctx2);
  TEST_ASSERT_EQUAL(HE_ERR_INIT_FAILED, res2);
}

void test_he_client_connect_fails_if_cipher_list_fails(void) {
  // Wolf set up
  WOLFSSL_METHOD *my_method = (WOLFSSL_METHOD *)0xdeadbeef;
  WOLFSSL_CTX *my_ctx = (WOLFSSL_CTX *)0xdeadbeef;
  wolfDTLS_client_method_ExpectAndReturn(my_method);
  wolfSSL_CTX_new_ExpectAndReturn(my_method, my_ctx);

  wolfSSL_CTX_load_verify_buffer_ExpectAndReturn(my_ctx, fake_cert, sizeof(fake_cert),
                                                 SSL_FILETYPE_PEM, SSL_SUCCESS);

  wolfSSL_CTX_SetMinVersion_ExpectAndReturn(my_ctx, WOLFSSL_DTLSV1_2, SSL_SUCCESS);

  wolfSSL_CTX_set_cipher_list_IgnoreAndReturn(SSL_FATAL_ERROR);

  int res2 = he_ssl_ctx_start(ctx2);
  TEST_ASSERT_EQUAL(HE_ERR_INIT_FAILED, res2);
}

void test_he_client_connect_fails_when_secure_renegotiation_is_not_available(void) {
  // Wolf set up
  WOLFSSL_METHOD *my_method = (WOLFSSL_METHOD *)0xdeadbeef;
  WOLFSSL_CTX *my_ctx = (WOLFSSL_CTX *)0xdeadbeef;
  wolfDTLS_client_method_ExpectAndReturn(my_method);
  wolfSSL_CTX_new_ExpectAndReturn(my_method, my_ctx);

  // This will be checked for explicitly later
  wolfSSL_CTX_set_cipher_list_IgnoreAndReturn(SSL_SUCCESS);

  wolfSSL_CTX_load_verify_buffer_ExpectAndReturn(my_ctx, fake_cert, sizeof(fake_cert),
                                                 SSL_FILETYPE_PEM, SSL_SUCCESS);

  wolfSSL_CTX_SetMinVersion_ExpectAndReturn(my_ctx, WOLFSSL_DTLSV1_2, SSL_SUCCESS);

  // Set mock callbacks from our own wolf code
  wolfSSL_CTX_SetIORecv_Expect(my_ctx, he_wolf_dtls_read);
  wolfSSL_CTX_SetIOSend_Expect(my_ctx, he_wolf_dtls_write);

  wolfSSL_CTX_UseSecureRenegotiation_ExpectAndReturn(my_ctx, WOLFSSL_FATAL_ERROR);

  int res2 = he_ssl_ctx_start(ctx2);
  TEST_ASSERT_EQUAL(HE_ERR_INIT_FAILED, res2);
}

void test_he_client_connect_succeeds(void) {
  // Wolf set up
  WOLFSSL_METHOD *my_method = (WOLFSSL_METHOD *)0xdeadbeef;
  WOLFSSL_CTX *my_ctx = (WOLFSSL_CTX *)0xdeadbeef;
  wolfDTLS_client_method_ExpectAndReturn(my_method);
  wolfSSL_CTX_new_ExpectAndReturn(my_method, my_ctx);

  // This will be checked for explicitly later
  wolfSSL_CTX_set_cipher_list_IgnoreAndReturn(SSL_SUCCESS);

  wolfSSL_CTX_load_verify_buffer_ExpectAndReturn(my_ctx, fake_cert, sizeof(fake_cert),
                                                 SSL_FILETYPE_PEM, SSL_SUCCESS);

  wolfSSL_CTX_SetMinVersion_ExpectAndReturn(my_ctx, WOLFSSL_DTLSV1_2, SSL_SUCCESS);

  // Set mock callbacks from our own wolf code
  wolfSSL_CTX_SetIORecv_Expect(my_ctx, he_wolf_dtls_read);
  wolfSSL_CTX_SetIOSend_Expect(my_ctx, he_wolf_dtls_write);

  wolfSSL_CTX_UseSecureRenegotiation_ExpectAndReturn(my_ctx, SSL_SUCCESS);

  int res2 = he_ssl_ctx_start(ctx2);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res2);
}

void test_he_client_connect_succeeds_streaming(void) {
  ctx2->connection_type = HE_CONNECTION_TYPE_STREAM;
  // Wolf set up
  WOLFSSL_METHOD *my_method = (WOLFSSL_METHOD *)0xdeadbeef;
  WOLFSSL_CTX *my_ctx = (WOLFSSL_CTX *)0xdeadbeef;
  wolfTLSv1_3_client_method_ExpectAndReturn(my_method);
  wolfSSL_CTX_new_ExpectAndReturn(my_method, my_ctx);

  // This will be checked for explicitly later
  wolfSSL_CTX_set_cipher_list_IgnoreAndReturn(SSL_SUCCESS);

  wolfSSL_CTX_load_verify_buffer_ExpectAndReturn(my_ctx, fake_cert, sizeof(fake_cert),
                                                 SSL_FILETYPE_PEM, SSL_SUCCESS);

  // Set mock callbacks from our own wolf code
  wolfSSL_CTX_SetIORecv_Expect(my_ctx, he_wolf_tls_read);
  wolfSSL_CTX_SetIOSend_Expect(my_ctx, he_wolf_tls_write);

  int res2 = he_ssl_ctx_start(ctx2);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res2);
}

void test_he_server_connect_fails_bad_config(void) {
  ctx3->auth_cb = NULL;
  int res = he_ssl_ctx_start_server(ctx3);
  TEST_ASSERT_EQUAL(HE_ERR_CONF_AUTH_CB_NOT_SET, res);
}

void test_he_server_connect_succeeds(void) {
  // Wolf set up
  WOLFSSL_METHOD *my_method = (WOLFSSL_METHOD *)0xdeadbeef;
  WOLFSSL_CTX *my_ctx = (WOLFSSL_CTX *)0xdeadbeef;
  wolfDTLS_server_method_ExpectAndReturn(my_method);
  wolfSSL_CTX_new_ExpectAndReturn(my_method, my_ctx);

  wolfSSL_CTX_use_certificate_file_ExpectAndReturn(my_ctx, ctx3->server_cert, SSL_FILETYPE_PEM,
                                                   SSL_SUCCESS);

  wolfSSL_CTX_use_PrivateKey_file_ExpectAndReturn(my_ctx, ctx3->server_key, SSL_FILETYPE_PEM,
                                                  SSL_SUCCESS);

  wolfSSL_CTX_set_cipher_list_ExpectAndReturn(
      my_ctx,
      "TLS13-CHACHA20-POLY1305-SHA256:ECDHE-RSA-CHACHA20-POLY1305"
      ":TLS13-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384",
      SSL_SUCCESS);

  // Set mock callbacks from our own wolf code
  wolfSSL_CTX_SetIORecv_Expect(my_ctx, he_wolf_dtls_read);
  wolfSSL_CTX_SetIOSend_Expect(my_ctx, he_wolf_dtls_write);

  wolfSSL_CTX_UseSecureRenegotiation_ExpectAndReturn(my_ctx, SSL_SUCCESS);

  int res2 = he_ssl_ctx_start_server(ctx3);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res2);
}

void test_he_server_connect_succeeds_streaming(void) {
  ctx3->connection_type = HE_CONNECTION_TYPE_STREAM;
  // Wolf set up
  WOLFSSL_METHOD *my_method = (WOLFSSL_METHOD *)0xdeadbeef;
  WOLFSSL_CTX *my_ctx = (WOLFSSL_CTX *)0xdeadbeef;
  wolfTLSv1_3_server_method_ExpectAndReturn(my_method);
  wolfSSL_CTX_new_ExpectAndReturn(my_method, my_ctx);

  wolfSSL_CTX_use_certificate_file_ExpectAndReturn(my_ctx, ctx3->server_cert, SSL_FILETYPE_PEM,
                                                   SSL_SUCCESS);

  wolfSSL_CTX_use_PrivateKey_file_ExpectAndReturn(my_ctx, ctx3->server_key, SSL_FILETYPE_PEM,
                                                  SSL_SUCCESS);

  wolfSSL_CTX_set_cipher_list_ExpectAndReturn(
      my_ctx, "TLS13-AES256-GCM-SHA384:TLS13-CHACHA20-POLY1305-SHA256", SSL_SUCCESS);

  // Set mock callbacks from our own wolf code
  wolfSSL_CTX_SetIORecv_Expect(my_ctx, he_wolf_tls_read);
  wolfSSL_CTX_SetIOSend_Expect(my_ctx, he_wolf_tls_write);

  int res2 = he_ssl_ctx_start_server(ctx3);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res2);
}

void test_he_ssl_ctx_set_minimum_supported_version(void) {
  he_return_code_t rc = HE_ERR_FAILED;

  // NULL pointer error
  rc = he_ssl_ctx_set_minimum_supported_version(NULL, 0, 0);
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, rc);

  // Default value
  rc = he_ssl_ctx_set_minimum_supported_version(ctx, 0, 0);
  TEST_ASSERT_EQUAL(HE_SUCCESS, rc);
  TEST_ASSERT_EQUAL(HE_WIRE_MINIMUM_PROTOCOL_MAJOR_VERSION,
                    ctx->minimum_supported_version.major_version);
  TEST_ASSERT_EQUAL(HE_WIRE_MINIMUM_PROTOCOL_MINOR_VERSION,
                    ctx->minimum_supported_version.minor_version);

  // Invalid versions
  rc =
      he_ssl_ctx_set_minimum_supported_version(ctx, HE_WIRE_MINIMUM_PROTOCOL_MAJOR_VERSION - 1, 99);
  TEST_ASSERT_EQUAL(HE_ERR_INCORRECT_PROTOCOL_VERSION, rc);
  rc = he_ssl_ctx_set_minimum_supported_version(ctx, HE_WIRE_MAXIMUM_PROTOCOL_MAJOR_VERSION + 1, 0);
  TEST_ASSERT_EQUAL(HE_ERR_INCORRECT_PROTOCOL_VERSION, rc);
  rc = he_ssl_ctx_set_minimum_supported_version(ctx, HE_WIRE_MAXIMUM_PROTOCOL_MAJOR_VERSION,
                                                HE_WIRE_MAXIMUM_PROTOCOL_MINOR_VERSION + 1);

  // Valid version
  rc = he_ssl_ctx_set_minimum_supported_version(ctx, 1, 1);
  TEST_ASSERT_EQUAL(HE_SUCCESS, rc);
  TEST_ASSERT_EQUAL(1, ctx->minimum_supported_version.major_version);
  TEST_ASSERT_EQUAL(1, ctx->minimum_supported_version.minor_version);
}

void test_he_ssl_ctx_set_maximum_supported_version(void) {
  he_return_code_t rc = HE_ERR_FAILED;

  // NULL pointer error
  rc = he_ssl_ctx_set_maximum_supported_version(NULL, 0, 0);
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, rc);

  // Default value
  rc = he_ssl_ctx_set_maximum_supported_version(ctx, 0, 0);
  TEST_ASSERT_EQUAL(HE_SUCCESS, rc);
  TEST_ASSERT_EQUAL(HE_WIRE_MAXIMUM_PROTOCOL_MAJOR_VERSION,
                    ctx->maximum_supported_version.major_version);
  TEST_ASSERT_EQUAL(HE_WIRE_MAXIMUM_PROTOCOL_MINOR_VERSION,
                    ctx->maximum_supported_version.minor_version);

  // Invalid versions
  rc =
      he_ssl_ctx_set_maximum_supported_version(ctx, HE_WIRE_MINIMUM_PROTOCOL_MAJOR_VERSION - 1, 99);
  TEST_ASSERT_EQUAL(HE_ERR_INCORRECT_PROTOCOL_VERSION, rc);
  rc = he_ssl_ctx_set_maximum_supported_version(ctx, HE_WIRE_MAXIMUM_PROTOCOL_MAJOR_VERSION + 1, 0);
  TEST_ASSERT_EQUAL(HE_ERR_INCORRECT_PROTOCOL_VERSION, rc);
  rc = he_ssl_ctx_set_maximum_supported_version(ctx, HE_WIRE_MAXIMUM_PROTOCOL_MAJOR_VERSION,
                                                HE_WIRE_MAXIMUM_PROTOCOL_MINOR_VERSION + 1);
  TEST_ASSERT_EQUAL(HE_ERR_INCORRECT_PROTOCOL_VERSION, rc);

  // Valid version
  rc = he_ssl_ctx_set_maximum_supported_version(ctx, 1, 1);
  TEST_ASSERT_EQUAL(HE_SUCCESS, rc);
  TEST_ASSERT_EQUAL(1, ctx->maximum_supported_version.major_version);
  TEST_ASSERT_EQUAL(1, ctx->maximum_supported_version.minor_version);
}

void test_he_ssl_ctx_is_supported_version_same_minimum_version(void) {
  ctx->minimum_supported_version.major_version = 1;
  ctx->minimum_supported_version.minor_version = 0;
  ctx->maximum_supported_version.major_version = 1;
  ctx->maximum_supported_version.minor_version = 0;

  TEST_ASSERT_TRUE(he_ssl_ctx_is_supported_version(ctx, 1, 0));
  TEST_ASSERT_FALSE(he_ssl_ctx_is_supported_version(ctx, 1, 1));
  TEST_ASSERT_FALSE(he_ssl_ctx_is_supported_version(ctx, 2, 0));
}
void test_he_ssl_ctx_is_supported_version_exact_minimum_version(void) {
  ctx->minimum_supported_version.major_version = 1;
  ctx->minimum_supported_version.minor_version = 1;
  ctx->maximum_supported_version.major_version = 1;
  ctx->maximum_supported_version.minor_version = 2;

  TEST_ASSERT_TRUE(he_ssl_ctx_is_supported_version(ctx, 1, 1));
  TEST_ASSERT_FALSE(he_ssl_ctx_is_supported_version(ctx, 1, 0));
}
void test_he_ssl_ctx_is_supported_version_exact_max_version(void) {
  ctx->minimum_supported_version.major_version = 1;
  ctx->minimum_supported_version.minor_version = 1;
  ctx->maximum_supported_version.major_version = 2;
  ctx->maximum_supported_version.minor_version = 2;

  TEST_ASSERT_TRUE(he_ssl_ctx_is_supported_version(ctx, 2, 2));
  TEST_ASSERT_FALSE(he_ssl_ctx_is_supported_version(ctx, 3, 1));
}

void test_he_ssl_ctx_is_supported_version_between_min_max_version(void) {
  ctx->minimum_supported_version.major_version = 1;
  ctx->minimum_supported_version.minor_version = 1;
  ctx->maximum_supported_version.major_version = 3;
  ctx->maximum_supported_version.minor_version = 50;

  TEST_ASSERT_TRUE(he_ssl_ctx_is_supported_version(ctx, 1, 5));
  TEST_ASSERT_TRUE(he_ssl_ctx_is_supported_version(ctx, 1, 56));
  TEST_ASSERT_TRUE(he_ssl_ctx_is_supported_version(ctx, 2, 1));
  TEST_ASSERT_TRUE(he_ssl_ctx_is_supported_version(ctx, 2, 255));
  TEST_ASSERT_TRUE(he_ssl_ctx_is_supported_version(ctx, 3, 0));
  TEST_ASSERT_TRUE(he_ssl_ctx_is_supported_version(ctx, 3, 49));
}

void test_he_ssl_ctx_is_supported_version_extremes(void) {
  ctx->minimum_supported_version.major_version = 1;
  ctx->minimum_supported_version.minor_version = 1;
  ctx->maximum_supported_version.major_version = 1;
  ctx->maximum_supported_version.minor_version = 2;

  TEST_ASSERT_FALSE(he_ssl_ctx_is_supported_version(ctx, 0, 0));
  TEST_ASSERT_FALSE(he_ssl_ctx_is_supported_version(ctx, 255, 255));
}

void test_he_ssl_ctx_is_latest_version(void) {
  ctx->minimum_supported_version.major_version = 1;
  ctx->minimum_supported_version.minor_version = 1;
  ctx->maximum_supported_version.major_version = 1;
  ctx->maximum_supported_version.minor_version = 2;

  TEST_ASSERT_FALSE(he_ssl_ctx_is_latest_version(ctx, 1, 1));
  TEST_ASSERT_FALSE(he_ssl_ctx_is_latest_version(ctx, 3, 1));
  TEST_ASSERT_FALSE(he_ssl_ctx_is_latest_version(ctx, 3, 1));
  TEST_ASSERT_TRUE(he_ssl_ctx_is_latest_version(ctx, 1, 2));
}
// Below this point are rote tests for setters and getters

void test_set_distinguished_name(void) {
  int res = he_ssl_ctx_set_server_dn(ctx, good_username);
  TEST_ASSERT_EQUAL_STRING(good_username, ctx->server_dn);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res);
}

void test_set_distinguished_name_with_long_string(void) {
  int res = he_ssl_ctx_set_server_dn(ctx, bad_string_too_long);
  TEST_ASSERT_EQUAL_STRING("", ctx->server_dn);
  TEST_ASSERT_EQUAL(HE_ERR_STRING_TOO_LONG, res);
}

void test_set_distinguished_name_with_empty_string(void) {
  int res = he_ssl_ctx_set_server_dn(ctx, "");
  TEST_ASSERT_EQUAL_STRING("", ctx->server_dn);
  TEST_ASSERT_EQUAL(HE_ERR_EMPTY_STRING, res);
}

void test_get_server_dn(void) {
  he_ssl_ctx_set_server_dn(ctx, good_username);
  const char *test_username = he_ssl_ctx_get_server_dn(ctx);
  TEST_ASSERT_NOT_NULL(test_username);
  TEST_ASSERT_EQUAL_STRING(good_username, test_username);
}

void test_is_server_dn_set(void) {
  bool res1 = he_ssl_ctx_is_server_dn_set(ctx);
  int res2 = he_ssl_ctx_set_server_dn(ctx, good_username);
  bool res3 = he_ssl_ctx_is_server_dn_set(ctx);

  TEST_ASSERT_EQUAL(false, res1);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res2);
  TEST_ASSERT_EQUAL(true, res3);
}

void test_set_use_chacha20(void) {
  int res1 = he_ssl_ctx_set_use_chacha20(ctx, true);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res1);
}

void test_get_use_chacha20(void) {
  bool res1 = he_ssl_ctx_get_use_chacha20(ctx);
  int res2 = he_ssl_ctx_set_use_chacha20(ctx, true);
  bool res3 = he_ssl_ctx_get_use_chacha20(ctx);
  TEST_ASSERT_EQUAL(false, res1);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res2);
  TEST_ASSERT_EQUAL(true, res3);
}

void test_set_ca(void) {
  int res1 = he_ssl_ctx_set_ca(ctx, fake_cert, sizeof(fake_cert));
  TEST_ASSERT_EQUAL(fake_cert, ctx->cert_buffer);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res1);
}

void test_set_ca_with_null_pointer(void) {
  int res1 = he_ssl_ctx_set_ca(ctx, 0, sizeof(fake_cert));
  TEST_ASSERT_EQUAL(0, ctx->cert_buffer);
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, res1);
}

void test_set_ca_with_zero_size(void) {
  int res1 = he_ssl_ctx_set_ca(ctx, fake_cert, 0);
  TEST_ASSERT_EQUAL(0, ctx->cert_buffer);
  TEST_ASSERT_EQUAL(HE_ERR_ZERO_SIZE, res1);
}

void test_client_is_ca_set(void) {
  bool res1 = he_ssl_ctx_is_ca_set(ctx);
  int res2 = he_ssl_ctx_set_ca(ctx, fake_cert, sizeof(fake_cert));
  bool res3 = he_ssl_ctx_is_ca_set(ctx);

  TEST_ASSERT_EQUAL(false, res1);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res2);
  TEST_ASSERT_EQUAL(true, res3);
}

void test_set_connection_type_streaming(void) {
  int res1 = he_ssl_ctx_set_connection_type(ctx, HE_CONNECTION_TYPE_STREAM);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res1);
  TEST_ASSERT_EQUAL(HE_CONNECTION_TYPE_STREAM, ctx->connection_type);
}

void test_set_connection_type_datagram(void) {
  int res1 = he_ssl_ctx_set_connection_type(ctx, HE_CONNECTION_TYPE_DATAGRAM);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res1);
  TEST_ASSERT_EQUAL(HE_CONNECTION_TYPE_DATAGRAM, ctx->connection_type);
}

void test_set_connection_type_invalid(void) {
  int res1 = he_ssl_ctx_set_connection_type(ctx, 42);
  TEST_ASSERT_EQUAL(HE_ERR_INVALID_CONNECTION_TYPE, res1);
}

void test_is_set_state_change_cb(void) {
  bool res1 = he_ssl_ctx_is_state_change_cb_set(ctx);
  TEST_ASSERT_EQUAL(false, res1);
  he_ssl_ctx_set_state_change_cb(ctx, state_change_cb);
  bool res2 = he_ssl_ctx_is_state_change_cb_set(ctx);
  TEST_ASSERT_EQUAL(true, res2);
  bool res3 = he_ssl_ctx_is_state_change_cb_set(NULL);
  TEST_ASSERT_EQUAL(false, res3);
}

void test_is_set_inside_write_cb(void) {
  bool res1 = he_ssl_ctx_is_inside_write_cb_set(ctx);
  TEST_ASSERT_EQUAL(false, res1);
  he_ssl_ctx_set_inside_write_cb(ctx, write_cb);
  bool res2 = he_ssl_ctx_is_inside_write_cb_set(ctx);
  TEST_ASSERT_EQUAL(true, res2);
  bool res3 = he_ssl_ctx_is_inside_write_cb_set(NULL);
  TEST_ASSERT_EQUAL(false, res3);
}

void test_is_set_outside_write_cb(void) {
  bool res1 = he_ssl_ctx_is_outside_write_cb_set(ctx);
  TEST_ASSERT_EQUAL(false, res1);
  he_ssl_ctx_set_outside_write_cb(ctx, write_cb);
  bool res2 = he_ssl_ctx_is_outside_write_cb_set(ctx);
  TEST_ASSERT_EQUAL(true, res2);
  bool res3 = he_ssl_ctx_is_outside_write_cb_set(NULL);
  TEST_ASSERT_EQUAL(false, res3);
}

void test_is_set_network_config_ipv4_cb(void) {
  bool res1 = he_ssl_ctx_is_network_config_ipv4_cb_set(ctx);
  TEST_ASSERT_EQUAL(false, res1);
  he_ssl_ctx_set_network_config_ipv4_cb(ctx, network_config_ipv4_cb);
  bool res2 = he_ssl_ctx_is_network_config_ipv4_cb_set(ctx);
  TEST_ASSERT_EQUAL(true, res2);
  bool res3 = he_ssl_ctx_is_network_config_ipv4_cb_set(NULL);
  TEST_ASSERT_EQUAL(false, res3);
}

void test_is_set_nudge_time_cb(void) {
  bool res1 = he_ssl_ctx_is_nudge_time_cb_set(ctx);
  TEST_ASSERT_EQUAL(false, res1);
  he_ssl_ctx_set_nudge_time_cb(ctx, nudge_time_cb);
  bool res2 = he_ssl_ctx_is_nudge_time_cb_set(ctx);
  TEST_ASSERT_EQUAL(true, res2);
  bool res3 = he_ssl_ctx_is_nudge_time_cb_set(NULL);
  TEST_ASSERT_EQUAL(false, res3);
}

void test_set_event_cb(void) {
  he_ssl_ctx_set_event_cb(ctx, event_cb);
  TEST_ASSERT_EQUAL(event_cb, ctx->event_cb);
}

void test_set_disable_roaming(void) {
  TEST_ASSERT_FALSE(ctx->disable_roaming_connections);
  he_ssl_ctx_set_disable_roaming(ctx);
  TEST_ASSERT_TRUE(ctx->disable_roaming_connections);
}

void test_is_set_disable_roaming(void) {
  bool res = he_ssl_ctx_is_roaming_disabled(ctx);
  TEST_ASSERT_FALSE(res);
  he_ssl_ctx_set_disable_roaming(ctx);
  res = he_ssl_ctx_is_roaming_disabled(ctx);
  TEST_ASSERT_TRUE(res);
}

void test_set_padding_type(void) {
  // Check it's currently not set
  TEST_ASSERT_EQUAL(HE_PADDING_NONE, ctx->padding_type);
  // Set it
  he_ssl_ctx_set_padding_type(ctx, HE_PADDING_FULL);
  // Check it was set
  TEST_ASSERT_EQUAL(HE_PADDING_FULL, ctx->padding_type);
}

void test_get_padding_type(void) {
  he_padding_type_t res = he_ssl_ctx_get_padding_type(ctx);
  TEST_ASSERT_EQUAL(HE_PADDING_NONE, res);
  ctx->padding_type = HE_PADDING_FULL;
  res = he_ssl_ctx_get_padding_type(ctx);
  TEST_ASSERT_EQUAL(HE_PADDING_FULL, res);
}

void test_set_aggressive_mode(void) {
  TEST_ASSERT_FALSE(ctx->use_aggressive_mode);
  he_ssl_ctx_set_aggressive_mode(ctx);
  TEST_ASSERT_TRUE(ctx->use_aggressive_mode);
}

#ifndef HE_NO_PQC
void test_use_pqc(void) {
  TEST_ASSERT_FALSE(ctx->use_pqc);
  TEST_ASSERT_EQUAL(HE_SUCCESS, he_ssl_ctx_set_use_pqc(ctx, true));
  TEST_ASSERT_TRUE(ctx->use_pqc);
  TEST_ASSERT_EQUAL(HE_SUCCESS, he_ssl_ctx_set_use_pqc(ctx, false));
  TEST_ASSERT_FALSE(ctx->use_pqc);
}
#endif  // HE_NO_PQC

void test_set_nudge_time_cb(void) {
  he_ssl_ctx_set_nudge_time_cb(ctx, nudge_time_cb);

  TEST_ASSERT_EQUAL(nudge_time_cb, ctx->nudge_time_cb);
}

void test_set_network_config_ipv4_cb(void) {
  he_ssl_ctx_set_network_config_ipv4_cb(ctx, network_config_ipv4_cb);
  TEST_ASSERT_EQUAL(network_config_ipv4_cb, ctx->network_config_ipv4_cb);
}

void test_set_server_config_cb(void) {
  he_ssl_ctx_set_server_config_cb(ctx, server_config_cb);
  TEST_ASSERT_EQUAL(server_config_cb, ctx->server_config_cb);
}

void test_set_inside_write_cb(void) {
  he_ssl_ctx_set_inside_write_cb(ctx, write_cb);
  TEST_ASSERT_EQUAL(write_cb, ctx->inside_write_cb);
}

void test_set_auth_cb(void) {
  he_ssl_ctx_set_auth_cb(ctx, auth_cb);
  TEST_ASSERT_EQUAL(auth_cb, ctx->auth_cb);
  TEST_ASSERT_TRUE(he_ssl_ctx_is_auth_cb_set(ctx));
}

void test_is_auth_cb_set_false(void) {
  TEST_ASSERT_FALSE(he_ssl_ctx_is_auth_cb_set(ctx));
}

void test_set_populate_network_config_cb(void) {
  he_ssl_ctx_set_populate_network_config_ipv4_cb(ctx, pop_network_config_cb);
  TEST_ASSERT_EQUAL(pop_network_config_cb, ctx->populate_network_config_ipv4_cb);
}

void test_set_server_cert_nulls(void) {
  int res = he_ssl_ctx_set_server_cert_key_files(ctx, good_username, NULL);
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, res);

  res = he_ssl_ctx_set_server_cert_key_files(ctx, NULL, good_password);
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, res);
}

void test_set_server_cert(void) {
  int res = he_ssl_ctx_set_server_cert_key_files(ctx, good_username, good_password);

  TEST_ASSERT_EQUAL(HE_SUCCESS, res);
  TEST_ASSERT_EQUAL(good_username, ctx->server_cert);
  TEST_ASSERT_EQUAL(good_password, ctx->server_key);
}

void test_is_server_cert_set(void) {
  TEST_ASSERT_FALSE(he_ssl_ctx_is_server_cert_key_set(ctx));

  ctx->server_cert = good_username;
  TEST_ASSERT_FALSE(he_ssl_ctx_is_server_cert_key_set(ctx));

  ctx->server_key = good_password;
  TEST_ASSERT_TRUE(he_ssl_ctx_is_server_cert_key_set(ctx));

  ctx->server_cert = NULL;
  TEST_ASSERT_FALSE(he_ssl_ctx_is_server_cert_key_set(ctx));
}

void test_he_ssl_ctx_set_auth_buf_cb_ctx_null(void) {
  he_ssl_ctx_set_auth_buf_cb(NULL, auth_buf_cb);
}

void test_he_ssl_ctx_set_aggressive_mode_ctx_null(void) {
  he_return_code_t res = he_ssl_ctx_set_aggressive_mode(NULL);
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, res);
}

void test_he_ssl_ctx_set_padding_type_ctx_null(void) {
  he_return_code_t res = he_ssl_ctx_set_padding_type(NULL, HE_PADDING_NONE);
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, res);
}

void test_he_ssl_ctx_is_roaming_disabled_ctx_null(void) {
  bool res = he_ssl_ctx_is_roaming_disabled(NULL);
  TEST_ASSERT_FALSE(res);
}

void test_he_ssl_ctx_set_disable_roaming_ctx_null(void) {
  he_return_code_t res = he_ssl_ctx_set_disable_roaming(NULL);
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, res);
}

void test_he_ssl_ctx_set_populate_network_config_ipv4_cb_ctx_null(void) {
  he_ssl_ctx_set_populate_network_config_ipv4_cb(NULL, pop_network_config_cb);
}

void test_he_ssl_ctx_is_auth_cb_set_ctx_null(void) {
  bool res = he_ssl_ctx_is_auth_cb_set(NULL);
  TEST_ASSERT_FALSE(res);
}

void test_he_ssl_ctx_set_auth_cb_ctx_null(void) {
  he_ssl_ctx_set_auth_cb(NULL, auth_cb);
}

void test_he_ssl_ctx_set_event_cb_ctx_null(void) {
  he_ssl_ctx_set_event_cb(NULL, event_cb);
}

void test_he_ssl_ctx_is_nudge_time_cb_set_ctx_null(void) {
  bool res = he_ssl_ctx_is_nudge_time_cb_set(NULL);
  TEST_ASSERT_FALSE(res);
}

void he_ssl_ctx_set_nudge_time_cb_ctx_null(void) {
  he_ssl_ctx_set_nudge_time_cb(NULL, nudge_time_cb);
}

void he_ssl_ctx_set_network_config_ipv4_cb_ctx_null(void) {
  he_ssl_ctx_set_network_config_ipv4_cb(NULL, network_config_ipv4_cb);
}

void he_ssl_ctx_set_outside_write_cb_ctx_null(void) {
  he_ssl_ctx_set_outside_write_cb(NULL, write_cb);
}

void he_ssl_ctx_set_inside_write_cb_ctx_null(void) {
  he_ssl_ctx_set_inside_write_cb(NULL, write_cb);
}

void test_he_ssl_ctx_is_ca_set_set_ctx_null(void) {
  bool res = he_ssl_ctx_is_ca_set(NULL);
  TEST_ASSERT_FALSE(res);
}

void test_he_ssl_ctx_set_server_cert_key_files_ctx_null(void) {
  he_return_code_t res = he_ssl_ctx_set_server_cert_key_files(NULL, fake_cert, fake_cert);
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, res);
}

void test_he_ssl_ctx_set_ca_ctx_null(void) {
  he_return_code_t res = he_ssl_ctx_set_ca(NULL, fake_cert, 100);
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, res);
}

void test_he_ssl_ctx_set_use_chacha20_ctx_null(void) {
  he_return_code_t res = he_ssl_ctx_set_use_chacha20(NULL, true);
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, res);
}

void test_he_ssl_ctx_get_use_chacha20_ctx_null(void) {
  bool res = he_ssl_ctx_get_use_chacha20(NULL);
  TEST_ASSERT_FALSE(res);
}

void test_he_ssl_ctx_is_server_dn_set_ctx_null(void) {
  bool res = he_ssl_ctx_is_server_dn_set(NULL);
  TEST_ASSERT_FALSE(res);
}

void test_he_ssl_ctx_get_server_dn_ctx_null(void) {
  const char *res = he_ssl_ctx_get_server_dn(NULL);
  TEST_ASSERT_EQUAL(NULL, res);
}

void test_he_ssl_ctx_set_server_dn_ctx_null(void) {
  he_return_code_t res = he_ssl_ctx_set_server_dn(NULL, "dn");
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, res);
}

void test_he_ssl_ctx_is_latest_version_ctx_null(void) {
  bool res = he_ssl_ctx_is_latest_version(NULL, 10, 10);
  TEST_ASSERT_FALSE(res);
}

void test_he_ssl_ctx_is_supported_version_ctx_null(void) {
  bool res = he_ssl_ctx_is_supported_version(NULL, 10, 10);
  TEST_ASSERT_FALSE(res);
}

void test_he_ssl_ctx_start_server_ctx_null(void) {
  he_return_code_t res = he_ssl_ctx_start_server(NULL);
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, res);
}

void test_he_ssl_ctx_start_ctx_null(void) {
  he_return_code_t res = he_ssl_ctx_start(NULL);
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, res);
}
