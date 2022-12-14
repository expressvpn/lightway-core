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
#include "conn.h"

// Direct Includes for Utility Functions
#include "config.h"
#include "memory.h"
#include "ssl_ctx.h"

// Internal Mocks
#include "mock_fake_dispatch.h"
#include "mock_wolf.h"

// External Mocks
#include "mock_ssl.h"
#include "mock_wolfio.h"
// TODO Research whether it's possible to directly use a Wolf header instead of our fake one
#include "mock_fake_rng.h"

he_ssl_ctx_t ssl_ctx;
he_conn_t conn;
he_return_code_t ret;
WOLFSSL wolf_ssl;

void setUp(void) {
  conn.wolf_ssl = &wolf_ssl;
}

void tearDown(void) {
  memset(&ssl_ctx, 0, sizeof(he_ssl_ctx_t));

  memset(&conn, 0, sizeof(he_conn_t));

  memset(&wolf_ssl, 0, sizeof(WOLFSSL));
  call_counter = 0;
}

void test_valid_to_connect_not_null(void) {
  he_conn_t *test = NULL;
  int res1 = he_conn_is_valid_client(&ssl_ctx, test);
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, res1);
}

void test_valid_to_connect_no_username(void) {
  he_conn_t *test = he_conn_create();
  int res1 = he_conn_is_valid_client(&ssl_ctx, test);
  TEST_ASSERT_EQUAL(HE_ERR_CONF_USERNAME_NOT_SET, res1);

  free(test);
}

void test_valid_to_connect_no_password(void) {
  he_conn_t *test = he_conn_create();
  int res1 = he_conn_set_username(test, "myuser");
  TEST_ASSERT_EQUAL(HE_SUCCESS, res1);

  int res2 = he_conn_is_valid_client(&ssl_ctx, test);
  TEST_ASSERT_EQUAL(HE_ERR_CONF_PASSWORD_NOT_SET, res2);

  free(test);
}

void test_valid_to_connect_auth_buffer(void) {
  he_conn_t *test = he_conn_create();
  int res1 = he_conn_set_auth_buffer2(test, fake_ipv4_packet, sizeof(fake_ipv4_packet));
  TEST_ASSERT_EQUAL(HE_SUCCESS, res1);

  int res2 = he_conn_set_outside_mtu(test, HE_MAX_WIRE_MTU);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res2);

  int res3 = he_conn_is_valid_client(&ssl_ctx, test);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res2);
}

void test_valid_to_connect_auth_buffer_and_username_password(void) {
  he_conn_t *test = he_conn_create();
  int res1 = he_conn_set_auth_buffer2(test, fake_ipv4_packet, sizeof(fake_ipv4_packet));
  TEST_ASSERT_EQUAL(HE_SUCCESS, res1);

  int res2 = he_conn_set_username(test, "myuser");
  TEST_ASSERT_EQUAL(HE_SUCCESS, res2);

  int res3 = he_conn_is_valid_client(&ssl_ctx, test);
  TEST_ASSERT_EQUAL(HE_ERR_CONF_CONFLICTING_AUTH_METHODS, res3);
}

void test_valid_to_connect_no_mtu(void) {
  he_conn_t *test = he_conn_create();
  int res1 = he_conn_set_username(test, "myuser");
  TEST_ASSERT_EQUAL(HE_SUCCESS, res1);

  int res2 = he_conn_set_password(test, "mypass");
  TEST_ASSERT_EQUAL(HE_SUCCESS, res2);

  int res3 = he_conn_is_valid_client(&ssl_ctx, test);
  TEST_ASSERT_EQUAL(HE_ERR_CONF_MTU_NOT_SET, res3);

  free(test);
}

void test_valid_to_connect_incorrect_protocol(void) {
  he_conn_t *test = he_conn_create();
  int res1 = he_conn_set_username(test, "myuser");
  TEST_ASSERT_EQUAL(HE_SUCCESS, res1);

  int res2 = he_conn_set_password(test, "mypass");
  TEST_ASSERT_EQUAL(HE_SUCCESS, res2);

  int res3 = he_conn_set_protocol_version(test, 0xFF, 0xFF);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res3);

  int res4 = he_conn_set_outside_mtu(test, HE_MAX_WIRE_MTU);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res4);

  int res5 = he_conn_is_valid_client(&ssl_ctx, test);
  TEST_ASSERT_EQUAL(HE_ERR_INCORRECT_PROTOCOL_VERSION, res5);

  free(test);
}

void test_conn_create_destroy(void) {
  he_conn_t *test_conn = NULL;

  test_conn = he_conn_create();

  TEST_ASSERT_NOT_NULL(test_conn);

  test_conn->wolf_ssl = &wolf_ssl;

  wolfSSL_free_Expect(&wolf_ssl);
  he_conn_destroy(test_conn);
}

void test_set_username(void) {
  int res = he_conn_set_username(&conn, good_username);
  TEST_ASSERT_EQUAL_STRING(good_username, conn.username);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res);
}

void test_set_username_with_long_string(void) {
  int res = he_conn_set_username(&conn, bad_string_too_long);
  TEST_ASSERT_EQUAL_STRING("", conn.username);
  TEST_ASSERT_EQUAL(HE_ERR_STRING_TOO_LONG, res);
}

void test_set_username_with_empty_string(void) {
  int res = he_conn_set_username(&conn, "");
  TEST_ASSERT_EQUAL_STRING("", conn.username);
  TEST_ASSERT_EQUAL(HE_ERR_EMPTY_STRING, res);
}

void test_get_username(void) {
  he_conn_set_username(&conn, good_username);
  const char *test_username = he_conn_get_username(&conn);
  TEST_ASSERT_NOT_NULL(test_username);
  TEST_ASSERT_EQUAL_STRING(good_username, test_username);
}

void test_is_username_set(void) {
  bool res1 = he_conn_is_username_set(&conn);
  int res2 = he_conn_set_username(&conn, good_username);
  bool res3 = he_conn_is_username_set(&conn);

  TEST_ASSERT_EQUAL(false, res1);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res2);
  TEST_ASSERT_EQUAL(true, res3);
}

// Handling Password

void test_set_password(void) {
  int res = he_conn_set_password(&conn, good_password);
  TEST_ASSERT_EQUAL_STRING(good_password, conn.password);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res);
}

void test_set_password_with_long_string(void) {
  int res = he_conn_set_password(&conn, bad_string_too_long);
  TEST_ASSERT_EQUAL_STRING("", conn.password);
  TEST_ASSERT_EQUAL(HE_ERR_STRING_TOO_LONG, res);
}

void test_set_password_with_empty_string(void) {
  int res = he_conn_set_password(&conn, "");
  TEST_ASSERT_EQUAL_STRING("", conn.password);
  TEST_ASSERT_EQUAL(HE_ERR_EMPTY_STRING, res);
}

void test_is_password_set(void) {
  bool res1 = he_conn_is_password_set(&conn);
  int res2 = he_conn_set_password(&conn, good_password);
  bool res3 = he_conn_is_password_set(&conn);

  TEST_ASSERT_EQUAL(false, res1);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res2);
  TEST_ASSERT_EQUAL(true, res3);
}

// Handling Auth buffer

void test_set_auth_buffer(void) {
  int res1 = he_conn_set_auth_buffer2(&conn, fake_ipv4_packet, sizeof(fake_ipv4_packet));

  TEST_ASSERT_EQUAL(HE_SUCCESS, res1);
  TEST_ASSERT_EQUAL(HE_AUTH_TYPE_CB, conn.auth_type);
  TEST_ASSERT_EQUAL(sizeof(fake_ipv4_packet), conn.auth_buffer_length);
  TEST_ASSERT_EQUAL_UINT8_ARRAY(fake_ipv4_packet, conn.auth_buffer, conn.auth_buffer_length);
}

void test_set_auth_buffer_too_long(void) {
  int res1 = he_conn_set_auth_buffer2(&conn, fake_ipv4_packet, HE_MAX_MTU);
  TEST_ASSERT_EQUAL(HE_ERR_STRING_TOO_LONG, res1);
}

void test_set_auth_buffer_nulls(void) {
  int res1 = he_conn_set_auth_buffer2(NULL, fake_ipv4_packet, sizeof(fake_ipv4_packet));
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, res1);
  int res2 = he_conn_set_auth_buffer2(&conn, NULL, sizeof(fake_ipv4_packet));
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, res2);
}

void test_set_auth_buffer_empty(void) {
  int res1 = he_conn_set_auth_buffer2(&conn, fake_ipv4_packet, 0);
  TEST_ASSERT_EQUAL(HE_ERR_EMPTY_STRING, res1);
}

void test_is_auth_buffer_set(void) {
  bool res1 = he_conn_is_auth_buffer_set(&conn);
  int res2 = he_conn_set_auth_buffer2(&conn, fake_ipv4_packet, sizeof(fake_ipv4_packet));
  bool res3 = he_conn_is_auth_buffer_set(&conn);

  TEST_ASSERT_EQUAL(false, res1);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res2);
  TEST_ASSERT_EQUAL(true, res3);
}

// Other getters and setters

void test_set_mtu(void) {
  int res1 = he_conn_set_outside_mtu(&conn, 10);
  TEST_ASSERT_EQUAL(10, conn.outside_mtu);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res1);
}

void test_get_mtu(void) {
  int res1 = he_conn_set_outside_mtu(&conn, 10);
  TEST_ASSERT_EQUAL(10, conn.outside_mtu);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res1);

  int res2 = he_conn_get_outside_mtu(&conn);
  TEST_ASSERT_EQUAL(10, res2);
}

void test_is_mtu_set(void) {
  bool res1 = he_conn_is_outside_mtu_set(&conn);
  int res2 = he_conn_set_outside_mtu(&conn, 10);
  bool res3 = he_conn_is_outside_mtu_set(&conn);
  TEST_ASSERT_EQUAL(false, res1);
  TEST_ASSERT_EQUAL(10, conn.outside_mtu);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res2);
  TEST_ASSERT_EQUAL(true, res3);
}

void test_set_context(void) {
  char test = 'x';

  he_conn_set_context(&conn, &test);
  TEST_ASSERT_EQUAL(&test, conn.data);
}

void test_get_context(void) {
  void *context = he_conn_get_context(&conn);
  TEST_ASSERT_NULL(context);
  int res1 = he_conn_set_context(&conn, fake_cert);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res1);
  context = he_conn_get_context(&conn);
  TEST_ASSERT_EQUAL(fake_cert, context);
}

void test_dont_call_state_change_cb_for_same_state(void) {
  // Check the counter is at zero
  TEST_ASSERT_EQUAL(0, call_counter);

  // Set our test callback - just increments the counter
  conn.state_change_cb = state_cb;

  // Cause a state change
  he_internal_change_conn_state(&conn, HE_STATE_CONNECTING);
  // Check it incremented by 1
  TEST_ASSERT_EQUAL(1, call_counter);

  // Do it again
  he_internal_change_conn_state(&conn, HE_STATE_CONNECTING);
  // Check it incremented by 1
  TEST_ASSERT_EQUAL(1, call_counter);
}

void test_call_state_change_cb_for_new_states(void) {
  // Check the counter is at zero
  TEST_ASSERT_EQUAL(0, call_counter);

  // Set our test callback - just increments the counter
  conn.state_change_cb = state_cb;

  // Cause a state change
  he_internal_change_conn_state(&conn, HE_STATE_CONNECTING);
  // Check it incremented by 1
  TEST_ASSERT_EQUAL(1, call_counter);

  // Do it again
  he_internal_change_conn_state(&conn, HE_STATE_ONLINE);
  // Check it incremented by 1
  TEST_ASSERT_EQUAL(2, call_counter);
}

void test_get_nudge_time(void) {
  // Set this manually as it will be set by Wolf after a read callback
  conn.wolf_timeout = 5;
  int res1 = he_conn_get_nudge_time(&conn);
  TEST_ASSERT_EQUAL(5, res1);
}

void test_get_nudge_time_while_connected(void) {
  // Set this manually as it will be set by Wolf after a read callback
  conn.wolf_timeout = 5;
  conn.state = HE_STATE_ONLINE;

  int res1 = he_conn_get_nudge_time(&conn);
  TEST_ASSERT_EQUAL(0, res1);
}

void test_get_nudge_time_while_connected_renegotiating(void) {
  // Set this manually as it will be set by Wolf after a read callback
  conn.wolf_timeout = 5;
  conn.state = HE_STATE_ONLINE;
  conn.renegotiation_in_progress = true;

  int res1 = he_conn_get_nudge_time(&conn);
  TEST_ASSERT_EQUAL(5, res1);
}

void test_he_internal_update_timeout_online(void) {
  TEST_ASSERT_EQUAL(0, call_counter);
  conn.state = HE_STATE_ONLINE;

  he_internal_update_timeout(&conn);
  TEST_ASSERT_EQUAL(0, call_counter);
}

void test_he_internal_update_timeout(void) {
  TEST_ASSERT_EQUAL(0, call_counter);

  wolfSSL_dtls_get_current_timeout_ExpectAndReturn(conn.wolf_ssl, 10);
  he_internal_update_timeout(&conn);
  TEST_ASSERT_EQUAL(conn.wolf_timeout, 10 * HE_WOLF_TIMEOUT_MULTIPLIER);

  TEST_ASSERT_EQUAL(0, call_counter);
}

void test_he_internal_update_timeout_renegotiation(void) {
  TEST_ASSERT_EQUAL(0, call_counter);
  conn.renegotiation_in_progress = true;

  wolfSSL_dtls_get_current_timeout_ExpectAndReturn(conn.wolf_ssl, 10);
  he_internal_update_timeout(&conn);
  TEST_ASSERT_EQUAL(conn.wolf_timeout, 10 * HE_WOLF_RENEGOTIATION_TIMEOUT_MULTIPLIER);

  TEST_ASSERT_EQUAL(0, call_counter);
}

void test_get_nudge_time_while_connected_renegotiating_bad_state(void) {
  // Set this manually as it will be set by Wolf after a read callback
  conn.wolf_timeout = 5;
  conn.state = HE_STATE_NONE;
  conn.renegotiation_in_progress = false;

  int res1 = he_conn_get_nudge_time(&conn);
  TEST_ASSERT_EQUAL(5, res1);
}

void test_he_internal_update_timeout_with_cb(void) {
  conn.nudge_time_cb = nudge_time_cb;

  wolfSSL_dtls_get_current_timeout_ExpectAndReturn(conn.wolf_ssl, 10);
  TEST_ASSERT_EQUAL(0, call_counter);
  he_internal_update_timeout(&conn);
  TEST_ASSERT_EQUAL(1, call_counter);
}

void test_he_nudge_connection_timed_out(void) {
  wolfSSL_dtls_got_timeout_ExpectAndReturn(conn.wolf_ssl, SSL_FATAL_ERROR);
  wolfSSL_get_error_ExpectAndReturn(conn.wolf_ssl, SSL_FATAL_ERROR, SSL_FATAL_ERROR);
  int res1 = he_conn_nudge(&conn);
  TEST_ASSERT_EQUAL(HE_CONNECTION_TIMED_OUT, res1);
}

void test_he_nudge(void) {
  wolfSSL_dtls_got_timeout_ExpectAndReturn(conn.wolf_ssl, SSL_SUCCESS);
  wolfSSL_dtls_get_current_timeout_ExpectAndReturn(conn.wolf_ssl, 10);
  int res1 = he_conn_nudge(&conn);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res1);
}

void test_he_nudge_need_read(void) {
  wolfSSL_dtls_got_timeout_ExpectAndReturn(conn.wolf_ssl, SSL_FATAL_ERROR);
  wolfSSL_get_error_ExpectAndReturn(conn.wolf_ssl, SSL_FATAL_ERROR, SSL_ERROR_WANT_READ);
  wolfSSL_dtls_get_current_timeout_ExpectAndReturn(conn.wolf_ssl, 10);
  int res1 = he_conn_nudge(&conn);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res1);
}

void test_he_nudge_need_write(void) {
  wolfSSL_dtls_got_timeout_ExpectAndReturn(conn.wolf_ssl, SSL_FATAL_ERROR);
  wolfSSL_get_error_ExpectAndReturn(conn.wolf_ssl, SSL_FATAL_ERROR, SSL_ERROR_WANT_WRITE);
  wolfSSL_dtls_get_current_timeout_ExpectAndReturn(conn.wolf_ssl, 10);
  int res1 = he_conn_nudge(&conn);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res1);
}

void test_he_nudge_with_cb(void) {
  conn.nudge_time_cb = nudge_time_cb;
  wolfSSL_dtls_got_timeout_ExpectAndReturn(conn.wolf_ssl, SSL_SUCCESS);
  wolfSSL_dtls_get_current_timeout_ExpectAndReturn(conn.wolf_ssl, 10);
  int res = he_conn_nudge(&conn);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res);
  TEST_ASSERT_EQUAL(1, call_counter);
}

void test_he_get_state(void) {
  // Change state
  he_internal_change_conn_state(&conn, HE_STATE_ONLINE);
  he_conn_state_t state = he_conn_get_state(&conn);
  TEST_ASSERT_EQUAL(HE_STATE_ONLINE, state);
}

void test_he_disconnect(void) {
  conn.state = HE_STATE_ONLINE;
  wolfSSL_write_IgnoreAndReturn(SSL_SUCCESS);
  wolfSSL_shutdown_ExpectAndReturn(conn.wolf_ssl, SSL_SUCCESS);
  conn.state_change_cb = state_change_cb;
  TEST_ASSERT_EQUAL(0, call_counter);
  int res1 = he_conn_disconnect(&conn);
  TEST_ASSERT_EQUAL(2, call_counter);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res1);
}

void test_send_keepalive_error_when_not_connected(void) {
  int res = he_conn_send_keepalive(&conn);
  TEST_ASSERT_EQUAL(HE_ERR_INVALID_CONN_STATE, res);
}

void test_send_keepalive_connected(void) {
  conn.state = HE_STATE_ONLINE;
  wolfSSL_write_IgnoreAndReturn(SSL_SUCCESS);
  int res = he_conn_send_keepalive(&conn);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res);
}

void test_disconnect_in_valid_states_sends_goodbye_and_shuts_down(void) {
  he_conn_state_t states[] = {HE_STATE_AUTHENTICATING, HE_STATE_CONFIGURING, HE_STATE_LINK_UP,
                              HE_STATE_ONLINE};
  for(int i = 0; i < sizeof(states) / sizeof(states[0]); ++i) {
    conn.state = states[i];
    conn.outside_write_cb = write_cb;
    conn.inside_write_cb = write_cb;
    // Sending goodbye
    wolfSSL_write_ExpectAnyArgsAndReturn(SSL_SUCCESS);
    // Shuts down the TLS connection
    wolfSSL_shutdown_ExpectAndReturn(conn.wolf_ssl, SSL_SUCCESS);
    he_return_code_t res = he_conn_disconnect(&conn);
    TEST_ASSERT_EQUAL(HE_SUCCESS, res);

    TEST_ASSERT_EQUAL(HE_STATE_DISCONNECTED, conn.state);
    TEST_ASSERT_EQUAL(NULL, conn.outside_write_cb);
    TEST_ASSERT_EQUAL(NULL, conn.inside_write_cb);
  }
}

void test_disconnect_reject_if_in_invalid_states(void) {
  he_conn_state_t states[] = {HE_STATE_NONE, HE_STATE_DISCONNECTED, HE_STATE_DISCONNECTING,
                              HE_STATE_CONNECTING};
  for(int i = 0; i < sizeof(states) / sizeof(states[0]); ++i) {
    conn.state = states[i];
    he_return_code_t res = he_conn_disconnect(&conn);
    TEST_ASSERT_EQUAL(HE_ERR_INVALID_CONN_STATE, res);
  }
}

void test_no_segfault_on_disconnect_before_initialisation(void) {
  conn.wolf_ssl = NULL;
  wolfSSL_shutdown_IgnoreAndReturn(SSL_FATAL_ERROR);
  he_return_code_t res = he_conn_disconnect(&conn);
  TEST_ASSERT_EQUAL(HE_ERR_NEVER_CONNECTED, res);
}

void test_he_nudge_doesnt_trigger_callback_when_online(void) {
  // Should get through the first time, but not the second
  conn.nudge_time_cb = nudge_time_cb;
  wolfSSL_dtls_got_timeout_ExpectAndReturn(conn.wolf_ssl, SSL_SUCCESS);
  wolfSSL_dtls_get_current_timeout_ExpectAndReturn(conn.wolf_ssl, 10);
  he_return_code_t res = he_conn_nudge(&conn);
  TEST_ASSERT_EQUAL(1, call_counter);
  // Now we're online - callback shouldn't get called
  conn.state = HE_STATE_ONLINE;
  wolfSSL_dtls_got_timeout_ExpectAndReturn(conn.wolf_ssl, SSL_SUCCESS);
  res = he_conn_nudge(&conn);
  TEST_ASSERT_EQUAL(1, call_counter);
}

void test_he_send_auth_should_not_reject_in_authenticating_state(void) {
  conn.state = HE_STATE_AUTHENTICATING;
  conn.auth_type = HE_AUTH_TYPE_USERPASS;
  wolfSSL_write_IgnoreAndReturn(100);
  he_return_code_t res = he_internal_send_auth(&conn);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res);
}

void test_he_nudge_sends_auth_in_authenticating_state(void) {
  conn.state = HE_STATE_AUTHENTICATING;
  dispatch_ExpectAndReturn("he_internal_send_auth", HE_SUCCESS);
  wolfSSL_dtls_get_current_timeout_ExpectAndReturn(conn.wolf_ssl, 10);

  he_conn_nudge(&conn);
}

void test_calculate_data_padding_check_default_is_none(void) {
  size_t res = he_internal_calculate_data_packet_length(&conn, 10);
  TEST_ASSERT_EQUAL(10, res);
}

void test_calculate_data_padding_full_small(void) {
  conn.padding_type = HE_PADDING_FULL;
  size_t res = he_internal_calculate_data_packet_length(&conn, 10);
  TEST_ASSERT_EQUAL(HE_MAX_MTU, res);
}

void test_calculate_data_padding_full_medium(void) {
  conn.padding_type = HE_PADDING_FULL;
  size_t res = he_internal_calculate_data_packet_length(&conn, 460);
  TEST_ASSERT_EQUAL(HE_MAX_MTU, res);
}

void test_calculate_data_padding_full_large(void) {
  conn.padding_type = HE_PADDING_FULL;
  size_t res = he_internal_calculate_data_packet_length(&conn, 910);
  TEST_ASSERT_EQUAL(HE_MAX_MTU, res);
}

void test_calculate_data_padding_none_small(void) {
  conn.padding_type = HE_PADDING_NONE;
  size_t res = he_internal_calculate_data_packet_length(&conn, 10);
  TEST_ASSERT_EQUAL(10, res);
}

void test_calculate_data_padding_none_medium(void) {
  conn.padding_type = HE_PADDING_NONE;
  size_t res = he_internal_calculate_data_packet_length(&conn, 460);
  TEST_ASSERT_EQUAL(460, res);
}

void test_calculate_data_padding_none_large(void) {
  conn.padding_type = HE_PADDING_NONE;
  size_t res = he_internal_calculate_data_packet_length(&conn, 910);
  TEST_ASSERT_EQUAL(910, res);
}

void test_calculate_data_padding_small(void) {
  conn.padding_type = HE_PADDING_450;
  size_t res = he_internal_calculate_data_packet_length(&conn, 10);
  TEST_ASSERT_EQUAL(450, res);
}

void test_calculate_data_padding_medium(void) {
  conn.padding_type = HE_PADDING_450;
  size_t res = he_internal_calculate_data_packet_length(&conn, 460);
  TEST_ASSERT_EQUAL(900, res);
}

void test_calculate_data_padding_large(void) {
  conn.padding_type = HE_PADDING_450;
  size_t res = he_internal_calculate_data_packet_length(&conn, 910);
  TEST_ASSERT_EQUAL(HE_MAX_MTU, res);
}

void test_calculate_data_padding_small_edge(void) {
  conn.padding_type = HE_PADDING_450;
  size_t res = he_internal_calculate_data_packet_length(&conn, 450);
  TEST_ASSERT_EQUAL(450, res);
}

void test_calculate_data_padding_medium_edge(void) {
  conn.padding_type = HE_PADDING_450;
  size_t res = he_internal_calculate_data_packet_length(&conn, 900);
  TEST_ASSERT_EQUAL(900, res);
}

void test_calculate_data_padding_large_edge(void) {
  conn.padding_type = HE_PADDING_450;
  size_t res = he_internal_calculate_data_packet_length(&conn, HE_MAX_MTU);
  TEST_ASSERT_EQUAL(HE_MAX_MTU, res);
}

void test_he_internal_send_message(void) {
  wolfSSL_write_ExpectAndReturn(conn.wolf_ssl, fake_ipv4_packet, sizeof(fake_ipv4_packet),
                                sizeof(fake_ipv4_packet));

  int rc = he_internal_send_message(&conn, fake_ipv4_packet, sizeof(fake_ipv4_packet));
  TEST_ASSERT_EQUAL(HE_SUCCESS, rc);
}

void test_he_internal_send_message_connection_was_closed(void) {
  wolfSSL_write_ExpectAndReturn(conn.wolf_ssl, fake_ipv4_packet, sizeof(fake_ipv4_packet), 0);
  wolfSSL_get_error_ExpectAndReturn(conn.wolf_ssl, 0, SSL_FATAL_ERROR);
  int rc = he_internal_send_message(&conn, fake_ipv4_packet, sizeof(fake_ipv4_packet));
  TEST_ASSERT_EQUAL(HE_ERR_CONNECTION_WAS_CLOSED, rc);
}

void test_he_internal_send_message_ssl_error_none(void) {
  wolfSSL_write_ExpectAndReturn(conn.wolf_ssl, fake_ipv4_packet, sizeof(fake_ipv4_packet), 0);
  wolfSSL_get_error_ExpectAndReturn(conn.wolf_ssl, 0, SSL_ERROR_NONE);
  int rc = he_internal_send_message(&conn, fake_ipv4_packet, sizeof(fake_ipv4_packet));
  TEST_ASSERT_EQUAL(HE_SUCCESS, rc);
}

void test_he_internal_send_message_ssl_want_write(void) {
  wolfSSL_write_ExpectAndReturn(conn.wolf_ssl, fake_ipv4_packet, sizeof(fake_ipv4_packet), -1);
  wolfSSL_get_error_ExpectAndReturn(conn.wolf_ssl, -1, SSL_ERROR_WANT_WRITE);
  int rc = he_internal_send_message(&conn, fake_ipv4_packet, sizeof(fake_ipv4_packet));
  TEST_ASSERT_EQUAL(HE_WANT_WRITE, rc);
}

void test_he_internal_send_message_ssl_want_read(void) {
  wolfSSL_write_ExpectAndReturn(conn.wolf_ssl, fake_ipv4_packet, sizeof(fake_ipv4_packet), -1);
  wolfSSL_get_error_ExpectAndReturn(conn.wolf_ssl, -1, SSL_ERROR_WANT_READ);
  int rc = he_internal_send_message(&conn, fake_ipv4_packet, sizeof(fake_ipv4_packet));
  TEST_ASSERT_EQUAL(HE_WANT_READ, rc);
}

void test_he_internal_send_message_ssl_error(void) {
  wolfSSL_write_ExpectAndReturn(conn.wolf_ssl, fake_ipv4_packet, sizeof(fake_ipv4_packet), -1);
  wolfSSL_get_error_ExpectAndReturn(conn.wolf_ssl, -1, SSL_FATAL_ERROR);
  int rc = he_internal_send_message(&conn, fake_ipv4_packet, sizeof(fake_ipv4_packet));
  TEST_ASSERT_EQUAL(HE_ERR_SSL_ERROR, rc);
}

void test_he_internal_update_timeout_with_cb_multiple_calls(void) {
  conn.nudge_time_cb = nudge_time_cb;

  wolfSSL_dtls_get_current_timeout_ExpectAndReturn(conn.wolf_ssl, 10);
  wolfSSL_dtls_get_current_timeout_ExpectAndReturn(conn.wolf_ssl, 10);
  wolfSSL_dtls_got_timeout_ExpectAndReturn(conn.wolf_ssl, 1);
  wolfSSL_dtls_get_current_timeout_ExpectAndReturn(conn.wolf_ssl, 10);
  wolfSSL_dtls_get_current_timeout_ExpectAndReturn(conn.wolf_ssl, 10);
  TEST_ASSERT_EQUAL(0, call_counter);
  he_internal_update_timeout(&conn);
  TEST_ASSERT_EQUAL(1, call_counter);
  // Should still be 1 as the callback should not have been called
  // as the timer hasn't been cleared yet
  he_internal_update_timeout(&conn);
  TEST_ASSERT_EQUAL(1, call_counter);
  // Let's clear the timeout with a nudge
  int res1 = he_conn_nudge(&conn);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res1);
  // Try the callback again
  he_internal_update_timeout(&conn);
  // Now it should have incremented
  TEST_ASSERT_EQUAL(2, call_counter);
}

void test_event_generation(void) {
  conn.event_cb = event_cb;
  he_internal_generate_event(&conn, HE_EVENT_FIRST_MESSAGE_RECEIVED);

  TEST_ASSERT_EQUAL(1, call_counter);
}

void test_event_generation_no_cb(void) {
  conn.event_cb = NULL;
  he_internal_generate_event(&conn, HE_EVENT_FIRST_MESSAGE_RECEIVED);

  TEST_ASSERT_EQUAL(0, call_counter);
}

void test_he_conn_generate_session_id(void) {
  uint64_t test_session = 0;
  wc_RNG_GenerateBlock_ExpectAndReturn(&conn.wolf_rng, (byte *)&test_session, sizeof(uint64_t), 0);

  int res = he_internal_generate_session_id(&conn, &test_session);

  TEST_ASSERT_EQUAL(HE_SUCCESS, res);
}

void test_he_conn_generate_session_id_error(void) {
  uint64_t test_session = 0;
  wc_RNG_GenerateBlock_ExpectAndReturn(&conn.wolf_rng, (byte *)&test_session, sizeof(uint64_t),
                                       FIXTURE_FATAL_ERROR);

  int res = he_internal_generate_session_id(&conn, &test_session);
  TEST_ASSERT_EQUAL(HE_ERR_RNG_FAILURE, res);
  TEST_ASSERT_EQUAL(0, test_session);
}

void test_he_conn_rotate_session_id_client(void) {
  uint64_t test_session = 0;

  conn.is_server = false;

  int res = he_conn_rotate_session_id(&conn, &test_session);

  TEST_ASSERT_EQUAL(HE_ERR_INVALID_CONN_STATE, res);
}

void test_he_conn_rotate_session_id_client_null_conn(void) {
  uint64_t test_session = 0;

  conn.is_server = false;

  int res = he_conn_rotate_session_id(NULL, &test_session);

  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, res);
}

void test_he_conn_rotate_session_id_already_pending(void) {
  uint64_t test_session = 0;
  conn.is_server = true;

  conn.pending_session_id = 0xdeadbeef;

  int res = he_conn_rotate_session_id(&conn, &test_session);

  TEST_ASSERT_EQUAL(HE_ERR_INVALID_CONN_STATE, res);
}

void test_he_conn_rotate_session_id_rng_failure(void) {
  uint64_t test_session = 0;
  conn.is_server = true;

  wc_RNG_GenerateBlock_ExpectAndReturn(&conn.wolf_rng, (byte *)NULL, sizeof(uint64_t),
                                       FIXTURE_FATAL_ERROR);
  wc_RNG_GenerateBlock_IgnoreArg_bytes();
  int res = he_conn_rotate_session_id(&conn, &test_session);

  TEST_ASSERT_EQUAL(HE_ERR_RNG_FAILURE, res);
}

int fixture_wc_RNG_GenerateBlock(RNG *rng, unsigned char *bytes, unsigned int size, int numCalls) {
  TEST_ASSERT_EQUAL(&conn.wolf_rng, rng);
  TEST_ASSERT_EQUAL(sizeof(uint64_t), size);

  uint64_t *number = (uint64_t *)bytes;
  *number = 0xdeadbeef;

  //(&conn.wolf_rng, (byte *)&test_session, sizeof(uint64_t), -1);
  return 0;
}

void test_he_conn_rotate_session_id(void) {
  uint64_t test_session = 0;
  conn.is_server = true;

  wc_RNG_GenerateBlock_Stub(fixture_wc_RNG_GenerateBlock);

  int res = he_conn_rotate_session_id(&conn, &test_session);

  TEST_ASSERT_EQUAL(HE_SUCCESS, res);
  TEST_ASSERT_EQUAL(0xdeadbeef, conn.pending_session_id);
  TEST_ASSERT_EQUAL(0xdeadbeef, test_session);
}

void test_he_conn_rotate_session_id_no_output(void) {
  conn.is_server = true;

  wc_RNG_GenerateBlock_Stub(fixture_wc_RNG_GenerateBlock);

  int res = he_conn_rotate_session_id(&conn, NULL);

  TEST_ASSERT_EQUAL(HE_SUCCESS, res);
  TEST_ASSERT_EQUAL(0xdeadbeef, conn.pending_session_id);
}

void test_he_conn_get_session_id(void) {
  uint64_t test_session = 0x00FF00FF00FF00FF;
  conn.session_id = test_session;

  uint64_t res = he_conn_get_session_id(&conn);
  TEST_ASSERT_EQUAL(test_session, res);
}

void test_he_conn_get_pending_session_id(void) {
  uint64_t test_session = 0x00FF00FF00FF00FF;
  conn.pending_session_id = test_session;

  uint64_t res = he_conn_get_pending_session_id(&conn);
  TEST_ASSERT_EQUAL(test_session, res);
}

void test_he_conn_set_session_id(void) {
  uint64_t test_session = 0x00FF00FF00FF00FF;

  // Check it's zero'd first
  TEST_ASSERT_EQUAL(0, conn.session_id);

  he_return_code_t res = he_conn_set_session_id(&conn, test_session);
  TEST_ASSERT_EQUAL(test_session, conn.session_id);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res);
}

void test_he_conn_set_session_id_already_set(void) {
  uint64_t test_session = 0x00FF00FF00FF00FF;
  uint64_t init_session = 0xFFFFFFFF00000000;

  conn.session_id = init_session;

  // Check it's set first
  TEST_ASSERT_EQUAL(init_session, conn.session_id);

  he_return_code_t res = he_conn_set_session_id(&conn, test_session);
  TEST_ASSERT_EQUAL(init_session, conn.session_id);
  TEST_ASSERT_EQUAL(HE_ERR_INVALID_CONN_STATE, res);
}

void test_he_conn_set_session_id_null_check(void) {
  he_return_code_t res = he_conn_set_session_id(NULL, 0);
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, res);
}

void test_he_conn_supports_renegotiation_is_null(void) {
  bool res = he_conn_supports_renegotiation(NULL);
  TEST_ASSERT_FALSE(res);
}

void test_he_conn_supports_renegotiation(void) {
  wolfSSL_SSL_get_secure_renegotiation_support_ExpectAndReturn(conn.wolf_ssl, true);
  bool res = he_conn_supports_renegotiation(&conn);
  TEST_ASSERT_TRUE(res);
}

void test_he_conn_set_protocol_version_null_conn(void) {
  he_return_code_t res = he_conn_set_protocol_version(NULL, 0x01, 0x01);
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, res);
}

// In general we try to avoid complex macros in libhelium, but these tests are so repetitive the
// value of capturing these lines outweighs to conns
#define HE_IS_FATAL_TEST(expected, error_code)     \
  res = he_conn_is_error_fatal(&conn, error_code); \
  TEST_ASSERT_EQUAL(expected, res);

void test_he_conn_is_error_fatal_streaming(void) {
  bool res = false;
  conn.connection_type = HE_CONNECTION_TYPE_STREAM;
  for(int i = 0; i >= HE_ERR_INVALID_AUTH_TYPE; i--) {
    switch(i) {
      case HE_SUCCESS:
      case HE_ERR_SSL_ERROR_NONFATAL:
      case HE_WANT_READ:
      case HE_WANT_WRITE:
      case HE_ERR_NOT_CONNECTED:
        HE_IS_FATAL_TEST(false, i);
        break;
      default:
        HE_IS_FATAL_TEST(true, i);
        break;
    }
  }
}

void test_he_conn_is_error_fatal_code_for_datagram(void) {
  bool res = false;
  conn.connection_type = HE_CONNECTION_TYPE_DATAGRAM;
  for(int i = 0; i >= HE_ERR_INVALID_AUTH_TYPE; i--) {
    switch(i) {
      case HE_SUCCESS:
      case HE_ERR_INVALID_CONN_STATE:
      case HE_ERR_SSL_ERROR_NONFATAL:
      case HE_WANT_READ:
      case HE_WANT_WRITE:
      case HE_ERR_NOT_CONNECTED:
      case HE_ERR_EMPTY_PACKET:
      case HE_ERR_PACKET_TOO_SMALL:
      case HE_ERR_NOT_HE_PACKET:
      case HE_ERR_UNSUPPORTED_PACKET_TYPE:
      case HE_ERR_BAD_PACKET:
      case HE_ERR_UNKNOWN_SESSION:
        HE_IS_FATAL_TEST(false, i);
        break;
      default:
        HE_IS_FATAL_TEST(true, i);
        break;
    }
  }
}

void test_he_conn_is_valid_server_no_mtu_set(void) {
  he_return_code_t res = he_conn_is_valid_server(&ssl_ctx, &conn);
  TEST_ASSERT_EQUAL(HE_ERR_CONF_MTU_NOT_SET, res);
}

void test_he_conn_is_valid_server_bad_protocol(void) {
  he_return_code_t res1 = he_conn_set_outside_mtu(&conn, 1500);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res1);

  he_return_code_t res2 = he_conn_set_protocol_version(&conn, 0xFF, 0xFF);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res2);

  he_return_code_t res3 = he_conn_is_valid_server(&ssl_ctx, &conn);
  TEST_ASSERT_EQUAL(HE_ERR_INCORRECT_PROTOCOL_VERSION, res3);
}

void test_he_conn_is_valid_server(void) {
  he_return_code_t res1 = he_conn_set_outside_mtu(&conn, 1500);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res1);

  he_return_code_t res2 = he_conn_set_protocol_version(&conn, 0x00, 0x00);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res2);

  he_return_code_t res3 = he_conn_is_valid_server(&ssl_ctx, &conn);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res3);
}

void test_he_conn_schedule_renegotiation(void) {
  TEST_ASSERT_FALSE(conn.renegotiation_due);

  he_return_code_t res = he_conn_schedule_renegotiation(&conn);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res);

  TEST_ASSERT_TRUE(conn.renegotiation_due);
}

void test_he_internal_renegotiate_ssl_not_online(void) {
  he_return_code_t res = he_internal_renegotiate_ssl(&conn);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res);
}

void test_he_internal_renegotiate_ssl_already_renegotiating(void) {
  // Set our state online and set renegotiation in progress
  conn.state = HE_STATE_ONLINE;
  conn.renegotiation_in_progress = true;

  he_return_code_t res = he_internal_renegotiate_ssl(&conn);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res);
}

void test_he_internal_renegotiate_dtls(void) {
  // Set our state online and set renegotiation in progress
  conn.state = HE_STATE_ONLINE;
  conn.renegotiation_in_progress = false;

  wolfSSL_SSL_get_secure_renegotiation_support_ExpectAndReturn(conn.wolf_ssl, true);
  wolfSSL_Rehandshake_ExpectAndReturn(conn.wolf_ssl, SSL_SUCCESS);

  he_return_code_t res = he_internal_renegotiate_ssl(&conn);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res);
}

void test_he_internal_renegotiate_dtls_not_supported(void) {
  // Set our state online and set renegotiation in progress
  conn.state = HE_STATE_ONLINE;
  conn.renegotiation_in_progress = false;

  wolfSSL_SSL_get_secure_renegotiation_support_ExpectAndReturn(conn.wolf_ssl, false);

  he_return_code_t res = he_internal_renegotiate_ssl(&conn);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res);
}

void test_he_internal_renegotiate_tls(void) {
  // Set our state online and set renegotiation in progress
  conn.state = HE_STATE_ONLINE;
  conn.renegotiation_in_progress = false;
  conn.connection_type = HE_CONNECTION_TYPE_STREAM;

  wolfSSL_SSL_get_secure_renegotiation_support_ExpectAndReturn(conn.wolf_ssl, false);
  wolfSSL_update_keys_ExpectAndReturn(conn.wolf_ssl, SSL_SUCCESS);

  he_return_code_t res = he_internal_renegotiate_ssl(&conn);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res);
}

void test_he_internal_renegotiate_ssl_error_want_read(void) {
  // Set our state online and set renegotiation in progress
  conn.state = HE_STATE_ONLINE;
  conn.renegotiation_in_progress = false;

  wolfSSL_SSL_get_secure_renegotiation_support_ExpectAndReturn(conn.wolf_ssl, true);
  wolfSSL_Rehandshake_ExpectAndReturn(conn.wolf_ssl, SSL_FATAL_ERROR);
  wolfSSL_get_error_ExpectAndReturn(conn.wolf_ssl, SSL_FATAL_ERROR, SSL_ERROR_WANT_READ);
  wolfSSL_dtls_get_current_timeout_ExpectAndReturn(conn.wolf_ssl, 10);

  he_return_code_t res = he_internal_renegotiate_ssl(&conn);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res);
}

void test_he_internal_renegotiate_ssl_error_want_write(void) {
  // Set our state online and set renegotiation in progress
  conn.state = HE_STATE_ONLINE;
  conn.renegotiation_in_progress = false;

  wolfSSL_SSL_get_secure_renegotiation_support_ExpectAndReturn(conn.wolf_ssl, true);
  wolfSSL_Rehandshake_ExpectAndReturn(conn.wolf_ssl, SSL_FATAL_ERROR);
  wolfSSL_get_error_ExpectAndReturn(conn.wolf_ssl, SSL_FATAL_ERROR, SSL_ERROR_WANT_WRITE);
  wolfSSL_dtls_get_current_timeout_ExpectAndReturn(conn.wolf_ssl, 10);

  he_return_code_t res = he_internal_renegotiate_ssl(&conn);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res);
}

void test_he_internal_renegotiate_ssl_error_fatal(void) {
  // Set our state online and set renegotiation in progress
  conn.state = HE_STATE_ONLINE;
  conn.renegotiation_in_progress = false;

  wolfSSL_SSL_get_secure_renegotiation_support_ExpectAndReturn(conn.wolf_ssl, true);
  wolfSSL_Rehandshake_ExpectAndReturn(conn.wolf_ssl, SSL_FATAL_ERROR);
  wolfSSL_get_error_ExpectAndReturn(conn.wolf_ssl, SSL_FATAL_ERROR, SSL_FATAL_ERROR);

  he_return_code_t res = he_internal_renegotiate_ssl(&conn);
  TEST_ASSERT_EQUAL(HE_ERR_SSL_ERROR, res);
}

void test_he_conn_server_connect_null_pointers(void) {
  he_return_code_t res = he_conn_server_connect(NULL, NULL, NULL, NULL);
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, res);
}

void test_he_conn_server_connect(void) {
  he_return_code_t res1 = he_conn_set_outside_mtu(&conn, 1500);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res1);

  he_return_code_t res2 = he_conn_set_protocol_version(&conn, 0x00, 0x00);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res2);

  wolfSSL_new_ExpectAndReturn(ssl_ctx.wolf_ctx, conn.wolf_ssl);
  wolfSSL_dtls_set_using_nonblock_Expect(conn.wolf_ssl, 1);
  wolfSSL_dtls_set_mtu_ExpectAndReturn(conn.wolf_ssl, 1423, SSL_SUCCESS);
  wolfSSL_SetIOWriteCtx_Expect(conn.wolf_ssl, &conn);
  wolfSSL_SetIOReadCtx_Expect(conn.wolf_ssl, &conn);

  wolfSSL_negotiate_ExpectAndReturn(conn.wolf_ssl, SSL_SUCCESS);
  wolfSSL_write_IgnoreAndReturn(SSL_SUCCESS);
  wolfSSL_dtls_get_current_timeout_ExpectAndReturn(conn.wolf_ssl, 10);
  wc_RNG_GenerateBlock_IgnoreAndReturn(0);

  he_return_code_t res = he_conn_server_connect(&conn, &ssl_ctx, NULL, NULL);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res);
}

void test_he_conn_server_connect_dn_set(void) {
  he_return_code_t res3 = he_ssl_ctx_set_server_dn(&ssl_ctx, "testdn");
  TEST_ASSERT_EQUAL(HE_SUCCESS, res3);

  he_return_code_t res1 = he_conn_set_outside_mtu(&conn, 1500);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res1);

  he_return_code_t res2 = he_conn_set_protocol_version(&conn, 0x00, 0x00);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res2);

  wolfSSL_new_ExpectAndReturn(ssl_ctx.wolf_ctx, conn.wolf_ssl);
  wolfSSL_dtls_set_using_nonblock_Expect(conn.wolf_ssl, 1);
  wolfSSL_dtls_set_mtu_ExpectAndReturn(conn.wolf_ssl, 1423, SSL_SUCCESS);
  wolfSSL_SetIOWriteCtx_Expect(conn.wolf_ssl, &conn);
  wolfSSL_SetIOReadCtx_Expect(conn.wolf_ssl, &conn);
  wolfSSL_check_domain_name_ExpectAndReturn(conn.wolf_ssl, ssl_ctx.server_dn, SSL_SUCCESS);

  wolfSSL_negotiate_ExpectAndReturn(conn.wolf_ssl, SSL_SUCCESS);
  wolfSSL_write_IgnoreAndReturn(SSL_SUCCESS);
  wolfSSL_dtls_get_current_timeout_ExpectAndReturn(conn.wolf_ssl, 10);
  wc_RNG_GenerateBlock_IgnoreAndReturn(0);

  he_return_code_t res = he_conn_server_connect(&conn, &ssl_ctx, NULL, NULL);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res);
}

void test_he_conn_server_connect_dn_set_fail(void) {
  he_return_code_t res3 = he_ssl_ctx_set_server_dn(&ssl_ctx, "testdn");
  TEST_ASSERT_EQUAL(HE_SUCCESS, res3);

  he_return_code_t res1 = he_conn_set_outside_mtu(&conn, 1500);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res1);

  he_return_code_t res2 = he_conn_set_protocol_version(&conn, 0x00, 0x00);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res2);

  wolfSSL_new_ExpectAndReturn(ssl_ctx.wolf_ctx, conn.wolf_ssl);
  wolfSSL_dtls_set_using_nonblock_Expect(conn.wolf_ssl, 1);
  wolfSSL_dtls_set_mtu_ExpectAndReturn(conn.wolf_ssl, 1423, SSL_SUCCESS);
  wolfSSL_SetIOWriteCtx_Expect(conn.wolf_ssl, &conn);
  wolfSSL_SetIOReadCtx_Expect(conn.wolf_ssl, &conn);
  wolfSSL_check_domain_name_ExpectAndReturn(conn.wolf_ssl, ssl_ctx.server_dn, SSL_FATAL_ERROR);

  he_return_code_t res = he_conn_server_connect(&conn, &ssl_ctx, NULL, NULL);
  TEST_ASSERT_EQUAL(HE_ERR_INIT_FAILED, res);
}

void test_he_internal_send_auth_bad_state(void) {
  conn.state = HE_STATE_ONLINE;
  he_return_code_t res = he_internal_send_auth(&conn);
  TEST_ASSERT_EQUAL(HE_ERR_INVALID_CONN_STATE, res);
}

void test_he_internal_send_auth_buf(void) {
  conn.state = HE_STATE_AUTHENTICATING;
  he_conn_set_auth_buffer2(&conn, fake_ipv4_packet, sizeof(fake_ipv4_packet));

  wolfSSL_write_ExpectAnyArgsAndReturn(150);

  he_return_code_t res = he_internal_send_auth(&conn);

  TEST_ASSERT_EQUAL(HE_SUCCESS, res);
}

void test_he_internal_send_goodbye_null_conn(void) {
  he_return_code_t res = he_internal_send_goodbye(NULL);
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, res);
}

void test_he_internal_send_goodbye_success(void) {
  wolfSSL_write_ExpectAnyArgsAndReturn(150);

  he_return_code_t res = he_internal_send_goodbye(&conn);

  TEST_ASSERT_EQUAL(HE_SUCCESS, res);
}

void test_he_internal_send_goodbye_failure_returns_success(void) {
  wolfSSL_write_ExpectAnyArgsAndReturn(-1);
  wolfSSL_get_error_ExpectAndReturn(conn.wolf_ssl, -1, SSL_ERROR_SSL);

  he_return_code_t res = he_internal_send_goodbye(&conn);

  TEST_ASSERT_EQUAL(HE_SUCCESS, res);
}

/**
 * @brief Test for a NULL pointer being passed to he_conn_is_error_fatal
 * This test is contrived due to how the function is used. If conn is NULL
 * it will return true for a fatal error.
 */
void test_he_conn_is_error_fatal_null_conn(void) {
  bool res = he_conn_is_error_fatal(NULL, HE_SUCCESS);
  TEST_ASSERT_TRUE(res);
}

void test_he_conn_disconnect_null_conn(void) {
  he_return_code_t res = he_conn_disconnect(NULL);
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, res);
}

void test_he_conn_schedule_renegotiation_null_conn(void) {
  he_return_code_t res = he_conn_schedule_renegotiation(NULL);
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, res);
}

void test_he_conn_get_nudge_time_null_conn(void) {
  he_return_code_t res = he_conn_get_nudge_time(NULL);
  TEST_ASSERT_EQUAL(0, res);
}

void test_he_conn_nudge_null_conn(void) {
  he_return_code_t res = he_conn_nudge(NULL);
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, res);
}

void test_he_conn_get_state_null_conn(void) {
  he_conn_state_t res = he_conn_get_state(NULL);
  TEST_ASSERT_EQUAL(HE_STATE_NONE, res);
}

void test_he_conn_rotate_session_id_null_conn(void) {
  uint64_t temp = 0;
  he_return_code_t res = he_conn_rotate_session_id(NULL, &temp);
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, res);
}

void test_he_conn_set_username_null_conn(void) {
  he_return_code_t res = he_conn_set_username(NULL, good_username);
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, res);
}

void test_he_conn_set_username_null_username(void) {
  he_return_code_t res = he_conn_set_username(&conn, NULL);
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, res);
}

void test_he_conn_set_password_null_conn(void) {
  he_return_code_t res = he_conn_set_password(NULL, good_password);
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, res);
}

void test_he_conn_set_password_null_password(void) {
  he_return_code_t res = he_conn_set_password(&conn, NULL);
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, res);
}

void test_he_conn_get_username_null_conn(void) {
  const char *res = he_conn_get_username(NULL);
  TEST_ASSERT_NULL(res);
}

void test_he_conn_is_username_set_null_conn(void) {
  bool res = he_conn_is_username_set(NULL);
  TEST_ASSERT_FALSE(res);
}

void test_he_conn_is_password_set_null_conn(void) {
  bool res = he_conn_is_password_set(NULL);
  TEST_ASSERT_FALSE(res);
}

void test_he_conn_is_auth_buffer_set_null_conn(void) {
  bool res = he_conn_is_auth_buffer_set(NULL);
  TEST_ASSERT_FALSE(res);
}

void test_he_conn_set_outside_mtu_conn_null(void) {
  he_return_code_t res = he_conn_set_outside_mtu(NULL, 1000);
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, res);
}

void test_he_conn_get_outside_mtu_conn_null(void) {
  int res = he_conn_get_outside_mtu(NULL);
  TEST_ASSERT_EQUAL(0, res);
}

void test_he_conn_is_outside_mtu_set_null_conn(void) {
  bool res = he_conn_is_outside_mtu_set(NULL);
  TEST_ASSERT_FALSE(res);
}

void test_he_internal_calculate_data_packet_length_conn_null(void) {
  size_t res = he_internal_calculate_data_packet_length(NULL, 1000);
  TEST_ASSERT_EQUAL(0, res);
}

void test_he_conn_set_context_null_conn(void) {
  he_return_code_t res = he_conn_set_context(NULL, good_password);
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, res);
}

void test_he_conn_set_context_null_context(void) {
  he_return_code_t res = he_conn_set_context(&conn, NULL);
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, res);
}

void test_he_conn_get_context_null_conn(void) {
  void *res = he_conn_get_context(NULL);
  TEST_ASSERT_NULL(res);
}

void test_he_conn_get_session_id_conn_null(void) {
  uint64_t res = he_conn_get_session_id(NULL);
  TEST_ASSERT_EQUAL(0, res);
}

void test_he_conn_get_pending_session_id_conn_null(void) {
  uint64_t res = he_conn_get_pending_session_id(NULL);
  TEST_ASSERT_EQUAL(0, res);
}

void test_he_internal_conn_configure_null(void) {
  he_return_code_t res = he_internal_conn_configure(NULL, NULL);
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, res);
}

void test_he_internal_conn_configure_no_version(void) {
  ssl_ctx.disable_roaming_connections = true;
  ssl_ctx.padding_type = HE_PADDING_FULL;
  ssl_ctx.use_aggressive_mode = true;
  ssl_ctx.connection_type = HE_CONNECTION_TYPE_STREAM;

  ssl_ctx.maximum_supported_version.major_version = 1;
  ssl_ctx.maximum_supported_version.minor_version = 1;

  ssl_ctx.auth_buf_cb = (he_auth_buf_cb_t)0x1;
  ssl_ctx.auth_cb = (he_auth_cb_t)0x2;
  ssl_ctx.event_cb = (he_event_cb_t)0x3;
  ssl_ctx.nudge_time_cb = (he_nudge_time_cb_t)0x4;
  ssl_ctx.state_change_cb = (he_state_change_cb_t)0x5;
  ssl_ctx.inside_write_cb = (he_inside_write_cb_t)0x6;
  ssl_ctx.outside_write_cb = (he_outside_write_cb_t)0x7;
  ssl_ctx.network_config_ipv4_cb = (he_network_config_ipv4_cb_t)0x8;
  ssl_ctx.populate_network_config_ipv4_cb = (he_populate_network_config_ipv4_cb_t)0x9;

  memset(&ssl_ctx.wolf_rng, 1, sizeof(WC_RNG));

  he_return_code_t res = he_internal_conn_configure(&conn, &ssl_ctx);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res);

  TEST_ASSERT_EQUAL(conn.disable_roaming_connections, ssl_ctx.disable_roaming_connections);
  TEST_ASSERT_EQUAL(conn.padding_type, ssl_ctx.padding_type);
  TEST_ASSERT_EQUAL(conn.use_aggressive_mode, ssl_ctx.use_aggressive_mode);
  TEST_ASSERT_EQUAL(conn.connection_type, ssl_ctx.connection_type);

  TEST_ASSERT_EQUAL(conn.protocol_version.major_version,
                    ssl_ctx.maximum_supported_version.major_version);
  TEST_ASSERT_EQUAL(conn.protocol_version.minor_version,
                    ssl_ctx.maximum_supported_version.minor_version);

  TEST_ASSERT_EQUAL(conn.auth_buf_cb, ssl_ctx.auth_buf_cb);
  TEST_ASSERT_EQUAL(conn.auth_cb, ssl_ctx.auth_cb);
  TEST_ASSERT_EQUAL(conn.event_cb, ssl_ctx.event_cb);
  TEST_ASSERT_EQUAL(conn.nudge_time_cb, ssl_ctx.nudge_time_cb);
  TEST_ASSERT_EQUAL(conn.state_change_cb, ssl_ctx.state_change_cb);
  TEST_ASSERT_EQUAL(conn.inside_write_cb, ssl_ctx.inside_write_cb);
  TEST_ASSERT_EQUAL(conn.outside_write_cb, ssl_ctx.outside_write_cb);
  TEST_ASSERT_EQUAL(conn.network_config_ipv4_cb, ssl_ctx.network_config_ipv4_cb);
  TEST_ASSERT_EQUAL(conn.populate_network_config_ipv4_cb, ssl_ctx.populate_network_config_ipv4_cb);

  TEST_ASSERT_EQUAL(0, memcmp(&conn.wolf_rng, &ssl_ctx.wolf_rng, sizeof(WC_RNG)));
}

void test_he_internal_is_valid_state_for_server_config(void) {
  TEST_ASSERT_FALSE(he_internal_is_valid_state_for_server_config(NULL));

  he_conn_state_t valid_states[] = {
      HE_STATE_LINK_UP,
      HE_STATE_CONFIGURING,
      HE_STATE_AUTHENTICATING,
      HE_STATE_ONLINE,
  };
  for(size_t i = 0; i < sizeof(valid_states) / sizeof(he_conn_state_t); i++) {
    conn.state = valid_states[i];
    TEST_ASSERT_TRUE(he_internal_is_valid_state_for_server_config(&conn));
  }

  he_conn_state_t invalid_states[] = {
      HE_STATE_CONNECTING,
      HE_STATE_DISCONNECTING,
      HE_STATE_DISCONNECTED,
      HE_STATE_NONE,
  };
  for(size_t i = 0; i < sizeof(invalid_states) / sizeof(he_conn_state_t); i++) {
    conn.state = invalid_states[i];
    TEST_ASSERT_FALSE(he_internal_is_valid_state_for_server_config(&conn));
  }
}

void test_he_conn_send_server_config_null(void) {
  ret = he_conn_send_server_config(NULL, empty_data, sizeof(empty_data));
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, ret);

  ret = he_conn_send_server_config(&conn, NULL, sizeof(empty_data));
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, ret);
}

void test_he_conn_send_server_config_invalid_state(void) {
  conn.is_server = false;
  ret = he_conn_send_server_config(&conn, empty_data, 42);
  TEST_ASSERT_EQUAL(HE_ERR_INVALID_CONN_STATE, ret);

  conn.is_server = true;
  conn.state = HE_STATE_CONNECTING;
  ret = he_conn_send_server_config(&conn, empty_data, 42);
  TEST_ASSERT_EQUAL(HE_ERR_INVALID_CONN_STATE, ret);
}

void test_he_conn_send_server_config_packet_too_large(void) {
  conn.is_server = true;
  conn.state = HE_STATE_ONLINE;
  ret = he_conn_send_server_config(&conn, empty_data, sizeof(empty_data));
  TEST_ASSERT_EQUAL(HE_ERR_PACKET_TOO_LARGE, ret);
}

void test_he_conn_get_current_cipher_null(void) {
  TEST_ASSERT_NULL(he_conn_get_current_cipher(NULL));

  conn.wolf_ssl = NULL;
  TEST_ASSERT_NULL(he_conn_get_current_cipher(&conn));
}

void test_he_conn_get_current_cipher(void) {
  WOLFSSL_CIPHER *mock_cipher = (WOLFSSL_CIPHER *)(uintptr_t)0xdeadbeef;
  wolfSSL_get_current_cipher_ExpectAndReturn(conn.wolf_ssl, mock_cipher);
  wolfSSL_CIPHER_get_name_ExpectAndReturn(mock_cipher, "mycipher");
  TEST_ASSERT_EQUAL_STRING("mycipher", he_conn_get_current_cipher(&conn));
}
