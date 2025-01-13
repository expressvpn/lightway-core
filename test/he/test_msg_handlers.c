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
#include "msg_handlers.h"

// Direct Includes for Utility Functions
#include "memory.h"
#include "frag.h"

// Internal Mocks
#include "mock_conn.h"
#include "mock_conn_internal.h"
#include "mock_ssl_ctx.h"
#include "mock_config.h"
#include "mock_network.h"
#include "mock_plugin_chain.h"
#include "mock_pmtud.h"

// External Mocks
#include "mock_ssl.h"
#include "mock_wolfio.h"

he_conn_t *conn = NULL;
he_return_code_t ret;
he_msg_config_ipv4_t empty_msg_config = {0};
he_network_config_ipv4_t empty_network_config = {0};

he_msg_auth_buf_t msg_auth = {.header.auth_type = HE_AUTH_TYPE_USERPASS};

int call_counter = 0;

he_return_code_t fixture_network_config_cb(he_conn_t *conn, he_network_config_ipv4_t *config,
                                           void *context) {
  call_counter++;
  memcpy(&empty_network_config, config, sizeof(he_network_config_ipv4_t));
  return HE_SUCCESS;
}

he_return_code_t fixture_network_config_cb_will_fail(he_conn_t *conn,
                                                     he_network_config_ipv4_t *config,
                                                     void *context) {
  call_counter++;
  memcpy(&empty_network_config, config, sizeof(he_network_config_ipv4_t));
  return HE_ERR_CALLBACK_FAILED;
}

he_return_code_t event_cb_pong(he_conn_t *conn, he_conn_event_t event, void *context) {
  call_counter++;
  TEST_ASSERT_EQUAL(HE_EVENT_PONG, event);
  return HE_SUCCESS;
}

bool auth_cb_fail(he_conn_t *conn, char const *username, char const *password, void *context) {
  call_counter++;
  return false;
}

bool auth_cb_succeed(he_conn_t *conn, char const *username, char const *password, void *context) {
  call_counter++;
  return true;
}

bool auth_token_cb_succeed(he_conn_t *conn, const uint8_t *token, size_t length, void *context) {
  call_counter++;
  return true;
}

bool auth_buf_cb_succeed(he_conn_t *conn, uint8_t auth_type, uint8_t *buffer, uint16_t length,
                         void *context) {
  call_counter++;
  return true;
}

he_return_code_t inside_write_cb(he_conn_t *conn, uint8_t *packet, size_t length, void *context) {
  call_counter++;
  return true;
}

void setUp(void) {
  conn = calloc(1, sizeof(he_conn_t));

  // Hardcoding for testing
  ret = 0;
  memset(&empty_msg_config, 0, sizeof(he_msg_config_ipv4_t));
  memset(&empty_network_config, 0, sizeof(he_network_config_ipv4_t));
  memset(&empty_data, 0, sizeof(empty_data));
  call_counter = 0;
}

void tearDown(void) {
  free(conn);
}

void test_msg_handler_noop(void) {
  ret = he_handle_msg_noop(conn, empty_data, 0);

  TEST_ASSERT_EQUAL(HE_SUCCESS, ret);
}

void test_msg_handler_noop_null_conn(void) {
  ret = he_handle_msg_noop(NULL, empty_data, 0);

  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, ret);
}

void test_msg_handler_noop_null_packet(void) {
  ret = he_handle_msg_noop(conn, NULL, 0);

  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, ret);
}

void test_msg_handler_noop_both_null(void) {
  ret = he_handle_msg_noop(NULL, NULL, 0);

  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, ret);
}

void test_msg_handler_ping_fails_when_not_in_connected_state(void) {
  conn->state = HE_STATE_DISCONNECTED;
  ret = he_handle_msg_ping(conn, empty_data, 0);
  TEST_ASSERT_EQUAL(HE_ERR_INVALID_CONN_STATE, ret);
}

void test_msg_handler_ping_successful(void) {
  conn->state = HE_STATE_ONLINE;

  he_internal_send_message_ExpectAndReturn(conn, NULL, sizeof(he_msg_pong_t), HE_SUCCESS);
  he_internal_send_message_IgnoreArg_message();

  ret = he_handle_msg_ping(conn, empty_data, sizeof(he_msg_ping_t));
  TEST_ASSERT_EQUAL(HE_SUCCESS, ret);
}

void test_msg_handler_ping_conn_null(void) {
  ret = he_handle_msg_ping(NULL, empty_data, 0);

  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, ret);
}

void test_msg_handler_ping_packet_null(void) {
  ret = he_handle_msg_ping(conn, NULL, 0);

  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, ret);
}

void test_msg_handler_ping_both_null(void) {
  ret = he_handle_msg_ping(NULL, NULL, 0);

  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, ret);
}

void test_msg_handler_ping_invalid_message(void) {
  conn->state = HE_STATE_ONLINE;

  ret = he_handle_msg_ping(conn, empty_data, 1);

  TEST_ASSERT_EQUAL(HE_ERR_PACKET_TOO_SMALL, ret);
}

void test_msg_handler_pong(void) {
  conn->ping_pending_id = 42;

  he_internal_generate_event_Expect(conn, HE_EVENT_PONG);

  he_msg_pong_t *pong = (he_msg_pong_t *)empty_data;
  pong->id = htons(42);
  ret = he_handle_msg_pong(conn, (uint8_t *)pong, sizeof(he_msg_pong_t));
  TEST_ASSERT_EQUAL(HE_SUCCESS, ret);
}

void test_msg_handler_pong_pmtud_ack(void) {
  conn->ping_pending_id = 42;
  conn->pmtud.probe_pending_id = 999;

  he_internal_pmtud_handle_probe_ack_ExpectAndReturn(conn, 999, HE_SUCCESS);

  he_msg_pong_t *pong = (he_msg_pong_t *)empty_data;
  pong->id = htons(999);
  ret = he_handle_msg_pong(conn, (uint8_t *)pong, sizeof(he_msg_pong_t));
  TEST_ASSERT_EQUAL(HE_SUCCESS, ret);
}

void test_msg_handler_pong_mismatch_id(void) {
  conn->ping_pending_id = 42;

  he_internal_pmtud_handle_probe_ack_ExpectAndReturn(conn, 999, HE_SUCCESS);

  he_msg_pong_t *pong = (he_msg_pong_t *)empty_data;
  pong->id = htons(999);
  ret = he_handle_msg_pong(conn, (uint8_t *)pong, sizeof(he_msg_pong_t));
  TEST_ASSERT_EQUAL(HE_SUCCESS, ret);
}

void test_msg_handler_pong_conn_null(void) {
  ret = he_handle_msg_pong(NULL, empty_data, 0);

  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, ret);
}

void test_msg_handler_pong_packet_null(void) {
  ret = he_handle_msg_pong(conn, NULL, 0);

  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, ret);
}

void test_msg_handler_pong_both_null(void) {
  ret = he_handle_msg_pong(NULL, NULL, 0);

  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, ret);
}

void test_msg_config_already_online(void) {
  conn->state = HE_STATE_ONLINE;

  ret = he_handle_msg_config_ipv4(conn, empty_data, 0);
  TEST_ASSERT_EQUAL(HE_SUCCESS, ret);

  ret = he_handle_msg_config_ipv4(conn, (uint8_t *)&empty_msg_config, sizeof(he_msg_config_ipv4_t));
  TEST_ASSERT_EQUAL(HE_SUCCESS, ret);
}

void test_msg_config_wrong_state_is_client(void) {
  ret = he_handle_msg_config_ipv4(conn, empty_data, 0);
  TEST_ASSERT_EQUAL(HE_ERR_INVALID_CONN_STATE, ret);
}

void test_msg_config_wrong_state_not_authenticating(void) {
  conn->is_server = true;
  conn->state = HE_STATE_CONNECTING;

  ret = he_handle_msg_config_ipv4(conn, empty_data, 0);
  TEST_ASSERT_EQUAL(HE_ERR_INVALID_CONN_STATE, ret);
}

void test_msg_config_packet_too_small(void) {
  conn->state = HE_STATE_AUTHENTICATING;
  ret = he_handle_msg_config_ipv4(conn, empty_data, 0);
  TEST_ASSERT_EQUAL(0, call_counter);
  TEST_ASSERT_EQUAL(HE_ERR_PACKET_TOO_SMALL, ret);
}

void test_msg_config_null_conn(void) {
  ret = he_handle_msg_config_ipv4(NULL, empty_data, 0);
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, ret);
}

void test_msg_config_null_packet(void) {
  ret = he_handle_msg_config_ipv4(conn, NULL, 0);
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, ret);
}

void test_msg_config_both_nulls(void) {
  ret = he_handle_msg_config_ipv4(NULL, NULL, 0);
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, ret);
}

void test_msg_config_with_config_callback(void) {
  conn->state = HE_STATE_AUTHENTICATING;
  conn->network_config_ipv4_cb = fixture_network_config_cb;

  he_internal_change_conn_state_Expect(conn, HE_STATE_CONFIGURING);
  he_internal_change_conn_state_Expect(conn, HE_STATE_ONLINE);

  ret = he_handle_msg_config_ipv4(conn, (uint8_t *)&empty_msg_config, sizeof(he_msg_config_ipv4_t));

  // Check all the strings are empty
  TEST_ASSERT_EQUAL_STRING("", &empty_network_config.dns_ip);
  TEST_ASSERT_EQUAL_STRING("", &empty_network_config.local_ip);
  TEST_ASSERT_EQUAL_STRING("", &empty_network_config.peer_ip);
  TEST_ASSERT_EQUAL(HE_MAX_MTU, empty_network_config.mtu);

  TEST_ASSERT_EQUAL(1, call_counter);
  TEST_ASSERT_EQUAL(HE_SUCCESS, ret);
}

void test_msg_config_with_config_callback_that_fails(void) {
  conn->state = HE_STATE_AUTHENTICATING;
  conn->network_config_ipv4_cb = fixture_network_config_cb_will_fail;

  he_internal_change_conn_state_Expect(conn, HE_STATE_CONFIGURING);

  ret = he_handle_msg_config_ipv4(conn, (uint8_t *)&empty_msg_config, sizeof(he_msg_config_ipv4_t));

  // Check all the strings are empty
  TEST_ASSERT_EQUAL_STRING("", &empty_network_config.dns_ip);
  TEST_ASSERT_EQUAL_STRING("", &empty_network_config.local_ip);
  TEST_ASSERT_EQUAL_STRING("", &empty_network_config.peer_ip);
  TEST_ASSERT_EQUAL(HE_MAX_MTU, empty_network_config.mtu);

  TEST_ASSERT_EQUAL(1, call_counter);
  TEST_ASSERT_EQUAL(HE_ERR_CALLBACK_FAILED, ret);
}

void test_msg_config_with_sane_mtu(void) {
  conn->state = HE_STATE_AUTHENTICATING;
  conn->network_config_ipv4_cb = fixture_network_config_cb;

  he_internal_change_conn_state_Expect(conn, HE_STATE_CONFIGURING);
  he_internal_change_conn_state_Expect(conn, HE_STATE_ONLINE);

  // Ignoring IP values for these tests, other test can check
  strncpy(empty_msg_config.mtu, "1242", HE_MAX_IPV4_STRING_LENGTH);

  ret = he_handle_msg_config_ipv4(conn, (uint8_t *)&empty_msg_config, sizeof(he_msg_config_ipv4_t));

  TEST_ASSERT_EQUAL(1, call_counter);
  TEST_ASSERT_EQUAL(HE_SUCCESS, ret);

  TEST_ASSERT_EQUAL(1242, empty_network_config.mtu);
}

void test_msg_config_with_too_large_mtu(void) {
  conn->state = HE_STATE_AUTHENTICATING;
  conn->network_config_ipv4_cb = fixture_network_config_cb;
  he_internal_change_conn_state_Expect(conn, HE_STATE_CONFIGURING);
  he_internal_change_conn_state_Expect(conn, HE_STATE_ONLINE);

  // Ignoring IP values for these tests, other test can check
  strncpy(empty_msg_config.mtu, "3929384", HE_MAX_IPV4_STRING_LENGTH);

  ret = he_handle_msg_config_ipv4(conn, (uint8_t *)&empty_msg_config, sizeof(he_msg_config_ipv4_t));

  TEST_ASSERT_EQUAL(1, call_counter);
  TEST_ASSERT_EQUAL(HE_SUCCESS, ret);

  TEST_ASSERT_EQUAL(HE_MAX_MTU, empty_network_config.mtu);
}

void test_msg_config_with_overflow_mtu(void) {
  conn->state = HE_STATE_AUTHENTICATING;
  conn->network_config_ipv4_cb = fixture_network_config_cb;
  he_internal_change_conn_state_Expect(conn, HE_STATE_CONFIGURING);
  he_internal_change_conn_state_Expect(conn, HE_STATE_ONLINE);

  // Ignoring IP values for these tests, other test can check
  strncpy(empty_msg_config.mtu, "999999999999999999999999", HE_MAX_IPV4_STRING_LENGTH);

  ret = he_handle_msg_config_ipv4(conn, (uint8_t *)&empty_msg_config, sizeof(he_msg_config_ipv4_t));

  TEST_ASSERT_EQUAL(1, call_counter);
  TEST_ASSERT_EQUAL(HE_SUCCESS, ret);

  TEST_ASSERT_EQUAL(HE_MAX_MTU, empty_network_config.mtu);
}

void test_msg_config_with_negative_mtu(void) {
  conn->state = HE_STATE_AUTHENTICATING;
  conn->network_config_ipv4_cb = fixture_network_config_cb;
  he_internal_change_conn_state_Expect(conn, HE_STATE_CONFIGURING);
  he_internal_change_conn_state_Expect(conn, HE_STATE_ONLINE);

  // Ignoring IP values for these tests, other test can check
  strncpy(empty_msg_config.mtu, "-1242", HE_MAX_IPV4_STRING_LENGTH);

  ret = he_handle_msg_config_ipv4(conn, (uint8_t *)&empty_msg_config, sizeof(he_msg_config_ipv4_t));

  TEST_ASSERT_EQUAL(1, call_counter);
  TEST_ASSERT_EQUAL(HE_SUCCESS, ret);

  TEST_ASSERT_EQUAL(HE_MAX_MTU, empty_network_config.mtu);
}

void test_msg_config_with_bad_mtu(void) {
  conn->state = HE_STATE_AUTHENTICATING;
  conn->network_config_ipv4_cb = fixture_network_config_cb;
  he_internal_change_conn_state_Expect(conn, HE_STATE_CONFIGURING);
  he_internal_change_conn_state_Expect(conn, HE_STATE_ONLINE);

  // Ignoring IP values for these tests, other test can check
  strncpy(empty_msg_config.mtu, "abcdefgh", HE_MAX_IPV4_STRING_LENGTH);

  ret = he_handle_msg_config_ipv4(conn, (uint8_t *)&empty_msg_config, sizeof(he_msg_config_ipv4_t));

  TEST_ASSERT_EQUAL(1, call_counter);
  TEST_ASSERT_EQUAL(HE_SUCCESS, ret);

  TEST_ASSERT_EQUAL(HE_MAX_MTU, empty_network_config.mtu);
}

void test_msg_config_with_evil_mtu(void) {
  conn->state = HE_STATE_AUTHENTICATING;
  conn->network_config_ipv4_cb = fixture_network_config_cb;
  he_internal_change_conn_state_Expect(conn, HE_STATE_CONFIGURING);
  he_internal_change_conn_state_Expect(conn, HE_STATE_ONLINE);

  // Ignoring IP values for these tests, other test can check
  // Make sure we can handle an unterminated string
  for(int i = 0; i < HE_MAX_IPV4_STRING_LENGTH; i++) {
    empty_msg_config.mtu[i] = 'a';
  }

  ret = he_handle_msg_config_ipv4(conn, (uint8_t *)&empty_msg_config, sizeof(he_msg_config_ipv4_t));

  TEST_ASSERT_EQUAL(1, call_counter);
  TEST_ASSERT_EQUAL(HE_SUCCESS, ret);

  TEST_ASSERT_EQUAL(HE_MAX_MTU, empty_network_config.mtu);
}

void test_msg_config_with_no_config_callback(void) {
  conn->state = HE_STATE_AUTHENTICATING;
  he_internal_change_conn_state_Expect(conn, HE_STATE_CONFIGURING);
  he_internal_change_conn_state_Expect(conn, HE_STATE_ONLINE);
  ret = he_handle_msg_config_ipv4(conn, (uint8_t *)&empty_msg_config, sizeof(he_msg_config_ipv4_t));

  // Nothing else to test as there is no callback to actually do anything
  TEST_ASSERT_EQUAL(HE_SUCCESS, ret);
}

void test_msg_data_conn_null(void) {
  ret = he_handle_msg_data(NULL, empty_data, 0);

  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, ret);
}

void test_msg_data_packet_null(void) {
  ret = he_handle_msg_data(conn, NULL, 0);

  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, ret);
}

void test_msg_data_both_null(void) {
  ret = he_handle_msg_data(NULL, NULL, 0);

  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, ret);
}

void test_msg_data_bad_state(void) {
  ret = he_handle_msg_data(conn, empty_data, 0);
  TEST_ASSERT_EQUAL(HE_ERR_INVALID_CONN_STATE, ret);
}

void test_msg_data_bad_packet(void) {
  conn->state = HE_STATE_ONLINE;
  he_plugin_egress_ExpectAnyArgsAndReturn(HE_SUCCESS);
  he_internal_is_ipv4_packet_valid_ExpectAnyArgsAndReturn(false);
  ret = he_handle_msg_data(conn, empty_data, sizeof(empty_data));
  TEST_ASSERT_EQUAL(HE_ERR_BAD_PACKET, ret);
}

void test_msg_data_truncated_message_super_small(void) {
  conn->state = HE_STATE_ONLINE;
  he_msg_data_t *pkt = (he_msg_data_t *)empty_data;
  pkt->length = htons(10000);
  ret = he_handle_msg_data(conn, empty_data, sizeof(he_msg_data_t) - 1);
  TEST_ASSERT_EQUAL(HE_ERR_PACKET_TOO_SMALL, ret);
}

void test_msg_data_truncated_message(void) {
  conn->state = HE_STATE_ONLINE;
  he_msg_data_t *pkt = (he_msg_data_t *)empty_data;
  pkt->length = htons(sizeof(empty_data) - sizeof(he_msg_data_t) + 1);
  ret = he_handle_msg_data(conn, empty_data, sizeof(empty_data));
  TEST_ASSERT_EQUAL(HE_ERR_POINTER_WOULD_OVERFLOW, ret);
}

void test_msg_data_something(void) {
  conn->state = HE_STATE_ONLINE;
  he_msg_data_t *pkt = (he_msg_data_t *)empty_data;
  pkt->length = htons(100);
  empty_data[sizeof(he_msg_data_t)] = 0x45;

  he_plugin_egress_ExpectAnyArgsAndReturn(HE_SUCCESS);
  he_internal_is_ipv4_packet_valid_ExpectAnyArgsAndReturn(true);
  ret = he_handle_msg_data(conn, empty_data, sizeof(empty_data));
  TEST_ASSERT_EQUAL(HE_SUCCESS, ret);
}

void test_msg_data_old_protocol_something(void) {
  conn->state = HE_STATE_ONLINE;
  conn->protocol_version.major_version = 1;
  conn->protocol_version.minor_version = 0;

  he_msg_data_t *pkt = (he_msg_data_t *)empty_data;
  pkt->length = 100;
  empty_data[sizeof(he_msg_data_t)] = 0x45;

  he_plugin_egress_ExpectAnyArgsAndReturn(HE_SUCCESS);
  he_internal_is_ipv4_packet_valid_ExpectAnyArgsAndReturn(true);
  ret = he_handle_msg_data(conn, empty_data, sizeof(empty_data));
  TEST_ASSERT_EQUAL(HE_SUCCESS, ret);
}

void test_msg_data_something_other_version(void) {
  conn->state = HE_STATE_ONLINE;
  conn->protocol_version.major_version = 1;
  conn->protocol_version.minor_version = 1;

  he_msg_data_t *pkt = (he_msg_data_t *)empty_data;
  pkt->length = htons(100);
  empty_data[sizeof(he_msg_data_t)] = 0x45;

  he_plugin_egress_ExpectAnyArgsAndReturn(HE_SUCCESS);
  he_internal_is_ipv4_packet_valid_ExpectAnyArgsAndReturn(true);
  ret = he_handle_msg_data(conn, empty_data, sizeof(empty_data));
  TEST_ASSERT_EQUAL(HE_SUCCESS, ret);
}

void test_msg_data_old_protocol_something_with_cb(void) {
  conn->state = HE_STATE_ONLINE;
  conn->protocol_version.major_version = 1;
  conn->protocol_version.minor_version = 0;
  conn->inside_write_cb = inside_write_cb;

  he_msg_data_t *pkt = (he_msg_data_t *)empty_data;
  pkt->length = 100;
  empty_data[sizeof(he_msg_data_t)] = 0x45;

  he_plugin_egress_ExpectAnyArgsAndReturn(HE_SUCCESS);
  he_internal_is_ipv4_packet_valid_ExpectAnyArgsAndReturn(true);
  ret = he_handle_msg_data(conn, empty_data, sizeof(empty_data));
  TEST_ASSERT_EQUAL(HE_SUCCESS, ret);
  TEST_ASSERT_EQUAL(1, call_counter);
}

void test_msg_data_plugin_drop(void) {
  conn->state = HE_STATE_ONLINE;
  conn->protocol_version.major_version = 1;
  conn->protocol_version.minor_version = 0;
  conn->inside_write_cb = inside_write_cb;

  he_msg_data_t *pkt = (he_msg_data_t *)empty_data;
  pkt->length = 100;
  empty_data[sizeof(he_msg_data_t)] = 0x45;

  he_plugin_egress_ExpectAnyArgsAndReturn(HE_ERR_PLUGIN_DROP);
  ret = he_handle_msg_data(conn, empty_data, sizeof(empty_data));
  TEST_ASSERT_EQUAL(HE_SUCCESS, ret);
  TEST_ASSERT_EQUAL(0, call_counter);
}

void test_msg_data_plugin_fail(void) {
  conn->state = HE_STATE_ONLINE;
  conn->protocol_version.major_version = 1;
  conn->protocol_version.minor_version = 0;
  conn->inside_write_cb = inside_write_cb;

  he_msg_data_t *pkt = (he_msg_data_t *)empty_data;
  pkt->length = 100;
  empty_data[sizeof(he_msg_data_t)] = 0x45;

  he_plugin_egress_ExpectAnyArgsAndReturn(HE_ERR_FAILED);
  ret = he_handle_msg_data(conn, empty_data, sizeof(empty_data));
  TEST_ASSERT_EQUAL(HE_ERR_FAILED, ret);
  TEST_ASSERT_EQUAL(0, call_counter);
}

void test_msg_data_plugin_overflow(void) {
  conn->state = HE_STATE_ONLINE;
  conn->protocol_version.major_version = 1;
  conn->protocol_version.minor_version = 0;
  conn->inside_write_cb = inside_write_cb;

  he_msg_data_t *pkt = (he_msg_data_t *)empty_data;
  pkt->length = 100;
  empty_data[sizeof(he_msg_data_t)] = 0x45;

  he_plugin_egress_Stub(stub_overflow_plugin);
  ret = he_handle_msg_data(conn, empty_data, sizeof(empty_data));
  TEST_ASSERT_EQUAL(HE_ERR_FAILED, ret);
  TEST_ASSERT_EQUAL(0, call_counter);
}

void test_deprecated_msg_13_bad_state(void) {
  ret = he_handle_msg_deprecated_13(conn, empty_data, 0);
  TEST_ASSERT_EQUAL(HE_ERR_INVALID_CONN_STATE, ret);
}

void test_deprecated_msg_13_bad_packet(void) {
  conn->state = HE_STATE_ONLINE;
  he_plugin_egress_ExpectAnyArgsAndReturn(HE_SUCCESS);
  he_internal_is_ipv4_packet_valid_ExpectAnyArgsAndReturn(false);
  ret = he_handle_msg_deprecated_13(conn, empty_data, sizeof(empty_data));
  TEST_ASSERT_EQUAL(HE_ERR_BAD_PACKET, ret);
}

void test_deprecated_msg_13_truncated_message_super_small(void) {
  conn->state = HE_STATE_ONLINE;
  he_deprecated_msg_13_t *pkt = (he_deprecated_msg_13_t *)empty_data;
  ret = he_handle_msg_deprecated_13(conn, empty_data, sizeof(he_deprecated_msg_13_t) - 1);
  TEST_ASSERT_EQUAL(HE_ERR_PACKET_TOO_SMALL, ret);
}

void test_deprecated_msg_13_truncated_message(void) {
  conn->state = HE_STATE_ONLINE;
  he_deprecated_msg_13_t *pkt = (he_deprecated_msg_13_t *)empty_data;
  pkt->length = htons(sizeof(empty_data) - sizeof(he_deprecated_msg_13_t) + 1);
  ret = he_handle_msg_deprecated_13(conn, empty_data, sizeof(empty_data));
  TEST_ASSERT_EQUAL(HE_ERR_POINTER_WOULD_OVERFLOW, ret);
}

void test_deprecated_msg_13_something(void) {
  conn->state = HE_STATE_ONLINE;
  he_deprecated_msg_13_t *pkt = (he_deprecated_msg_13_t *)empty_data;
  pkt->length = htons(100);
  empty_data[sizeof(he_deprecated_msg_13_t)] = 0x45;

  he_plugin_egress_ExpectAnyArgsAndReturn(HE_SUCCESS);
  he_internal_is_ipv4_packet_valid_ExpectAnyArgsAndReturn(true);

  ret = he_handle_msg_deprecated_13(conn, empty_data, sizeof(empty_data));
  TEST_ASSERT_EQUAL(HE_SUCCESS, ret);
}

void test_msg_auth_response(void) {
  ret = he_handle_msg_auth_response(conn, empty_data, 0);
  TEST_ASSERT_EQUAL(HE_ERR_ACCESS_DENIED, ret);
}

void test_msg_auth_response_null_conn(void) {
  ret = he_handle_msg_auth_response(NULL, empty_data, 0);
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, ret);
}

void test_msg_auth_response_null_packet(void) {
  ret = he_handle_msg_auth_response(conn, NULL, 0);
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, ret);
}

void test_msg_auth_response_both_nulls(void) {
  ret = he_handle_msg_auth_response(NULL, NULL, 0);
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, ret);
}

void test_msg_auth_null_pointer_conn(void) {
  // Simple NULL pointer check
  he_return_code_t res = he_handle_msg_auth(NULL, empty_data, sizeof(empty_data));
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, res);
}

void test_msg_auth_null_pointer_packet(void) {
  // Simple NULL pointer check
  he_return_code_t res = he_handle_msg_auth(conn, NULL, sizeof(empty_data));
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, res);
}

void test_msg_auth_not_server(void) {
  // Fail if this is a client
  conn->is_server = false;
  he_return_code_t res = he_handle_msg_auth(conn, empty_data, sizeof(empty_data));
  TEST_ASSERT_EQUAL(HE_ERR_INVALID_CONN_STATE, res);
}

void test_msg_auth_not_link_up_or_online(void) {
  // This is a server context
  conn->is_server = true;
  // Fail due to not being in LINK_UP or ONLINE state
  conn->state = HE_STATE_CONNECTING;
  he_return_code_t res = he_handle_msg_auth(conn, empty_data, sizeof(empty_data));
  TEST_ASSERT_EQUAL(HE_ERR_INVALID_CONN_STATE, res);
}

void test_msg_auth_link_up_but_not_server(void) {
  // This is a client context
  conn->is_server = false;
  // Valid state for this message
  conn->state = HE_STATE_LINK_UP;
  he_return_code_t res = he_handle_msg_auth(conn, empty_data, sizeof(empty_data));
  TEST_ASSERT_EQUAL(HE_ERR_INVALID_CONN_STATE, res);
}

void test_msg_auth_online_but_not_server(void) {
  // This is a client context
  conn->is_server = false;
  // Valid state for this message
  conn->state = HE_STATE_ONLINE;
  he_return_code_t res = he_handle_msg_auth(conn, empty_data, sizeof(empty_data));
  TEST_ASSERT_EQUAL(HE_ERR_INVALID_CONN_STATE, res);
}

void test_msg_auth_auth_cb_null_ipv4_config_null(void) {
  // Basic good setup for a server
  conn->is_server = true;
  conn->state = HE_STATE_LINK_UP;
  conn->protocol_version.major_version = 1;
  conn->protocol_version.minor_version = 0;
  // No auth callback or IPv4 config callback set
  conn->auth_cb = NULL;
  conn->populate_network_config_ipv4_cb = NULL;

  he_return_code_t res = he_handle_msg_auth(conn, empty_data, sizeof(empty_data));
  TEST_ASSERT_EQUAL(HE_ERR_INVALID_CONN_STATE, res);
}

void test_msg_auth_auth_cb_good_ipv4_config_null(void) {
  // Basic good setup for a server
  conn->is_server = true;
  conn->state = HE_STATE_LINK_UP;
  conn->protocol_version.major_version = 1;
  conn->protocol_version.minor_version = 0;
  // Aauth callback but no IPv4 config callback set
  conn->auth_cb = auth_cb_fail;
  conn->populate_network_config_ipv4_cb = NULL;

  he_return_code_t res = he_handle_msg_auth(conn, empty_data, sizeof(empty_data));
  TEST_ASSERT_EQUAL(HE_ERR_INVALID_CONN_STATE, res);
}

void test_msg_auth_auth_cb_null_ipv4_config_good(void) {
  // Basic good setup for a server
  conn->is_server = true;
  conn->state = HE_STATE_LINK_UP;
  conn->protocol_version.major_version = 1;
  conn->protocol_version.minor_version = 0;
  // No auth callback but IPv4 config callback set
  conn->auth_cb = NULL;
  conn->populate_network_config_ipv4_cb = fixture_network_config_cb;

  he_return_code_t res = he_handle_msg_auth(conn, empty_data, sizeof(empty_data));
  TEST_ASSERT_EQUAL(HE_ERR_INVALID_CONN_STATE, res);
}

void test_msg_auth_auth_cb_packet_too_small(void) {
  // Basic good setup for a server
  conn->is_server = true;
  conn->state = HE_STATE_LINK_UP;
  conn->protocol_version.major_version = 1;
  conn->protocol_version.minor_version = 0;
  // Auth callback and IPv4 config callback set
  conn->auth_cb = auth_cb_fail;
  conn->populate_network_config_ipv4_cb = fixture_network_config_cb;

  he_msg_auth_t *auth_message = (he_msg_auth_t *)empty_data;
  auth_message->header.auth_type = HE_AUTH_TYPE_USERPASS;

  // Call with a small size to trigger the size check
  he_return_code_t res = he_handle_msg_auth(conn, empty_data, 10);
  TEST_ASSERT_EQUAL(HE_ERR_PACKET_TOO_SMALL, res);
}

void test_msg_auth_auth_access_denied(void) {
  // Basic good setup for a server
  conn->is_server = true;
  conn->state = HE_STATE_LINK_UP;
  conn->protocol_version.major_version = 1;
  conn->protocol_version.minor_version = 0;
  // Auth callback and IPv4 config callback set
  conn->auth_cb = auth_cb_fail;
  conn->populate_network_config_ipv4_cb = fixture_network_config_cb;

  he_internal_send_message_ExpectAndReturn(conn, NULL, sizeof(he_msg_auth_response_t), HE_SUCCESS);
  he_internal_send_message_IgnoreArg_message();
  he_internal_change_conn_state_Expect(conn, HE_STATE_DISCONNECTING);

  he_msg_auth_t *auth_message = (he_msg_auth_t *)empty_data;
  auth_message->header.auth_type = HE_AUTH_TYPE_USERPASS;

  // We should get access denied and the call counter should be 1
  he_return_code_t res = he_handle_msg_auth(conn, empty_data, sizeof(empty_data));
  TEST_ASSERT_EQUAL(HE_ERR_ACCESS_DENIED, res);
  TEST_ASSERT_EQUAL(1, call_counter);
}

void test_msg_auth_fail_network_config_cb(void) {
  // Basic good setup for a server
  conn->is_server = true;
  conn->state = HE_STATE_LINK_UP;
  conn->protocol_version.major_version = 1;
  conn->protocol_version.minor_version = 0;
  // Auth callback and IPv4 config callback set
  conn->auth_cb = auth_cb_succeed;
  conn->populate_network_config_ipv4_cb = fixture_network_config_cb_will_fail;

  he_internal_send_message_ExpectAndReturn(conn, NULL, sizeof(he_msg_auth_response_t), HE_SUCCESS);
  he_internal_send_message_IgnoreArg_message();

  he_msg_auth_t *auth_message = (he_msg_auth_t *)empty_data;
  auth_message->header.auth_type = HE_AUTH_TYPE_USERPASS;

  // We should get access denied and the call counter should be 1
  he_return_code_t res = he_handle_msg_auth(conn, empty_data, sizeof(empty_data));
  TEST_ASSERT_EQUAL(HE_ERR_CALLBACK_FAILED, res);
  TEST_ASSERT_EQUAL(2, call_counter);
}

void test_msg_auth_auth_access_granted(void) {
  // Basic good setup for a server
  conn->is_server = true;
  conn->state = HE_STATE_LINK_UP;
  conn->protocol_version.major_version = 1;
  conn->protocol_version.minor_version = 0;
  // Auth callback and IPv4 config callback set
  conn->auth_cb = auth_cb_succeed;
  conn->populate_network_config_ipv4_cb = fixture_network_config_cb;

  he_internal_send_message_ExpectAndReturn(conn, NULL, sizeof(he_msg_config_ipv4_t), HE_SUCCESS);
  he_internal_send_message_IgnoreArg_message();
  he_internal_change_conn_state_Expect(conn, HE_STATE_ONLINE);

  he_msg_auth_t *auth_message = (he_msg_auth_t *)empty_data;
  auth_message->header.auth_type = HE_AUTH_TYPE_USERPASS;

  // We should get success here and the call counter should be 2
  he_return_code_t res = he_handle_msg_auth(conn, empty_data, sizeof(empty_data));
  TEST_ASSERT_EQUAL(HE_SUCCESS, res);
  TEST_ASSERT_EQUAL(2, call_counter);
}

void test_msg_auth_token_packet_too_small(void) {
  // Basic good setup for a server
  conn->is_server = true;
  conn->state = HE_STATE_LINK_UP;
  conn->protocol_version.major_version = 1;
  conn->protocol_version.minor_version = 0;
  // Auth callback and IPv4 config callback set
  conn->auth_token_cb = auth_token_cb_succeed;
  conn->populate_network_config_ipv4_cb = fixture_network_config_cb;

  he_msg_auth_token_t *auth_message = (he_msg_auth_token_t *)empty_data;
  auth_message->header.auth_type = HE_AUTH_TYPE_TOKEN;

  TEST_ASSERT_EQUAL(4, sizeof(he_msg_auth_token_t));

  // Call with a small size to trigger the size check
  he_return_code_t res = he_handle_msg_auth(conn, empty_data, 4);
  TEST_ASSERT_EQUAL(HE_ERR_PACKET_TOO_SMALL, res);
}

void test_msg_auth_token_packet_invalid_length(void) {
  // Basic good setup for a server
  conn->is_server = true;
  conn->state = HE_STATE_LINK_UP;
  conn->protocol_version.major_version = 1;
  conn->protocol_version.minor_version = 0;
  // Auth callback and IPv4 config callback set
  conn->auth_token_cb = auth_token_cb_succeed;
  conn->populate_network_config_ipv4_cb = fixture_network_config_cb;

  he_msg_auth_token_t *auth_message = (he_msg_auth_token_t *)empty_data;
  auth_message->header.auth_type = HE_AUTH_TYPE_TOKEN;

  // Set the auth token length to a large size to trigger the size check
  auth_message->token_length = ntohs(2048);

  he_return_code_t res = he_handle_msg_auth(conn, empty_data, 20);
  TEST_ASSERT_EQUAL(HE_ERR_PACKET_TOO_SMALL, res);
}

void test_msg_auth_token_access_granted(void) {
  // Basic good setup for a server
  conn->is_server = true;
  conn->state = HE_STATE_LINK_UP;
  conn->protocol_version.major_version = 1;
  conn->protocol_version.minor_version = 0;
  // Auth callback and IPv4 config callback set
  conn->auth_token_cb = auth_token_cb_succeed;
  conn->populate_network_config_ipv4_cb = fixture_network_config_cb;

  he_msg_auth_token_t *auth_message = (he_msg_auth_token_t *)empty_data;
  auth_message->header.auth_type = HE_AUTH_TYPE_TOKEN;
  auth_message->token_length = ntohs(12);
  strcpy((char *)auth_message->token, "access token");

  he_internal_send_message_ExpectAndReturn(conn, NULL, sizeof(he_msg_config_ipv4_t), HE_SUCCESS);
  he_internal_send_message_IgnoreArg_message();
  he_internal_change_conn_state_Expect(conn, HE_STATE_ONLINE);

  TEST_ASSERT_EQUAL(0x35, sizeof(he_msg_auth_response_t));
  TEST_ASSERT_EQUAL(0x69, sizeof(he_msg_config_ipv4_t));

  // We should get success here and the call counter should be 2
  he_return_code_t res =
      he_handle_msg_auth(conn, (uint8_t *)auth_message, sizeof(he_msg_auth_token_t) + 12);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res);
  TEST_ASSERT_EQUAL(2, call_counter);
}

void test_msg_auth_buf_packet_too_small(void) {
  // Basic good setup for a server
  conn->is_server = true;
  conn->state = HE_STATE_LINK_UP;
  conn->protocol_version.major_version = 1;
  conn->protocol_version.minor_version = 0;
  // Auth callback and IPv4 config callback set
  conn->auth_buf_cb = auth_buf_cb_succeed;
  conn->populate_network_config_ipv4_cb = fixture_network_config_cb;

  he_msg_auth_buf_t *auth_message = (he_msg_auth_buf_t *)empty_data;
  auth_message->header.auth_type = HE_AUTH_TYPE_CB;

  TEST_ASSERT_EQUAL(4, sizeof(he_msg_auth_buf_t));

  // Call with a small size to trigger the size check
  he_return_code_t res = he_handle_msg_auth(conn, empty_data, 4);
  TEST_ASSERT_EQUAL(HE_ERR_PACKET_TOO_SMALL, res);
}

void test_msg_auth_buf_packet_invalid_length(void) {
  // Basic good setup for a server
  conn->is_server = true;
  conn->state = HE_STATE_LINK_UP;
  conn->protocol_version.major_version = 1;
  conn->protocol_version.minor_version = 0;
  // Auth callback and IPv4 config callback set
  conn->auth_buf_cb = auth_buf_cb_succeed;
  conn->populate_network_config_ipv4_cb = fixture_network_config_cb;

  he_msg_auth_buf_t *auth_message = (he_msg_auth_buf_t *)empty_data;
  auth_message->header.auth_type = HE_AUTH_TYPE_CB;

  // Set the auth buffer length to a large size to trigger the size check
  auth_message->buffer_length = ntohs(2048);

  he_return_code_t res = he_handle_msg_auth(conn, empty_data, 20);
  TEST_ASSERT_EQUAL(HE_ERR_PACKET_TOO_SMALL, res);
}

void test_msg_auth_buf_access_granted(void) {
  // Basic good setup for a server
  conn->is_server = true;
  conn->state = HE_STATE_LINK_UP;
  conn->protocol_version.major_version = 1;
  conn->protocol_version.minor_version = 0;
  // Auth callback and IPv4 config callback set
  conn->auth_buf_cb = auth_buf_cb_succeed;
  conn->populate_network_config_ipv4_cb = fixture_network_config_cb;

  he_msg_auth_buf_t *auth_message = (he_msg_auth_buf_t *)empty_data;
  auth_message->header.auth_type = HE_AUTH_TYPE_CB;
  auth_message->buffer_length = ntohs(10);

  he_internal_send_message_ExpectAndReturn(conn, NULL, sizeof(he_msg_config_ipv4_t), HE_SUCCESS);
  he_internal_send_message_IgnoreArg_message();
  he_internal_change_conn_state_Expect(conn, HE_STATE_ONLINE);

  TEST_ASSERT_EQUAL(0x35, sizeof(he_msg_auth_response_t));
  TEST_ASSERT_EQUAL(0x69, sizeof(he_msg_config_ipv4_t));

  // We should get success here and the call counter should be 2
  he_return_code_t res =
      he_handle_msg_auth(conn, (uint8_t *)auth_message, sizeof(he_msg_auth_buf_t) + 10);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res);
  TEST_ASSERT_EQUAL(2, call_counter);
}

void test_msg_auth_invalid_auth_type(void) {
  // Basic good setup for a server
  conn->is_server = true;
  conn->state = HE_STATE_LINK_UP;
  conn->protocol_version.major_version = 1;
  conn->protocol_version.minor_version = 0;
  // Auth callback and IPv4 config callback set
  conn->auth_buf_cb = auth_buf_cb_succeed;
  conn->populate_network_config_ipv4_cb = fixture_network_config_cb;

  he_msg_auth_buf_t *auth_message = (he_msg_auth_buf_t *)empty_data;
  auth_message->header.auth_type = HE_AUTH_TYPE_CB + 1;
  auth_message->buffer_length = ntohs(10);

  he_internal_send_message_ExpectAndReturn(conn, NULL, sizeof(he_msg_auth_response_t), HE_SUCCESS);
  he_internal_send_message_IgnoreArg_message();
  he_internal_change_conn_state_Expect(conn, HE_STATE_DISCONNECTING);

  // We should get success here and the call counter should be 2
  he_return_code_t res =
      he_handle_msg_auth(conn, (uint8_t *)auth_message, sizeof(he_msg_auth_buf_t) + 10);
  TEST_ASSERT_EQUAL(HE_ERR_ACCESS_DENIED, res);
  TEST_ASSERT_EQUAL(0, call_counter);
}

void test_he_handle_msg_auth_response_with_config(void) {
  he_return_code_t res =
      he_handle_msg_auth_response_with_config(conn, empty_data, sizeof(empty_data));
  TEST_ASSERT_EQUAL(HE_SUCCESS, res);
}

void test_msg_auth_response_with_config_null_conn(void) {
  ret = he_handle_msg_auth_response_with_config(NULL, empty_data, 0);
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, ret);
}

void test_msg_auth_response_with_config_null_packet(void) {
  ret = he_handle_msg_auth_response_with_config(conn, NULL, 0);
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, ret);
}

void test_msg_auth_response_with_config_both_nulls(void) {
  ret = he_handle_msg_auth_response_with_config(NULL, NULL, 0);
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, ret);
}

void test_msg_goodbye_valid(void) {
  ret = he_handle_msg_goodbye(conn, empty_data, sizeof(empty_data));
  TEST_ASSERT_EQUAL(HE_ERR_SERVER_GOODBYE, ret);
}

void test_msg_goodbye_null(void) {
  ret = he_handle_msg_goodbye(NULL, empty_data, sizeof(empty_data));
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, ret);
  ret = he_handle_msg_goodbye(NULL, NULL, sizeof(empty_data));
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, ret);
  ret = he_handle_msg_goodbye(conn, NULL, sizeof(empty_data));
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, ret);
}

void test_handle_msg_server_config_null(void) {
  ret = he_handle_msg_server_config(NULL, empty_data, sizeof(empty_data));
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, ret);
  ret = he_handle_msg_server_config(conn, NULL, sizeof(empty_data));
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, ret);
}

void test_handle_msg_server_config_invalid_state(void) {
  conn->is_server = true;
  ret = he_handle_msg_server_config(conn, empty_data, sizeof(empty_data));
  TEST_ASSERT_EQUAL(HE_ERR_INVALID_CONN_STATE, ret);

  conn->is_server = false;
  he_internal_is_valid_state_for_server_config_ExpectAndReturn(conn, false);
  ret = he_handle_msg_server_config(conn, empty_data, sizeof(empty_data));
  TEST_ASSERT_EQUAL(HE_ERR_INVALID_CONN_STATE, ret);
}

void test_handle_msg_server_config_packet_too_small(void) {
  conn->is_server = false;
  he_internal_is_valid_state_for_server_config_ExpectAndReturn(conn, true);
  ret = he_handle_msg_server_config(conn, empty_data, 1);
  TEST_ASSERT_EQUAL(HE_ERR_PACKET_TOO_SMALL, ret);
}

void test_handle_msg_server_config_buffer_overflow(void) {
  conn->is_server = false;
  he_internal_is_valid_state_for_server_config_ExpectAndReturn(conn, true);

  he_msg_server_config_t *msg = (he_msg_server_config_t *)empty_data;
  msg->buffer_length = htons(sizeof(empty_data) - sizeof(he_msg_server_config_t) + 1);
  ret = he_handle_msg_server_config(conn, empty_data, sizeof(empty_data));
  TEST_ASSERT_EQUAL(HE_ERR_POINTER_WOULD_OVERFLOW, ret);
}

void test_handle_msg_server_config_valid(void) {
  conn->is_server = false;
  conn->state_change_cb = state_change_cb;
  he_internal_is_valid_state_for_server_config_ExpectAndReturn(conn, true);

  he_msg_server_config_t *msg = (he_msg_server_config_t *)empty_data;
  msg->buffer_length = htons(42);
  ret = he_handle_msg_server_config(conn, empty_data, sizeof(empty_data));
  TEST_ASSERT_EQUAL(HE_SUCCESS, ret);
}

void test_msg_data_frag_conn_null(void) {
  ret = he_handle_msg_data_with_frag(NULL, empty_data, 0);

  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, ret);
}

void test_msg_data_frag_packet_null(void) {
  ret = he_handle_msg_data_with_frag(conn, NULL, 0);

  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, ret);
}

void test_msg_data_frag_both_null(void) {
  ret = he_handle_msg_data_with_frag(NULL, NULL, 0);

  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, ret);
}

void test_msg_data_frag_bad_state(void) {
  ret = he_handle_msg_data_with_frag(conn, empty_data, 0);
  TEST_ASSERT_EQUAL(HE_ERR_INVALID_CONN_STATE, ret);
}

void test_msg_data_frag_length_would_overflow(void) {
  conn->state = HE_STATE_ONLINE;

  he_msg_data_frag_t *msg = (he_msg_data_frag_t *)empty_data;
  msg->length = htons(1200);

  ret = he_handle_msg_data_with_frag(conn, empty_data, 1199);
  TEST_ASSERT_EQUAL(HE_ERR_POINTER_WOULD_OVERFLOW, ret);
}

void test_msg_data_frag_offset_would_overflow(void) {
  conn->state = HE_STATE_ONLINE;

  he_msg_data_frag_t *msg = (he_msg_data_frag_t *)empty_data;
  msg->length = htons(477);
  msg->offset = htons(1024);

  ret = he_handle_msg_data_with_frag(conn, empty_data, 477 + sizeof(he_msg_data_frag_t));
  TEST_ASSERT_EQUAL(HE_ERR_POINTER_WOULD_OVERFLOW, ret);
}

static size_t make_fragment(uint8_t *buffer, uint16_t id, uint16_t offset, uint16_t length,
                            uint8_t mf) {
  he_msg_data_frag_t *msg = (he_msg_data_frag_t *)buffer;
  msg->id = htons(id);
  msg->length = htons(length);
  uint16_t off = (mf << 13) | (offset >> 3);
  msg->offset = htons(off);
  return length + sizeof(he_msg_data_frag_t);
}

void test_msg_data_frag_cache_new_fragment(void) {
  conn->state = HE_STATE_ONLINE;
  conn->frag_table = he_internal_fragment_table_create(0);

  size_t length = make_fragment(empty_data, 123, 512, 512, 1);
  ret = he_handle_msg_data_with_frag(conn, empty_data, length);
  TEST_ASSERT_EQUAL(HE_SUCCESS, ret);

  he_fragment_entry_t *entry = conn->frag_table->entries[123];
  TEST_ASSERT_NOT_NULL(entry);
  TEST_ASSERT_GREATER_OR_EQUAL(0, entry->timestamp);
  TEST_ASSERT_NOT_NULL(entry->fragments);
  TEST_ASSERT_EQUAL(512, entry->fragments->begin);
  TEST_ASSERT_EQUAL(1024, entry->fragments->end);
  TEST_ASSERT_FALSE(entry->fragments->last_frag);
  TEST_ASSERT_NULL(entry->fragments->next);

  // Clean up
  he_internal_fragment_table_destroy(conn->frag_table);
}

void test_msg_data_frag_reassemble_full_packet(void) {
  conn->state = HE_STATE_ONLINE;
  conn->frag_table = he_internal_fragment_table_create(0);

  // Received the 2nd fragment
  size_t len1 = make_fragment(empty_data, 123, 512, 512, 1);
  ret = he_handle_msg_data_with_frag(conn, empty_data, len1);
  TEST_ASSERT_EQUAL(HE_SUCCESS, ret);

  // Received the first fragment
  size_t len2 = make_fragment(empty_data, 123, 0, 512, 1);
  ret = he_handle_msg_data_with_frag(conn, empty_data, len2);
  TEST_ASSERT_EQUAL(HE_SUCCESS, ret);

  // Received the final fragment
  he_plugin_egress_ExpectAnyArgsAndReturn(HE_SUCCESS);
  he_internal_is_ipv4_packet_valid_ExpectAnyArgsAndReturn(true);
  size_t len3 = make_fragment(empty_data, 123, 1024, 301, 0);
  ret = he_handle_msg_data_with_frag(conn, empty_data, len3);
  TEST_ASSERT_EQUAL(HE_SUCCESS, ret);

  // Entry for the fragment id should be removed
  he_fragment_entry_t *entry = conn->frag_table->entries[123];
  TEST_ASSERT_NULL(entry);

  // Clean up
  he_internal_fragment_table_destroy(conn->frag_table);
}

void test_msg_data_frag_overlap_fragments(void) {
  conn->state = HE_STATE_ONLINE;
  conn->frag_table = he_internal_fragment_table_create(0);

  // Received the 2nd fragment
  size_t len1 = make_fragment(empty_data, 123, 512, 512, 1);
  ret = he_handle_msg_data_with_frag(conn, empty_data, len1);
  TEST_ASSERT_EQUAL(HE_SUCCESS, ret);

  // Received a bad fragment, it should be dropped
  size_t len2 = make_fragment(empty_data, 123, 0, 768, 1);
  ret = he_handle_msg_data_with_frag(conn, empty_data, len2);
  TEST_ASSERT_EQUAL(HE_ERR_BAD_FRAGMENT, ret);

  // Clean up
  he_internal_fragment_table_destroy(conn->frag_table);
}
