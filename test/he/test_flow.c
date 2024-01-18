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
#include "flow.h"

// Direct Includes for Utility Functions
#include "config.h"
#include "core.h"
#include "frag.h"
#include "memory.h"

#include <wolfssl/error-ssl.h>

// Internal Mocks
#include "mock_msg_handlers.h"
#include "mock_conn.h"
#include "mock_conn_internal.h"
#include "mock_fake_dispatch.h"
#include "mock_network.h"
#include "mock_plugin_chain.h"
#include "mock_mss.h"

// External Mocks
#include "mock_ssl.h"

uint8_t *packet = NULL;
uint8_t *buffer = NULL;
size_t packet_max_length = 1500;
size_t buffer_max_length = 1500;

size_t test_buffer_length = 1200;

size_t test_packet_size = 1100;

he_conn_t *conn = NULL;

void setUp(void) {
  srand(time(NULL));

  packet = calloc(1, packet_max_length);
  packet[0] = 'H';
  packet[1] = 'e';
  packet[2] = 0x01;
  packet[3] = 0x01;

  buffer = calloc(1, buffer_max_length);
  conn = calloc(1, sizeof(he_conn_t));
  conn->protocol_version.major_version = 1;
  conn->protocol_version.minor_version = 1;
  conn->outside_mtu = HE_MAX_WIRE_MTU;

  conn->packet_seen = false;
  conn->incoming_data = packet;
  conn->incoming_data_length = packet_max_length;

  // Generate a random blob to represent the packet
  // Start at 4 so we have a valid Helium packet still
  for(int a = 4; a < packet_max_length; a++) {
    packet[a] = rand() % 256;
  }
}

void tearDown(void) {
  free(buffer);
  free(packet);
  free(conn);
}

he_return_code_t fixture_inside_packet_send_message(he_conn_t *conn, uint8_t *message,
                                                    uint16_t length, int numCalls) {
  he_msg_data_t *data_message = (he_msg_data_t *)message;
  if(conn->protocol_version.major_version == 1 && conn->protocol_version.minor_version == 0) {
    TEST_ASSERT_EQUAL(sizeof(fake_ipv4_packet), data_message->length);
  } else {
    TEST_ASSERT_EQUAL(sizeof(fake_ipv4_packet), ntohs(data_message->length));
  }
  return HE_SUCCESS;
}

void test_inside_packet_received_packet_null(void) {
  he_return_code_t res1 = he_conn_inside_packet_received(conn, NULL, packet_max_length);
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, res1);
}

void test_inside_packet_received_conn_null(void) {
  he_return_code_t res1 = he_conn_inside_packet_received(NULL, fake_ipv4_packet, packet_max_length);
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, res1);
}

void test_inside_pkt_received_not_connected(void) {
  he_return_code_t res1 =
      he_conn_inside_packet_received(conn, fake_ipv4_packet, sizeof(fake_ipv4_packet));
  TEST_ASSERT_EQUAL(HE_ERR_INVALID_CONN_STATE, res1);
}

void test_inside_pkt_received(void) {
  conn->state = HE_STATE_ONLINE;
  he_return_code_t res1 =
      he_conn_inside_packet_received(conn, fake_ipv4_packet, HE_IPV4_HEADER_SIZE - 1);
  TEST_ASSERT_EQUAL(HE_ERR_PACKET_TOO_SMALL, res1);
}

void test_inside_pkt_received_too_large(void) {
  conn->state = HE_STATE_ONLINE;
  conn->outside_mtu = 1300;
  he_return_code_t res1 =
      he_conn_inside_packet_received(conn, fake_ipv4_packet, 1300 - HE_WOLF_MAX_HEADER_SIZE);
  TEST_ASSERT_EQUAL(HE_ERR_PACKET_TOO_LARGE, res1);
}

void test_inside_pkt_bad_packet(void) {
  conn->state = HE_STATE_ONLINE;
  he_internal_is_ipv4_packet_valid_ExpectAndReturn(bad_fake_ipv4_packet,
                                                   sizeof(bad_fake_ipv4_packet), false);
  he_return_code_t res1 =
      he_conn_inside_packet_received(conn, bad_fake_ipv4_packet, sizeof(bad_fake_ipv4_packet));
  TEST_ASSERT_EQUAL(HE_ERR_UNSUPPORTED_PACKET_TYPE, res1);
}

void test_inside_pkt_good_packet(void) {
  conn->state = HE_STATE_ONLINE;
  he_internal_is_ipv4_packet_valid_ExpectAndReturn(fake_ipv4_packet, sizeof(fake_ipv4_packet),
                                                   true);
  he_conn_get_effective_pmtu_ExpectAndReturn(conn, 1350);
  he_plugin_ingress_ExpectAnyArgsAndReturn(HE_SUCCESS);
  he_internal_calculate_data_packet_length_ExpectAndReturn(conn, sizeof(fake_ipv4_packet), 1242);
  he_internal_send_message_ExpectAndReturn(conn, NULL, 1242 + sizeof(he_msg_data_t), HE_SUCCESS);
  he_internal_send_message_IgnoreArg_message();
  he_internal_send_message_AddCallback(fixture_inside_packet_send_message);
  he_return_code_t res1 =
      he_conn_inside_packet_received(conn, fake_ipv4_packet, sizeof(fake_ipv4_packet));
  TEST_ASSERT_EQUAL(HE_SUCCESS, res1);
}

void test_inside_pkt_good_packet_with_legacy_behaviour(void) {
  conn->state = HE_STATE_ONLINE;
  he_internal_is_ipv4_packet_valid_ExpectAndReturn(fake_ipv4_packet, sizeof(fake_ipv4_packet),
                                                   true);
  he_plugin_ingress_IgnoreAndReturn(HE_SUCCESS);
  conn->protocol_version.major_version = 1;
  conn->protocol_version.minor_version = 0;

  he_conn_get_effective_pmtu_ExpectAndReturn(conn, 1350);
  he_internal_calculate_data_packet_length_ExpectAndReturn(conn, sizeof(fake_ipv4_packet), 1242);
  he_internal_send_message_ExpectAndReturn(conn, NULL, 1242 + sizeof(he_msg_data_t), HE_SUCCESS);
  he_internal_send_message_IgnoreArg_message();
  he_internal_send_message_AddCallback(fixture_inside_packet_send_message);
  he_return_code_t res1 =
      he_conn_inside_packet_received(conn, fake_ipv4_packet, sizeof(fake_ipv4_packet));
  TEST_ASSERT_EQUAL(HE_SUCCESS, res1);
}

void test_he_internal_flow_should_fragment(void) {
  // Don't frag for Lightway TCP
  conn->connection_type = HE_CONNECTION_TYPE_STREAM;
  TEST_ASSERT_FALSE(he_internal_flow_should_fragment(conn, 1200, 1350));

  // Don't frag if PMTUD search hasn't completed
  conn->connection_type = HE_CONNECTION_TYPE_DATAGRAM;
  conn->pmtud_state = HE_PMTUD_STATE_SEARCHING;
  TEST_ASSERT_FALSE(he_internal_flow_should_fragment(conn, 1200, 1350));

  // Don't frag if the packet length is exactly effective_pmtu
  conn->connection_type = HE_CONNECTION_TYPE_DATAGRAM;
  conn->pmtud_state = HE_PMTUD_STATE_SEARCH_COMPLETE;
  TEST_ASSERT_FALSE(he_internal_flow_should_fragment(conn, 1200, 1200));

  // Should frag if packet length is greater than effective_pmtu
  TEST_ASSERT_TRUE(he_internal_flow_should_fragment(conn, 1200, 1201));
}

void test_inside_pkt_good_packet_clamp_mss_success(void) {
  conn->state = HE_STATE_ONLINE;
  conn->pmtud_state = HE_PMTUD_STATE_SEARCH_COMPLETE;
  he_internal_is_ipv4_packet_valid_ExpectAndReturn(fake_ipv4_packet, sizeof(fake_ipv4_packet),
                                                   true);
  he_conn_get_effective_pmtu_ExpectAndReturn(conn, 100);
  he_internal_clamp_mss_ExpectAndReturn(fake_ipv4_packet, sizeof(fake_ipv4_packet),
                                        100 - HE_MSS_OVERHEAD, HE_SUCCESS);
  he_plugin_ingress_ExpectAnyArgsAndReturn(HE_SUCCESS);
  he_internal_calculate_data_packet_length_ExpectAndReturn(conn, sizeof(fake_ipv4_packet), 1242);
  he_internal_send_message_ExpectAndReturn(conn, NULL, 1242 + sizeof(he_msg_data_t), HE_SUCCESS);
  he_internal_send_message_IgnoreArg_message();
  he_internal_send_message_AddCallback(fixture_inside_packet_send_message);
  int res1 = he_conn_inside_packet_received(conn, fake_ipv4_packet, sizeof(fake_ipv4_packet));
  TEST_ASSERT_EQUAL(HE_SUCCESS, res1);
}

void test_inside_pkt_good_packet_clamp_mss_failed(void) {
  conn->state = HE_STATE_ONLINE;
  conn->pmtud_state = HE_PMTUD_STATE_SEARCH_COMPLETE;
  he_internal_is_ipv4_packet_valid_ExpectAndReturn(fake_ipv4_packet, sizeof(fake_ipv4_packet),
                                                   true);
  he_conn_get_effective_pmtu_ExpectAndReturn(conn, 100);
  he_internal_clamp_mss_ExpectAndReturn(fake_ipv4_packet, sizeof(fake_ipv4_packet),
                                        100 - HE_MSS_OVERHEAD, HE_ERR_FAILED);
  int res1 = he_conn_inside_packet_received(conn, fake_ipv4_packet, sizeof(fake_ipv4_packet));
  TEST_ASSERT_EQUAL(HE_ERR_FAILED, res1);
}

void test_inside_pkt_plugin_drop(void) {
  conn->state = HE_STATE_ONLINE;

  he_internal_is_ipv4_packet_valid_ExpectAndReturn(fake_ipv4_packet, sizeof(fake_ipv4_packet),
                                                   true);
  he_conn_get_effective_pmtu_ExpectAndReturn(conn, 1350);
  he_plugin_ingress_ExpectAnyArgsAndReturn(HE_ERR_PLUGIN_DROP);

  he_return_code_t res1 =
      he_conn_inside_packet_received(conn, fake_ipv4_packet, sizeof(fake_ipv4_packet));

  TEST_ASSERT_EQUAL(HE_SUCCESS, res1);
}

void test_inside_pkt_plugin_fail(void) {
  conn->state = HE_STATE_ONLINE;

  he_internal_is_ipv4_packet_valid_ExpectAndReturn(fake_ipv4_packet, sizeof(fake_ipv4_packet),
                                                   true);
  he_conn_get_effective_pmtu_ExpectAndReturn(conn, 1350);
  he_plugin_ingress_ExpectAnyArgsAndReturn(HE_ERR_FAILED);

  he_return_code_t res1 =
      he_conn_inside_packet_received(conn, fake_ipv4_packet, sizeof(fake_ipv4_packet));

  TEST_ASSERT_EQUAL(HE_ERR_FAILED, res1);
}

void test_inside_pkt_plugin_overflow_fail(void) {
  conn->state = HE_STATE_ONLINE;

  he_internal_is_ipv4_packet_valid_ExpectAndReturn(fake_ipv4_packet, sizeof(fake_ipv4_packet),
                                                   true);
  he_conn_get_effective_pmtu_ExpectAndReturn(conn, 1350);
  he_plugin_ingress_Stub(stub_overflow_plugin);

  he_return_code_t res1 =
      he_conn_inside_packet_received(conn, fake_ipv4_packet, sizeof(fake_ipv4_packet));

  TEST_ASSERT_EQUAL(HE_ERR_FAILED, res1);
}

void test_inside_pkt_plugin_large_mtu(void) {
  uint8_t buffer[8000];
  conn->state = HE_STATE_ONLINE;
  conn->outside_mtu = 9000;

  he_internal_is_ipv4_packet_valid_ExpectAndReturn(buffer, sizeof(buffer), true);
  he_conn_get_effective_pmtu_ExpectAndReturn(conn, 1350);
  he_plugin_ingress_ExpectAnyArgsAndReturn(HE_SUCCESS);

  he_return_code_t res1 = he_conn_inside_packet_received(conn, buffer, sizeof(buffer));

  TEST_ASSERT_EQUAL(HE_ERR_FAILED, res1);
}

void test_outside_pktrcv_packet_null(void) {
  he_return_code_t res1 = he_conn_outside_data_received(conn, NULL, test_buffer_length);
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, res1);
}

void test_outside_pktrcv_conn_null(void) {
  he_return_code_t res1 = he_conn_outside_data_received(NULL, packet, test_buffer_length);
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, res1);
}

void test_outside_pktrcv_packet_too_small(void) {
  he_return_code_t res1 = he_internal_flow_outside_packet_received(conn, packet, 0);
  TEST_ASSERT_EQUAL(HE_ERR_PACKET_TOO_SMALL, res1);
}

void test_outside_pktrcv_invalid_header(void) {
  packet[0] = '0';
  he_return_code_t res1 =
      he_internal_flow_outside_packet_received(conn, packet, test_buffer_length);
  TEST_ASSERT_EQUAL(HE_ERR_NOT_HE_PACKET, res1);
}

void test_outside_pktrcv_invalid_header2(void) {
  packet[1] = '0';
  he_return_code_t res1 =
      he_internal_flow_outside_packet_received(conn, packet, test_buffer_length);
  TEST_ASSERT_EQUAL(HE_ERR_NOT_HE_PACKET, res1);
}

void test_outside_pktrcv_invalid_version(void) {
  packet[2] = 0x03;
  he_return_code_t res1 =
      he_internal_flow_outside_packet_received(conn, packet, test_buffer_length);
  TEST_ASSERT_EQUAL(HE_ERR_INCORRECT_PROTOCOL_VERSION, res1);
}

void test_outside_pktrcv_good_packet(void) {
  dispatch_ExpectAndReturn("he_internal_flow_outside_data_verify_connection", HE_SUCCESS);
  he_internal_generate_event_Expect(conn, HE_EVENT_FIRST_MESSAGE_RECEIVED);
  dispatch_ExpectAndReturn("he_internal_flow_outside_data_handle_messages", HE_SUCCESS);
  wolfSSL_read_ExpectAndReturn(conn->wolf_ssl, &conn->read_packet.packet,
                               sizeof(conn->read_packet.packet), SSL_FATAL_ERROR);
  wolfSSL_get_error_ExpectAndReturn(conn->wolf_ssl, SSL_FATAL_ERROR, SSL_ERROR_WANT_READ);

  he_return_code_t res1 =
      he_internal_flow_outside_packet_received(conn, packet, test_buffer_length);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res1);
  he_return_code_t res2 = he_internal_flow_outside_data_verify_connection(conn);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res2);
  he_return_code_t res3 = he_internal_flow_outside_data_handle_messages(conn);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res3);
}

void test_outside_pktrcv_good_packet_in_connecting_want_read(void) {
  dispatch_ExpectAndReturn("he_internal_flow_outside_data_verify_connection", HE_SUCCESS);
  he_internal_generate_event_Expect(conn, HE_EVENT_FIRST_MESSAGE_RECEIVED);
  wolfSSL_negotiate_ExpectAndReturn(conn->wolf_ssl, SSL_FATAL_ERROR);
  wolfSSL_get_error_ExpectAndReturn(conn->wolf_ssl, SSL_FATAL_ERROR, SSL_ERROR_WANT_READ);
  he_internal_update_timeout_Expect(conn);
  conn->state = HE_STATE_CONNECTING;
  he_return_code_t res1 =
      he_internal_flow_outside_packet_received(conn, packet, test_buffer_length);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res1);
  he_return_code_t res2 = he_internal_flow_outside_data_verify_connection(conn);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res2);
}

void test_outside_pktrcv_good_packet_in_connecting_want_write(void) {
  dispatch_ExpectAndReturn("he_internal_flow_outside_data_verify_connection", HE_SUCCESS);
  he_internal_generate_event_Expect(conn, HE_EVENT_FIRST_MESSAGE_RECEIVED);
  wolfSSL_negotiate_ExpectAndReturn(conn->wolf_ssl, SSL_FATAL_ERROR);
  wolfSSL_get_error_ExpectAndReturn(conn->wolf_ssl, SSL_FATAL_ERROR, SSL_ERROR_WANT_WRITE);
  he_internal_update_timeout_Expect(conn);
  conn->state = HE_STATE_CONNECTING;
  he_return_code_t res1 =
      he_internal_flow_outside_packet_received(conn, packet, test_buffer_length);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res1);
  he_return_code_t res2 = he_internal_flow_outside_data_verify_connection(conn);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res2);
}

void test_outside_pktrcv_good_packet_in_connecting_actual_error(void) {
  dispatch_ExpectAndReturn("he_internal_flow_outside_data_verify_connection", HE_SUCCESS);
  he_internal_generate_event_Expect(conn, HE_EVENT_FIRST_MESSAGE_RECEIVED);
  wolfSSL_negotiate_ExpectAndReturn(conn->wolf_ssl, FATAL_ERROR);
  wolfSSL_get_error_ExpectAndReturn(conn->wolf_ssl, FATAL_ERROR, SSL_FATAL_ERROR);
  conn->state = HE_STATE_CONNECTING;
  he_return_code_t res1 =
      he_internal_flow_outside_packet_received(conn, packet, test_buffer_length);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res1);
  he_return_code_t res2 = he_internal_flow_outside_data_verify_connection(conn);
  TEST_ASSERT_EQUAL(HE_ERR_SSL_ERROR, res2);
}

void test_outside_pktrcv_good_packet_in_connecting_all_good(void) {
  dispatch_ExpectAndReturn("he_internal_flow_outside_data_verify_connection", HE_SUCCESS);
  he_internal_generate_event_Expect(conn, HE_EVENT_FIRST_MESSAGE_RECEIVED);
  wolfSSL_negotiate_ExpectAndReturn(conn->wolf_ssl, SSL_SUCCESS);
  he_internal_change_conn_state_Expect(conn, HE_STATE_LINK_UP);
  dispatch_ExpectAndReturn("he_internal_flow_outside_data_handle_messages", HE_SUCCESS);
  conn->state = HE_STATE_CONNECTING;

  wolfSSL_read_ExpectAndReturn(conn->wolf_ssl, &conn->read_packet.packet,
                               sizeof(conn->read_packet.packet), SSL_FATAL_ERROR);

  wolfSSL_get_error_ExpectAndReturn(conn->wolf_ssl, SSL_FATAL_ERROR, SSL_ERROR_WANT_READ);

  // For this test it doesn't matter what it's called with as long as it's called
  // Revisit this as part of the audit
  wolfSSL_write_IgnoreAndReturn(100);

  he_return_code_t res1 =
      he_internal_flow_outside_packet_received(conn, packet, test_buffer_length);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res1);
  he_return_code_t res2 = he_internal_flow_outside_data_verify_connection(conn);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res2);
  he_return_code_t res3 = he_internal_flow_outside_data_handle_messages(conn);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res3);
}

void test_packet_session_reject(void) {
  he_return_code_t res = he_internal_flow_outside_packet_received(
      conn, fake_he_packet_session_reject, sizeof(fake_he_packet_session_reject));
  TEST_ASSERT_EQUAL(HE_ERR_REJECTED_SESSION, res);
}

void test_plugin_drop_returns_he_success(void) {
  he_plugin_ingress_ExpectAnyArgsAndReturn(HE_ERR_PLUGIN_DROP);
  he_return_code_t res = he_conn_outside_data_received(conn, packet, packet_max_length);
  TEST_ASSERT_EQUAL_INT(HE_SUCCESS, res);
}

void test_plugin_error_returns_error(void) {
  he_plugin_ingress_ExpectAnyArgsAndReturn(HE_ERR_NULL_POINTER);
  he_return_code_t res = he_conn_outside_data_received(conn, packet, packet_max_length);
  TEST_ASSERT_EQUAL_INT(HE_ERR_NULL_POINTER, res);
}

void test_session_id_change(void) {
  conn->state = HE_STATE_ONLINE;
  conn->session_id = 0xFFFF;

  he_wire_hdr_t *pkt = (he_wire_hdr_t *)empty_data;
  pkt->session = 0xDEADBAD;

  he_internal_update_session_incoming(conn, pkt);
  TEST_ASSERT_EQUAL(0xDEADBAD, conn->session_id);
}

void test_session_id_unset_doesnt_trigger_change(void) {
  conn->state = HE_STATE_ONLINE;
  conn->session_id = 0xFFFF;

  he_wire_hdr_t *pkt = (he_wire_hdr_t *)empty_data;
  pkt->session = 0;

  he_internal_update_session_incoming(conn, pkt);
  TEST_ASSERT_EQUAL(0xFFFF, conn->session_id);
}

void test_session_id_server_session_is_same(void) {
  conn->state = HE_STATE_ONLINE;
  conn->is_server = true;
  conn->session_id = 0xFFFF;

  he_wire_hdr_t *pkt = (he_wire_hdr_t *)empty_data;
  pkt->session = 0xFFFF;

  he_internal_update_session_incoming(conn, pkt);
  TEST_ASSERT_EQUAL(0xFFFF, conn->session_id);
}

void test_session_id_server_session_unknown(void) {
  conn->state = HE_STATE_ONLINE;
  conn->is_server = true;
  conn->session_id = 0xFFFF;
  conn->pending_session_id = 0xbeef;

  he_wire_hdr_t *pkt = (he_wire_hdr_t *)empty_data;
  pkt->session = 0xdead;

  he_return_code_t res = he_internal_update_session_incoming(conn, pkt);
  TEST_ASSERT_EQUAL(0xFFFF, conn->session_id);
  TEST_ASSERT_EQUAL(HE_ERR_UNKNOWN_SESSION, res);
}

void test_session_id_server_session_rotation(void) {
  conn->state = HE_STATE_ONLINE;
  conn->is_server = true;
  conn->session_id = 0xFFFF;
  conn->pending_session_id = 0xbeef;

  he_wire_hdr_t *pkt = (he_wire_hdr_t *)empty_data;
  pkt->session = 0xbeef;

  he_internal_generate_event_Expect(conn, HE_EVENT_PENDING_SESSION_ACKNOWLEDGED);
  he_return_code_t res = he_internal_update_session_incoming(conn, pkt);
  TEST_ASSERT_EQUAL(0xbeef, conn->session_id);
  TEST_ASSERT_EQUAL(0, conn->pending_session_id);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res);
}

void test_handle_process_packet_wants_read(void) {
  dispatch_ExpectAndReturn("he_internal_flow_outside_data_verify_connection", HE_SUCCESS);
  he_internal_generate_event_Expect(conn, HE_EVENT_FIRST_MESSAGE_RECEIVED);
  dispatch_ExpectAndReturn("he_internal_flow_outside_data_handle_messages", HE_SUCCESS);
  wolfSSL_read_ExpectAndReturn(conn->wolf_ssl, conn->read_packet.packet,
                               sizeof(conn->read_packet.packet), 1200);
  wolfSSL_read_ExpectAndReturn(conn->wolf_ssl, conn->read_packet.packet,
                               sizeof(conn->read_packet.packet), 1000);
  wolfSSL_read_ExpectAndReturn(conn->wolf_ssl, conn->read_packet.packet,
                               sizeof(conn->read_packet.packet), SSL_FATAL_ERROR);
  wolfSSL_get_error_ExpectAndReturn(conn->wolf_ssl, SSL_FATAL_ERROR, SSL_ERROR_WANT_READ);

  he_return_code_t res = he_internal_flow_outside_packet_received(conn, packet, packet_max_length);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res);
  he_return_code_t res2 = he_internal_flow_outside_data_verify_connection(conn);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res2);
  he_return_code_t res3 = he_internal_flow_outside_data_handle_messages(conn);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res3);

  TEST_ASSERT_EQUAL(0, conn->read_packet.packet_size);
  TEST_ASSERT_FALSE(conn->read_packet.has_packet);
}

void test_handle_process_packet_wants_write(void) {
  dispatch_ExpectAndReturn("he_internal_flow_outside_data_verify_connection", HE_SUCCESS);
  he_internal_generate_event_Expect(conn, HE_EVENT_FIRST_MESSAGE_RECEIVED);
  dispatch_ExpectAndReturn("he_internal_flow_outside_data_handle_messages", HE_SUCCESS);
  wolfSSL_read_ExpectAndReturn(conn->wolf_ssl, conn->read_packet.packet,
                               sizeof(conn->read_packet.packet), 1200);
  wolfSSL_read_ExpectAndReturn(conn->wolf_ssl, conn->read_packet.packet,
                               sizeof(conn->read_packet.packet), 1000);
  wolfSSL_read_ExpectAndReturn(conn->wolf_ssl, conn->read_packet.packet,
                               sizeof(conn->read_packet.packet), SSL_FATAL_ERROR);
  wolfSSL_get_error_ExpectAndReturn(conn->wolf_ssl, SSL_FATAL_ERROR, SSL_ERROR_WANT_WRITE);

  he_return_code_t res = he_internal_flow_outside_packet_received(conn, packet, packet_max_length);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res);
  he_return_code_t res2 = he_internal_flow_outside_data_verify_connection(conn);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res2);
  he_return_code_t res3 = he_internal_flow_outside_data_handle_messages(conn);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res3);

  TEST_ASSERT_EQUAL(0, conn->read_packet.packet_size);
  TEST_ASSERT_FALSE(conn->read_packet.has_packet);
}

void test_handle_process_packet_other_error(void) {
  dispatch_ExpectAndReturn("he_internal_flow_outside_data_verify_connection", HE_SUCCESS);
  he_internal_generate_event_Expect(conn, HE_EVENT_FIRST_MESSAGE_RECEIVED);
  dispatch_ExpectAndReturn("he_internal_flow_outside_data_handle_messages", HE_SUCCESS);
  wolfSSL_read_ExpectAndReturn(conn->wolf_ssl, conn->read_packet.packet,
                               sizeof(conn->read_packet.packet), 1200);
  wolfSSL_read_ExpectAndReturn(conn->wolf_ssl, conn->read_packet.packet,
                               sizeof(conn->read_packet.packet), 1000);
  wolfSSL_read_ExpectAndReturn(conn->wolf_ssl, conn->read_packet.packet,
                               sizeof(conn->read_packet.packet), SSL_FATAL_ERROR);
  wolfSSL_get_error_ExpectAndReturn(conn->wolf_ssl, SSL_FATAL_ERROR, SSL_FATAL_ERROR);

  he_return_code_t res = he_internal_flow_outside_packet_received(conn, packet, packet_max_length);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res);
  he_return_code_t res2 = he_internal_flow_outside_data_verify_connection(conn);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res2);
  he_return_code_t res3 = he_internal_flow_outside_data_handle_messages(conn);
  TEST_ASSERT_EQUAL(HE_ERR_SSL_ERROR_NONFATAL, res3);

  TEST_ASSERT_EQUAL(0, conn->read_packet.packet_size);
  TEST_ASSERT_FALSE(conn->read_packet.has_packet);
}

void test_handle_process_packet_connection_closed(void) {
  dispatch_ExpectAndReturn("he_internal_flow_outside_data_verify_connection", HE_SUCCESS);
  he_internal_generate_event_Expect(conn, HE_EVENT_FIRST_MESSAGE_RECEIVED);
  dispatch_ExpectAndReturn("he_internal_flow_outside_data_handle_messages", HE_SUCCESS);
  wolfSSL_read_ExpectAndReturn(conn->wolf_ssl, conn->read_packet.packet,
                               sizeof(conn->read_packet.packet), 1200);
  wolfSSL_read_ExpectAndReturn(conn->wolf_ssl, conn->read_packet.packet,
                               sizeof(conn->read_packet.packet), 0);
  wolfSSL_get_error_ExpectAndReturn(conn->wolf_ssl, 0, SSL_ERROR_SSL);

  he_return_code_t res = he_internal_flow_outside_packet_received(conn, packet, packet_max_length);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res);
  he_return_code_t res2 = he_internal_flow_outside_data_verify_connection(conn);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res2);
  he_return_code_t res3 = he_internal_flow_outside_data_handle_messages(conn);
  TEST_ASSERT_EQUAL(HE_ERR_CONNECTION_WAS_CLOSED, res3);

  TEST_ASSERT_EQUAL(0, conn->read_packet.packet_size);
  TEST_ASSERT_FALSE(conn->read_packet.has_packet);
}

void test_dnsmismatch_gets_returned(void) {
  conn->state = HE_STATE_CONNECTING;

  dispatch_ExpectAndReturn("he_internal_flow_outside_data_verify_connection", HE_SUCCESS);
  he_internal_generate_event_Expect(conn, HE_EVENT_FIRST_MESSAGE_RECEIVED);
  wolfSSL_negotiate_ExpectAndReturn(conn->wolf_ssl, SSL_FATAL_ERROR);
  wolfSSL_get_error_ExpectAndReturn(conn->wolf_ssl, SSL_FATAL_ERROR, DOMAIN_NAME_MISMATCH);

  he_return_code_t res1 =
      he_internal_flow_outside_packet_received(conn, fake_he_packet, sizeof(fake_he_packet));
  TEST_ASSERT_EQUAL(HE_SUCCESS, res1);
  he_return_code_t res2 = he_internal_flow_outside_data_verify_connection(conn);
  TEST_ASSERT_EQUAL(HE_ERR_SERVER_DN_MISMATCH, res2);
}

void test_cert_verify_failed_gets_returned(void) {
  conn->state = HE_STATE_CONNECTING;

  dispatch_ExpectAndReturn("he_internal_flow_outside_data_verify_connection", HE_SUCCESS);
  he_internal_generate_event_Expect(conn, HE_EVENT_FIRST_MESSAGE_RECEIVED);
  wolfSSL_negotiate_ExpectAndReturn(conn->wolf_ssl, SSL_FATAL_ERROR);
  wolfSSL_get_error_ExpectAndReturn(conn->wolf_ssl, SSL_FATAL_ERROR, ASN_SIG_CONFIRM_E);

  he_return_code_t res1 =
      he_internal_flow_outside_packet_received(conn, fake_he_packet, sizeof(fake_he_packet));
  TEST_ASSERT_EQUAL(HE_SUCCESS, res1);
  he_return_code_t res2 = he_internal_flow_outside_data_verify_connection(conn);
  TEST_ASSERT_EQUAL(HE_ERR_CANNOT_VERIFY_SERVER_CERT, res2);
}

void test_handle_process_packet_app_data_ready(void) {
  dispatch_ExpectAndReturn("he_internal_flow_outside_data_verify_connection", HE_SUCCESS);
  he_internal_generate_event_Expect(conn, HE_EVENT_FIRST_MESSAGE_RECEIVED);
  dispatch_ExpectAndReturn("he_internal_flow_outside_data_handle_messages", HE_SUCCESS);

  // Trigger the APP_DATA_READY error
  wolfSSL_read_ExpectAndReturn(conn->wolf_ssl, conn->read_packet.packet,
                               sizeof(conn->read_packet.packet), SSL_FATAL_ERROR);
  wolfSSL_get_error_ExpectAndReturn(conn->wolf_ssl, SSL_FATAL_ERROR, APP_DATA_READY);

  // We should then immediately try again to read a message
  wolfSSL_read_ExpectAndReturn(conn->wolf_ssl, conn->read_packet.packet,
                               sizeof(conn->read_packet.packet), 1200);
  wolfSSL_read_ExpectAndReturn(conn->wolf_ssl, conn->read_packet.packet,
                               sizeof(conn->read_packet.packet), 1000);
  wolfSSL_read_ExpectAndReturn(conn->wolf_ssl, conn->read_packet.packet,
                               sizeof(conn->read_packet.packet), SSL_FATAL_ERROR);
  wolfSSL_get_error_ExpectAndReturn(conn->wolf_ssl, SSL_FATAL_ERROR, SSL_ERROR_WANT_READ);

  he_return_code_t res = he_internal_flow_outside_packet_received(conn, packet, packet_max_length);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res);
  he_return_code_t res2 = he_internal_flow_outside_data_verify_connection(conn);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res2);
  he_return_code_t res3 = he_internal_flow_outside_data_handle_messages(conn);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res3);

  TEST_ASSERT_EQUAL(0, conn->read_packet.packet_size);
  TEST_ASSERT_FALSE(conn->read_packet.has_packet);
}

void test_outside_datarcv_good_packet_datagram(void) {
  he_plugin_ingress_ExpectAnyArgsAndReturn(HE_SUCCESS);
  dispatch_ExpectAndReturn("he_internal_flow_outside_packet_received", HE_SUCCESS);

  he_return_code_t res1 = he_conn_outside_data_received(conn, packet, packet_max_length);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res1);
}

void test_outside_datarcv_good_buffer_streaming(void) {
  conn->connection_type = HE_CONNECTION_TYPE_STREAM;
  he_plugin_ingress_ExpectAnyArgsAndReturn(HE_SUCCESS);
  dispatch_ExpectAndReturn("he_internal_flow_outside_stream_received", HE_SUCCESS);

  he_return_code_t res1 = he_conn_outside_data_received(conn, packet, packet_max_length);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res1);
}

void test_outside_strmrcv_good_buffer_streaming(void) {
  conn->connection_type = HE_CONNECTION_TYPE_STREAM;

  dispatch_ExpectAndReturn("he_internal_flow_outside_data_verify_connection", HE_SUCCESS);

  he_return_code_t res1 =
      he_internal_flow_outside_stream_received(conn, fake_ipv4_packet, sizeof(fake_ipv4_packet));

  TEST_ASSERT_EQUAL(HE_SUCCESS, res1);
  TEST_ASSERT_EQUAL(fake_ipv4_packet, conn->incoming_data);
  TEST_ASSERT_EQUAL(sizeof(fake_ipv4_packet), conn->incoming_data_length);
  TEST_ASSERT_EQUAL(fake_ipv4_packet, conn->incoming_data_read_offset_ptr);
  TEST_ASSERT_EQUAL(sizeof(fake_ipv4_packet), conn->incoming_data_left_to_read);
}

void test_outside_data_negotiate_good_buffer_streaming(void) {
  // We aren't going to test all the permutations here because we have so many scenarios for the
  // datagram flow
  conn->connection_type = HE_CONNECTION_TYPE_STREAM;

  he_internal_generate_event_Expect(conn, HE_EVENT_FIRST_MESSAGE_RECEIVED);
  dispatch_ExpectAndReturn("he_internal_flow_outside_data_handle_messages", HE_SUCCESS);

  he_return_code_t res1 = he_internal_flow_outside_data_verify_connection(conn);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res1);
}

void test_outside_data_received_disconnecting(void) {
  // Set our state to disconnecting
  conn->state = HE_STATE_DISCONNECTING;
  // Call outside packet received
  he_return_code_t res =
      he_conn_outside_data_received(conn, fake_ipv4_packet, sizeof(fake_ipv4_packet));
  TEST_ASSERT_EQUAL(HE_ERR_INVALID_CONN_STATE, res);
}

void test_outside_data_received_disconnected(void) {
  // Set our state to disconnected
  conn->state = HE_STATE_DISCONNECTED;
  // Call outside packet received
  he_return_code_t res =
      he_conn_outside_data_received(conn, fake_ipv4_packet, sizeof(fake_ipv4_packet));
  TEST_ASSERT_EQUAL(HE_ERR_INVALID_CONN_STATE, res);
}

void test_he_internal_flow_process_message_too_small(void) {
  conn->read_packet.packet_size = 0;

  he_return_code_t res = he_internal_flow_process_message(conn);
  TEST_ASSERT_EQUAL(HE_ERR_SSL_ERROR, res);
}

void test_he_internal_flow_process_message_null_conn(void) {
  he_return_code_t res = he_internal_flow_process_message(NULL);
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, res);
}

void test_he_internal_flow_fetch_message_null_conn(void) {
  he_return_code_t res = he_internal_flow_fetch_message(NULL);
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, res);
}
// In general we try to avoid complex macros in libhelium, but these tests are so repetitive the
// value of capturing these lines
#define HE_MSG_SWITCH_TEST(test_msgid)          \
  msg->msgid = (test_msgid);                    \
  res = he_internal_flow_process_message(conn); \
  TEST_ASSERT_EQUAL(HE_SUCCESS, res);
#define HE_MSG_SWITCH_TEST_EXPECT(test_msg_id, msg_fn)                                    \
  msg_fn##_ExpectAndReturn(conn, conn->read_packet.packet, conn->read_packet.packet_size, \
                           HE_SUCCESS);                                                   \
  HE_MSG_SWITCH_TEST(test_msg_id);

void test_he_internal_flow_process_message_switch(void) {
  conn->read_packet.packet_size = 1;
  he_msg_hdr_t *msg = (he_msg_hdr_t *)conn->read_packet.packet;
  he_return_code_t res = HE_ERR_FAILED;

  HE_MSG_SWITCH_TEST_EXPECT(HE_MSGID_NOOP, he_handle_msg_noop);
  HE_MSG_SWITCH_TEST_EXPECT(HE_MSGID_PING, he_handle_msg_ping);
  HE_MSG_SWITCH_TEST_EXPECT(HE_MSGID_PONG, he_handle_msg_pong);
  HE_MSG_SWITCH_TEST_EXPECT(HE_MSGID_DATA, he_handle_msg_data);
  HE_MSG_SWITCH_TEST_EXPECT(HE_MSGID_GOODBYE, he_handle_msg_goodbye);

  HE_MSG_SWITCH_TEST_EXPECT(HE_MSGID_DEPRECATED_13, he_handle_msg_deprecated_13);

  HE_MSG_SWITCH_TEST(HE_MSGID_AUTH_RESPONSE_WITH_CONFIG);
  HE_MSG_SWITCH_TEST(HE_MSGID_EXTENSION);
}

void test_he_internal_flow_process_message_switch_client(void) {
  conn->read_packet.packet_size = 1;
  he_msg_hdr_t *msg = (he_msg_hdr_t *)conn->read_packet.packet;
  he_return_code_t res = HE_ERR_FAILED;

  // This is false by default but just to make this explicit
  conn->is_server = false;

  HE_MSG_SWITCH_TEST_EXPECT(HE_MSGID_CONFIG_IPV4, he_handle_msg_config_ipv4);
  HE_MSG_SWITCH_TEST_EXPECT(HE_MSGID_AUTH_RESPONSE, he_handle_msg_auth_response);

  // No expectation of call here
  HE_MSG_SWITCH_TEST(HE_MSGID_AUTH);
}

void test_he_internal_flow_process_message_switch_server(void) {
  conn->read_packet.packet_size = 1;
  he_msg_hdr_t *msg = (he_msg_hdr_t *)conn->read_packet.packet;
  he_return_code_t res = HE_ERR_FAILED;

  conn->is_server = true;

  HE_MSG_SWITCH_TEST_EXPECT(HE_MSGID_AUTH, he_handle_msg_auth);

  HE_MSG_SWITCH_TEST(HE_MSGID_CONFIG_IPV4);
  HE_MSG_SWITCH_TEST(HE_MSGID_AUTH_RESPONSE);
}

void test_outside_data_handle_messages_triggers_renegotiation(void) {
  conn->renegotiation_due = true;
  wolfSSL_read_ExpectAndReturn(conn->wolf_ssl, conn->read_packet.packet,
                               sizeof(conn->read_packet.packet), SSL_FATAL_ERROR);
  wolfSSL_get_error_ExpectAndReturn(conn->wolf_ssl, SSL_FATAL_ERROR, SSL_ERROR_WANT_READ);

  he_internal_renegotiate_ssl_ExpectAndReturn(conn, HE_SUCCESS);

  he_internal_flow_outside_data_handle_messages(conn);
}

void test_outside_data_handle_messages_triggers_renegotiation_error(void) {
  conn->renegotiation_due = true;
  wolfSSL_read_ExpectAndReturn(conn->wolf_ssl, conn->read_packet.packet,
                               sizeof(conn->read_packet.packet), SSL_FATAL_ERROR);
  wolfSSL_get_error_ExpectAndReturn(conn->wolf_ssl, SSL_FATAL_ERROR, SSL_ERROR_WANT_READ);

  he_internal_renegotiate_ssl_ExpectAndReturn(conn, HE_ERR_SSL_ERROR);

  he_return_code_t ret = he_internal_flow_outside_data_handle_messages(conn);

  TEST_ASSERT_EQUAL(HE_ERR_SSL_ERROR, ret);
}

void test_outside_data_handle_messages_skips_postprocessing_for_stream(void) {
  conn->connection_type = HE_CONNECTION_TYPE_STREAM;
  wolfSSL_read_ExpectAndReturn(conn->wolf_ssl, conn->read_packet.packet,
                               sizeof(conn->read_packet.packet), SSL_FATAL_ERROR);
  wolfSSL_get_error_ExpectAndReturn(conn->wolf_ssl, SSL_FATAL_ERROR, SSL_ERROR_WANT_READ);

  he_internal_flow_outside_data_handle_messages(conn);
}

void test_outside_data_handle_messages_generates_renegotiation_event(void) {
  wolfSSL_read_ExpectAndReturn(conn->wolf_ssl, conn->read_packet.packet,
                               sizeof(conn->read_packet.packet), SSL_FATAL_ERROR);
  wolfSSL_get_error_ExpectAndReturn(conn->wolf_ssl, SSL_FATAL_ERROR, SSL_ERROR_WANT_READ);

  // Renegotiation in process, conn does not expect renegotiation, no event
  conn->renegotiation_in_progress = true;
  wolfSSL_version_ExpectAndReturn(conn->wolf_ssl, DTLS1_2_VERSION);
  wolfSSL_SSL_renegotiate_pending_ExpectAndReturn(conn->wolf_ssl, 1);
  he_internal_update_timeout_Expect(conn);
  he_internal_flow_outside_data_handle_messages(conn);
  TEST_ASSERT_TRUE(conn->renegotiation_in_progress);

  // Reset expectations
  wolfSSL_read_ExpectAndReturn(conn->wolf_ssl, conn->read_packet.packet,
                               sizeof(conn->read_packet.packet), SSL_FATAL_ERROR);
  wolfSSL_get_error_ExpectAndReturn(conn->wolf_ssl, SSL_FATAL_ERROR, SSL_ERROR_WANT_READ);

  // Renegotiation in process, and conn expects renegotiation, no event, no change
  conn->renegotiation_in_progress = true;
  wolfSSL_version_ExpectAndReturn(conn->wolf_ssl, DTLS1_2_VERSION);
  wolfSSL_SSL_renegotiate_pending_ExpectAndReturn(conn->wolf_ssl, 1);
  he_internal_update_timeout_Expect(conn);
  he_internal_flow_outside_data_handle_messages(conn);
  TEST_ASSERT_TRUE(conn->renegotiation_in_progress);

  // Reset expectations
  wolfSSL_read_ExpectAndReturn(conn->wolf_ssl, conn->read_packet.packet,
                               sizeof(conn->read_packet.packet), SSL_FATAL_ERROR);
  wolfSSL_get_error_ExpectAndReturn(conn->wolf_ssl, SSL_FATAL_ERROR, SSL_ERROR_WANT_READ);

  // Renegotiation completed, conn expects renegotiation, expect event and conn reset
  conn->renegotiation_in_progress = true;
  wolfSSL_version_ExpectAndReturn(conn->wolf_ssl, DTLS1_2_VERSION);
  wolfSSL_SSL_renegotiate_pending_ExpectAndReturn(conn->wolf_ssl, 0);
  he_internal_generate_event_Expect(conn, HE_EVENT_SECURE_RENEGOTIATION_COMPLETED);
  he_internal_update_timeout_Expect(conn);

  he_internal_flow_outside_data_handle_messages(conn);
  TEST_ASSERT_FALSE(conn->renegotiation_in_progress);
}

void test_he_internal_update_session_incoming_hdr_null(void) {
  he_return_code_t res = he_internal_update_session_incoming(conn, NULL);
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, res);
}

void test_he_internal_update_session_incoming_conn_null(void) {
  he_wire_hdr_t *hdr = (he_wire_hdr_t *)empty_data;
  he_return_code_t res = he_internal_update_session_incoming(NULL, hdr);
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, res);
}

void test_he_internal_flow_outside_packet_received_conn_null(void) {
  he_return_code_t res = he_internal_flow_outside_packet_received(NULL, packet, 10);
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, res);
}

void test_he_internal_flow_outside_packet_received_packet_null(void) {
  he_return_code_t res = he_internal_flow_outside_packet_received(conn, NULL, 10);
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, res);
}

void test_he_internal_flow_outside_stream_received_conn_null(void) {
  he_return_code_t res = he_internal_flow_outside_stream_received(NULL, packet, 10);
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, res);
}

void test_he_internal_flow_outside_stream_received_buffer_null(void) {
  he_return_code_t res = he_internal_flow_outside_stream_received(conn, NULL, 10);
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, res);
}

void test_he_internal_flow_outside_data_verify_connection_conn_null(void) {
  he_return_code_t res = he_internal_flow_outside_data_verify_connection(NULL);
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, res);
}

void test_he_internal_flow_outside_data_handle_messages_conn_null(void) {
  he_return_code_t res = he_internal_flow_outside_data_handle_messages(NULL);
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, res);
}
