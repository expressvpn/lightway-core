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
#include "wolf.h"

// Direct Includes for Utility Functions
#include "core.h"

// Internal Mocks
#include "mock_plugin_chain.h"

uint8_t *packet = NULL;
uint8_t *buffer = NULL;
size_t packet_max_length = 1500;
size_t buffer_max_length = 1500;

size_t test_buffer_length = 1200;

size_t test_packet_size = 1100;

WOLFSSL *ssl = NULL;
he_conn_t *conn = NULL;

int write_callback_count = 0;

he_return_code_t outside_write_test(he_conn_t *conn1, uint8_t *packet1, size_t length1,
                                    void *context1) {
  TEST_ASSERT_EQUAL(conn, conn1);
  TEST_ASSERT_NOT_EQUAL(packet, packet1);
  TEST_ASSERT_EQUAL_MEMORY(packet, packet1 + sizeof(he_wire_hdr_t), test_packet_size);
  TEST_ASSERT_EQUAL(test_packet_size + sizeof(he_wire_hdr_t), length1);
  TEST_ASSERT_NULL(context1);
  // Bump counter
  write_callback_count++;
  return HE_SUCCESS;
}

he_return_code_t outside_write_test_with_context(he_conn_t *conn1, uint8_t *packet1, size_t length1,
                                                 void *context1) {
  TEST_ASSERT_EQUAL(conn, conn1);
  TEST_ASSERT_NOT_EQUAL(packet, packet1);
  TEST_ASSERT_EQUAL_MEMORY(packet, packet1 + sizeof(he_wire_hdr_t), test_packet_size);
  TEST_ASSERT_EQUAL(test_packet_size + sizeof(he_wire_hdr_t), length1);
  TEST_ASSERT_EQUAL(conn, context1);
  return HE_SUCCESS;
}

he_return_code_t outside_write_test_for_streaming(he_conn_t *conn1, uint8_t *packet1,
                                                  size_t length1, void *context1) {
  TEST_ASSERT_EQUAL(conn, conn1);
  TEST_ASSERT_NOT_EQUAL(packet, packet1);
  TEST_ASSERT_NOT_EQUAL(packet, packet1);
  TEST_ASSERT_EQUAL_MEMORY(packet, packet1, test_packet_size);
  TEST_ASSERT_EQUAL(test_packet_size, length1);
  TEST_ASSERT_EQUAL(conn, context1);
  return HE_SUCCESS;
}

he_return_code_t outside_write_test_for_streaming_large(he_conn_t *conn1, uint8_t *packet1,
                                                        size_t length1, void *context1) {
  TEST_ASSERT_EQUAL(conn, conn1);
  TEST_ASSERT_NOT_EQUAL(packet, packet1);
  TEST_ASSERT_EQUAL_MEMORY(packet, packet1, HE_MAX_WIRE_MTU);
  TEST_ASSERT_EQUAL(HE_MAX_WIRE_MTU, length1);
  TEST_ASSERT_EQUAL(conn, context1);
  return HE_SUCCESS;
}

he_return_code_t outside_write_return_failure(he_conn_t *conn1, uint8_t *packet1, size_t length1,
                                              void *context1) {
  return HE_ERR_FAILED;
}

void assert_standard_header(uint8_t write_buffer[]) {
  TEST_ASSERT_EQUAL_CHAR('H', write_buffer[0]);
  TEST_ASSERT_EQUAL_CHAR('e', write_buffer[1]);
}

void assert_standard_version(uint8_t write_buffer[]) {
  TEST_ASSERT_EQUAL(HE_WIRE_MAXIMUM_PROTOCOL_MAJOR_VERSION, write_buffer[2]);
  TEST_ASSERT_EQUAL(HE_WIRE_MAXIMUM_PROTOCOL_MINOR_VERSION, write_buffer[3]);
}

void assert_standard_reserved_section(uint8_t write_buffer[]) {
  TEST_ASSERT_EQUAL(0x00, conn->write_buffer[5]);
  TEST_ASSERT_EQUAL(0x00, conn->write_buffer[6]);
  TEST_ASSERT_EQUAL(0x00, conn->write_buffer[7]);
}

void setUp(void) {
  srand(time(NULL));

  packet = calloc(1, packet_max_length);
  buffer = calloc(1, buffer_max_length);
  conn = calloc(1, sizeof(he_conn_t));

  conn->packet_seen = false;
  conn->incoming_data = packet;
  conn->incoming_data_length = packet_max_length;
  conn->outside_write_cb = outside_write_test;
  conn->protocol_version.major_version = HE_WIRE_MAXIMUM_PROTOCOL_MAJOR_VERSION;
  conn->protocol_version.minor_version = HE_WIRE_MAXIMUM_PROTOCOL_MINOR_VERSION;

  // Generate a random blob to represent the packet
  for(int a = 0; a < packet_max_length; a++) {
    packet[a] = rand() % 256;
  }

  write_callback_count = 0;

  he_plugin_egress_IgnoreAndReturn(HE_SUCCESS);
}

void tearDown(void) {
  free(buffer);
  free(packet);
  free(conn);
}

void test_read_raw_buffer_pass_to_read(void) {
  int res1 = he_wolf_dtls_read(ssl, (char *)buffer, packet_max_length, conn);

  TEST_ASSERT_EQUAL(packet_max_length, res1);

  TEST_ASSERT_EQUAL_MEMORY(packet, buffer, res1);
}

void test_read_no_data_error_triggered_on_second_read(void) {
  TEST_ASSERT_FALSE(conn->packet_seen);

  int res1 = he_wolf_dtls_read(ssl, (char *)packet, packet_max_length, conn);

  TEST_ASSERT_TRUE(conn->packet_seen);

  int res2 = he_wolf_dtls_read(ssl, (char *)packet, packet_max_length, conn);

  TEST_ASSERT_EQUAL(packet_max_length, res1);
  TEST_ASSERT_EQUAL(WOLFSSL_CBIO_ERR_WANT_READ, res2);
}

void test_read_buffer_too_small(void) {
  size_t too_small = 500;

  int res1 = he_wolf_dtls_read(ssl, (char *)packet, too_small, conn);
  int res2 = he_wolf_dtls_read(ssl, (char *)packet, too_small, conn);

  TEST_ASSERT_EQUAL(0, res1);
  TEST_ASSERT_EQUAL(WOLFSSL_CBIO_ERR_WANT_READ, res2);
}

void test_write_create_packet(void) {
  int res1 = he_wolf_dtls_write(ssl, (char *)packet, test_packet_size, conn);

  // Checks that the data written is what WolfSSL expects - Helium headers are extra and not covered
  // here
  TEST_ASSERT_EQUAL(test_packet_size, res1);

  // Test we have a valid helium header
  assert_standard_header(conn->write_buffer);
  assert_standard_version(conn->write_buffer);
  assert_standard_reserved_section(conn->write_buffer);

  TEST_ASSERT_EQUAL(0x00, conn->write_buffer[4]);
  TEST_ASSERT_EQUAL_MEMORY(&conn->session_id, &conn->write_buffer[8], sizeof(conn->session_id));

  // Test packet is unchanged
  TEST_ASSERT_EQUAL_MEMORY(packet, conn->write_buffer + sizeof(he_wire_hdr_t), test_packet_size);

  // Test that the callback is set correctly
  TEST_ASSERT_EQUAL(outside_write_test, conn->outside_write_cb);
}
void test_write_packet_too_big(void) {
  size_t test_packet_size = 4000;
  int res1 = he_wolf_dtls_write(ssl, (char *)packet, test_packet_size, conn);

  // Make sure it returns an error correctly
  TEST_ASSERT_EQUAL(WOLFSSL_CBIO_ERR_GENERAL, res1);

  // Ensure the write buffer wasn't touched
  TEST_ASSERT_EQUAL(0, conn->write_buffer[0]);
}

void test_write_context_gets_passed(void) {
  conn->data = conn;
  conn->outside_write_cb = outside_write_test_with_context;
  int res1 = he_wolf_dtls_write(ssl, (char *)packet, test_packet_size, conn);
  TEST_ASSERT_EQUAL(test_packet_size, res1);
}

void test_internal_pkt_header_writer(void) {
  conn->session_id = 0x1234567891234567;

  int res1 = he_internal_write_packet_header(conn, (he_wire_hdr_t *)conn->write_buffer);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res1);

  // Test we have a valid helium header
  assert_standard_header(conn->write_buffer);
  assert_standard_version(conn->write_buffer);
  assert_standard_reserved_section(conn->write_buffer);

  TEST_ASSERT_EQUAL(0x00, conn->write_buffer[4]);
  TEST_ASSERT_EQUAL_MEMORY(&conn->session_id, &conn->write_buffer[8], sizeof(conn->session_id));
}

void test_internal_pkt_header_writer_aggressive_mode(void) {
  conn->session_id = 0x1234567891234567;
  conn->use_aggressive_mode = true;

  int res1 = he_internal_write_packet_header(conn, (he_wire_hdr_t *)conn->write_buffer);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res1);

  // Test we have a valid helium header
  assert_standard_header(conn->write_buffer);
  assert_standard_version(conn->write_buffer);
  assert_standard_reserved_section(conn->write_buffer);

  TEST_ASSERT_EQUAL(0x01, conn->write_buffer[4]);
  TEST_ASSERT_EQUAL_MEMORY(&conn->session_id, &conn->write_buffer[8], sizeof(conn->session_id));
}

void test_internal_pkt_header_writer_disabled_roaming_sessions(void) {
  uint64_t temp_session = HE_PACKET_SESSION_REJECT;

  // Setting this manually so that these tests don't have a dependency on conn
  conn->disable_roaming_connections = true;

  int res1 = he_internal_write_packet_header(conn, (he_wire_hdr_t *)conn->write_buffer);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res1);

  // Test we have a valid helium header
  assert_standard_header(conn->write_buffer);
  assert_standard_version(conn->write_buffer);
  assert_standard_reserved_section(conn->write_buffer);

  TEST_ASSERT_EQUAL(0x00, conn->write_buffer[4]);
  TEST_ASSERT_EQUAL_MEMORY(&temp_session, &conn->write_buffer[8], sizeof(conn->session_id));
}
void test_internal_pkt_header_various_nulls(void) {
  int res1 = he_internal_write_packet_header(NULL, (he_wire_hdr_t *)conn->write_buffer);
  int res2 = he_internal_write_packet_header(conn, NULL);
  int res3 = he_internal_write_packet_header(NULL, NULL);

  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, res1);
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, res2);
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, res3);
}

void test_internal_pkt_header_writer_pending_session(void) {
  conn->session_id = 0x1234567891234567;
  conn->pending_session_id = 0x9876543219876543;
  int res1 = he_internal_write_packet_header(conn, (he_wire_hdr_t *)conn->write_buffer);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res1);

  // Test we have a valid helium header
  assert_standard_header(conn->write_buffer);
  assert_standard_version(conn->write_buffer);
  assert_standard_reserved_section(conn->write_buffer);

  TEST_ASSERT_EQUAL(0x00, conn->write_buffer[4]);
  TEST_ASSERT_EQUAL_MEMORY(&conn->pending_session_id, &conn->write_buffer[8],
                           sizeof(conn->session_id));
}

void test_write_dont_explode_if_not_write_cb_set(void) {
  // Unset the callback
  conn->outside_write_cb = NULL;

  int res1 = he_wolf_dtls_write(ssl, (char *)packet, test_packet_size, conn);

  // Checks that the data written is what WolfSSL expects - Helium headers are extra and not covered
  // here
  TEST_ASSERT_EQUAL(test_packet_size, res1);

  // Test we have a valid helium header
  assert_standard_header(conn->write_buffer);
  assert_standard_version(conn->write_buffer);
  assert_standard_reserved_section(conn->write_buffer);

  TEST_ASSERT_EQUAL(0x00, conn->write_buffer[4]);
  TEST_ASSERT_EQUAL_MEMORY(&conn->session_id, &conn->write_buffer[8], sizeof(conn->session_id));

  // Test packet is unchanged
  TEST_ASSERT_EQUAL_MEMORY(packet, conn->write_buffer + sizeof(he_wire_hdr_t), test_packet_size);

  // Test that the callback is set correctly
  TEST_ASSERT_NULL(conn->outside_write_cb);
}

void test_write_accepts_conn_version(void) {
  conn->protocol_version.major_version = 0xFF;
  conn->protocol_version.minor_version = 0x99;

  int res1 = he_wolf_dtls_write(ssl, (char *)packet, test_packet_size, conn);

  // Checks that the data written is what WolfSSL expects - Helium headers are extra and not covered
  // here
  TEST_ASSERT_EQUAL(test_packet_size, res1);

  // Test we have a valid helium header
  assert_standard_header(conn->write_buffer);
  assert_standard_reserved_section(conn->write_buffer);

  TEST_ASSERT_EQUAL(0xFF, conn->write_buffer[2]);
  TEST_ASSERT_EQUAL(0x99, conn->write_buffer[3]);

  TEST_ASSERT_EQUAL(0x00, conn->write_buffer[4]);
  TEST_ASSERT_EQUAL_MEMORY(&conn->session_id, &conn->write_buffer[8], sizeof(conn->session_id));

  // Test packet is unchanged
  TEST_ASSERT_EQUAL_MEMORY(packet, conn->write_buffer + sizeof(he_wire_hdr_t), test_packet_size);
}

void test_aggressive_mode_is_off_write_callback_called_once_when_online(void) {
  // Set online
  conn->state = HE_STATE_ONLINE;

  // Call a write
  he_return_code_t res1 = he_wolf_dtls_write(ssl, (char *)packet, test_packet_size, conn);

  // Test that the callback is set correctly
  TEST_ASSERT_EQUAL(outside_write_test, conn->outside_write_cb);

  // Test that the callback was triggered once
  TEST_ASSERT_EQUAL(1, write_callback_count);
}

void test_aggressive_mode_is_on_write_callback_called_three_times_when_online(void) {
  // Enable aggressive mode
  conn->use_aggressive_mode = true;

  // Call a write
  he_return_code_t res2 = he_wolf_dtls_write(ssl, (char *)packet, test_packet_size, conn);

  // Test that the callback is set correctly
  TEST_ASSERT_EQUAL(outside_write_test, conn->outside_write_cb);

  // Test that the callback was triggered three times
  TEST_ASSERT_EQUAL(3, write_callback_count);
}

void test_aggressive_mode_on_before_online(void) {
  // Call a write
  he_return_code_t res2 = he_wolf_dtls_write(ssl, (char *)packet, test_packet_size, conn);

  // Test that the callback is set correctly
  TEST_ASSERT_EQUAL(outside_write_test, conn->outside_write_cb);

  // Test that the callback was triggered once
  TEST_ASSERT_EQUAL(3, write_callback_count);
}

void test_plugin_drop_results_in_no_write(void) {
  he_plugin_egress_StopIgnore();
  he_plugin_egress_ExpectAnyArgsAndReturn(HE_ERR_PLUGIN_DROP);

  // Call a write
  he_return_code_t res2 = he_wolf_dtls_write(ssl, (char *)packet, test_packet_size, conn);

  // Test that the callback is set correctly
  TEST_ASSERT_EQUAL(outside_write_test, conn->outside_write_cb);

  // Test that the callback was triggered once
  TEST_ASSERT_EQUAL(0, write_callback_count);
}

void test_plugin_error_results_in_no_write(void) {
  he_plugin_egress_StopIgnore();
  he_plugin_egress_ExpectAnyArgsAndReturn(HE_ERR_FAILED);

  // Call a write
  he_return_code_t res2 = he_wolf_dtls_write(ssl, (char *)packet, test_packet_size, conn);

  // Test that the callback is set correctly
  TEST_ASSERT_EQUAL(outside_write_test, conn->outside_write_cb);

  // Test that the callback was triggered once
  TEST_ASSERT_EQUAL(0, write_callback_count);
}

void test_outside_write_failure_returns_failure(void) {
  conn->outside_write_cb = outside_write_return_failure;
  int res = he_wolf_dtls_write(ssl, (char *)packet, test_packet_size, conn);

  TEST_ASSERT_EQUAL(WOLFSSL_CBIO_ERR_GENERAL, res);
}

void test_dtls_overflow_plugin_egress_returns_failure(void) {
  he_plugin_egress_StopIgnore();
  he_plugin_egress_Stub(stub_overflow_plugin);

  int res = he_wolf_dtls_write(ssl, (char *)packet, test_packet_size, conn);

  TEST_ASSERT_EQUAL(WOLFSSL_CBIO_ERR_GENERAL, res);
}

void test_tls_read_no_bytes_left(void) {
  // Set available to zero
  conn->incoming_data_left_to_read = 0;
  int res = he_wolf_tls_read(ssl, (char *)packet, 1000, conn);

  TEST_ASSERT_EQUAL(WOLFSSL_CBIO_ERR_WANT_READ, res);
}

void test_tls_read_simple(void) {
  // Set up some state
  he_internal_setup_stream_state(conn, packet, packet_max_length);

  int res = he_wolf_tls_read(ssl, (char *)buffer, buffer_max_length, conn);

  TEST_ASSERT_EQUAL(buffer_max_length, res);
}

void test_tls_read_half_size(void) {
  // Set up some state
  he_internal_setup_stream_state(conn, packet, packet_max_length);

  // Data count
  int count = 500;
  // Test buffer size
  int test_buffer_size = 1000;

  int res = he_wolf_tls_read(ssl, (char *)buffer, test_buffer_size, conn);

  TEST_ASSERT_EQUAL(test_buffer_size, res);
  TEST_ASSERT_EQUAL(count, conn->incoming_data_left_to_read);
}

void test_tls_write_simple(void) {
  // Set up some state
  conn->data = conn;
  conn->outside_write_cb = outside_write_test_for_streaming;

  int res1 = he_wolf_tls_write(ssl, (char *)packet, test_packet_size, conn);

  // Make sure it sent all the data
  TEST_ASSERT_EQUAL(test_packet_size, res1);
  TEST_ASSERT_EQUAL_MEMORY(packet, &conn->write_buffer[0], test_packet_size);
}

void test_tls_write_attemps_lots_of_data_but_only_write_our_buffer_size(void) {
  // Set up some state
  conn->data = conn;
  conn->outside_write_cb = outside_write_test_for_streaming_large;

  int res1 = he_wolf_tls_write(ssl, (char *)packet, HE_MAX_WIRE_MTU * 2, conn);

  // Make sure it sent only HE_MAX_WIRE_MTU worth of data and told wolf just that many
  TEST_ASSERT_EQUAL(HE_MAX_WIRE_MTU, res1);
  TEST_ASSERT_EQUAL_MEMORY(packet, &conn->write_buffer[0], HE_MAX_WIRE_MTU);
}

void test_plugin_drop_results_in_no_write_tls(void) {
  he_plugin_egress_StopIgnore();
  he_plugin_egress_ExpectAnyArgsAndReturn(HE_ERR_PLUGIN_DROP);

  // Call a write
  he_return_code_t res2 = he_wolf_tls_write(ssl, (char *)packet, test_packet_size, conn);

  // Test that the callback is set correctly
  TEST_ASSERT_EQUAL(outside_write_test, conn->outside_write_cb);

  // Test that the callback was triggered once
  TEST_ASSERT_EQUAL(0, write_callback_count);
}

void test_plugin_error_results_in_no_write_tls(void) {
  he_plugin_egress_StopIgnore();
  he_plugin_egress_ExpectAnyArgsAndReturn(HE_ERR_FAILED);

  // Call a write
  he_return_code_t res2 = he_wolf_tls_write(ssl, (char *)packet, test_packet_size, conn);

  // Test that the callback is set correctly
  TEST_ASSERT_EQUAL(outside_write_test, conn->outside_write_cb);

  // Test that the callback was triggered once
  TEST_ASSERT_EQUAL(0, write_callback_count);
}

void test_tls_write_dont_explode_if_not_write_cb_set(void) {
  // Unset the callback
  conn->outside_write_cb = NULL;

  int res1 = he_wolf_tls_write(ssl, (char *)packet, test_packet_size, conn);

  TEST_ASSERT_EQUAL(test_packet_size, res1);

  // Test that the callback is set correctly
  TEST_ASSERT_NULL(conn->outside_write_cb);
}

void test_tls_write_outside_cb_cb_returns_failure(void) {
  conn->outside_write_cb = outside_write_return_failure;
  int res = he_wolf_tls_write(ssl, (char *)packet, test_packet_size, conn);

  TEST_ASSERT_EQUAL(WOLFSSL_CBIO_ERR_GENERAL, res);
}

void test_tls_overflow_plugin_egress_returns_failure(void) {
  he_plugin_egress_StopIgnore();
  he_plugin_egress_Stub(stub_overflow_plugin);

  int res = he_wolf_tls_write(ssl, (char *)packet, test_packet_size, conn);

  TEST_ASSERT_EQUAL(WOLFSSL_CBIO_ERR_GENERAL, res);
}

void test_impossible_sizes(void) {
  int res = he_wolf_dtls_read(ssl, (char *)packet, -1, conn);
  TEST_ASSERT_EQUAL(res, -1);
  res = he_wolf_dtls_write(ssl, (char *)packet, -1, conn);
  TEST_ASSERT_EQUAL(res, -1);
  res = he_wolf_tls_read(ssl, (char *)packet, -1, conn);
  TEST_ASSERT_EQUAL(res, -1);
  res = he_wolf_tls_write(ssl, (char *)packet, -1, conn);
  TEST_ASSERT_EQUAL(res, -1);
}
