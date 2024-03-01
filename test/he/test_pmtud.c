/**
 * Lightway Core
 * Copyright (C) 2023 Express VPN International Ltd.
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
#include <unity.h>

#include "he.h"
#include "he_internal.h"
#include "test_defs.h"

// Unit under test
#include "pmtud.h"

// Mocks
#include "mock_conn_internal.h"
#include "mock_conn.h"

// Helper macros
#define EXPECT_HE_INTERNAL_SEND_MESSAGE(rc)                         \
  do {                                                              \
    he_internal_send_message_ExpectAndReturn(&conn, NULL, 0, (rc)); \
    he_internal_send_message_IgnoreArg_message();                   \
    he_internal_send_message_IgnoreArg_length();                    \
  } while(0)

static he_conn_t conn = {0};

void setUp(void) {
}

void tearDown(void) {
  memset(&conn, 0, sizeof(he_conn_t));
  call_counter = 0;
}

void test_he_internal_pmtud_send_probe(void) {
  conn.state = HE_STATE_ONLINE;
  conn.pmtud_state = HE_PMTUD_STATE_BASE;
  conn.pmtud_time_cb = pmtud_time_cb;
  conn.ping_next_id = 42;

  uint16_t probe_mtu = 1212;

  // The expected ping message length should be equal to the length of the of data message of the
  // given payload size
  uint16_t expected_length = probe_mtu + sizeof(he_msg_data_t);
  he_internal_send_message_ExpectAndReturn(&conn, NULL, expected_length, HE_SUCCESS);
  he_internal_send_message_IgnoreArg_message();

  he_return_code_t res = he_internal_pmtud_send_probe(&conn, probe_mtu);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res);
  TEST_ASSERT_EQUAL(1, call_counter);
  TEST_ASSERT_EQUAL(probe_mtu, conn.pmtud_probing_size);
  TEST_ASSERT_EQUAL(42, conn.pmtud_probe_pending_id);
}

void test_he_internal_pmtud_send_probe_failed(void) {
  conn.state = HE_STATE_ONLINE;
  conn.pmtud_state = HE_PMTUD_STATE_BASE;
  conn.pmtud_time_cb = pmtud_time_cb;
  conn.ping_next_id = 42;

  uint16_t probe_mtu = 1212;

  // The expected ping message length should be equal to the length of the of data message of the
  // given payload size
  uint16_t expected_length = probe_mtu + sizeof(he_msg_data_t);
  he_internal_send_message_ExpectAndReturn(&conn, NULL, expected_length, HE_ERR_SSL_ERROR);
  he_internal_send_message_IgnoreArg_message();

  he_return_code_t res = he_internal_pmtud_send_probe(&conn, probe_mtu);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res);
  TEST_ASSERT_EQUAL(1, call_counter);
  TEST_ASSERT_EQUAL(probe_mtu, conn.pmtud_probing_size);
  TEST_ASSERT_EQUAL(0, conn.pmtud_probe_pending_id);
}

void test_he_internal_pmtud_send_probe_nulls(void) {
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, he_internal_pmtud_send_probe(NULL, 1350));
}

void test_he_internal_pmtud_send_probe_invalid_conn_state(void) {
  TEST_ASSERT_EQUAL(HE_ERR_INVALID_CONN_STATE, he_internal_pmtud_send_probe(&conn, 1350));
}

void test_he_internal_pmtud_send_probe_when_probe_mtu_too_small(void) {
  conn.state = HE_STATE_ONLINE;
  conn.pmtud_state = HE_PMTUD_STATE_BASE;
  TEST_ASSERT_EQUAL(1416, MAX_PLPMTU);
  TEST_ASSERT_EQUAL(HE_ERR_INVALID_MTU_SIZE, he_internal_pmtud_send_probe(&conn, 120));
}

void test_he_internal_pmtud_send_probe_when_probe_mtu_too_large(void) {
  conn.state = HE_STATE_ONLINE;
  conn.pmtud_state = HE_PMTUD_STATE_BASE;
  TEST_ASSERT_EQUAL(HE_ERR_INVALID_MTU_SIZE, he_internal_pmtud_send_probe(&conn, HE_MAX_WIRE_MTU));
}

void test_he_internal_pmtud_handle_probe_ack_invalid_id(void) {
  // ignore invalid probe id
  conn.pmtud_probe_pending_id = 123;
  TEST_ASSERT_EQUAL(HE_SUCCESS, he_internal_pmtud_handle_probe_ack(&conn, 199));
}

void test_he_internal_pmtud_handle_probe_ack_from_base(void) {
  conn.state = HE_STATE_ONLINE;
  conn.pmtud_state = HE_PMTUD_STATE_BASE;
  conn.pmtud_probe_pending_id = 123;
  conn.pmtud_state_change_cb = pmtud_state_change_cb;
  conn.pmtud_time_cb = pmtud_time_cb;
  conn.pmtud_base = HE_MAX_MTU;

  EXPECT_HE_INTERNAL_SEND_MESSAGE(HE_SUCCESS);

  TEST_ASSERT_EQUAL(HE_SUCCESS, he_internal_pmtud_handle_probe_ack(&conn, 123));

  // New state should be searching
  TEST_ASSERT_EQUAL(HE_PMTUD_STATE_SEARCHING, conn.pmtud_state);
  // Should be using big step when first entering searching state
  TEST_ASSERT_TRUE(conn.pmtud_is_using_big_step);
  // Current probing size should be BASE_PMTU + BIG_STEP
  TEST_ASSERT_EQUAL(conn.pmtud_base + PMTUD_PROBE_BIG_STEP, conn.pmtud_probing_size);
  // Both callbacks should be called
  TEST_ASSERT_EQUAL(2, call_counter);
  // Probe count should be reset
  TEST_ASSERT_EQUAL(1, conn.pmtud_probe_count);
}

void test_he_internal_pmtud_handle_probe_ack_from_error(void) {
  conn.state = HE_STATE_ONLINE;
  conn.pmtud_state = HE_PMTUD_STATE_ERROR;
  conn.pmtud_probe_pending_id = 123;
  conn.pmtud_state_change_cb = pmtud_state_change_cb;
  conn.pmtud_time_cb = pmtud_time_cb;
  conn.pmtud_base = HE_MAX_MTU;

  EXPECT_HE_INTERNAL_SEND_MESSAGE(HE_SUCCESS);

  TEST_ASSERT_EQUAL(HE_SUCCESS, he_internal_pmtud_handle_probe_ack(&conn, 123));

  // New state should be searching
  TEST_ASSERT_EQUAL(HE_PMTUD_STATE_SEARCHING, conn.pmtud_state);
  // Should be using big step when first entering searching state
  TEST_ASSERT_TRUE(conn.pmtud_is_using_big_step);
  // Current probing size should be BASE_PMTU + BIG_STEP
  TEST_ASSERT_EQUAL(conn.pmtud_base + PMTUD_PROBE_BIG_STEP, conn.pmtud_probing_size);
  // Both callbacks should be called
  TEST_ASSERT_EQUAL(2, call_counter);
  // Probe count should be reset
  TEST_ASSERT_EQUAL(1, conn.pmtud_probe_count);
}

static void test_handle_probe_ack_from_searching(uint16_t probe_size, bool use_big_step) {
  conn.state = HE_STATE_ONLINE;
  conn.pmtud_state = HE_PMTUD_STATE_SEARCHING;
  conn.pmtud_probe_pending_id = 123;
  conn.pmtud_state_change_cb = pmtud_state_change_cb;
  conn.pmtud_time_cb = pmtud_time_cb;
  conn.pmtud_base = MIN_PLPMTU;
  conn.pmtud_probing_size = probe_size;
  conn.pmtud_is_using_big_step = use_big_step;

  if(probe_size < MAX_PLPMTU) {
    EXPECT_HE_INTERNAL_SEND_MESSAGE(HE_SUCCESS);
  }

  TEST_ASSERT_EQUAL(HE_SUCCESS, he_internal_pmtud_handle_probe_ack(&conn, 123));

  if(probe_size >= MAX_PLPMTU) {
    // State should enter search complete
    TEST_ASSERT_EQUAL(HE_PMTUD_STATE_SEARCH_COMPLETE, conn.pmtud_state);
    // Effective PMTU should be set
    TEST_ASSERT_EQUAL(MAX_PLPMTU, conn.effective_pmtu);
    // pmtud_state_change_cb callback should be called twice, once to cancel the timer
    // and once more to retry probing
    TEST_ASSERT_EQUAL(2, call_counter);
  } else {
    // State should still be searching if the probed size is smaller than MAX_PLPMTU
    TEST_ASSERT_EQUAL(HE_PMTUD_STATE_SEARCHING, conn.pmtud_state);
    // Probe size should be incremented
    if(use_big_step) {
      TEST_ASSERT_EQUAL(probe_size + PMTUD_PROBE_BIG_STEP, conn.pmtud_probing_size);
    } else {
      TEST_ASSERT_EQUAL(probe_size + PMTUD_PROBE_SMALL_STEP, conn.pmtud_probing_size);
    }
    // Only the pmtud_time_cb callback should be called
    TEST_ASSERT_EQUAL(1, call_counter);
  }
}

void test_he_internal_pmtud_handle_probe_ack_from_searching_big_step(void) {
  test_handle_probe_ack_from_searching(MAX_PLPMTU - 120, true);
}

void test_he_internal_pmtud_handle_probe_ack_from_searching_small_step(void) {
  test_handle_probe_ack_from_searching(MAX_PLPMTU - 120, false);
}

void test_he_internal_pmtud_handle_probe_ack_from_searching_to_search_complete(void) {
  test_handle_probe_ack_from_searching(MAX_PLPMTU, true);
}

void test_he_internal_pmtud_handle_probe_ack_completed_retries(void) {
  conn.state = HE_STATE_ONLINE;
  conn.pmtud_state = HE_PMTUD_STATE_SEARCH_COMPLETE;
  conn.pmtud_probe_pending_id = 123;
  conn.pmtud_state_change_cb = pmtud_state_change_cb;
  conn.pmtud_time_cb = pmtud_time_cb;

  TEST_ASSERT_EQUAL(HE_SUCCESS, he_internal_pmtud_handle_probe_ack(&conn, 123));

  // Timer was restarted to probe again
  TEST_ASSERT_EQUAL(1, call_counter);
}

void test_he_internal_pmtud_handle_probe_timeout_try_again(void) {
  conn.state = HE_STATE_ONLINE;
  conn.pmtud_state = HE_PMTUD_STATE_SEARCHING;
  conn.pmtud_probe_count = 1;
  conn.pmtud_time_cb = pmtud_time_cb;
  conn.ping_next_id = 43;
  conn.pmtud_probing_size = MAX_PLPMTU - 120;

  // It should send probe again when probe count hasn't reached MAX_PROBES
  EXPECT_HE_INTERNAL_SEND_MESSAGE(HE_SUCCESS);

  TEST_ASSERT_EQUAL(HE_SUCCESS, he_internal_pmtud_handle_probe_timeout(&conn));

  TEST_ASSERT_EQUAL(2, conn.pmtud_probe_count);
  TEST_ASSERT_EQUAL(43, conn.pmtud_probe_pending_id);
  TEST_ASSERT_EQUAL(44, conn.ping_next_id);
}

void test_he_internal_pmtud_handle_probe_timeout_confirm_base_failed(void) {
  conn.state = HE_STATE_ONLINE;
  conn.pmtud_state = HE_PMTUD_STATE_BASE;
  conn.pmtud_probe_count = MAX_PROBES;
  conn.pmtud_time_cb = pmtud_time_cb;
  conn.pmtud_probing_size = MIN_PLPMTU;

  // Probe count reached MAX_PROBES,
  // it should call he_internal_pmtud_confirm_base_failed if current state is BASE
  // and the probe size is NOT INITIAL_PLPMTU.
  TEST_ASSERT_EQUAL(HE_SUCCESS, he_internal_pmtud_handle_probe_timeout(&conn));

  // The new state should be Error
  TEST_ASSERT_EQUAL(HE_PMTUD_STATE_ERROR, conn.pmtud_state);

  // The probe count and pending id should be reset to 0
  TEST_ASSERT_EQUAL(0, conn.pmtud_probe_count);
  TEST_ASSERT_EQUAL(0, conn.pmtud_probe_pending_id);

  // pmtud_time_cb should be called to retry the error
  TEST_ASSERT_EQUAL(1, call_counter);
}

void test_he_internal_pmtud_handle_probe_timeout_confirm_base_retry_with_min_plpmtu(void) {
  conn.state = HE_STATE_ONLINE;
  conn.pmtud_state = HE_PMTUD_STATE_BASE;
  conn.pmtud_probe_count = MAX_PROBES;
  conn.pmtud_time_cb = pmtud_time_cb;
  conn.pmtud_probing_size = INITIAL_PLPMTU;
  conn.ping_next_id = 42;

  EXPECT_HE_INTERNAL_SEND_MESSAGE(HE_SUCCESS);

  // Probe count reached MAX_PROBES when confirming base.
  // It should try again using MIN_PLPMTU.
  TEST_ASSERT_EQUAL(HE_SUCCESS, he_internal_pmtud_handle_probe_timeout(&conn));

  // The new state should still be BASE
  TEST_ASSERT_EQUAL(HE_PMTUD_STATE_BASE, conn.pmtud_state);

  // The probe count and pending id should be set
  TEST_ASSERT_EQUAL(1, conn.pmtud_probe_count);
  TEST_ASSERT_EQUAL(42, conn.pmtud_probe_pending_id);

  // The new probe size should be MIN_PLPMTU
  TEST_ASSERT_EQUAL(MIN_PLPMTU, conn.pmtud_probing_size);

  // pmtud_time_cb should be called to retry the error
  TEST_ASSERT_EQUAL(1, call_counter);
}

void test_he_internal_pmtud_start_base_probing(void) {
  conn.state = HE_STATE_ONLINE;
  conn.pmtud_state = HE_PMTUD_STATE_DISABLED;
  conn.pmtud_time_cb = pmtud_time_cb;
  conn.ping_next_id = 42;

  EXPECT_HE_INTERNAL_SEND_MESSAGE(HE_SUCCESS);

  he_return_code_t rc = he_internal_pmtud_start_base_probing(&conn);

  // The new state should be BASE
  TEST_ASSERT_EQUAL(HE_PMTUD_STATE_BASE, conn.pmtud_state);

  // The probe count and pending id should be set
  TEST_ASSERT_EQUAL(1, conn.pmtud_probe_count);
  TEST_ASSERT_EQUAL(42, conn.pmtud_probe_pending_id);

  // The probe size should be INITIAL_PLPMTU
  TEST_ASSERT_EQUAL(INITIAL_PLPMTU, conn.pmtud_probing_size);

  // pmtud_time_cb should be called to retry the error
  TEST_ASSERT_EQUAL(1, call_counter);

  TEST_ASSERT_EQUAL(HE_SUCCESS, rc);
}

void test_he_internal_pmtud_handle_probe_timeout_search_completed(void) {
  conn.state = HE_STATE_ONLINE;
  conn.pmtud_state = HE_PMTUD_STATE_SEARCHING;
  conn.pmtud_probe_count = 3;
  conn.pmtud_probing_size = MAX_PLPMTU - 120;
  conn.pmtud_is_using_big_step = false;
  conn.pmtud_time_cb = pmtud_time_cb;

  // Probe count reached MAX_PROBES,
  TEST_ASSERT_EQUAL(HE_SUCCESS, he_internal_pmtud_handle_probe_timeout(&conn));

  // The new state should be Search Complete
  TEST_ASSERT_EQUAL(HE_PMTUD_STATE_SEARCH_COMPLETE, conn.pmtud_state);

  // The effective mtu should be set
  TEST_ASSERT_EQUAL(MAX_PLPMTU - 120 - PMTUD_PROBE_SMALL_STEP, conn.effective_pmtu);

  // The probe count and pending id should be reset to 0
  TEST_ASSERT_EQUAL(0, conn.pmtud_probe_count);
  TEST_ASSERT_EQUAL(0, conn.pmtud_probe_pending_id);

  // pmtud_time_cb should be called to schedule a retest
  TEST_ASSERT_EQUAL(1, call_counter);
}

void test_he_internal_pmtud_handle_probe_timeout_blackhole_detected(void) {
  conn.state = HE_STATE_ONLINE;
  conn.pmtud_state = HE_PMTUD_STATE_SEARCH_COMPLETE;
  conn.pmtud_probe_count = MAX_PROBES;
  conn.pmtud_probing_size = MAX_PLPMTU - 120;
  conn.pmtud_is_using_big_step = false;
  conn.pmtud_time_cb = pmtud_time_cb;

  EXPECT_HE_INTERNAL_SEND_MESSAGE(HE_SUCCESS);

  // Probe count reached MAX_PROBES,
  TEST_ASSERT_EQUAL(HE_SUCCESS, he_internal_pmtud_handle_probe_timeout(&conn));

  // The new state should be Base
  TEST_ASSERT_EQUAL(HE_PMTUD_STATE_BASE, conn.pmtud_state);

  // The base mtu should be set to MIN_PLPMTU
  TEST_ASSERT_EQUAL(MIN_PLPMTU, conn.pmtud_base);

  // The probe count should be reset to 1
  TEST_ASSERT_EQUAL(1, conn.pmtud_probe_count);

  // pmtud_time_cb should be called
  TEST_ASSERT_EQUAL(1, call_counter);
}

void test_he_internal_pmtud_handle_probe_timeout_on_error_try_again(void) {
  conn.state = HE_STATE_ONLINE;
  conn.pmtud_state = HE_PMTUD_STATE_ERROR;
  conn.pmtud_probe_count = MAX_PROBES;
  conn.pmtud_time_cb = pmtud_time_cb;

  TEST_ASSERT_EQUAL(HE_SUCCESS, he_internal_pmtud_handle_probe_timeout(&conn));

  TEST_ASSERT_EQUAL(0, conn.pmtud_probe_count);

  // pmtud_time_cb should be called to start a new timer
  TEST_ASSERT_EQUAL(1, call_counter);
}
