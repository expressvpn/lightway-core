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

static he_conn_t conn = {0};

void setUp(void) {
}

void tearDown(void) {
  memset(&conn, 0, sizeof(he_conn_t));
}

void test_he_internal_pmtud_send_probe(void) {
  conn.state = HE_STATE_ONLINE;
  conn.pmtud_state = HE_PMTUD_STATE_BASE;

  uint16_t probe_mtu = 1212;

  // The expected ping message length should be equal to the length of the of data message of the
  // given payload size
  uint16_t expected_length = probe_mtu + sizeof(he_msg_data_t);
  he_internal_send_message_ExpectAndReturn(&conn, NULL, expected_length, HE_SUCCESS);
  he_internal_send_message_IgnoreArg_message();
  he_return_code_t res = he_internal_pmtud_send_probe(&conn, probe_mtu);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res);
}

void test_he_internal_pmtud_send_probe_nulls(void) {
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, he_internal_pmtud_send_probe(NULL, 1350));
}

void test_he_internal_pmtud_send_probe_invalid_state(void) {
  TEST_ASSERT_EQUAL(HE_ERR_INVALID_CONN_STATE, he_internal_pmtud_send_probe(&conn, 1350));

  conn.state = HE_STATE_ONLINE;
  TEST_ASSERT_EQUAL(HE_ERR_INVALID_CONN_STATE, he_internal_pmtud_send_probe(&conn, 1350));
}

void test_he_internal_pmtud_send_probe_invalid_probe_mtu(void) {
  conn.state = HE_STATE_ONLINE;
  conn.pmtud_state = HE_PMTUD_STATE_BASE;
  TEST_ASSERT_EQUAL(1416, MAX_PLPMTU);
  TEST_ASSERT_EQUAL(HE_ERR_INVALID_MTU_SIZE, he_internal_pmtud_send_probe(&conn, 120));
  TEST_ASSERT_EQUAL(HE_ERR_INVALID_MTU_SIZE, he_internal_pmtud_send_probe(&conn, HE_MAX_WIRE_MTU));
}

void test_he_internal_change_pmtud_state_disabled_to_base(void) {
  conn.state = HE_STATE_ONLINE;
  conn.pmtud_state = HE_PMTUD_STATE_DISABLED;

  he_internal_generate_event_Expect(&conn, HE_EVENT_PMTU_DISCOVERY_STARTED);
  he_internal_change_pmtud_state(&conn, HE_PMTUD_STATE_BASE);

  TEST_ASSERT_EQUAL(HE_PMTUD_STATE_BASE, conn.pmtud_state);
  TEST_ASSERT_EQUAL(HE_MAX_MTU, conn.pmtud_base);
  TEST_ASSERT_EQUAL(0, conn.pmtud_probe_count);
}
