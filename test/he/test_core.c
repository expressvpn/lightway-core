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

#include "mock_conn.h"

// Unit under test
#include "core.h"

he_conn_t *conn;

void setUp(void) {
  conn = calloc(1, sizeof(he_conn_t));
}

void tearDown(void) {
  free(conn);
}

void test_he_internal_stream_setup_state_overwrite(void) {
  he_conn_set_ssl_error_Expect(conn, 0);

  conn->incoming_data_left_to_read = 42;
  int res = he_internal_setup_stream_state(conn, empty_data, sizeof(empty_data));

  TEST_ASSERT_EQUAL(HE_ERR_SSL_ERROR, res);
}
