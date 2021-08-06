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

#include "core.h"

he_return_code_t he_internal_setup_stream_state(he_conn_t *conn, uint8_t *data, size_t length) {
  if(conn->incoming_data_left_to_read != 0) {
    // Somehow this function was called without reading all data from a previous buffer
    // This is bad
    return HE_ERR_SSL_ERROR;
  }
  // Set up the location of the buffer and its length
  conn->incoming_data = data;
  conn->incoming_data_length = length;

  // Initialise the offset pointer and data left counter
  conn->incoming_data_left_to_read = conn->incoming_data_length;
  conn->incoming_data_read_offset_ptr = conn->incoming_data;

  return HE_SUCCESS;
}
