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

#include "wolf.h"
#include "plugin_chain.h"

int he_wolf_dtls_read(WOLFSSL *ssl, char *buf, int sz, void *ctx) {
  (void)ssl; /* will not need ssl context */

  if(sz < 0) {
    // Should never ever happen but we'll just abort
    return WOLFSSL_CBIO_ERR_GENERAL;
  }

  // Abort if any of the IO buffers are null pointers
  if(!buf || !ctx) {
    return WOLFSSL_CBIO_ERR_GENERAL;
  }

  // Get DTLS context
  he_conn_t *conn = (he_conn_t *)ctx;

  // This can be null if no data has been received yet, tell wolfSSL to stop asking
  if(!conn->incoming_data) {
    return WOLFSSL_CBIO_ERR_WANT_READ;
  }

  // WolfSSL will call this function any time it wants to read. As we're using libuv
  // there will only ever be one packet per callback. WolfSSL will call this function
  // any time it wants to read, it doesn't know there's only ever one, so we need to
  // check and send the equivalent of "would block" if we've already processed the
  // provided packet.
  if(conn->packet_seen) {
    // We've already processed this packet, tell WolfSSL to stop asking
    return WOLFSSL_CBIO_ERR_WANT_READ;
  }

  // Check that we have enough space to write the packet
  if(conn->incoming_data_length > sz) {
    // We can't write this packet and split it - have to drop
    conn->packet_seen = true;
    return 0;
  }

  // Copy the data out of the packet into WolfSSL's buffer
  memcpy(buf, conn->incoming_data, conn->incoming_data_length);
  // Set flag so we can ignore this packet next time
  conn->packet_seen = true;

  // The amount of data we copied into WolfSSL's buffer
  return (int)conn->incoming_data_length;
}

int he_internal_write_packet_header(he_conn_t *conn, he_wire_hdr_t *hdr) {
  if(!hdr || !conn) {
    return HE_ERR_NULL_POINTER;
  }

  // Write Helium identifier
  hdr->he[0] = 'H';
  hdr->he[1] = 'e';

  hdr->major_version = conn->protocol_version.major_version;
  hdr->minor_version = conn->protocol_version.minor_version;

  // If aggressive connect is set
  if(conn->use_aggressive_mode) {
    hdr->aggressive_mode = 1;
  }

  // Check to see if roaming connections have been disabled
  if(!conn->disable_roaming_connections) {
    // Use memcpy not a direct assign to avoid CPU alignment issues
    if(conn->pending_session_id != HE_PACKET_SESSION_EMPTY) {
      memcpy(&hdr->session, &conn->pending_session_id, sizeof(hdr->session));
    } else {
      memcpy(&hdr->session, &conn->session_id, sizeof(hdr->session));
    }
  } else {
    uint64_t temp_session = HE_PACKET_SESSION_REJECT;
    memcpy(&hdr->session, &temp_session, sizeof(hdr->session));
  }
  return HE_SUCCESS;
}

int he_wolf_dtls_write(WOLFSSL *ssl, char *buf, int sz, void *ctx) {
  (void)ssl; /* will not need ssl context */

  if(sz < 0) {
    // Should never ever happen but we'll just abort
    return WOLFSSL_CBIO_ERR_GENERAL;
  }

  // Abort if any of the IO buffers are null pointers
  if(!buf || !ctx) {
    return WOLFSSL_CBIO_ERR_GENERAL;
  }

  // Get DTLS context
  he_conn_t *conn = (he_conn_t *)ctx;

  // Check we have enough space
  // @TODO: Take MTU settings into account
  if(sz + sizeof(he_wire_hdr_t) > sizeof(conn->write_buffer)) {
    // We have to drop the packet as we can never send it (in theory this should never happen
    // due to earlier constraints)
    return WOLFSSL_CBIO_ERR_GENERAL;
  }

  // Initialise the write buffer
  he_internal_write_packet_header(conn, (he_wire_hdr_t *)conn->write_buffer);

  // Copy in the data behind the header
  // TODO Actively investigating why the analyzer thinks that conn->write_buffer is not the same
  // as &conn->write_buffer[0]
  memcpy((&conn->write_buffer[0]) + sizeof(he_wire_hdr_t), buf, sz);

  // Note that the parallel call to ingress is in conn.c:he_internal_outside_data_received
  size_t post_plugin_length = sz + sizeof(he_wire_hdr_t);
  he_return_code_t res = he_plugin_egress(conn->outside_plugins, &conn->write_buffer[0],
                                          &post_plugin_length, sizeof(conn->write_buffer));

  if(res == HE_ERR_PLUGIN_DROP) {
    // Plugin said to drop it, we drop it
    // Parallel to returning HE_SUCCESS on ingress
    return sz;
  } else if(res != HE_SUCCESS || post_plugin_length > sizeof(conn->write_buffer)) {
    return WOLFSSL_CBIO_ERR_GENERAL;
  }

  // Call the write callback if set
  if(conn->outside_write_cb) {
    res = conn->outside_write_cb(conn, conn->write_buffer, post_plugin_length, conn->data);
    if(res != HE_SUCCESS) {
      return WOLFSSL_CBIO_ERR_GENERAL;
    }

    // If we're not yet connected, be aggressive and send two more packets. If aggressive mode
    // is set, always be aggressive and send two more.
    if(conn->state != HE_STATE_ONLINE || conn->use_aggressive_mode) {
      conn->outside_write_cb(conn, conn->write_buffer, post_plugin_length, conn->data);
      if(res != HE_SUCCESS) {
        return WOLFSSL_CBIO_ERR_GENERAL;
      }

      conn->outside_write_cb(conn, conn->write_buffer, post_plugin_length, conn->data);
      if(res != HE_SUCCESS) {
        return WOLFSSL_CBIO_ERR_GENERAL;
      }
    }
  }

  // Return the size written
  return sz;
}

int he_wolf_tls_read(WOLFSSL *ssl, char *buf, int sz, void *ctx) {
  (void)ssl;  // will not need ssl context

  if(sz < 0) {
    // Should never ever happen but we'll just abort
    return WOLFSSL_CBIO_ERR_GENERAL;
  }

  // Abort if any of the IO buffers are null pointers
  if(!buf || !ctx) {
    return WOLFSSL_CBIO_ERR_GENERAL;
  }

  // Get TLS context
  he_conn_t *conn = (he_conn_t *)ctx;

  // Check to see if there's any bytes left to copy to Wolf
  if(conn->incoming_data_left_to_read == 0) {
    // No - then return with need data
    return WOLFSSL_CBIO_ERR_WANT_READ;
  }

  // Abort if incoming_data_read_offset_ptr is null - this is set internally in libhelium
  if(!conn->incoming_data_read_offset_ptr) {
    return WOLFSSL_CBIO_ERR_GENERAL;
  }

  // How many bytes should we give to Wolf
  size_t number_of_bytes_to_copy = 0;

  // Figure out how much to copy
  if(sz < conn->incoming_data_left_to_read) {
    number_of_bytes_to_copy = sz;
  } else {
    number_of_bytes_to_copy = conn->incoming_data_left_to_read;
  }

  // Copy the bytes in to Wolf's buffer
  memcpy(buf, conn->incoming_data_read_offset_ptr, number_of_bytes_to_copy);

  // Update number of bytes left and increment the offset pointer
  conn->incoming_data_left_to_read -= number_of_bytes_to_copy;
  conn->incoming_data_read_offset_ptr += number_of_bytes_to_copy;

  // The amount of data we copied into WolfSSL's buffer
  return (int)number_of_bytes_to_copy;
}

int he_wolf_tls_write(WOLFSSL *ssl, char *buf, int sz, void *ctx) {
  (void)ssl; /* will not need ssl context */

  if(sz < 0) {
    // Should never ever happen but we'll just abort
    return WOLFSSL_CBIO_ERR_GENERAL;
  }

  // Abort if any of the IO buffers are null pointers
  if(!buf || !ctx) {
    return WOLFSSL_CBIO_ERR_GENERAL;
  }

  // Get DTLS context
  he_conn_t *conn = (he_conn_t *)ctx;

  // Check we have enough space -- we never have to return here, we can just tell wolfSSL that we
  // sent less than expected and it will work
  size_t number_of_bytes_to_copy = 0;

  // Figure out how much to copy
  if(sz < sizeof(conn->write_buffer)) {
    number_of_bytes_to_copy = sz;
  } else {
    number_of_bytes_to_copy = sizeof(conn->write_buffer);
  }

  // Copy in the data
  memcpy((&conn->write_buffer[0]), buf, number_of_bytes_to_copy);

  // Note that the parallel call to ingress is in conn.t.c:he_conn_outside_data_received
  size_t post_plugin_length = number_of_bytes_to_copy;
  he_return_code_t res = he_plugin_egress(conn->outside_plugins, &conn->write_buffer[0],
                                          &post_plugin_length, sizeof(conn->write_buffer));

  if(res == HE_ERR_PLUGIN_DROP) {
    // Plugin said to drop it, we drop it
    // Parallel to returning HE_SUCCESS on ingress
    return sz;
  } else if(res != HE_SUCCESS || post_plugin_length > sizeof(conn->write_buffer)) {
    return WOLFSSL_CBIO_ERR_GENERAL;
  }

  // Call the write callback if set
  if(conn->outside_write_cb) {
    res = conn->outside_write_cb(conn, conn->write_buffer, post_plugin_length, conn->data);
    if(res != HE_SUCCESS) {
      return WOLFSSL_CBIO_ERR_GENERAL;
    }
  }

  // Return the size written
  return (int)number_of_bytes_to_copy;
}
