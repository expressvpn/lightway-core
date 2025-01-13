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

/**
 * @file flow.h
 * @brief Functions for the flow of packets through Helium
 *
 */

#ifndef FLOW_H
#define FLOW_H

#include "he.h"
#include "he_internal.h"

/**
 * @brief Called when the host application needs to deliver an inside packet to Helium.
 * @param conn A valid connection
 * @param packet A pointer to the packet data
 * @param length The length of the packet
 * @return HE_ERR_INVALID_CLIENT_STATE Helium will reject packets if it is not in the
 * HE_STATE_ONLINE state
 * @return HE_ERR_PACKET_TOO_SMALL The packet is too small to be a valid Helium packet
 * @return HE_ERR_UNSUPPORTED_PACKET_TYPE The packet is not an IPv4 packet
 * @return HE_ERR_FAILED The packet was rejected as it won't fit in internal buffers
 * @return HE_SUCCESS Packet was processed normally
 * @note It is expected that Helium will support IPv6 almost immediately, so it is worth keeping
 * this in mind.
 * @note These error codes may change before final release as new issues come to light.
 */
he_return_code_t he_conn_inside_packet_received(he_conn_t *conn, uint8_t *packet, size_t length);

/**
 * @brief Called when the host application needs to deliver outside data to be processed by Helium
 * @param conn A valid Helium connection
 * @param buffer A pointer to the packet data
 * @param length The length of the packet
 * @return HE_ERR_NULL_POINTER The pointer provided is a NULL pointer
 * @return HE_ERR_PACKET_TOO_SMALL The packet is too small to be a valid Helium packet
 * @return HE_ERR_NOT_HE_PACKET The packet is not a Helium packet (it does not have the Helium
 * header)
 * @return HE_ERR_SSL_ERROR Something went wrong decrypting the packet - this is a FATAL error for
 * the connection
 * @return HE_ERR_SERVER_DN_MISMATCH The name in the server's cert did not match local configuration
 * @return HE_ERR_CANNOT_VERIFY_SERVER_CERT The server certificate couldn't be verified using the
 * configured CA Cert
 * @return HE_SUCCESS The packet was processed normally.
 * @note These error codes may change before final release as new issues come to light.
 * @note If the conn has registered plugins, they may arbitrarily change the packet data,
 * but are restricted here to not exceeding the provided length. Users
 * who wish to have more control over this should *not* register plugins upon connection, but
 * instead call the plugin API explicitly prior to invoking this function.
 */
he_return_code_t he_conn_outside_data_received(he_conn_t *conn, uint8_t *buffer, size_t length);

he_return_code_t he_internal_flow_process_message(he_conn_t *conn, he_packet_buffer_t *read_packet);
he_return_code_t he_internal_flow_fetch_message(he_conn_t *conn, he_packet_buffer_t *read_packet);
he_return_code_t he_internal_update_session_incoming(he_conn_t *conn, he_wire_hdr_t *hdr);

he_return_code_t he_internal_flow_outside_packet_received(he_conn_t *conn, uint8_t *packet,
                                                          size_t length);
he_return_code_t he_internal_flow_outside_stream_received(he_conn_t *conn, uint8_t *buffer,
                                                          size_t length);
he_return_code_t he_internal_flow_outside_data_verify_connection(he_conn_t *conn);
he_return_code_t he_internal_flow_outside_data_handle_messages(he_conn_t *conn);

bool he_internal_flow_should_fragment(he_conn_t *conn, uint16_t effective_pmtu, uint16_t length);

#ifdef HE_ENABLE_MULTITHREADED
extern HE_THREAD_LOCAL uint8_t *cur_packet;
extern HE_THREAD_LOCAL size_t cur_packet_length;
extern HE_THREAD_LOCAL bool packet_seen;

static inline void he_internal_set_packet(he_conn_t *conn, uint8_t *packet, size_t len) {
  cur_packet_length = len;
  cur_packet = packet;
}

static inline void he_internal_set_packet_seen(he_conn_t *conn, bool value) {
  packet_seen = value;
}

static inline bool he_internal_is_packet_seen(he_conn_t *conn) {
  return packet_seen;
}

static inline bool he_internal_is_pkt_available(he_conn_t *conn) {
  return !packet_seen && cur_packet;
}

static inline size_t he_internal_copy_packet(he_conn_t *conn, char *buf) {
  memcpy(buf, cur_packet, cur_packet_length);
  return cur_packet_length;
}

static inline size_t he_internal_get_packet_length(he_conn_t *conn) {
  return cur_packet_length;
}

#else // HE_ENABLE_MULTITHREADED

static inline void he_internal_set_packet(he_conn_t *conn, uint8_t *packet, size_t len) {
  conn->incoming_data_length = len;
  conn->incoming_data = packet;
}

static inline void he_internal_set_packet_seen(he_conn_t *conn, bool value) {
  conn->packet_seen = value;
}

static inline bool he_internal_is_packet_seen(he_conn_t *conn) {
  return conn->packet_seen;
}

static inline bool he_internal_is_pkt_available(he_conn_t *conn) {
  return !!conn->incoming_data;
}

static inline size_t he_internal_copy_packet(he_conn_t *conn, char *buf) {
  memcpy(buf, conn->incoming_data, conn->incoming_data_length);
  return conn->incoming_data_length;
}

static inline size_t he_internal_get_packet_length(he_conn_t *conn) {
  return conn->incoming_data_length;
}
#endif // HE_ENABLE_MULTITHREADED

#endif  // FLOW_H
