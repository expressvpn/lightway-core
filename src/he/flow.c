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

#include "flow.h"
#include "frag.h"
#include "core.h"
#include "msg_handlers.h"
#include "conn.h"
#include "conn_internal.h"
#include "plugin_chain.h"
#include "mss.h"
#include "network.h"

#ifndef WOLFSSL_USER_SETTINGS
#include <wolfssl/options.h>
#endif
#include <wolfssl/error-ssl.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/settings.h>

bool he_internal_flow_should_fragment(he_conn_t *conn, uint16_t effective_pmtu, uint16_t length) {
  return conn->connection_type == HE_CONNECTION_TYPE_DATAGRAM &&
         conn->pmtud_state == HE_PMTUD_STATE_SEARCH_COMPLETE && length > effective_pmtu;
}

he_return_code_t he_conn_inside_packet_received(he_conn_t *conn, uint8_t *packet, size_t length) {
  // Return if packet or conn is null
  if(!packet || !conn) {
    return HE_ERR_NULL_POINTER;
  }

  // If we're not connected, we can't do anything with this packet
  if(conn->state != HE_STATE_ONLINE) {
    return HE_ERR_INVALID_CONN_STATE;
  }

  // Packet should be at least large enough to hold an empty IPv4 packet
  if(length < HE_IPV4_HEADER_SIZE) {
    return HE_ERR_PACKET_TOO_SMALL;
  }

  // Return if the packet is too large.
  // Note that we can fragment the packet if necessary.
  size_t capacity = conn->outside_mtu - HE_PACKET_OVERHEAD;
  if(length > capacity) {
    return HE_ERR_PACKET_TOO_LARGE;
  }

  // Reject non-ipv4 packets
  if(!he_internal_is_ipv4_packet_valid(packet, length)) {
    return HE_ERR_UNSUPPORTED_PACKET_TYPE;
  }

  // Clamp the MSS if PMTU has been fixed
  he_return_code_t ret = HE_SUCCESS;
  uint16_t effective_pmtu = he_conn_get_effective_pmtu(conn);
  if(conn->pmtud_state == HE_PMTUD_STATE_SEARCH_COMPLETE) {
    ret = he_internal_clamp_mss(packet, length, effective_pmtu - HE_MSS_OVERHEAD);
    if(ret != HE_SUCCESS) {
      return ret;
    }
  }

  // Process the packet with plugins.
  // Note that the packet size might grow or shrink depends on the plugins.
  size_t post_plugin_length = length;
  int res = he_plugin_ingress(conn->inside_plugins, packet, &post_plugin_length, capacity);

  if(res == HE_ERR_PLUGIN_DROP) {
    // No one needs to know
    return HE_SUCCESS;
  }

  if(res != HE_SUCCESS) {
    return HE_ERR_FAILED;
  }

  if(post_plugin_length > capacity) {
    // This should never happen, but we check it anyway
    return HE_ERR_FAILED;
  }

  // Check if we need fragment the packet
  bool should_frag = he_internal_flow_should_fragment(conn, effective_pmtu, post_plugin_length);
  if(!should_frag) {
    // Packet will not fit our buffer
    if(post_plugin_length + sizeof(he_msg_data_t) > HE_MAX_WIRE_MTU) {
      return HE_ERR_FAILED;
    }

    // Get the actual length after padding
    size_t actual_length = he_internal_calculate_data_packet_length(conn, post_plugin_length);

    // Send the data without fragmentation
    uint8_t bytes[HE_MAX_WIRE_MTU] = {0};

    // Allocate some space for the data message
    he_msg_data_t *hdr = (he_msg_data_t *)bytes;

    // Set message type
    hdr->msg_header.msgid = HE_MSGID_DATA;

    // Set data length
    // Prior to May 2021, a bug here passed the "length" in host order instead of network order
    // We have fixed this as of protocol version 1.1 but still support the bug for older clients
    if(conn->protocol_version.major_version == 1 && conn->protocol_version.minor_version == 0) {
      hdr->length = post_plugin_length;
    } else {
      hdr->length = htons(post_plugin_length);
    }

    // Copy packet into the buffer
    memcpy(bytes + sizeof(he_msg_data_t), packet, post_plugin_length);

    ret = he_internal_send_message(conn, (uint8_t *)bytes, actual_length + sizeof(he_msg_data_t));
  } else {
    // Calculate the frag size.
    // The effective_pmtu is the largest packets size we can send in a he_msg_data_t message,
    // but since he_msg_data_frag_t has slightly more overhead, we cannot use the effective_pmtu as
    // the frag size directly.
    uint16_t frag_size = effective_pmtu + sizeof(he_msg_data_t) - sizeof(he_msg_data_frag_t);

    // Send the data with fragmentation.
    // Note that we won't add any padding to the fragmented packets

    ret = he_internal_frag_and_send_message(conn, (uint8_t *)packet, post_plugin_length, frag_size);
  }
  return ret;
}

he_return_code_t he_internal_flow_process_message(he_conn_t *conn) {
  // Return if conn is null
  if(!conn) {
    return HE_ERR_NULL_POINTER;
  }

  // If the packet is too small then either the client is sending corrupted data or something is
  // very wrong with the SSL connection
  if(conn->read_packet.packet_size < sizeof(he_msg_hdr_t)) {
    conn->read_packet.has_packet = false;
    conn->wolf_error = 0;
    return HE_ERR_SSL_ERROR;
  }

  he_packet_buffer_t *pkt_buff = &conn->read_packet;

  // Cast the header
  he_msg_hdr_t *msg_hdr = (he_msg_hdr_t *)&pkt_buff->packet;
  uint8_t *buf = pkt_buff->packet;
  int buf_len = pkt_buff->packet_size;

  switch(msg_hdr->msgid) {
    case HE_MSGID_NOOP:
      return he_handle_msg_noop(conn, buf, buf_len);
    case HE_MSGID_PING:
      return he_handle_msg_ping(conn, buf, buf_len);
    case HE_MSGID_PONG:
      return he_handle_msg_pong(conn, buf, buf_len);
    case HE_MSGID_AUTH:
      if(conn->is_server) {
        return he_handle_msg_auth(conn, buf, buf_len);
      }
      // Otherwise do nothing
      return HE_SUCCESS;
    case HE_MSGID_DATA:
      return he_handle_msg_data(conn, buf, buf_len);
    case HE_MSGID_CONFIG_IPV4:
      if(!conn->is_server) {
        return he_handle_msg_config_ipv4(conn, buf, buf_len);
      }
      // Otherwise do nothing
      return HE_SUCCESS;
    case HE_MSGID_AUTH_RESPONSE:
      if(!conn->is_server) {
        return he_handle_msg_auth_response(conn, buf, buf_len);
      }
      // Otherwise do nothing
      return HE_SUCCESS;
    case HE_MSGID_AUTH_RESPONSE_WITH_CONFIG:
      // Not used yet
      return HE_SUCCESS;
    case HE_MSGID_GOODBYE:
      return he_handle_msg_goodbye(conn, buf, buf_len);
    case HE_MSGID_EXTENSION:
      // Not used yet
      return HE_SUCCESS;
    case HE_MSGID_DEPRECATED_13:
      return he_handle_msg_deprecated_13(conn, buf, buf_len);
    case HE_MSGID_SERVER_CONFIG:
      if(!conn->is_server) {
        return he_handle_msg_server_config(conn, buf, buf_len);
      }
      // Otherwise do nothing
      return HE_SUCCESS;
    case HE_MSGID_DATA_WITH_FRAG:
      return he_handle_msg_data_with_frag(conn, buf, buf_len);
    default:
      // Invalid message - just ignore it
      break;
  }

  return HE_SUCCESS;
}

he_return_code_t he_internal_flow_fetch_message(he_conn_t *conn) {
  // Return if conn is null
  if(!conn) {
    return HE_ERR_NULL_POINTER;
  }

  // Try to read out a packet
  int res =
      wolfSSL_read(conn->wolf_ssl, conn->read_packet.packet, sizeof(conn->read_packet.packet));

  if(res <= 0) {
    conn->read_packet.has_packet = false;
    conn->read_packet.packet_size = 0;

    int error = wolfSSL_get_error(conn->wolf_ssl, res);
    switch(error) {
      case SSL_ERROR_NONE:
        // Previous API appeared to return an error code but no error actually occurred
        return HE_SUCCESS;

      case APP_DATA_READY:
        return he_internal_flow_fetch_message(conn);

      case SSL_ERROR_WANT_READ:
      case SSL_ERROR_WANT_WRITE:
        // The underlying I/O is non-blocking and it could not satisfy the needs of wolfSSL_read
        // to continue.
        return HE_SUCCESS;

      default:
        if(res == 0) {
          return HE_ERR_CONNECTION_WAS_CLOSED;
        } else {
          // if this is TCP then any SSL error is fatal (stream corruption).
          // If this is D/TLS we can actually ignore corrupted packets.
          if (conn->connection_type == HE_CONNECTION_TYPE_STREAM) {
            conn->wolf_error = error;
            return HE_ERR_SSL_ERROR;
          } else {
            return HE_ERR_SSL_ERROR_NONFATAL;
          }
        }
    }
  } else {
    conn->read_packet.has_packet = true;
    conn->read_packet.packet_size = res;
  }

  return HE_SUCCESS;
}

he_return_code_t he_internal_update_session_incoming(he_conn_t *conn, he_wire_hdr_t *hdr) {
  // Return if hdr or conn is null
  if(!hdr || !conn) {
    return HE_ERR_NULL_POINTER;
  }

  /// Exit early if the session ID is not set
  if(!hdr->session) {
    return HE_SUCCESS;
  }

  if(conn->is_server) {
    // We don't want to change to just any session ID, only the one we wanted to rotate to

    // This is obviously fine
    if(hdr->session == conn->session_id) {
      return HE_SUCCESS;
    } else if(hdr->session == conn->pending_session_id) {
      conn->session_id = hdr->session;
      conn->pending_session_id = HE_PACKET_SESSION_EMPTY;
      he_internal_generate_event(conn, HE_EVENT_PENDING_SESSION_ACKNOWLEDGED);
      return HE_SUCCESS;
    } else {
      return HE_ERR_UNKNOWN_SESSION;
    }
  } else {
    // Clients just accept it
    conn->session_id = hdr->session;
    return HE_SUCCESS;
  }
}

he_return_code_t he_conn_outside_data_received(he_conn_t *conn, uint8_t *buffer, size_t length) {
  // Return if buffer or conn is null
  if(!buffer || !conn) {
    return HE_ERR_NULL_POINTER;
  }

  // Return if we're either disconnected or disconnecting
  if(conn->state == HE_STATE_DISCONNECTING || conn->state == HE_STATE_DISCONNECTED) {
    return HE_ERR_INVALID_CONN_STATE;
  }

  // Note that he_internal_plugins_egress is in wolf.c:he_wolf_dtls_write
  size_t post_plugin_length = length;
  int res = he_plugin_ingress(conn->outside_plugins, buffer, &post_plugin_length, length);

  if(res == HE_ERR_PLUGIN_DROP) {
    // No one needs to know
    return HE_SUCCESS;
  }

  if(res != HE_SUCCESS) {
    return res;
  }

  // Sanity-check length -- contract says that it can't be longer than length but just-in-case
  if(post_plugin_length > length) {
    return HE_ERR_FAILED;
  }

  if(conn->connection_type == HE_CONNECTION_TYPE_DATAGRAM) {
    /// Streaming Stuff
    return HE_DISPATCH(he_internal_flow_outside_packet_received, conn, buffer, post_plugin_length);
  } else if(conn->connection_type == HE_CONNECTION_TYPE_STREAM) {
    return HE_DISPATCH(he_internal_flow_outside_stream_received, conn, buffer, post_plugin_length);
  } else {
    return HE_ERR_INVALID_CONN_STATE;
  }
}

he_return_code_t he_internal_flow_outside_packet_received(he_conn_t *conn, uint8_t *packet,
                                                          size_t length) {
  // Return if packet or conn is null
  if(!packet || !conn) {
    return HE_ERR_NULL_POINTER;
  }

  // Return if packet is definitely too small
  if(length < sizeof(he_wire_hdr_t)) {
    return HE_ERR_PACKET_TOO_SMALL;
  }

  // Check for Helium's header
  he_wire_hdr_t *hdr = (he_wire_hdr_t *)packet;

  if(hdr->he[0] != 'H' || hdr->he[1] != 'e') {
    // Not helium data, drop it
    return HE_ERR_NOT_HE_PACKET;
  }

  if(hdr->major_version != conn->protocol_version.major_version ||
     hdr->minor_version != conn->protocol_version.minor_version) {
    return HE_ERR_INCORRECT_PROTOCOL_VERSION;
  }

  // Kill the connection if the server has rejected our session (i.e. server restarted)
  if(!memcmp(&HE_PACKET_SESSION_REJECT, &hdr->session, sizeof(uint64_t))) {
    return HE_ERR_REJECTED_SESSION;
  }

  // If the session ID from the server is non-zero
  // then we inherit the session ID
  he_return_code_t res1 = he_internal_update_session_incoming(conn, hdr);

  if(res1 != HE_SUCCESS) {
    return res1;
  }

  // Update pointer and length in our connection state
  // We need to pull the wire header off first
  conn->incoming_data_length = length - sizeof(he_wire_hdr_t);
  conn->incoming_data = packet + sizeof(he_wire_hdr_t);

  // Make sure that this packet is marked as unseen
  conn->packet_seen = false;

  return HE_DISPATCH(he_internal_flow_outside_data_verify_connection, conn);
}

he_return_code_t he_internal_flow_outside_stream_received(he_conn_t *conn, uint8_t *buffer,
                                                          size_t length) {
  // Return if buffer or conn is null
  if(!buffer || !conn) {
    return HE_ERR_NULL_POINTER;
  }

  int res = he_internal_setup_stream_state(conn, buffer, length);
  if(res != HE_SUCCESS) {
    return res;
  }
  return HE_DISPATCH(he_internal_flow_outside_data_verify_connection, conn);
}

he_return_code_t he_internal_flow_outside_data_verify_connection(he_conn_t *conn) {
  // Return if conn is null
  if(!conn) {
    return HE_ERR_NULL_POINTER;
  }

  // Check to see if this is our first message and trigger an event change if it is
  if(!conn->first_message_received) {
    conn->first_message_received = true;
    he_internal_generate_event(conn, HE_EVENT_FIRST_MESSAGE_RECEIVED);
  }

  if(conn->state == HE_STATE_CONNECTING) {
    // Continue trying to negotiate the connection...
    int wolf_read = wolfSSL_negotiate(conn->wolf_ssl);

    if(wolf_read != SSL_SUCCESS) {
      // Probably not really a fatal error - just async IO
      int error = wolfSSL_get_error(conn->wolf_ssl, wolf_read);

      if(error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) {
        // Check the server did not fail certificate verification
        if(error == ASN_SIG_CONFIRM_E) {
          return HE_ERR_CANNOT_VERIFY_SERVER_CERT;
        }
        // Check the server did fail the DN check
        if(error == DOMAIN_NAME_MISMATCH) {
          return HE_ERR_SERVER_DN_MISMATCH;
        }

        conn->wolf_error = error;
        // We can't recover from any other errors
        return HE_ERR_SSL_ERROR;
      }

      // Update timer
      if(conn->connection_type == HE_CONNECTION_TYPE_DATAGRAM) {
        he_internal_update_timeout(conn);
      }

      // The hosting app doesn't need to know we need more data
      return HE_SUCCESS;
    }

    // If we got here, then the secure connection is up
    he_internal_change_conn_state(conn, HE_STATE_LINK_UP);
  }

  // At this point we should have a good tunnel
  return HE_DISPATCH(he_internal_flow_outside_data_handle_messages, conn);
}

he_return_code_t he_internal_flow_outside_data_handle_messages(he_conn_t *conn) {
  // Return if conn is null
  if(!conn) {
    return HE_ERR_NULL_POINTER;
  }

  // Handle messages
  while(true) {
    // Do we have a message?
    he_return_code_t ret = he_internal_flow_fetch_message(conn);

    if(ret != HE_SUCCESS) {
      return ret;
    }

    if(!conn->read_packet.has_packet) {
      break;
    }

    // Process the message
    ret = he_internal_flow_process_message(conn);

    if(ret != HE_SUCCESS) return ret;
  }

  if(conn->renegotiation_due) {
    he_internal_renegotiate_ssl(conn);
  }

  // D/TLS Renegotiation and timeout updates
  if(conn->renegotiation_in_progress) {
    int resp_pending = 0;

    if(wolfSSL_version(conn->wolf_ssl) == DTLS1_2_VERSION) {
      // DTLS 1.2
      resp_pending = wolfSSL_SSL_renegotiate_pending(conn->wolf_ssl);
    } else {
      // D/TLS 1.3
      if(wolfSSL_key_update_response(conn->wolf_ssl, &resp_pending) != 0) {
        return HE_ERR_SSL_ERROR;
      }
    }

    // Check for renegotiation_in_progress
    if(conn->renegotiation_in_progress && !resp_pending) {
      he_internal_generate_event(conn, HE_EVENT_SECURE_RENEGOTIATION_COMPLETED);
    }
    conn->renegotiation_in_progress = resp_pending;

    // Update the timeout
    he_internal_update_timeout(conn);
  }

  // Zero out the packet, ensures that if the connection is unused
  // for extended periods the old outdated data is cleared from memory
  memset(&conn->read_packet, 0, sizeof(conn->read_packet));

  // All went well
  return HE_SUCCESS;
}
