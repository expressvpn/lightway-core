/**
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

#include <time.h>

#include "msg_handlers.h"

#include "conn.h"
#include "conn_internal.h"
#include "core.h"
#include "frag.h"
#include "network.h"
#include "plugin_chain.h"
#include "memory.h"

he_return_code_t he_handle_msg_noop(he_conn_t *conn, uint8_t *packet, int length) {
  if(conn == NULL || packet == NULL) {
    return HE_ERR_NULL_POINTER;
  }

  // Don't need to do anything for this message type
  return HE_SUCCESS;
}

he_return_code_t he_handle_msg_ping(he_conn_t *conn, uint8_t *packet, int length) {
  if(conn == NULL || packet == NULL) {
    return HE_ERR_NULL_POINTER;
  }

  // We only want to do stuff with pings when the connection is ONLINE
  if(conn->state != HE_STATE_ONLINE) {
    return HE_ERR_INVALID_CONN_STATE;
  }

  // Return if it's not a valid ping message
  if(length < sizeof(he_msg_ping_t)) {
    return HE_ERR_PACKET_TOO_SMALL;
  }

  // Get the ping message
  he_msg_ping_t *ping = (he_msg_ping_t *)packet;

  // Create the pong message
  he_msg_pong_t pong = {0};
  pong.msg_header.msgid = HE_MSGID_PONG;
  pong.id = ping->id;

  // Send pong
  return he_internal_send_message(conn, (uint8_t *)&pong, sizeof(he_msg_pong_t));
}

he_return_code_t he_handle_msg_pong(he_conn_t *conn, uint8_t *packet, int length) {
  if(conn == NULL || packet == NULL) {
    return HE_ERR_NULL_POINTER;
  }

  // Ignore the message if it's not a valid pong message
  if(length < sizeof(he_msg_pong_t)) {
    return HE_SUCCESS;
  }

  // Get the pong message, and ignore it if the id doesn't match
  he_msg_pong_t *pong = (he_msg_pong_t *)packet;
  uint16_t id = ntohs(pong->id);
  if(id == conn->ping_pending_id) {
    // Tell the host application that we received a PONG
    he_internal_generate_event(conn, HE_EVENT_PONG);
    return HE_SUCCESS;
  }
  if(id == conn->pmtud.probe_pending_id) {
    // Received ack of a pmtud probe
    he_internal_pmtud_handle_probe_ack(conn, id);
    return HE_SUCCESS;
  }

  // Ignore the pong message
  return HE_SUCCESS;
}

he_return_code_t he_handle_msg_server_config(he_conn_t *conn, uint8_t *packet, int length) {
  if(conn == NULL || packet == NULL) {
    return HE_ERR_NULL_POINTER;
  }

  // Only handle the server config message on client side
  if(conn->is_server) {
    return HE_ERR_INVALID_CONN_STATE;
  }
  // Check that we're in the right state to receive a server config message
  if(!he_internal_is_valid_state_for_server_config(conn)) {
    return HE_ERR_INVALID_CONN_STATE;
  }

  // Check the packet is big enough
  if(length < sizeof(he_msg_server_config_t)) {
    return HE_ERR_PACKET_TOO_SMALL;
  }

  he_msg_server_config_t *msg = (he_msg_server_config_t *)packet;

  // Check the buffer length
  uint16_t buffer_length = ntohs(msg->buffer_length);
  if(buffer_length > length - sizeof(he_msg_server_config_t)) {
    // Buffer would overflow
    return HE_ERR_POINTER_WOULD_OVERFLOW;
  }

  // Call configure callback if set
  if(conn->server_config_cb) {
    // Check the callback returned successfully
    if(conn->server_config_cb(conn, msg->buffer, buffer_length, conn->data) != HE_SUCCESS) {
      // Return error without changing state. It's client-side app's responsibility to
      // call `he_client_disconnect` when seeing HE_ERR_CALLBACK_FAILED error from
      // he_conn_outside_packet_received function.
      return HE_ERR_CALLBACK_FAILED;
    }
  }

  return HE_SUCCESS;
}

he_return_code_t he_handle_msg_config_ipv4(he_conn_t *conn, uint8_t *packet, int length) {
  if(conn == NULL || packet == NULL) {
    return HE_ERR_NULL_POINTER;
  }

  // CSR-10: since connecting always kicks off 3 packets,
  // we simply ignore config msgs if we are already online
  if(conn->state == HE_STATE_ONLINE) {
    return HE_SUCCESS;
  }

  // Check that we're in the right state to receive a config
  if(conn->is_server || conn->state != HE_STATE_AUTHENTICATING) {
    return HE_ERR_INVALID_CONN_STATE;
  }

  // Check the packet is going to be big enough
  if(length < sizeof(he_msg_config_ipv4_t)) {
    return HE_ERR_PACKET_TOO_SMALL;
  }

  // Cast the packet
  he_msg_config_ipv4_t *pkt = (he_msg_config_ipv4_t *)packet;

  // Set up some space for the config callback
  he_network_config_ipv4_t config = {0};

  // Safely copy the values out and ensure null termination
  strncpy(config.local_ip, pkt->local_ip, HE_MAX_IPV4_STRING_LENGTH);
  config.local_ip[HE_MAX_IPV4_STRING_LENGTH - 1] = '\0';

  strncpy(config.peer_ip, pkt->peer_ip, HE_MAX_IPV4_STRING_LENGTH);
  config.peer_ip[HE_MAX_IPV4_STRING_LENGTH - 1] = '\0';

  strncpy(config.dns_ip, pkt->dns_ip, HE_MAX_IPV4_STRING_LENGTH);
  config.dns_ip[HE_MAX_IPV4_STRING_LENGTH - 1] = '\0';

  int parsed_mtu_value;
  // Before calling sscanf null-terminate the string
  pkt->mtu[HE_MAX_IPV4_STRING_LENGTH - 1] = '\0';
  // Note that res is the "number of variables populated", so we need to check for 1
  int res = sscanf(pkt->mtu, "%u", &parsed_mtu_value);

  if(res != 1 || parsed_mtu_value <= 0 || parsed_mtu_value > HE_MAX_MTU) {
    config.mtu = HE_MAX_MTU;
  } else {
    config.mtu = parsed_mtu_value;
  }

  // Copy out the session ID
  conn->session_id = pkt->session;

  // Change state to configuring...
  he_internal_change_conn_state(conn, HE_STATE_CONFIGURING);

  // Call configure callback if set
  if(conn->network_config_ipv4_cb) {
    // Check the callback returned successfully
    if(conn->network_config_ipv4_cb(conn, &config, conn->data) != HE_SUCCESS) {
      // Return error without changing state. It's client-side app's responsibility to
      // call `he_client_disconnect` when seeing HE_ERR_CALLBACK_FAILED error from
      // he_conn_outside_packet_received function.
      return HE_ERR_CALLBACK_FAILED;
    }
  }

  // All went well so...
  he_internal_change_conn_state(conn, HE_STATE_ONLINE);

  return HE_SUCCESS;
}

void he_internal_send_auth_denied_response(he_conn_t *conn) {
  // Allocate some space for the config message
  he_msg_auth_response_t response = {0};

  response.msg_header.msgid = HE_MSGID_AUTH_RESPONSE;
  response.status = HE_AUTH_STATUS_SUCCESS;

  he_internal_send_message(conn, (uint8_t *)&response, sizeof(he_msg_auth_response_t));
}

he_return_code_t he_handle_msg_auth(he_conn_t *conn, uint8_t *packet, int length) {
  if(conn == NULL || packet == NULL) {
    return HE_ERR_NULL_POINTER;
  }

  // Check we're in the right state:
  // 1. We must be a server
  // 2. We must be in either LINK_UP or ONLINE
  if(!conn->is_server && (conn->state != HE_STATE_LINK_UP && conn->state != HE_STATE_ONLINE)) {
    return HE_ERR_INVALID_CONN_STATE;
  }

  // Check that we actually have auth handlers setup
  if(conn->populate_network_config_ipv4_cb == NULL) {
    return HE_ERR_INVALID_CONN_STATE;
  }

  // One of the authentication callbacks must be set
  if(conn->auth_cb == NULL && conn->auth_token_cb == NULL && conn->auth_buf_cb == NULL) {
    return HE_ERR_INVALID_CONN_STATE;
  }

  // Check the packet is big enough
  if(length < sizeof(he_msg_auth_hdr_t)) {
    return HE_ERR_PACKET_TOO_SMALL;
  }

  // Cast header
  he_msg_auth_hdr_t *msg = (he_msg_auth_hdr_t *)packet;

  bool auth_state = false;
  he_return_code_t auth_res = HE_ERR_ACCESS_DENIED;

  switch(msg->auth_type) {
    case HE_AUTH_TYPE_USERPASS:
      if(conn->auth_cb) {
        // Check the packet is big enough
        if(length < sizeof(he_msg_auth_t)) {
          return HE_ERR_PACKET_TOO_SMALL;
        }

        he_msg_auth_t *msg_userpass = (he_msg_auth_t *)packet;
        auth_state =
            conn->auth_cb(conn, msg_userpass->username, msg_userpass->password, conn->data);
        // At this point the user is authenticated or not
        // We no longer need msg->password, let's zero it out
        memset(msg_userpass->password, 0, HE_CONFIG_TEXT_FIELD_LENGTH);
        // Copy username into the connection. Force NULL terminator after since strncpy does not
        // insert 0 if username is HE_CONFIG_TEXT_FIELD_LENGTH exactly
        strncpy(conn->username, msg_userpass->username, HE_CONFIG_TEXT_FIELD_LENGTH);
        conn->username[HE_CONFIG_TEXT_FIELD_LENGTH] = 0;
      } else {
        auth_res = HE_ERR_ACCESS_DENIED_NO_AUTH_USERPASS_HANDLER;
      }
      break;
    case HE_AUTH_TYPE_TOKEN:
      if(conn->auth_token_cb) {
        // Check the packet is big enough
        if(length <= sizeof(he_msg_auth_token_t)) {
          return HE_ERR_PACKET_TOO_SMALL;
        }
        he_msg_auth_token_t *msg_token = (he_msg_auth_token_t *)packet;

        // Check the auth token length
        uint16_t auth_token_length = ntohs(msg_token->token_length);
        if(auth_token_length > (length - sizeof(he_msg_auth_hdr_t))) {
          return HE_ERR_PACKET_TOO_SMALL;
        }
        auth_state = conn->auth_token_cb(conn, msg_token->token, auth_token_length, conn->data);
      } else {
        auth_res = HE_ERR_ACCESS_DENIED_NO_AUTH_TOKEN_HANDLER;
      }
      break;
    case HE_AUTH_TYPE_CB:
      if(conn->auth_buf_cb) {
        // Check the packet is big enough
        if(length <= sizeof(he_msg_auth_buf_t)) {
          return HE_ERR_PACKET_TOO_SMALL;
        }

        he_msg_auth_buf_t *msg_buf = (he_msg_auth_buf_t *)packet;

        // Check the auth buffer length
        uint16_t auth_buf_length = ntohs(msg_buf->buffer_length);
        if(auth_buf_length > (length - sizeof(he_msg_auth_hdr_t))) {
          return HE_ERR_PACKET_TOO_SMALL;
        }
        auth_state = conn->auth_buf_cb(conn, msg_buf->header.auth_type, msg_buf->buffer,
                                       auth_buf_length, conn->data);
      } else {
        auth_res = HE_ERR_ACCESS_DENIED_NO_AUTH_BUF_HANDLER;
      }
      break;
    default:
      // The auth packet contains invalid auth type. We just deny the access instead of logging it
      // as a server error.
      auth_res = HE_ERR_ACCESS_DENIED;
      break;
  }

  if(!auth_state) {
    he_internal_send_auth_denied_response(conn);
    he_internal_change_conn_state(conn, HE_STATE_DISCONNECTING);
    return auth_res;
  }

  // Create config to send to the client

  // Allocate some space for the config message
  uint8_t msg_buffer[sizeof(he_msg_config_ipv4_t)] = {0};

  he_msg_config_ipv4_t *response = (he_msg_config_ipv4_t *)&msg_buffer;
  response->msg_header.msgid = HE_MSGID_CONFIG_IPV4;

  // Copy the session ID into the response
  response->session = conn->session_id;

  // Set up some space for the config callback
  he_network_config_ipv4_t config = {0};

  // Copy the homogonized network configuration into the auth response
  int res = conn->populate_network_config_ipv4_cb(conn, &config, conn->data);
  if(res != HE_SUCCESS) {
    // Not recoverable so we just tell the client they failed auth
    he_internal_send_auth_denied_response(conn);
    return res;
  }

  // Safely copy the values out and ensure null termination
  strncpy(response->local_ip, config.local_ip, HE_MAX_IPV4_STRING_LENGTH);
  response->local_ip[HE_MAX_IPV4_STRING_LENGTH - 1] = '\0';

  strncpy(response->peer_ip, config.peer_ip, HE_MAX_IPV4_STRING_LENGTH);
  response->peer_ip[HE_MAX_IPV4_STRING_LENGTH - 1] = '\0';

  strncpy(response->dns_ip, config.dns_ip, HE_MAX_IPV4_STRING_LENGTH);
  response->dns_ip[HE_MAX_IPV4_STRING_LENGTH - 1] = '\0';

  strncpy(response->mtu, HE_MAX_MTU_STR, sizeof(response->mtu));

  // Send config
  he_internal_send_message(conn, (uint8_t *)response, sizeof(he_msg_config_ipv4_t));

  // All went well so...
  he_internal_change_conn_state(conn, HE_STATE_ONLINE);

  return HE_SUCCESS;
}

static he_return_code_t internal_handle_data(he_conn_t *conn, uint8_t *inside_packet,
                                             uint16_t pkt_length) {
  // Note that the parallel call to ingress is in conn.c:he_internal_outside_data_received
  size_t post_plugin_length = pkt_length;
  he_return_code_t res =
      he_plugin_egress(conn->inside_plugins, inside_packet, &post_plugin_length, pkt_length);

  if(res == HE_ERR_PLUGIN_DROP) {
    // Plugin said to drop it, we drop it
    return HE_SUCCESS;
  } else if(res != HE_SUCCESS) {
    return HE_ERR_FAILED;
  }

  // Sanity-check length -- contract says that it can't be longer than pkt_length but just in case
  if(post_plugin_length > pkt_length) {
    return HE_ERR_FAILED;
  }

  // Validate packet
  if(!he_internal_is_ipv4_packet_valid(inside_packet, post_plugin_length)) {
    // Invalid packet
    return HE_ERR_BAD_PACKET;
  }

  // Packet seems to be fine, hand it over
  if(conn->inside_write_cb) {
    conn->inside_write_cb(conn, inside_packet, post_plugin_length, conn->data);
  }

  return HE_SUCCESS;
}

he_return_code_t he_handle_msg_data(he_conn_t *conn, uint8_t *packet, int length) {
  if(conn == NULL || packet == NULL) {
    return HE_ERR_NULL_POINTER;
  }

  // Check we're in the ONLINE state
  if(conn->state != HE_STATE_ONLINE) {
    return HE_ERR_INVALID_CONN_STATE;
  }

  // Quick header check
  if(length < sizeof(he_msg_data_t)) {
    return HE_ERR_PACKET_TOO_SMALL;
  }

  // Apply header
  he_msg_data_t *pkt = (he_msg_data_t *)packet;

  // We use this a lot so convert it just the once
  // Prior to May 2021, a bug here passed the "length" in host-order instead of network order
  // We have fixed this as of protocol version 1.1 but still support the bug for older clients
  uint16_t pkt_length;
  if(conn->protocol_version.major_version == 1 && conn->protocol_version.minor_version == 0) {
    pkt_length = pkt->length;
  } else {
    pkt_length = ntohs(pkt->length);
  }

  // Check the packet length is sufficient
  if(pkt_length > length - sizeof(he_msg_data_t)) {
    return HE_ERR_POINTER_WOULD_OVERFLOW;
  }

  uint8_t *inside_packet = packet + sizeof(he_msg_data_t);

  return internal_handle_data(conn, inside_packet, pkt_length);
}

he_return_code_t he_handle_msg_data_with_frag(he_conn_t *conn, uint8_t *packet, int length) {
  if(conn == NULL || packet == NULL) {
    return HE_ERR_NULL_POINTER;
  }

  // Check we're in the ONLINE state
  if(conn->state != HE_STATE_ONLINE) {
    return HE_ERR_INVALID_CONN_STATE;
  }

  // Quick header check
  if(length < sizeof(he_msg_data_frag_t)) {
    return HE_ERR_PACKET_TOO_SMALL;
  }

  // Apply header
  he_msg_data_frag_t *pkt = (he_msg_data_frag_t *)packet;

  // Check the packet length
  uint16_t pkt_length = ntohs(pkt->length);
  if(pkt_length > length - sizeof(he_msg_data_frag_t)) {
    return HE_ERR_POINTER_WOULD_OVERFLOW;
  }
  uint16_t off = ntohs(pkt->offset);
  uint16_t offset = (off & HE_FRAG_OFF_MASK) * 8;
  uint8_t mf = (off & HE_FRAG_MF_MASK) >> 13;
  if(offset + pkt_length > HE_MAX_WIRE_MTU) {
    return HE_ERR_POINTER_WOULD_OVERFLOW;
  }

  // Get the fragment identifier
  uint16_t frag_id = ntohs(pkt->id);

  // Look up in fragment table
  he_fragment_entry_t *entry = he_internal_fragment_table_find(conn->frag_table, frag_id);
  if(entry == NULL) {
    return HE_ERR_NO_MEMORY;
  }

  // Check if the entry has expired
  time_t now = time(NULL);
  if(now - entry->timestamp > HE_FRAG_TTL) {
    // Entry has expired, reset and reuse the entry
    he_fragment_entry_reset(entry);
    entry->timestamp = now;
  }

  // Now we have an entry to work with,
  // update the entry with new fragment
  bool assembled = false;
  he_return_code_t ret = he_fragment_entry_update(entry, packet + sizeof(he_msg_data_frag_t),
                                                  offset, pkt_length, mf, &assembled);
  if(ret != HE_SUCCESS) {
    return ret;
  }

  if(assembled) {
    // We now have a fully assembled packet, handle it and remove the entry
    he_return_code_t rc = internal_handle_data(conn, entry->data, entry->fragments->end);

    // Cleanup the entry
    he_internal_fragment_table_delete(conn->frag_table, frag_id);

    return rc;
  }
  return HE_SUCCESS;
}

he_return_code_t he_handle_msg_deprecated_13(he_conn_t *conn, uint8_t *packet, int length) {
  if(conn == NULL || packet == NULL) {
    return HE_ERR_NULL_POINTER;
  }

  // Check we're in the ONLINE state
  if(conn->state != HE_STATE_ONLINE) {
    return HE_ERR_INVALID_CONN_STATE;
  }

  // Quick header check
  if(length < sizeof(he_deprecated_msg_13_t)) {
    return HE_ERR_PACKET_TOO_SMALL;
  }

  // Apply header
  he_deprecated_msg_13_t *pkt = (he_deprecated_msg_13_t *)packet;

  // We use this a lot so convert it just the once
  uint16_t pkt_length = ntohs(pkt->length);

  // Check the packet length is sufficient
  if(pkt_length > length - sizeof(he_deprecated_msg_13_t)) {
    return HE_ERR_POINTER_WOULD_OVERFLOW;
  }

  uint8_t *inside_packet = packet + sizeof(he_deprecated_msg_13_t);
  return internal_handle_data(conn, inside_packet, pkt_length);
}

he_return_code_t he_handle_msg_auth_response_with_config(he_conn_t *conn, uint8_t *packet,
                                                         int length) {
  if(conn == NULL || packet == NULL) {
    return HE_ERR_NULL_POINTER;
  }

  return HE_SUCCESS;
}

he_return_code_t he_handle_msg_auth_response(he_conn_t *conn, uint8_t *packet, int length) {
  if(conn == NULL || packet == NULL) {
    return HE_ERR_NULL_POINTER;
  }

  // Right now this means the login failed, so just shutdown
  return HE_ERR_ACCESS_DENIED;
}

he_return_code_t he_handle_msg_goodbye(he_conn_t *conn, uint8_t *packet, int length) {
  if(conn == NULL || packet == NULL) {
    return HE_ERR_NULL_POINTER;
  }

  // No processing, just tell the host the conn is closed
  return HE_ERR_SERVER_GOODBYE;
}
