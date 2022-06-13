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

#include "conn.h"
#include "core.h"
#include "config.h"
#include "ssl_ctx.h"

#ifndef WOLFSSL_USER_SETTINGS
#include <wolfssl/options.h>
#endif
#include <wolfssl/error-ssl.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/settings.h>

#include "memory.h"

bool he_conn_is_error_fatal(he_conn_t *conn, he_return_code_t error_msg) {
  // Return if conn is null - that's definitely a fatal error!
  if(!conn) {
    return true;
  }

  // TCP connection errors are quite fatal, but we can ignore a lot of errors in D/TLS

  if(conn->connection_type == HE_CONNECTION_TYPE_STREAM) {
    switch(error_msg) {
      // Obvious
      case HE_SUCCESS:
      // Explicitly non-fatal
      case HE_ERR_SSL_ERROR_NONFATAL:
      case HE_WANT_READ:
      case HE_WANT_WRITE:
      // Just need to call connect
      case HE_ERR_NOT_CONNECTED:
        return false;
      default:
        return true;
    }
  }
  // D/TLS here, we validate elsewhere that the connection type is one of two values
  switch(error_msg) {
    // Obvious
    case HE_SUCCESS:
    // Can be caused by out-of-order or repeated messages
    case HE_ERR_INVALID_CONN_STATE:
    // Explicitly non-fatal
    case HE_ERR_SSL_ERROR_NONFATAL:
    case HE_WANT_READ:
    case HE_WANT_WRITE:
    // Just call connect
    case HE_ERR_NOT_CONNECTED:
    // Random bad packets
    case HE_ERR_EMPTY_PACKET:
    case HE_ERR_PACKET_TOO_SMALL:
    case HE_ERR_NOT_HE_PACKET:
    case HE_ERR_UNSUPPORTED_PACKET_TYPE:
    case HE_ERR_BAD_PACKET:
    case HE_ERR_UNKNOWN_SESSION:
      return false;
    default:
      return true;
  }
}

he_return_code_t he_conn_is_valid_client(he_ssl_ctx_t *ssl_ctx, he_conn_t *conn) {
  if(!conn) {
    return HE_ERR_NULL_POINTER;
  }

  if(!he_conn_is_auth_buffer_set(conn)) {
    if(!he_conn_is_username_set(conn)) {
      return HE_ERR_CONF_USERNAME_NOT_SET;
    }

    if(!he_conn_is_password_set(conn)) {
      return HE_ERR_CONF_PASSWORD_NOT_SET;
    }
  } else if(he_conn_is_username_set(conn)) {
    return HE_ERR_CONF_CONFLICTING_AUTH_METHODS;
  }

  if(!he_conn_is_outside_mtu_set(conn)) {
    return HE_ERR_CONF_MTU_NOT_SET;
  }

  if(conn->protocol_version.major_version != 0 &&
     !he_ssl_ctx_is_latest_version(ssl_ctx, conn->protocol_version.major_version,
                                   conn->protocol_version.minor_version)) {
    return HE_ERR_INCORRECT_PROTOCOL_VERSION;
  }

  return HE_SUCCESS;
}

he_return_code_t he_conn_is_valid_server(he_ssl_ctx_t *ssl_ctx, he_conn_t *conn) {
  if(!conn) {
    return HE_ERR_NULL_POINTER;
  }

  if(!he_conn_is_outside_mtu_set(conn)) {
    return HE_ERR_CONF_MTU_NOT_SET;
  }

  if(conn->protocol_version.major_version != 0 &&
     !he_ssl_ctx_is_supported_version(ssl_ctx, conn->protocol_version.major_version,
                                      conn->protocol_version.minor_version)) {
    return HE_ERR_INCORRECT_PROTOCOL_VERSION;
  }

  return HE_SUCCESS;
}

he_conn_t *he_conn_create() {
  return he_internal_calloc(1, sizeof(he_conn_t));
}

void he_conn_destroy(he_conn_t *conn) {
  if(conn) {
    wolfSSL_free(conn->wolf_ssl);
    he_internal_free(conn);
  }
}

he_return_code_t he_internal_conn_configure(he_conn_t *conn, he_ssl_ctx_t *ctx) {
  // Return if conn is null
  if(!conn) {
    return HE_ERR_NULL_POINTER;
  }

  // Copy important values from the shared context object
  conn->disable_roaming_connections = ctx->disable_roaming_connections;
  conn->padding_type = ctx->padding_type;
  conn->use_aggressive_mode = ctx->use_aggressive_mode;
  conn->connection_type = ctx->connection_type;

  // Only copy if unset
  if(conn->protocol_version.major_version == 0) {
    conn->protocol_version.major_version = ctx->maximum_supported_version.major_version;
    conn->protocol_version.minor_version = ctx->maximum_supported_version.minor_version;
  }

  conn->state_change_cb = ctx->state_change_cb;
  conn->nudge_time_cb = ctx->nudge_time_cb;
  conn->inside_write_cb = ctx->inside_write_cb;
  conn->outside_write_cb = ctx->outside_write_cb;
  conn->network_config_ipv4_cb = ctx->network_config_ipv4_cb;
  conn->event_cb = ctx->event_cb;
  conn->auth_cb = ctx->auth_cb;
  conn->auth_buf_cb = ctx->auth_buf_cb;
  conn->populate_network_config_ipv4_cb = ctx->populate_network_config_ipv4_cb;

  // Copy the RNG to allow for generation of session IDs
  conn->wolf_rng = ctx->wolf_rng;

  return HE_SUCCESS;
}

static he_return_code_t he_conn_internal_connect(he_conn_t *conn, he_ssl_ctx_t *ctx,
                                                 he_plugin_chain_t *inside_plugins,
                                                 he_plugin_chain_t *outside_plugins) {
  int res = 0;  // Return value container

  if(conn == NULL || ctx == NULL) {
    return HE_ERR_NULL_POINTER;
  }

  res = he_internal_conn_configure(conn, ctx);

  conn->inside_plugins = inside_plugins;
  conn->outside_plugins = outside_plugins;

  if(res != HE_SUCCESS) {
    return res;
  }

  // Create connection
  if((conn->wolf_ssl = wolfSSL_new(ctx->wolf_ctx)) == NULL) {
    return HE_ERR_INIT_FAILED;
  }

  // Here we do the changes that are different for datagram and streaming

  if(ctx->connection_type == HE_CONNECTION_TYPE_DATAGRAM) {
    // Set to non-blocking mode -- streaming is always non-blocking
    wolfSSL_dtls_set_using_nonblock(conn->wolf_ssl, 1);

    // Set the MTU
    // TODO Can we change conn->mtu to be uint16_t?
    // No need to tell wolf to include space for its own headers
    res = wolfSSL_dtls_set_mtu(
        conn->wolf_ssl, (uint16_t)conn->outside_mtu - HE_PACKET_OVERHEAD + HE_WOLF_MAX_HEADER_SIZE);
    if(res != SSL_SUCCESS) {
      // MTU size is invalid
      return HE_ERR_INVALID_MTU_SIZE;
    }
  }

  // Below this point everything should be the same for D/TLS and TLS
  // Set a pointer to our conn context - needed so the read / write callbacks can find us
  wolfSSL_SetIOWriteCtx(conn->wolf_ssl, conn);
  wolfSSL_SetIOReadCtx(conn->wolf_ssl, conn);

  // If set, verify the server's DN
  if(he_ssl_ctx_is_server_dn_set(ctx)) {
    res = wolfSSL_check_domain_name(conn->wolf_ssl, ctx->server_dn);
    if(res != SSL_SUCCESS) {
      return HE_ERR_INIT_FAILED;
    }
  }

  // Change state to connecting
  he_internal_change_conn_state(conn, HE_STATE_CONNECTING);

  // Trigger a connection
  res = wolfSSL_negotiate(conn->wolf_ssl);

  // This will always "fail" as we're not using blocking sockets - it always needs more data
  // than it has.
  if(res != SSL_SUCCESS) {
    // Check error conditions
    int error = wolfSSL_get_error(conn->wolf_ssl, res);

    // We aren't hiding an error condition here and there's no point telling the host app
    // that we need more data - it will deliver it when it has any anyway. If that proves
    // to be insufficient, we can use HE_WANT_READ and HE_WANT_WRITE.
    switch(error) {
      case SSL_ERROR_WANT_READ:
        // Fall through as we want the same behaviour as WANT_WRITE
      case SSL_ERROR_WANT_WRITE:
        he_internal_change_conn_state(conn, HE_STATE_CONNECTING);
        // Update timer
        he_internal_update_timeout(conn);
        return HE_SUCCESS;
      default:
        return HE_ERR_CONNECT_FAILED;
    }
  } else {
    // Unlikely to happen in production, but theoretically could happen in testing
    he_internal_change_conn_state(conn, HE_STATE_LINK_UP);
    // Update timer
    he_internal_update_timeout(conn);
    return HE_SUCCESS;
  }
}

he_return_code_t he_conn_client_connect(he_conn_t *conn, he_ssl_ctx_t *ctx,
                                        he_plugin_chain_t *inside_plugins,
                                        he_plugin_chain_t *outside_plugins) {
  // Return if conn or ctx is null
  if(!conn || !ctx) {
    return HE_ERR_NULL_POINTER;
  }

  int res = he_conn_is_valid_client(ctx, conn);

  if(res != HE_SUCCESS) {
    return res;
  }

  res = he_conn_internal_connect(conn, ctx, inside_plugins, outside_plugins);

  if(conn) {
    conn->is_server = false;
  }

  return res;
}

he_return_code_t he_conn_server_connect(he_conn_t *conn, he_ssl_ctx_t *ctx,
                                        he_plugin_chain_t *inside_plugins,
                                        he_plugin_chain_t *outside_plugins) {
  // Return if conn or ctx is null
  if(!conn || !ctx) {
    return HE_ERR_NULL_POINTER;
  }

  int res = he_conn_is_valid_server(ctx, conn);

  res = he_conn_internal_connect(conn, ctx, inside_plugins, outside_plugins);

  // Even if we didn't get a success result we want to set this boolean correctly
  if(conn) {
    conn->is_server = true;
  }

  if(res != HE_SUCCESS) {
    return res;
  }

  // We generate a session ID regardless of whether we've disabled floating connections, we just
  // don't send it.
  uint64_t session_id = 0;
  res = he_internal_generate_session_id(conn, &session_id);

  if(res != HE_SUCCESS) {
    return res;
  }

  conn->session_id = session_id;

  return HE_SUCCESS;
}

he_return_code_t he_conn_disconnect(he_conn_t *conn) {
  // Return if conn is null
  if(!conn) {
    return HE_ERR_NULL_POINTER;
  }

  // Return not initialised if connect hasn't been called
  if(!conn->wolf_ssl) {
    return HE_ERR_NEVER_CONNECTED;
  }

  // Return error if in the wrong state
  if(conn->state == HE_STATE_DISCONNECTING || conn->state == HE_STATE_NONE ||
     conn->state == HE_STATE_CONNECTING || conn->state == HE_STATE_DISCONNECTED) {
    return HE_ERR_INVALID_CONN_STATE;
  }

  // Update state - we're disconnecting
  he_internal_change_conn_state(conn, HE_STATE_DISCONNECTING);

  he_internal_send_goodbye(conn);

  // Talk to the other end to shut down the D/TLS session
  // Note: We aren't checking the return code as we're going to destroy
  //       this instance anyway - we call shutdown as a courtesy
  wolfSSL_shutdown(conn->wolf_ssl);

  // Disable read and write callbacks
  conn->inside_write_cb = NULL;
  conn->outside_write_cb = NULL;
  conn->wolf_timeout = 0;

  // Change to disconnected state
  he_internal_change_conn_state(conn, HE_STATE_DISCONNECTED);

  // This will always be successful
  return HE_SUCCESS;
}

void he_internal_change_conn_state(he_conn_t *conn, he_conn_state_t state) {
  // Return if conn is null
  if(!conn) {
    return;
  }

  // NOOP if we're already in that state
  if(conn->state == state) {
    return;
  }
  // Update status
  conn->state = state;
  // Trigger the state callback if set

  if(conn->state_change_cb) {
    conn->state_change_cb(conn, conn->state, conn->data);
  }

  // Handle anything specific to a given state change
  switch(state) {
    case HE_STATE_LINK_UP:
      // If we are a conn we need to send auth
      if(!conn->is_server) {
        he_internal_send_auth(conn);
      }
      break;
    default:
      // Nothing to do in the default case
      break;
  }
}

he_return_code_t he_internal_send_message(he_conn_t *conn, uint8_t *message, uint16_t length) {
  // Return if conn is null
  if(!conn) {
    return HE_ERR_NULL_POINTER;
  }

  // For now - this will just do a simple write and assume it works
  int res = wolfSSL_write(conn->wolf_ssl, message, (int)length);

  if(res <= 0) {
    int error = wolfSSL_get_error(conn->wolf_ssl, res);
    switch(error) {
      case SSL_ERROR_NONE:
        // Previous API appeared to return an error code but no error actually occurred
        return HE_SUCCESS;
      case SSL_ERROR_WANT_WRITE:
        // The underlying I/O is non-blocking and it could not satisfy the needs of wolfSSL_write to
        // continue.
        return HE_WANT_WRITE;
      case SSL_ERROR_WANT_READ:
        // The underlying I/O is non-blocking and it could not satisfy the needs of wolfSSL_write to
        // continue.
        return HE_WANT_READ;
      default:
        return (res == 0) ? HE_ERR_CONNECTION_WAS_CLOSED : HE_ERR_SSL_ERROR;
    }
  }

  return HE_SUCCESS;
}

he_return_code_t he_internal_send_goodbye(he_conn_t *conn) {
  // Return if conn is null
  if(!conn) {
    return HE_ERR_NULL_POINTER;
  }

  // Create our goodbye message
  he_msg_goodbye_t goodbye = {0};
  // Set message type
  goodbye.msg_header.msgid = HE_MSGID_GOODBYE;

  // Send the message - we don't actually care if it got sent or not
  he_internal_send_message(conn, (uint8_t *)&goodbye, sizeof(goodbye));

  // Assume success
  return HE_SUCCESS;
}

he_return_code_t he_conn_send_keepalive(he_conn_t *conn) {
  // Return if conn is null
  if(!conn) {
    return HE_ERR_NULL_POINTER;
  }

  if(conn->state != HE_STATE_ONLINE) {
    return HE_ERR_INVALID_CONN_STATE;
  }

  // Craft a PING message
  he_msg_ping_t ping = {0};
  ping.msg_header.msgid = HE_MSGID_PING;

  // Send it
  return he_internal_send_message(conn, (uint8_t *)&ping, sizeof(he_msg_ping_t));
}

static he_return_code_t he_internal_send_auth_userpass(he_conn_t *conn) {
  // Return if conn is null
  if(!conn) {
    return HE_ERR_NULL_POINTER;
  }

  // Allocate some space for the authentication message
  he_msg_auth_t auth = {0};

  // Set message type
  auth.header.msg_header.msgid = HE_MSGID_AUTH;
  // Set user pass auth
  auth.header.auth_type = HE_AUTH_TYPE_USERPASS;

  // Get and set the cred lengths
  auth.username_length = (uint8_t)strnlen(conn->username, sizeof(conn->username) - 1);
  auth.password_length = (uint8_t)strnlen(conn->password, sizeof(conn->password) - 1);

  // Copy the creds into the message
  memcpy(&auth.username, conn->username, auth.username_length);
  memcpy(&auth.password, conn->password, auth.password_length);

  // Send the authentication request with the padded buffer
  return he_internal_send_message(conn, (uint8_t *)&auth, sizeof(he_msg_auth_t));
}

static he_return_code_t he_internal_send_auth_buf(he_conn_t *conn) {
  // Return if conn is null
  if(!conn) {
    return HE_ERR_NULL_POINTER;
  }

  // Allocate some space for the authentication message -- we just set it to max MTU
  uint8_t auth_buf[HE_MAX_MTU] = {0};

  // Not worried about overflow here since we check auth_buffer_length elsewhere
  uint16_t msg_size = sizeof(he_msg_auth_buf_t) + conn->auth_buffer_length;

  // This should be impossible but we check anyway -- belt-and-braces in C
  if(msg_size > sizeof(auth_buf)) {
    return HE_ERR_INVALID_CONN_STATE;
  }

  he_msg_auth_buf_t *auth = (he_msg_auth_buf_t *)auth_buf;

  auth->header.msg_header.msgid = HE_MSGID_AUTH;
  auth->header.auth_type = conn->auth_type;
  auth->buffer_length = htons(conn->auth_buffer_length);
  memcpy(auth->buffer, conn->auth_buffer, conn->auth_buffer_length);

  return he_internal_send_message(conn, auth_buf, msg_size);
}

he_return_code_t he_internal_send_auth(he_conn_t *conn) {
  // Return if conn is null
  if(!conn) {
    return HE_ERR_NULL_POINTER;
  }

  // Check we're in the right state
  if(conn->state != HE_STATE_LINK_UP && conn->state != HE_STATE_AUTHENTICATING) {
    return HE_ERR_INVALID_CONN_STATE;
  }

  // Change state to authenticating
  he_internal_change_conn_state(conn, HE_STATE_AUTHENTICATING);

  switch(conn->auth_type) {
    case HE_AUTH_TYPE_USERPASS:
      return he_internal_send_auth_userpass(conn);
    case HE_AUTH_TYPE_CB:
      return he_internal_send_auth_buf(conn);
    default:
      return HE_ERR_INVALID_AUTH_TYPE;
  }
}

he_return_code_t he_conn_schedule_renegotiation(he_conn_t *conn) {
  // Return if conn is null
  if(!conn) {
    return HE_ERR_NULL_POINTER;
  }

  conn->renegotiation_due = true;
  return HE_SUCCESS;
}

he_return_code_t he_internal_renegotiate_ssl(he_conn_t *conn) {
  // Return if conn is null
  if(!conn) {
    return HE_ERR_NULL_POINTER;
  }

  conn->renegotiation_due = false;
  if(conn->renegotiation_in_progress || conn->state != HE_STATE_ONLINE) {
    // If we already have a negotiation in flight, no need to start a new one.
    // If we haven't completed the initial handshake and authorisation process,
    // also no need to start a renegotiation here.
    return HE_SUCCESS;
  }

  int wolf_res = -1;

  // Not all conns support D/TLS negotiation but all TCP conns support rekeying
  if(wolfSSL_SSL_get_secure_renegotiation_support(conn->wolf_ssl)) {
    wolf_res = wolfSSL_Rehandshake(conn->wolf_ssl);
    conn->renegotiation_in_progress = true;
    he_internal_generate_event(conn, HE_EVENT_SECURE_RENEGOTIATION_STARTED);
  } else if(conn->connection_type == HE_CONNECTION_TYPE_STREAM) {
    wolf_res = wolfSSL_update_keys(conn->wolf_ssl);
  } else {
    // No renegotiation support, this is fine
    return HE_SUCCESS;
  }

  if(wolf_res != SSL_SUCCESS) {
    int error = wolfSSL_get_error(conn->wolf_ssl, wolf_res);

    switch(error) {
      case SSL_ERROR_WANT_READ:
      case SSL_ERROR_WANT_WRITE:
      case APP_DATA_READY:
        // All expected, just keep on trucking
        he_internal_update_timeout(conn);
        return HE_SUCCESS;
      default:
        return HE_ERR_SSL_ERROR;
    }
  }

  // Will never happen in production but could happen in testing
  return HE_SUCCESS;
}

void he_internal_update_timeout(he_conn_t *conn) {
  // This is only necessary for the initial D/TLS handshake and when we are in the middle of a
  // renegotiation, so we stop updating the timeout once Helium is connected and no renegotiation
  // is ongoing

  // Return if conn is null
  if(!conn) {
    return;
  }

  if(conn->state == HE_STATE_ONLINE && !conn->renegotiation_in_progress) {
    return;
  }

  // Update status
  conn->wolf_timeout = wolfSSL_dtls_get_current_timeout(conn->wolf_ssl);

  // Scale the timeout value
  if(conn->renegotiation_in_progress) {
    conn->wolf_timeout *= HE_WOLF_RENEGOTIATION_TIMEOUT_MULTIPLIER;
  } else {
    conn->wolf_timeout *= HE_WOLF_TIMEOUT_MULTIPLIER;
  }

  // Trigger the timeout callback if set and if a timer isn't already running
  // This prevents runaway timers that never have the chance to complete
  if(conn->nudge_time_cb && !conn->is_nudge_timer_running) {
    conn->nudge_time_cb(conn, conn->wolf_timeout, conn->data);
    conn->is_nudge_timer_running = true;
  }
}

int he_conn_get_nudge_time(he_conn_t *conn) {
  // Return if conn is null
  if(!conn) {
    return 0;
  }

  if(conn->state == HE_STATE_ONLINE && !conn->renegotiation_in_progress) {
    return 0;
  }
  return conn->wolf_timeout;
}

he_return_code_t he_conn_nudge(he_conn_t *conn) {
  // Return if conn is null
  if(!conn) {
    return HE_ERR_NULL_POINTER;
  }

  // We've been nudged so there is no timer running
  conn->is_nudge_timer_running = false;

  // If we are in HE_STATE_AUTHENTICATING then we need to resend our AUTH request
  if(conn->state == HE_STATE_AUTHENTICATING) {
    // Re-send auth request (this is idempotent)
    HE_DISPATCH(he_internal_send_auth, conn);
  } else {
    // Nudge Wolf
    int res = wolfSSL_dtls_got_timeout(conn->wolf_ssl);

    if(res != SSL_SUCCESS) {
      // Connection has failed
      int error = wolfSSL_get_error(conn->wolf_ssl, res);

      switch(error) {
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
          break;
        // Note that in this state we are treating APP_DATA_READY as error, because
        // something is very strange if we end up with that message here
        default:
          he_internal_change_conn_state(conn, HE_STATE_DISCONNECTED);
          return HE_CONNECTION_TIMED_OUT;
      }
    }
  }

  // Update the timeout counter and handle callback if needed
  he_internal_update_timeout(conn);

  return HE_SUCCESS;
}

he_conn_state_t he_conn_get_state(he_conn_t *conn) {
  // Return if conn is null
  if(!conn) {
    return HE_STATE_NONE;
  }

  return conn->state;
}

void he_internal_generate_event(he_conn_t *conn, he_conn_event_t event) {
  // Return if conn is null
  if(!conn) {
    return;
  }

  // Trigger event callback if set
  if(conn->event_cb) {
    conn->event_cb(conn, event, conn->data);
  }
}

he_return_code_t he_internal_generate_session_id(he_conn_t *conn, uint64_t *session_id_out) {
  // Return if conn is null
  if(!conn) {
    return HE_ERR_NULL_POINTER;
  }

  // We have the "real" structure instead of a pointer, so no null check, we depend on
  // wolf to error if the RNG hasn't been initialised before we call this function
  int res = wc_RNG_GenerateBlock(&conn->wolf_rng, (byte *)session_id_out, sizeof(uint64_t));
  if(res != 0) {
    return HE_ERR_RNG_FAILURE;
  }
  return HE_SUCCESS;
}

he_return_code_t he_conn_rotate_session_id(he_conn_t *conn, uint64_t *new_session_id_out) {
  if(!conn) {
    return HE_ERR_NULL_POINTER;
  }

  if(!conn->is_server || conn->pending_session_id != 0) {
    return HE_ERR_INVALID_CONN_STATE;
  }

  uint64_t new_session_id = 0;

  he_return_code_t res = he_internal_generate_session_id(conn, &new_session_id);

  if(res != HE_SUCCESS) {
    return res;
  }

  conn->pending_session_id = new_session_id;

  if(new_session_id_out != NULL) {
    *new_session_id_out = new_session_id;
  }

  return HE_SUCCESS;
}

bool he_conn_supports_renegotiation(he_conn_t *conn) {
  if(conn == NULL) {
    return false;
  }

  return wolfSSL_SSL_get_secure_renegotiation_support(conn->wolf_ssl);
}

he_return_code_t he_conn_set_protocol_version(he_conn_t *conn, uint8_t major_version,
                                              uint8_t minor_version) {
  if(conn == NULL) {
    return HE_ERR_NULL_POINTER;
  }

  conn->protocol_version.major_version = major_version;
  conn->protocol_version.minor_version = minor_version;
  return HE_SUCCESS;
}

// Getters and setters

int he_conn_set_username(he_conn_t *conn, const char *username) {
  // Return if conn is null
  if(!conn || !username) {
    return HE_ERR_NULL_POINTER;
  }

  conn->auth_type = HE_AUTH_TYPE_USERPASS;
  return he_internal_set_config_string(conn->username, username);
}

const char *he_conn_get_username(const he_conn_t *conn) {
  // Return if conn is null
  if(!conn) {
    return NULL;
  }

  return (const char *)conn->username;
}

bool he_conn_is_username_set(const he_conn_t *conn) {
  // Return if conn is null
  if(!conn) {
    return false;
  }

  return !he_internal_config_is_empty_string(conn->username);
}

he_return_code_t he_conn_set_password(he_conn_t *conn, const char *password) {
  // Return if conn is null
  if(!conn || !password) {
    return HE_ERR_NULL_POINTER;
  }

  conn->auth_type = HE_AUTH_TYPE_USERPASS;
  return he_internal_set_config_string(conn->password, password);
}

bool he_conn_is_password_set(const he_conn_t *conn) {
  // Return if conn is null
  if(!conn) {
    return false;
  }

  return !he_internal_config_is_empty_string(conn->password);
}

he_return_code_t he_conn_set_auth_buffer(he_conn_t *conn, uint8_t auth_type, const uint8_t *buffer,
                                         uint16_t length) {
  return he_conn_set_auth_buffer2(conn, buffer, length);
}

he_return_code_t he_conn_set_auth_buffer2(he_conn_t *conn, const uint8_t *buffer, uint16_t length) {
  if(conn == NULL || buffer == NULL) {
    return HE_ERR_NULL_POINTER;
  }

  if(length == 0) {
    return HE_ERR_EMPTY_STRING;
  }

  if(length > HE_MAX_MTU - sizeof(he_msg_auth_buf_t)) {
    return HE_ERR_STRING_TOO_LONG;
  }

  conn->auth_type = HE_AUTH_TYPE_CB;
  memcpy(conn->auth_buffer, buffer, length);
  conn->auth_buffer_length = length;

  return HE_SUCCESS;
}

bool he_conn_is_auth_buffer_set(const he_conn_t *conn) {
  // Return if conn is null
  if(!conn) {
    return false;
  }

  return conn->auth_buffer_length != 0;
}

int he_conn_set_outside_mtu(he_conn_t *conn, int mtu) {
  // Return if conn is null
  if(!conn) {
    return HE_ERR_NULL_POINTER;
  }

  // Set the MTU
  he_internal_set_config_int(&conn->outside_mtu, mtu);

  return HE_SUCCESS;
}

int he_conn_get_outside_mtu(he_conn_t *conn) {
  // Return if conn is null
  if(!conn) {
    return 0;
  }

  return conn->outside_mtu;
}

bool he_conn_is_outside_mtu_set(he_conn_t *conn) {
  // Return if conn is null
  if(!conn) {
    return false;
  }

  if(conn->outside_mtu) {
    return true;
  }

  return false;
}

size_t he_internal_calculate_data_packet_length(he_conn_t *conn, size_t length) {
  // Return if conn is null
  if(!conn) {
    return 0;
  }

  // Is padding enabled? If not return the length provided
  if(conn->padding_type == HE_PADDING_NONE) {
    return length;
  }

  // Is full padding enabled IPSEC style?
  if(conn->padding_type == HE_PADDING_FULL) {
    return HE_MAX_MTU;
  }

  // Pad data packets at boundaries to obfuscate true length
  // but also don't fill the entire packet to save bandwidth
  if(length <= 450) {
    // ~67% of packets were below 319 bytes
    return 450;
  } else if(length <= 900) {
    // ~8% of packets were in the middle
    return 900;
  } else {
    // ~25% of packets were above 1280
    return HE_MAX_MTU;
  }
}

he_return_code_t he_conn_set_context(he_conn_t *conn, void *data) {
  // Return if conn is null
  if(!conn || !data) {
    return HE_ERR_NULL_POINTER;
  }

  // Store the context pointer
  conn->data = data;
  return HE_SUCCESS;
}

void *he_conn_get_context(he_conn_t *conn) {
  // Return if conn is null
  if(!conn) {
    return NULL;
  }

  return conn->data;
}

uint64_t he_conn_get_session_id(he_conn_t *conn) {
  // Return if conn is null
  if(!conn) {
    return 0;
  }

  return conn->session_id;
}

uint64_t he_conn_get_pending_session_id(he_conn_t *conn) {
  // Return if conn is null
  if(!conn) {
    return 0;
  }

  return conn->pending_session_id;
}

he_return_code_t he_conn_set_session_id(he_conn_t *conn, uint64_t session_id) {
  if(conn == NULL) {
    return HE_ERR_NULL_POINTER;
  }

  if(conn->session_id != 0) {
    return HE_ERR_INVALID_CONN_STATE;
  }

  conn->session_id = session_id;
  return HE_SUCCESS;
}
