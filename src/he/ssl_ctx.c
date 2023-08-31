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

#include "ssl_ctx.h"
#include "config.h"

#ifndef WOLFSSL_USER_SETTINGS
#include <wolfssl/options.h>
#endif
#include <wolfssl/error-ssl.h>
#include <wolfssl/ssl.h>

#include "wolf.h"

#include "memory.h"

he_return_code_t he_init() {
  // Initialise WolfSSL
  int res = wolfSSL_Init();

  if(res != SSL_SUCCESS) {
    return HE_ERR_INIT_FAILED;
  }

  return HE_SUCCESS;
}

he_return_code_t he_cleanup() {
  // Clean up WolfSSL
  int res = wolfSSL_Cleanup();

  if(res != SSL_SUCCESS) {
    return HE_ERR_CLEANUP_FAILED;
  }

  return HE_SUCCESS;
}

static he_return_code_t he_ssl_ctx_is_valid_common(he_ssl_ctx_t *ctx) {
  if(!ctx) {
    return HE_ERR_NULL_POINTER;
  }

  if(!he_ssl_ctx_is_outside_write_cb_set(ctx)) {
    return HE_ERR_CONF_OUTSIDE_WRITE_CB_NOT_SET;
  }

  return HE_SUCCESS;
}

he_return_code_t he_ssl_ctx_is_valid_client(he_ssl_ctx_t *ctx) {
  // Return if ctx is null
  if(!ctx) {
    return HE_ERR_NULL_POINTER;
  }

  int res = he_ssl_ctx_is_valid_common(ctx);

  if(res != HE_SUCCESS) {
    return res;
  }

  if(!he_ssl_ctx_is_ca_set(ctx)) {
    return HE_ERR_CONF_CA_NOT_SET;
  }

  // All okay
  return HE_SUCCESS;
}

he_return_code_t he_ssl_ctx_is_valid_server(he_ssl_ctx_t *ctx) {
  // Return if ctx is null
  if(!ctx) {
    return HE_ERR_NULL_POINTER;
  }

  int res = he_ssl_ctx_is_valid_common(ctx);

  if(res != HE_SUCCESS) {
    return res;
  }

  if(!he_ssl_ctx_is_server_cert_key_set(ctx)) {
    return HE_ERR_CONF_CA_NOT_SET;
  }

  if(!he_ssl_ctx_is_auth_cb_set(ctx)) {
    return HE_ERR_CONF_AUTH_CB_NOT_SET;
  }

  // All okay
  return HE_SUCCESS;
}

he_ssl_ctx_t *he_ssl_ctx_create() {
  return he_calloc(1, sizeof(he_ssl_ctx_t));
}

void he_ssl_ctx_destroy(he_ssl_ctx_t *ctx) {
  if(ctx) {
    wolfSSL_CTX_free(ctx->wolf_ctx);
    he_free(ctx);
  }
}

static he_return_code_t he_ssl_ctx_start_common(he_ssl_ctx_t *ctx) {
  // Return if ctx is null
  if(!ctx) {
    return HE_ERR_NULL_POINTER;
  }

  // Set supported protocol versions
  ctx->minimum_supported_version.major_version = HE_WIRE_MINIMUM_PROTOCOL_MAJOR_VERSION;
  ctx->minimum_supported_version.minor_version = HE_WIRE_MINIMUM_PROTOCOL_MINOR_VERSION;
  ctx->maximum_supported_version.major_version = HE_WIRE_MAXIMUM_PROTOCOL_MAJOR_VERSION;
  ctx->maximum_supported_version.minor_version = HE_WIRE_MAXIMUM_PROTOCOL_MINOR_VERSION;

  // Add custom IO callbacks
  if(ctx->connection_type == HE_CONNECTION_TYPE_STREAM) {
    wolfSSL_CTX_SetIORecv(ctx->wolf_ctx, he_wolf_tls_read);
    wolfSSL_CTX_SetIOSend(ctx->wolf_ctx, he_wolf_tls_write);
  } else {
    wolfSSL_CTX_SetIORecv(ctx->wolf_ctx, he_wolf_dtls_read);
    wolfSSL_CTX_SetIOSend(ctx->wolf_ctx, he_wolf_dtls_write);
  }

  // Enable secure renegotiation
  if(ctx->connection_type == HE_CONNECTION_TYPE_DATAGRAM &&
     wolfSSL_CTX_UseSecureRenegotiation(ctx->wolf_ctx) != WOLFSSL_SUCCESS) {
    return HE_ERR_INIT_FAILED;
  }

  return HE_SUCCESS;
}

he_return_code_t he_ssl_ctx_start(he_ssl_ctx_t *ctx) {
  // Return if ctx is null
  if(!ctx) {
    return HE_ERR_NULL_POINTER;
  }

  // Return holder
  int res = 0;

  res = he_ssl_ctx_is_valid_client(ctx);

  if(res != HE_SUCCESS) {
    return res;
  }

  // First we do the ctx->wolf_ctx setup
  if(ctx->connection_type == HE_CONNECTION_TYPE_STREAM) {
    // Create Wolf context using the TLS protocol v1.3
    ctx->wolf_ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
  } else if(ctx->connection_type == HE_CONNECTION_TYPE_DATAGRAM) {
    // Create Wolf context using the highest D/TLS protocol built in (1.3)
    ctx->wolf_ctx = wolfSSL_CTX_new(wolfDTLS_client_method());
  }  // No need for an else clause, we will fail on the next line.

  if(ctx->wolf_ctx == NULL) {
    return HE_ERR_INIT_FAILED;
  }

  // Everything below this point for the ctx->wolf_ctx is the same regardless of connection
  // type

  // Load cert chain
  res = wolfSSL_CTX_load_verify_buffer(ctx->wolf_ctx, ctx->cert_buffer, ctx->cert_buffer_size,
                                       SSL_FILETYPE_PEM);

  if(res != SSL_SUCCESS) {
    switch(res) {
      case SSL_BAD_FILETYPE:
        return HE_ERR_SSL_BAD_FILETYPE;
      case SSL_BAD_FILE:
        return HE_ERR_SSL_BAD_FILE;
      case MEMORY_E:
        return HE_ERR_SSL_OUT_OF_MEMORY;
      case ASN_INPUT_E:
        return HE_ERR_SSL_ASN_INPUT;
      case BUFFER_E:
        return HE_ERR_SSL_BUFFER;
      default:
        return HE_ERR_SSL_CERT;
    }
  }

  // Explicitly set the cipher list
  if(ctx->connection_type == HE_CONNECTION_TYPE_STREAM) {
    if(ctx->use_chacha) {
      res = wolfSSL_CTX_set_cipher_list(ctx->wolf_ctx, "TLS13-CHACHA20-POLY1305-SHA256");
    } else {
      res = wolfSSL_CTX_set_cipher_list(ctx->wolf_ctx, "TLS13-AES256-GCM-SHA384");
    }
  } else {
    res = wolfSSL_CTX_SetMinVersion(ctx->wolf_ctx, WOLFSSL_DTLSV1_2);
    // Fail if the minimum version can't be set
    if(res != SSL_SUCCESS) {
      return HE_ERR_INIT_FAILED;
    }

    if(ctx->use_chacha) {
      res = wolfSSL_CTX_set_cipher_list(
          ctx->wolf_ctx, "TLS13-CHACHA20-POLY1305-SHA256:ECDHE-RSA-CHACHA20-POLY1305");
    } else {
      res = wolfSSL_CTX_set_cipher_list(ctx->wolf_ctx,
                                        "TLS13-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384");
    }
  }

  // Fail if the ciphers can't be set
  if(res != SSL_SUCCESS) {
    return HE_ERR_INIT_FAILED;
  }

  return he_ssl_ctx_start_common(ctx);
}

he_return_code_t he_ssl_ctx_start_server(he_ssl_ctx_t *ctx) {
  // Return if ctx is null
  if(!ctx) {
    return HE_ERR_NULL_POINTER;
  }

  int res = he_ssl_ctx_is_valid_server(ctx);
  if(res != HE_SUCCESS) {
    return res;
  }

  // First we do the ctx->wolf_ctx setup
  if(ctx->connection_type == HE_CONNECTION_TYPE_STREAM) {
    // Create Wolf context using the TLS protocol v1.3
    ctx->wolf_ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
  } else if(ctx->connection_type == HE_CONNECTION_TYPE_DATAGRAM) {
    // Create Wolf context using the highest D/TLS protocol built in (1.3)
    ctx->wolf_ctx = wolfSSL_CTX_new(wolfDTLS_server_method());
  }  // No need for an else clause, we will fail on the next line.

  if(ctx->wolf_ctx == NULL) {
    return HE_ERR_INIT_FAILED;
  }

  // Load server certs into ctx
  if(wolfSSL_CTX_use_certificate_file(ctx->wolf_ctx, ctx->server_cert, SSL_FILETYPE_PEM) !=
     SSL_SUCCESS) {
    return HE_ERR_INIT_FAILED;
  }

  // Load server key into ctx
  if(wolfSSL_CTX_use_PrivateKey_file(ctx->wolf_ctx, ctx->server_key, SSL_FILETYPE_PEM) !=
     SSL_SUCCESS) {
    return HE_ERR_INIT_FAILED;
  }

  // Initialise Wolf's RNG
  if(wc_InitRng(&ctx->wolf_rng) != 0) {
    return HE_ERR_INIT_FAILED;
  }

  // Explicitly set the cipher list
  if(ctx->connection_type == HE_CONNECTION_TYPE_STREAM) {
    res = wolfSSL_CTX_set_cipher_list(ctx->wolf_ctx,
                                      "TLS13-AES256-GCM-SHA384:TLS13-CHACHA20-POLY1305-SHA256");
  } else {
    res = wolfSSL_CTX_set_cipher_list(ctx->wolf_ctx,
                                      "TLS13-CHACHA20-POLY1305-SHA256:ECDHE-RSA-CHACHA20-POLY1305"
                                      ":TLS13-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384");
  }

  // Fail if the ciphers can't be set
  if(res != SSL_SUCCESS) {
    return HE_ERR_INIT_FAILED;
  }

  return he_ssl_ctx_start_common(ctx);
}

he_return_code_t he_ssl_ctx_stop(he_ssl_ctx_t *context) {
  // Currently a no-op, provided in case we ever need something
  return HE_SUCCESS;
}

static bool he_is_valid_wire_protocol_version(uint8_t major_version, uint8_t minor_version) {
  if(major_version < HE_WIRE_MINIMUM_PROTOCOL_MAJOR_VERSION ||
     (major_version == HE_WIRE_MINIMUM_PROTOCOL_MAJOR_VERSION &&
      minor_version < HE_WIRE_MINIMUM_PROTOCOL_MINOR_VERSION) ||
     major_version > HE_WIRE_MAXIMUM_PROTOCOL_MAJOR_VERSION ||
     (major_version == HE_WIRE_MAXIMUM_PROTOCOL_MAJOR_VERSION &&
      minor_version > HE_WIRE_MAXIMUM_PROTOCOL_MINOR_VERSION)) {
    return false;
  }
  return true;
}

he_return_code_t he_ssl_ctx_set_minimum_supported_version(he_ssl_ctx_t *context,
                                                          uint8_t major_version,
                                                          uint8_t minor_version) {
  if(!context) {
    return HE_ERR_NULL_POINTER;
  }

  // Use default value if both the major and minor versions are 0
  if(major_version == 0 && minor_version == 0) {
    major_version = HE_WIRE_MINIMUM_PROTOCOL_MAJOR_VERSION;
    minor_version = HE_WIRE_MINIMUM_PROTOCOL_MINOR_VERSION;
  }

  // Validate the new version
  if(!he_is_valid_wire_protocol_version(major_version, minor_version)) {
    return HE_ERR_INCORRECT_PROTOCOL_VERSION;
  }

  // Set the minimum_supported_version
  context->minimum_supported_version.major_version = major_version;
  context->minimum_supported_version.minor_version = minor_version;
  return HE_SUCCESS;
}

he_return_code_t he_ssl_ctx_set_maximum_supported_version(he_ssl_ctx_t *context,
                                                          uint8_t major_version,
                                                          uint8_t minor_version) {
  if(!context) {
    return HE_ERR_NULL_POINTER;
  }

  // Use default value if both the major and minor versions are 0
  if(major_version == 0 && minor_version == 0) {
    major_version = HE_WIRE_MAXIMUM_PROTOCOL_MAJOR_VERSION;
    minor_version = HE_WIRE_MAXIMUM_PROTOCOL_MINOR_VERSION;
  }

  // Validate the new version
  if(!he_is_valid_wire_protocol_version(major_version, minor_version)) {
    return HE_ERR_INCORRECT_PROTOCOL_VERSION;
  }

  // Set the maximum_supported_version
  context->maximum_supported_version.major_version = major_version;
  context->maximum_supported_version.minor_version = minor_version;
  return HE_SUCCESS;
}

bool he_ssl_ctx_is_supported_version(he_ssl_ctx_t *context, uint8_t major_version,
                                     uint8_t minor_version) {
  // Return if ctx is null
  if(!context) {
    return false;
  }

  // It's certainly possible to write this as one big boolean, but this version is quite readable
  if(major_version < context->minimum_supported_version.major_version ||
     major_version > context->maximum_supported_version.major_version) {
    return false;
  }

  // If we reach this point we know that major_version is between the supported values.
  // Now we check to make sure that if the provided major_version matches the minimum
  // or maximum we check the minor version.

  // If the major version is between the minimum and maximum without equaling either
  // the minor version is irrelevant, 3.x is between 2.0 and 4.0 regardless of what `x` equals.

  if(major_version == context->minimum_supported_version.major_version &&
     minor_version < context->minimum_supported_version.minor_version) {
    return false;
  }

  if(major_version == context->maximum_supported_version.major_version &&
     minor_version > context->maximum_supported_version.minor_version) {
    return false;
  }

  return true;
}

bool he_ssl_ctx_is_latest_version(he_ssl_ctx_t *context, uint8_t major_version,
                                  uint8_t minor_version) {
  // Return if ctx is null
  if(!context) {
    return false;
  }

  return (major_version == context->maximum_supported_version.major_version &&
          minor_version == context->maximum_supported_version.minor_version);
}
// Getters and setters below this point

he_return_code_t he_ssl_ctx_set_server_dn(he_ssl_ctx_t *ctx, const char *distinguished_name) {
  // Return if ctx is null
  if(!ctx) {
    return HE_ERR_NULL_POINTER;
  }

  return he_internal_set_config_string(ctx->server_dn, distinguished_name);
}

const char *he_ssl_ctx_get_server_dn(he_ssl_ctx_t *ctx) {
  // Return if ctx is null
  if(!ctx) {
    return NULL;
  }

  return (const char *)ctx->server_dn;
}

bool he_ssl_ctx_is_server_dn_set(he_ssl_ctx_t *ctx) {
  // Return if ctx is null
  if(!ctx) {
    return false;
  }

  return !he_internal_config_is_empty_string(ctx->server_dn);
}

he_return_code_t he_ssl_ctx_set_use_chacha20(he_ssl_ctx_t *ctx, bool use) {
  // Return if ctx is null
  if(!ctx) {
    return HE_ERR_NULL_POINTER;
  }

  ctx->use_chacha = use;
  return HE_SUCCESS;
}

bool he_ssl_ctx_get_use_chacha20(he_ssl_ctx_t *ctx) {
  // Return if ctx is null
  if(!ctx) {
    return false;
  }

  return ctx->use_chacha;
}

he_return_code_t he_ssl_ctx_set_ca(he_ssl_ctx_t *ctx, uint8_t *cert_buffer, size_t length) {
  // Return if ctx is null
  if(!ctx) {
    return HE_ERR_NULL_POINTER;
  }

  // Check for NULL pointer
  if(!cert_buffer) {
    return HE_ERR_NULL_POINTER;
  }

  // Check size is set
  if(!length) {
    return HE_ERR_ZERO_SIZE;
  }

  // Assign pointer
  ctx->cert_buffer = cert_buffer;

  // Set size
  ctx->cert_buffer_size = length;

  return HE_SUCCESS;
}

bool he_ssl_ctx_is_ca_set(he_ssl_ctx_t *ctx) {
  // Return if ctx is null
  if(!ctx) {
    return false;
  }

  return ctx->cert_buffer;
}

he_return_code_t he_ssl_ctx_set_server_cert_key_files(he_ssl_ctx_t *ctx, const char *server_cert,
                                                      const char *server_key) {
  // Return if ctx is null
  if(!ctx) {
    return HE_ERR_NULL_POINTER;
  }

  if(server_cert == NULL || server_key == NULL) {
    return HE_ERR_NULL_POINTER;
  }

  ctx->server_cert = server_cert;
  ctx->server_key = server_key;

  return HE_SUCCESS;
}

bool he_ssl_ctx_is_server_cert_key_set(he_ssl_ctx_t *ctx) {
  // Return if ctx is null
  if(!ctx) {
    return HE_ERR_NULL_POINTER;
  }

  return ctx->server_cert != NULL && ctx->server_key != NULL;
}

he_return_code_t he_ssl_ctx_set_connection_type(he_ssl_ctx_t *ctx,
                                                he_connection_type_t connection_type) {
  // Return if ctx is null
  if(!ctx) {
    return HE_ERR_NULL_POINTER;
  }

  if(connection_type != HE_CONNECTION_TYPE_STREAM &&
     connection_type != HE_CONNECTION_TYPE_DATAGRAM) {
    return HE_ERR_INVALID_CONNECTION_TYPE;
  }
  ctx->connection_type = connection_type;
  return HE_SUCCESS;
}

void he_ssl_ctx_set_state_change_cb(he_ssl_ctx_t *ctx, he_state_change_cb_t state_change_cb) {
  // Return if ctx is null
  if(!ctx) {
    return;
  }

  ctx->state_change_cb = state_change_cb;
}

bool he_ssl_ctx_is_state_change_cb_set(he_ssl_ctx_t *ctx) {
  if(!ctx) {
    return false;
  }
  return ctx->state_change_cb;
}

void he_ssl_ctx_set_inside_write_cb(he_ssl_ctx_t *ctx, he_inside_write_cb_t inside_write_cb) {
  // Return if ctx is null
  if(!ctx) {
    return;
  }

  ctx->inside_write_cb = inside_write_cb;
}

bool he_ssl_ctx_is_inside_write_cb_set(he_ssl_ctx_t *ctx) {
  if(!ctx) {
    return false;
  }
  return ctx->inside_write_cb;
}

void he_ssl_ctx_set_outside_write_cb(he_ssl_ctx_t *ctx, he_outside_write_cb_t outside_write_cb) {
  // Return if ctx is null
  if(!ctx) {
    return;
  }

  ctx->outside_write_cb = outside_write_cb;
}

bool he_ssl_ctx_is_outside_write_cb_set(he_ssl_ctx_t *ctx) {
  if(!ctx) {
    return false;
  }
  return ctx->outside_write_cb;
}

void he_ssl_ctx_set_network_config_ipv4_cb(he_ssl_ctx_t *ctx,
                                           he_network_config_ipv4_cb_t network_config_ipv4_cb) {
  // Return if ctx is null
  if(!ctx) {
    return;
  }

  ctx->network_config_ipv4_cb = network_config_ipv4_cb;
}

void he_ssl_ctx_set_server_config_cb(he_ssl_ctx_t *ctx, he_server_config_cb_t server_config_cb) {
  // Return if ctx is null
  if(!ctx) {
    return;
  }

  ctx->server_config_cb = server_config_cb;
}

bool he_ssl_ctx_is_network_config_ipv4_cb_set(he_ssl_ctx_t *ctx) {
  if(!ctx) {
    return false;
  }
  return ctx->network_config_ipv4_cb;
}

void he_ssl_ctx_set_nudge_time_cb(he_ssl_ctx_t *ctx, he_nudge_time_cb_t nudge_time_cb) {
  // Return if ctx is null
  if(!ctx) {
    return;
  }

  ctx->nudge_time_cb = nudge_time_cb;
}

bool he_ssl_ctx_is_nudge_time_cb_set(he_ssl_ctx_t *ctx) {
  if(!ctx) {
    return false;
  }
  return ctx->nudge_time_cb;
}

void he_ssl_ctx_set_event_cb(he_ssl_ctx_t *ctx, he_event_cb_t event_cb) {
  // Return if ctx is null
  if(!ctx) {
    return;
  }

  ctx->event_cb = event_cb;
}

void he_ssl_ctx_set_auth_cb(he_ssl_ctx_t *ctx, he_auth_cb_t auth_cb) {
  // Return if ctx is null
  if(!ctx) {
    return;
  }

  ctx->auth_cb = auth_cb;
}

void he_ssl_ctx_set_auth_buf_cb(he_ssl_ctx_t *ctx, he_auth_buf_cb_t auth_buf_cb) {
  // Return if ctx is null
  if(!ctx) {
    return;
  }

  ctx->auth_buf_cb = auth_buf_cb;
}

bool he_ssl_ctx_is_auth_cb_set(he_ssl_ctx_t *ctx) {
  // Return if ctx is null
  if(!ctx) {
    return false;
  }

  return ctx->auth_cb != NULL || ctx->auth_buf_cb != NULL;
}

void he_ssl_ctx_set_populate_network_config_ipv4_cb(
    he_ssl_ctx_t *ctx, he_populate_network_config_ipv4_cb_t pop_network_cb) {
  // Return if ctx is null
  if(!ctx) {
    return;
  }

  ctx->populate_network_config_ipv4_cb = pop_network_cb;
}

he_return_code_t he_ssl_ctx_set_disable_roaming(he_ssl_ctx_t *ctx) {
  // Return if ctx is null
  if(!ctx) {
    return HE_ERR_NULL_POINTER;
  }

  // Simply set the disable flag
  ctx->disable_roaming_connections = true;
  return HE_SUCCESS;
}

bool he_ssl_ctx_is_roaming_disabled(he_ssl_ctx_t *ctx) {
  // Return if ctx is null
  if(!ctx) {
    return false;
  }

  return ctx->disable_roaming_connections;
}

he_return_code_t he_ssl_ctx_set_padding_type(he_ssl_ctx_t *ctx, he_padding_type_t padding_type) {
  // Return if ctx is null
  if(!ctx) {
    return HE_ERR_NULL_POINTER;
  }

  // Simply set the padding type
  ctx->padding_type = padding_type;
  return HE_SUCCESS;
}

he_padding_type_t he_ssl_ctx_get_padding_type(he_ssl_ctx_t *ctx) {
  // Return if ctx is null
  if(!ctx) {
    return HE_ERR_NULL_POINTER;
  }

  return ctx->padding_type;
}

he_return_code_t he_ssl_ctx_set_aggressive_mode(he_ssl_ctx_t *ctx) {
  // Return if ctx is null
  if(!ctx) {
    return HE_ERR_NULL_POINTER;
  }

  ctx->use_aggressive_mode = true;
  return HE_SUCCESS;
}

#ifndef HE_NO_PQC
he_return_code_t he_ssl_ctx_set_use_pqc(he_ssl_ctx_t *ctx, bool enabled) {
  // Return if ctx is null
  if(!ctx) {
    return HE_ERR_NULL_POINTER;
  }

  ctx->use_pqc = enabled;
  return HE_SUCCESS;
}
#endif
