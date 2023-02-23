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

#include "client.h"
#include "ssl_ctx.h"
#include "conn.h"
#include "plugin_chain.h"
#include "memory.h"

he_client_t *he_client_create() {
  he_client_t *client = he_calloc(1, sizeof(he_client_t));
  if(!client) {
    return NULL;
  }
  client->ssl_ctx = he_ssl_ctx_create();
  client->conn = he_conn_create();
  client->inside_plugins = he_plugin_create_chain();
  client->outside_plugins = he_plugin_create_chain();

  if(client->ssl_ctx == NULL || client->conn == NULL || client->inside_plugins == NULL ||
     client->outside_plugins == NULL) {
    he_client_destroy(client);
    return NULL;
  }
  return client;
}

he_return_code_t he_client_destroy(he_client_t *client) {
  if(client) {
    he_conn_destroy(client->conn);
    he_ssl_ctx_destroy(client->ssl_ctx);
    he_plugin_destroy_chain(client->inside_plugins);
    he_plugin_destroy_chain(client->outside_plugins);

    // Should be safe to free now
    he_free(client);
  }
  return HE_SUCCESS;
}

he_return_code_t he_client_connect(he_client_t *client) {
  if(client == NULL) {
    return HE_ERR_NULL_POINTER;
  }

  // Return holder
  int res = 0;

  // First we do the client->wolf_ctx setup
  res = he_ssl_ctx_start(client->ssl_ctx);

  if(res != HE_SUCCESS) {
    return res;
  }

  // Then we connect with the client
  res = he_conn_client_connect(client->conn, client->ssl_ctx, client->inside_plugins,
                               client->outside_plugins);

  if(res != HE_SUCCESS) {
    return res;
  }

  return HE_SUCCESS;
}

he_return_code_t he_client_disconnect(he_client_t *client) {
  if(client == NULL) {
    return HE_ERR_NULL_POINTER;
  }
  int res = he_ssl_ctx_stop(client->ssl_ctx);

  if(res != HE_SUCCESS) {
    return res;
  }

  return he_conn_disconnect(client->conn);
}

he_return_code_t he_client_is_config_valid(he_client_t *client) {
  if(client == NULL) {
    return HE_ERR_NULL_POINTER;
  }

  he_return_code_t ret = he_ssl_ctx_is_valid_client(client->ssl_ctx);

  if(ret != HE_SUCCESS) {
    return ret;
  }

  return he_conn_is_valid_client(client->ssl_ctx, client->conn);
}
