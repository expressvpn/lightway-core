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

#include "plugin_chain.h"
#include "memory.h"

he_plugin_chain_t *he_plugin_create_chain(void) {
  return he_calloc(1, sizeof(he_plugin_chain_t));
}

void he_plugin_destroy_chain(he_plugin_chain_t *chain) {
  if(chain) {
    he_plugin_destroy_chain(chain->next);
    he_free(chain);
  }
}

he_return_code_t he_plugin_register_plugin(he_plugin_chain_t *chain, plugin_struct_t *plugin) {
  if(chain == NULL || plugin == NULL) {
    return HE_ERR_NULL_POINTER;
  }

  // A bit odd, but we initialise the plugin AFTER walking the chain
  if(!chain->plugin) {
    chain->plugin = plugin;
    return HE_SUCCESS;
  }

  if(!chain->next) {
    chain->next = he_plugin_create_chain();
    if(chain->next == NULL) {
      return HE_ERR_INIT_FAILED;
    }
  }

  // This does a null pointer check for us
  return he_plugin_register_plugin(chain->next, plugin);
}

he_return_code_t he_plugin_ingress(he_plugin_chain_t *chain, uint8_t *packet, size_t *length,
                                   size_t capacity) {
  // Expected!
  if(chain == NULL) {
    return HE_SUCCESS;
  }

  plugin_struct_t *plugin = chain->plugin;

  if(plugin && plugin->do_ingress != NULL) {
    int res = plugin->do_ingress(packet, length, capacity, plugin->data);
    if(res == HE_PLUGIN_FAIL) {
      return HE_ERR_FAILED;
    }

    if(res == HE_PLUGIN_DROP) {
      return HE_ERR_PLUGIN_DROP;
    }
  }

  return he_plugin_ingress(chain->next, packet, length, capacity);
}

he_return_code_t he_plugin_egress(he_plugin_chain_t *chain, uint8_t *packet, size_t *length,
                                  size_t capacity) {
  // Expected!
  if(chain == NULL) {
    return HE_SUCCESS;
  }

  int res = he_plugin_egress(chain->next, packet, length, capacity);
  if(res != HE_SUCCESS) {
    return res;
  }

  plugin_struct_t *plugin = chain->plugin;

  if(plugin && plugin->do_egress != NULL) {
    res = plugin->do_egress(packet, length, capacity, plugin->data);
    if(res == HE_PLUGIN_FAIL) {
      return HE_ERR_FAILED;
    }
    if(res == HE_PLUGIN_DROP) {
      return HE_ERR_PLUGIN_DROP;
    }
  }
  return HE_SUCCESS;
}
