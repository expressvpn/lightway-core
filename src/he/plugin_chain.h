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
 * @file plugin_chain.h
 * @brief Creation, destruction, registration, and execution for a plugin chain
 *
 */

#ifndef PLUGIN_CHAIN_H
#define PLUGIN_CHAIN_H

#include "he_internal.h"

/**
 * @brief Creates a Helium plugin chain
 * @return he_plugin_chain_t* Returns a pointer to a valid plugin chain
 * @note This function allocates memory
 *
 * This function must be called to create the initial plugin chain for use
 * with other functions
 */
he_plugin_chain_t *he_plugin_create_chain(void);

/**
 * @brief Releases all memory allocated by Helium for this plugin chain
 * @param chain A pointer to a valid plugin chain
 * @note he_plugin_destroy_chain does NOT free the `plugin` objects registered to the plugin
 * chain.
 */
void he_plugin_destroy_chain(he_plugin_chain_t *chain);

/**
 * @brief Register the plugin to the plugin chain
 * @param chain A pointer to a valid plugin chain
 * @param plugin A pointer to the *initialised* plugin struct
 * @return HE_SUCCESS Plugin was successfully registered
 * @return HE_ERR_NULL_POINTER Either parameter was NULL
 * @return HE_ERR_INIT_FAILED Registering the plugin failed
 * @note The plugin chain only keeps a reference to the plugin object. The caller is still
 * responsible for freeing the memory used by the `plugin` object after use.
 */
he_return_code_t he_plugin_register_plugin(he_plugin_chain_t *chain, plugin_struct_t *plugin);

/**
 * @brief Execute the ingress function of each registered plugin
 * @param chain A pointer to a valid plugin chain
 * @param packet A pointer to the packet data
 * @param length A pointer to the length of the packet data. If the packet size changed after
 * processed by this function, the `length` will be set to the new length of the packet data.
 * @param capacity The length of the underlying buffer for packet
 * @return HE_SUCCESS All plugins executed successfully
 * @return HE_ERR_PLUGIN_DROP A plugin marked this packet for a drop
 * @return HE_ERR_FAILED An error occurred processing this packet
 * @note The content of packet may be modified, grow or shrunk, depending on the registered plugins
 */
he_return_code_t he_plugin_ingress(he_plugin_chain_t *chain, uint8_t *packet, size_t *length,
                                   size_t capacity);

/**
 * @brief Execute the egress function of each registered plugin
 * @param chain A pointer to a valid plugin chain
 * @param packet A pointer to the packet data
 * @param length A pointer to the length of the packet data. If the packet size changed after
 * processed by this function, the `length` will be set to the new length of the packet data.
 * @param capacity The length of the underlying buffer for packet
 * @return HE_SUCCESS All plugins executed successfully
 * @return HE_ERR_PLUGIN_DROP A plugin marked this packet for a drop
 * @return HE_ERR_FAILED An error occurred processing this packet
 * @note The content of packet may be modified, grow or shrunk, depending on the registered plugins
 */
he_return_code_t he_plugin_egress(he_plugin_chain_t *chain, uint8_t *packet, size_t *length,
                                  size_t capacity);

#endif  // PLUGIN_CHAIN_H
