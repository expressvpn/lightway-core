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
 * @file he_plugin.h
 * @brief The internal plugin API definitions.
 *
 * This file is separated out to clearly indicate that a plugin implementation only needs to care
 * about this API, not the full set of types and functions included
 *
 * @bug This file should be identical to include/he_plugin.h. Resolving this duplication is an
 * outstanding concern.
 *
 */

#ifndef HE_PLUGIN
#define HE_PLUGIN

#include <stddef.h>
#include <stdint.h>

typedef enum he_plugin_return_code {
  HE_PLUGIN_SUCCESS = 0,
  HE_PLUGIN_FAIL = -1,
  HE_PLUGIN_DROP = -2,
} he_plugin_return_code_t;

typedef he_plugin_return_code_t (*plugin_do_ingress)(uint8_t *packet, size_t *length,
                                                     size_t capacity, void *data);
typedef he_plugin_return_code_t (*plugin_do_egress)(uint8_t *packet, size_t *length,
                                                    size_t capacity, void *data);

typedef struct plugin_struct {
  plugin_do_ingress do_ingress;
  plugin_do_egress do_egress;
  void *data;
} plugin_struct_t;

#endif
