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
 * @file plugin_stats.h
 * @brief Example plugin implementation
 *
 */

#ifndef PLUGIN_STATS
#define PLUGIN_STATS

#include <stddef.h>
#include <he_plugin.h>

// This is the only "public" API
he_plugin_return_code_t stats_plugin_create(plugin_struct_t *plugin_struct);
void stats_plugin_destroy(plugin_struct_t *plugin_struct);

// Everything else here is for testing

#define PACKET_SAMPLE_N 100000

typedef struct stats {
  double sum;
  double sumsq;
  unsigned long n;
  double min;
  double max;
} stats_t;

typedef struct packet_stats {
  stats_t incoming;
  stats_t outgoing;
} packet_stats_t;

he_plugin_return_code_t stats_plugin_do_ingress(uint8_t *packet, size_t *length, size_t capacity,
                                                packet_stats_t *data);
he_plugin_return_code_t stats_plugin_do_egress(uint8_t *packet, size_t *length, size_t capacity,
                                               packet_stats_t *data);

#endif  // PLUGIN_STATS
