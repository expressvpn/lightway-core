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

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include "plugin_stats.h"

// With apologies to https://github.com/zedshaw/liblcthw/blob/master/src/lcthw/stats.c

static double stats_mean(stats_t *st) {
  return st->sum / st->n;
}

static double stats_stddev(stats_t *st) {
  return sqrt((st->sumsq - (st->sum * st->sum / st->n)) / (st->n - 1));
}

static void stats_sample(stats_t *st, double s) {
  st->sum += s;
  st->sumsq += s * s;

  if(st->n == 0) {
    st->min = s;
    st->max = s;
  } else {
    if(st->min > s) st->min = s;
    if(st->max < s) st->max = s;
  }

  st->n += 1;
}

static void stats_dump(stats_t *st) {
  fprintf(stderr,
          "sum: %f, sumsq: %f, n: %ld, "
          "min: %f, max: %f, mean: %f, stddev: %f\n",
          st->sum, st->sumsq, st->n, st->min, st->max, stats_mean(st), stats_stddev(st));
}

he_plugin_return_code_t stats_plugin_do_ingress(uint8_t *packet, size_t *length, size_t capacity,
                                                packet_stats_t *data) {
  if(data == NULL) {
    return HE_PLUGIN_FAIL;
  }

  stats_t *incoming = &data->incoming;

  stats_sample(incoming, *length);

  if(incoming->n % PACKET_SAMPLE_N == 0) {
    fprintf(stderr, "Ingress: ");
    stats_dump(incoming);
  }
  return HE_PLUGIN_SUCCESS;
}

he_plugin_return_code_t stats_plugin_do_egress(uint8_t *packet, size_t *length, size_t capacity,
                                               packet_stats_t *data) {
  if(data == NULL) {
    return HE_PLUGIN_FAIL;
  }

  stats_t *outgoing = &data->outgoing;

  stats_sample(outgoing, *length);

  if(outgoing->n % PACKET_SAMPLE_N == 0) {
    fprintf(stderr, "Egress: ");
    stats_dump(outgoing);
  }
  return HE_PLUGIN_SUCCESS;
}

he_plugin_return_code_t stats_plugin_create(plugin_struct_t *plugin_struct) {
  packet_stats_t *stats = calloc(1, sizeof(packet_stats_t));
  if(stats == NULL) {
    return HE_PLUGIN_FAIL;
  }

  plugin_struct->do_ingress = (plugin_do_ingress)stats_plugin_do_ingress;
  plugin_struct->do_egress = (plugin_do_egress)stats_plugin_do_egress;
  plugin_struct->data = stats;

  return HE_PLUGIN_SUCCESS;
}

void stats_plugin_destroy(plugin_struct_t *plugin_struct) {
  if(plugin_struct && plugin_struct->data) {
    free(plugin_struct->data);
  }
}
