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

#include <he.h>
#include "unity.h"
#include "test_defs.h"

// Unit under test
#include "plugin_stats.h"

packet_stats_t stats;
plugin_struct_t plugin = {0};

const int NUM_SAMPLES = 10;
size_t samples[] = {61061334, 96783204, 12747090, 82395131, 3333483,
                    69755066, 10626275, 76587523, 49382973, 95788115};

stats_t expect = {
    .sumsq = 42516409741139184,
    .sum = 558460194,
    .min = 3333483,
    .max = 96783204,
    .n = 10,
};

void setUp(void) {
  int res = stats_plugin_create(&plugin);
  TEST_ASSERT_EQUAL(HE_PLUGIN_SUCCESS, res);
  TEST_ASSERT_NOT_NULL(plugin.data);
}

void tearDown(void) {
  stats_plugin_destroy(&plugin);
  memset(&plugin, 0, sizeof(plugin_struct_t));
  memset(&stats, 0, sizeof(packet_stats_t));
}

void test_construction(void) {
  TEST_ASSERT_EQUAL(0, stats.incoming.n);
  TEST_ASSERT_EQUAL(0, stats.outgoing.n);
}

static void internal_test_stats(stats_t *st) {
  TEST_ASSERT_EQUAL(expect.sumsq, st->sumsq);
  TEST_ASSERT_EQUAL(expect.sum, st->sum);
  TEST_ASSERT_EQUAL(expect.min, st->min);
  TEST_ASSERT_EQUAL(expect.max, st->max);
  TEST_ASSERT_EQUAL(expect.n, st->n);
}

void test_operations(void) {
  for(int i = 0; i < NUM_SAMPLES; i++) {
    stats_plugin_do_ingress(NULL, &samples[i], samples[i], &stats);
    stats_plugin_do_egress(NULL, &samples[i], samples[i], &stats);
  }

  internal_test_stats(&stats.incoming);
  internal_test_stats(&stats.outgoing);
}

void test_operations_through_plugin_api(void) {
  for(int i = 0; i < NUM_SAMPLES; i++) {
    plugin.do_ingress(NULL, &samples[i], samples[i], plugin.data);
  }

  packet_stats_t *packet_stats = (packet_stats_t *)plugin.data;

  internal_test_stats(&packet_stats->incoming);
}

void test_null(void) {
  int res = stats_plugin_do_ingress(NULL, &samples[0], samples[0], NULL);
  TEST_ASSERT_EQUAL(res, HE_PLUGIN_FAIL);

  res = stats_plugin_do_egress(NULL, &samples[0], samples[0], NULL);
  TEST_ASSERT_EQUAL(res, HE_PLUGIN_FAIL);

  // Just make sure it doesn't blow up
  stats_plugin_destroy(NULL);

  plugin_struct_t empty_plugin = {0};

  stats_plugin_destroy(&empty_plugin);
}

void test_print_doesnt_explode(void) {
  // No sane way to verify the fprint output but will at least make sure we get it here
  stats.incoming.n = PACKET_SAMPLE_N - 1;
  int res = stats_plugin_do_ingress(NULL, &samples[0], samples[0], &stats);
  TEST_ASSERT_EQUAL(HE_PLUGIN_SUCCESS, res);

  stats.outgoing.n = PACKET_SAMPLE_N - 1;
  res = stats_plugin_do_egress(NULL, &samples[0], samples[0], &stats);
  TEST_ASSERT_EQUAL(HE_PLUGIN_SUCCESS, res);
}
