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
#include "plugin_chain.h"

// Mocked Includes
#include "mock_memory.h"

uint8_t *packet = NULL;
size_t packet_max_length = 1500;

size_t test_packet_size = 1100;

int ingress_count = 0;
int egress_count = 0;

he_plugin_return_code_t call_counting_plugin_ingress(uint8_t *packet, size_t *length,
                                                     size_t capacity, void *data) {
  ingress_count++;
  return HE_PLUGIN_SUCCESS;
}

he_plugin_return_code_t call_counting_plugin_egress(uint8_t *packet, size_t *length,
                                                    size_t capacity, void *data) {
  egress_count++;
  return HE_PLUGIN_SUCCESS;
}

plugin_struct_t call_counting_plugin = {.do_ingress = call_counting_plugin_ingress,
                                        .do_egress = call_counting_plugin_egress};

he_plugin_return_code_t drop_if_zero(uint8_t *packet, size_t *length, size_t capacity, void *data) {
  for(int i = 0; i < *length; i++) {
    if(packet[i] != 0) {
      return HE_PLUGIN_SUCCESS;
    }
  }

  return HE_PLUGIN_DROP;
}

plugin_struct_t zero_dropping_plugin = {
    .do_ingress = drop_if_zero,
    .do_egress = drop_if_zero,
};

he_plugin_return_code_t always_fail(uint8_t *packet, size_t *length, size_t capacity, void *data) {
  return HE_PLUGIN_FAIL;
}

plugin_struct_t failing_plugin = {
    .do_ingress = always_fail,
    .do_egress = always_fail,
};

he_plugin_return_code_t zero_packet(uint8_t *packet, size_t *length, size_t capacity, void *data) {
  for(int i = 0; i < *length; i++) {
    // Perfect secrecy!!
    packet[i] = 0;
  }
  return HE_PLUGIN_SUCCESS;
}

plugin_struct_t wipeout_plugin = {
    .do_ingress = zero_packet,
    .do_egress = zero_packet,
};

plugin_struct_t only_ingress_plugin = {
    .do_ingress = call_counting_plugin_ingress,
};
plugin_struct_t only_egress_plugin = {
    .do_egress = call_counting_plugin_egress,
};

void setUp(void) {
  packet = calloc(1, packet_max_length);
  test_packet_size = 1100;
  // Generate a random blob to represent the packet
  for(int a = 0; a < packet_max_length; a++) {
    packet[a] = rand() % 256;
  }
  ingress_count = 0;
  egress_count = 0;
}

void tearDown(void) {
  free(packet);
}

void test_register_fails_on_null(void) {
  he_plugin_chain_t chain = {0};
  int res = he_plugin_register_plugin(NULL, &call_counting_plugin);
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, res);

  res = he_plugin_register_plugin(&chain, NULL);
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, res);
}

void test_ingress_egress_do_nothing_if_nothing_registered(void) {
  he_return_code_t res = HE_ERR_FAILED;
  he_plugin_chain_t chain = {0};

  res = he_plugin_ingress(&chain, packet, &test_packet_size, packet_max_length);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res);

  res = he_plugin_egress(&chain, packet, &test_packet_size, packet_max_length);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res);
}

void test_ingress_egress_call_counts(void) {
  he_return_code_t res = HE_ERR_FAILED;
  he_plugin_chain_t chain = {0};
  res = he_plugin_register_plugin(&chain, &call_counting_plugin);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res);

  res = he_plugin_ingress(&chain, packet, &test_packet_size, packet_max_length);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res);
  TEST_ASSERT_EQUAL(1, ingress_count);
  TEST_ASSERT_EQUAL(0, egress_count);

  res = he_plugin_egress(&chain, packet, &test_packet_size, packet_max_length);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res);
  TEST_ASSERT_EQUAL(1, ingress_count);
  TEST_ASSERT_EQUAL(1, egress_count);
}

void test_multiple_plugins(void) {
  he_return_code_t res = HE_ERR_FAILED;
  he_plugin_chain_t chain = {0};
  he_plugin_chain_t chain_sibling = {0};
  res = he_plugin_register_plugin(&chain, &call_counting_plugin);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res);

  he_calloc_ExpectAndReturn(1, sizeof(he_plugin_chain_t), &chain_sibling);
  res = he_plugin_register_plugin(&chain, &call_counting_plugin);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res);

  res = he_plugin_ingress(&chain, packet, &test_packet_size, packet_max_length);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res);
  TEST_ASSERT_EQUAL(2, ingress_count);
  TEST_ASSERT_EQUAL(0, egress_count);

  res = he_plugin_egress(&chain, packet, &test_packet_size, packet_max_length);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res);
  TEST_ASSERT_EQUAL(2, ingress_count);
  TEST_ASSERT_EQUAL(2, egress_count);
}

void test_ingress_egress_opposite_order(void) {
  he_return_code_t res = HE_ERR_FAILED;
  he_plugin_chain_t chain = {0};
  he_plugin_chain_t chain_sibling = {0};
  res = he_plugin_register_plugin(&chain, &zero_dropping_plugin);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res);

  // Ingress runs in registration order, egress runs in reverse
  // Therefore, we would expect ingress to return success,
  // since we check for zero BEFORE zeroing out the packet,
  // whereas we would expect egress to return "drop",
  // since we zero out the packet before running the zero-dropping plugin.

  he_calloc_ExpectAndReturn(1, sizeof(he_plugin_chain_t), &chain_sibling);
  res = he_plugin_register_plugin(&chain, &wipeout_plugin);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res);

  res = he_plugin_ingress(&chain, packet, &test_packet_size, packet_max_length);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res);

  res = he_plugin_egress(&chain, packet, &test_packet_size, packet_max_length);
  TEST_ASSERT_EQUAL(HE_ERR_PLUGIN_DROP, res);
}

void test_ingress_drop(void) {
  // Note that egress drop is tested above
  he_plugin_chain_t chain = {0};
  int res = he_plugin_register_plugin(&chain, &zero_dropping_plugin);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res);

  size_t packet_length = sizeof(empty_data);

  res = he_plugin_ingress(&chain, empty_data, &packet_length, sizeof(empty_data));
  TEST_ASSERT_EQUAL(HE_ERR_PLUGIN_DROP, res);
}

void test_plugin_failure(void) {
  he_plugin_chain_t chain = {0};
  int res = he_plugin_register_plugin(&chain, &failing_plugin);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res);

  res = he_plugin_ingress(&chain, packet, &test_packet_size, packet_max_length);
  TEST_ASSERT_EQUAL(HE_ERR_FAILED, res);

  res = he_plugin_egress(&chain, packet, &test_packet_size, packet_max_length);
  TEST_ASSERT_EQUAL(HE_ERR_FAILED, res);
}

void test_ingress_only_plugin(void) {
  he_plugin_chain_t chain = {0};
  int res = he_plugin_register_plugin(&chain, &only_ingress_plugin);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res);

  res = he_plugin_ingress(&chain, packet, &test_packet_size, packet_max_length);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res);
  TEST_ASSERT_EQUAL(1, ingress_count);

  res = he_plugin_egress(&chain, packet, &test_packet_size, packet_max_length);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res);
  TEST_ASSERT_EQUAL(0, egress_count);
}

void test_egress_only_plugin(void) {
  he_plugin_chain_t chain = {0};
  int res = he_plugin_register_plugin(&chain, &only_egress_plugin);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res);

  res = he_plugin_ingress(&chain, packet, &test_packet_size, packet_max_length);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res);
  TEST_ASSERT_EQUAL(0, ingress_count);

  res = he_plugin_egress(&chain, packet, &test_packet_size, packet_max_length);
  TEST_ASSERT_EQUAL(HE_SUCCESS, res);
  TEST_ASSERT_EQUAL(1, egress_count);
}

void test_plugin_destroy_chain_null(void) {
  he_plugin_destroy_chain(NULL);
}

void test_plugin_destroy_chain_single(void) {
  he_plugin_chain_t chain = {0};
  he_free_Expect(&chain);
  he_plugin_destroy_chain(&chain);
}

void test_plugin_destroy_chain_multiple_plugins(void) {
  he_plugin_chain_t sibling = {0};
  he_plugin_chain_t chain = {
      .next = &sibling,
  };
  he_free_Expect(&sibling);
  he_free_Expect(&chain);
  he_plugin_destroy_chain(&chain);
}
