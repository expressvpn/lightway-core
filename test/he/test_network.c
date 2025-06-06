#include <unity.h>
#include "test_defs.h"

#include "network.h"

void test_he_internal_is_ipv4_packet_valid_null_packet(void) {
  // Test with a NULL packet
  bool res = he_internal_is_ipv4_packet_valid(NULL, 0);
  TEST_ASSERT_EQUAL(false, res);
}

void test_he_internal_is_ipv4_packet_valid(void) {
  // Test with a Valid packet
  bool res = he_internal_is_ipv4_packet_valid(fake_ipv4_packet, sizeof(fake_ipv4_packet));
  TEST_ASSERT_EQUAL(true, res);
}

void test_he_internal_is_ipv4_packet_valid_invalid_packet(void) {
  // Test with a invalid packet
  bool res = he_internal_is_ipv4_packet_valid(bad_fake_ipv4_packet, sizeof(bad_fake_ipv4_packet));
  TEST_ASSERT_EQUAL(false, res);
}

void test_he_internal_is_ipv4_packet_valid_packet_too_small(void) {
  // Test with too small a packet
  bool res = he_internal_is_ipv4_packet_valid(fake_ipv4_packet, sizeof(ipv4_header_t) - 1);
  TEST_ASSERT_EQUAL(false, res);
}
