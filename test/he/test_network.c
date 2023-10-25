#include <unity.h>

#include "network.h"
#include "test_defs.h"

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
