#include <unity.h>
#include <stdint.h>

// Unit under test
#include "utils.h"

void test_he_return_code_name(void) {
  // he_return_code_t's are negative
  const struct {
    he_return_code_t rc;
    const char *rc_name;
  } cases[] = {
      {HE_SUCCESS, "HE_SUCCESS"},
      {HE_ERR_STRING_TOO_LONG, "HE_ERR_STRING_TOO_LONG"},
      {HE_ERR_EMPTY_STRING, "HE_ERR_EMPTY_STRING"},
      {HE_ERR_INVALID_CONN_STATE, "HE_ERR_INVALID_CONN_STATE"},
      {HE_ERR_NULL_POINTER, "HE_ERR_NULL_POINTER"},
      {HE_ERR_EMPTY_PACKET, "HE_ERR_EMPTY_PACKET"},
      {HE_ERR_PACKET_TOO_SMALL, "HE_ERR_PACKET_TOO_SMALL"},
      {HE_ERR_ZERO_SIZE, "HE_ERR_ZERO_SIZE"},
      {HE_ERR_NEGATIVE_NUMBER, "HE_ERR_NEGATIVE_NUMBER"},
      {HE_ERR_INIT_FAILED, "HE_ERR_INIT_FAILED"},
      {HE_ERR_NO_MEMORY, "HE_ERR_NO_MEMORY"},
      {HE_ERR_NOT_HE_PACKET, "HE_ERR_NOT_HE_PACKET"},
      {HE_ERR_SSL_BAD_FILETYPE, "HE_ERR_SSL_BAD_FILETYPE"},
      {HE_ERR_SSL_BAD_FILE, "HE_ERR_SSL_BAD_FILE"},
      {HE_ERR_SSL_OUT_OF_MEMORY, "HE_ERR_SSL_OUT_OF_MEMORY"},
      {HE_ERR_SSL_ASN_INPUT, "HE_ERR_SSL_ASN_INPUT"},
      {HE_ERR_SSL_BUFFER, "HE_ERR_SSL_BUFFER"},
      {HE_ERR_SSL_CERT, "HE_ERR_SSL_CERT"},
      {HE_ERR_SSL_ERROR, "HE_ERR_SSL_ERROR"},
      {HE_ERR_CONF_USERNAME_NOT_SET, "HE_ERR_CONF_USERNAME_NOT_SET"},
      {HE_ERR_CONF_PASSWORD_NOT_SET, "HE_ERR_CONF_PASSWORD_NOT_SET"},
      {HE_ERR_CONF_CA_NOT_SET, "HE_ERR_CONF_CA_NOT_SET"},
      {HE_ERR_CONF_MTU_NOT_SET, "HE_ERR_CONF_MTU_NOT_SET"},
      {HE_WANT_READ, "HE_WANT_READ"},
      {HE_WANT_WRITE, "HE_WANT_WRITE"},
      {HE_ERR_CONF_OUTSIDE_WRITE_CB_NOT_SET, "HE_ERR_CONF_OUTSIDE_WRITE_CB_NOT_SET"},
      {HE_ERR_CONNECT_FAILED, "HE_ERR_CONNECT_FAILED"},
      {HE_CONNECTION_TIMED_OUT, "HE_CONNECTION_TIMED_OUT"},
      {HE_ERR_NOT_CONNECTED, "HE_ERR_NOT_CONNECTED"},
      {HE_ERR_UNSUPPORTED_PACKET_TYPE, "HE_ERR_UNSUPPORTED_PACKET_TYPE"},
      {HE_ERR_CONNECTION_WAS_CLOSED, "HE_ERR_CONNECTION_WAS_CLOSED"},
      {HE_ERR_BAD_PACKET, "HE_ERR_BAD_PACKET"},
      {HE_ERR_CALLBACK_FAILED, "HE_ERR_CALLBACK_FAILED"},
      {HE_ERR_FAILED, "HE_ERR_FAILED"},
      {HE_ERR_SERVER_DN_MISMATCH, "HE_ERR_SERVER_DN_MISMATCH"},
      {HE_ERR_CANNOT_VERIFY_SERVER_CERT, "HE_ERR_CANNOT_VERIFY_SERVER_CERT"},
      {HE_ERR_NEVER_CONNECTED, "HE_ERR_NEVER_CONNECTED"},
      {HE_ERR_INVALID_MTU_SIZE, "HE_ERR_INVALID_MTU_SIZE"},
      {HE_ERR_CLEANUP_FAILED, "HE_ERR_CLEANUP_FAILED"},
      {HE_ERR_REJECTED_SESSION, "HE_ERR_REJECTED_SESSION"},
      {HE_ERR_ACCESS_DENIED, "HE_ERR_ACCESS_DENIED"},
      {HE_ERR_PACKET_TOO_LARGE, "HE_ERR_PACKET_TOO_LARGE"},
      {HE_ERR_INACTIVITY_TIMEOUT, "HE_ERR_INACTIVITY_TIMEOUT"},
      {HE_ERR_POINTER_WOULD_OVERFLOW, "HE_ERR_POINTER_WOULD_OVERFLOW"},
      {HE_ERR_INVALID_CONNECTION_TYPE, "HE_ERR_INVALID_CONNECTION_TYPE"},
      {HE_ERR_RNG_FAILURE, "HE_ERR_RNG_FAILURE"},
      {HE_ERR_CONF_AUTH_CB_NOT_SET, "HE_ERR_CONF_AUTH_CB_NOT_SET"},
      {HE_ERR_PLUGIN_DROP, "HE_ERR_PLUGIN_DROP"},
      {HE_ERR_UNKNOWN_SESSION, "HE_ERR_UNKNOWN_SESSION"},
      {HE_ERR_SSL_ERROR_NONFATAL, "HE_ERR_SSL_ERROR_NONFATAL"},
      {HE_ERR_INCORRECT_PROTOCOL_VERSION, "HE_ERR_INCORRECT_PROTOCOL_VERSION"},
      {HE_ERR_CONF_CONFLICTING_AUTH_METHODS, "HE_ERR_CONF_CONFLICTING_AUTH_METHODS"},
      {HE_ERR_ACCESS_DENIED_NO_AUTH_BUF_HANDLER, "HE_ERR_ACCESS_DENIED_NO_AUTH_BUF_HANDLER"},
      {HE_ERR_ACCESS_DENIED_NO_AUTH_USERPASS_HANDLER,
       "HE_ERR_ACCESS_DENIED_NO_AUTH_USERPASS_HANDLER"},
      {HE_ERR_SERVER_GOODBYE, "HE_ERR_SERVER_GOODBYE"},
      {HE_ERR_INVALID_AUTH_TYPE, "HE_ERR_INVALID_AUTH_TYPE"},
      {HE_ERR_ACCESS_DENIED_NO_AUTH_TOKEN_HANDLER, "HE_ERR_ACCESS_DENIED_NO_AUTH_TOKEN_HANDLER"},
      {HE_ERR_PMTUD_CALLBACKS_NOT_SET, "HE_ERR_PMTUD_CALLBACKS_NOT_SET"},
      {HE_ERR_BAD_FRAGMENT, "HE_ERR_BAD_FRAGMENT"},
      {HE_ERR_SECURE_RENEGOTIATION_ERROR, "HE_ERR_SECURE_RENEGOTIATION_ERROR"},
      {HE_ERR_SECURE_RENEGOTIATION_ERROR - 1, "HE_ERR_UNKNOWN"},
      {1, "HE_ERR_UNKNOWN"},
      {-1, NULL},
  };

  for(int i = 0; cases[i].rc_name != NULL; i++) {
    const char *status = he_return_code_name(cases[i].rc);
    TEST_ASSERT_EQUAL_STRING(cases[i].rc_name, status);
  }
}

void test_he_client_state_name(void) {
  const struct {
    he_conn_state_t st;
    const char *st_name;
  } cases[] = {
      {HE_STATE_NONE, "HE_STATE_NONE"},
      {HE_STATE_DISCONNECTED, "HE_STATE_DISCONNECTED"},
      {HE_STATE_CONNECTING, "HE_STATE_CONNECTING"},
      {HE_STATE_DISCONNECTING, "HE_STATE_DISCONNECTING"},
      {HE_STATE_AUTHENTICATING, "HE_STATE_AUTHENTICATING"},
      {HE_STATE_LINK_UP, "HE_STATE_LINK_UP"},
      {HE_STATE_ONLINE, "HE_STATE_ONLINE"},
      {HE_STATE_CONFIGURING, "HE_STATE_CONFIGURING"},
      {HE_STATE_CONFIGURING + 1, "HE_STATE_UNKNOWN"},
      {HE_STATE_DISCONNECTING - 1, "HE_STATE_UNKNOWN"},  // NULL
      {-1, "HE_STATE_UNKNOWN"},
      {-1, NULL},
  };

  for(int i = 0; cases[i].st_name != NULL; i++) {
    const char *state = he_client_state_name(cases[i].st);
    TEST_ASSERT_EQUAL_STRING(cases[i].st_name, state);
  }
}

void test_he_client_event_name(void) {
  const struct {
    he_conn_event_t ev;
    const char *ev_name;
  } cases[] = {
      {0, "HE_EVENT_UNKNOWN"},
      {HE_EVENT_FIRST_MESSAGE_RECEIVED, "HE_EVENT_FIRST_MESSAGE_RECEIVED"},
      {HE_EVENT_PONG, "HE_EVENT_PONG"},
      {HE_EVENT_SECURE_RENEGOTIATION_STARTED, "HE_EVENT_SECURE_RENEGOTIATION_STARTED"},
      {HE_EVENT_SECURE_RENEGOTIATION_COMPLETED, "HE_EVENT_SECURE_RENEGOTIATION_COMPLETED"},
      {HE_EVENT_PENDING_SESSION_ACKNOWLEDGED, "HE_EVENT_PENDING_SESSION_ACKNOWLEDGED"},
      {HE_EVENT_PENDING_SESSION_ACKNOWLEDGED + 1, "HE_EVENT_UNKNOWN"},
      {-1, "HE_EVENT_UNKNOWN"},
      {-1, NULL},
  };

  for(int i = 0; cases[i].ev_name != NULL; i++) {
    const char *state = he_client_event_name(cases[i].ev);
    TEST_ASSERT_EQUAL_STRING(cases[i].ev_name, state);
  }
}

void test_he_connection_protocol_name(void) {
  const struct {
    he_connection_protocol_t protocol;
    const char *protocol_name;
  } cases[] = {
      {HE_CONNECTION_PROTOCOL_NONE, "HE_CONNECTION_PROTOCOL_NONE"},
      {HE_CONNECTION_PROTOCOL_TLS_1_3, "HE_CONNECTION_PROTOCOL_TLS_1_3"},
      {HE_CONNECTION_PROTOCOL_DTLS_1_2, "HE_CONNECTION_PROTOCOL_DTLS_1_2"},
      {HE_CONNECTION_PROTOCOL_DTLS_1_3, "HE_CONNECTION_PROTOCOL_DTLS_1_3"},
      {HE_CONNECTION_PROTOCOL_DTLS_1_3 + 1, "HE_CONNECTION_PROTOCOL_UNKNOWN"},
      {-1, "HE_CONNECTION_PROTOCOL_UNKNOWN"},
      {-1, NULL},
  };

  for(int i = 0; cases[i].protocol_name != NULL; i++) {
    const char *state = he_connection_protocol_name(cases[i].protocol);
    TEST_ASSERT_EQUAL_STRING(cases[i].protocol_name, state);
  }
}

const char src[10] = "123456789";

void test_he_safe_strncpy(void) {
  TEST_ASSERT_EQUAL(10, sizeof(src));
  TEST_ASSERT_EQUAL(9, strlen(src));

  char dst[10];
  TEST_ASSERT_EQUAL(dst, he_safe_strncpy(dst, src, sizeof(dst)));
  TEST_ASSERT_EQUAL(dst[10 - 1], '\0');
  TEST_ASSERT_EQUAL_INT(0, strcmp(dst, "123456789"));
}

void test_he_safe_strncpy_bigger_dst(void) {
  char bigger_dst[15];
  TEST_ASSERT_EQUAL(bigger_dst, he_safe_strncpy(bigger_dst, src, sizeof(bigger_dst)));
  TEST_ASSERT_EQUAL(bigger_dst[15 - 1], '\0');
  TEST_ASSERT_EQUAL_INT(0, strcmp(bigger_dst, "123456789"));
}

void test_he_safe_strncpy_smaller_dst(void) {
  char smaller_dst[5];
  TEST_ASSERT_EQUAL(smaller_dst, he_safe_strncpy(smaller_dst, src, sizeof(smaller_dst)));
  TEST_ASSERT_EQUAL(smaller_dst[5 - 1], '\0');
  TEST_ASSERT_EQUAL_INT(0, strcmp(smaller_dst, "1234"));
}

void test_he_safe_strncpy_boundary_check(void) {
  char overflow_dst[9];
  TEST_ASSERT_EQUAL(overflow_dst, he_safe_strncpy(overflow_dst, src, sizeof(overflow_dst)));
  TEST_ASSERT_EQUAL(overflow_dst[9 - 1], '\0');
  TEST_ASSERT_EQUAL_INT(0, strcmp(overflow_dst, "12345678"));
}
