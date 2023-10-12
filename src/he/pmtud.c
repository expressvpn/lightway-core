#include "he.h"
#include "conn.h"
#include "conn_internal.h"
#include "he_internal.h"

#include "pmtud.h"

#ifndef MAX
#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#endif

#ifndef MIN
#define MIN(x, y) (((x) < (y)) ? (x) : (y))
#endif

static void he_internal_pmtud_change_state(he_conn_t *conn, he_pmtud_state_t state) {
  if(conn == NULL) {
    return;
  }
  if(conn->pmtud_state_change_cb) {
    conn->pmtud_state_change_cb(conn, state, conn->data);
  }
  conn->pmtud_state = state;
}

he_return_code_t he_internal_pmtud_send_probe(he_conn_t *conn, uint16_t probe_mtu) {
  if(!conn) {
    return HE_ERR_NULL_POINTER;
  }

  if(conn->state != HE_STATE_ONLINE || conn->pmtud_state == HE_PMTUD_STATE_DISABLED) {
    return HE_ERR_INVALID_CONN_STATE;
  }

  if(probe_mtu < MIN_PLPMTU || probe_mtu > MAX_PLPMTU) {
    return HE_ERR_INVALID_MTU_SIZE;
  }

  // Craft a probe message
  uint8_t buf[HE_MAX_WIRE_MTU] = {0};
  he_msg_ping_t *probe = (he_msg_ping_t *)buf;
  probe->msg_header.msgid = HE_MSGID_PING;

  // Set identifier
  uint16_t id = conn->pmtud_probe_next_id++;
  probe->id = htons(id);

  // Set payload for the probe message
  uint16_t payload_size = probe_mtu + sizeof(he_msg_data_t) - sizeof(he_msg_ping_t);
  probe->length = payload_size;

  // TODO: fill payload with random data

  // Send it
  he_return_code_t res = he_internal_send_message(conn, buf, sizeof(he_msg_ping_t) + payload_size);
  if(res == HE_SUCCESS) {
    conn->pmtud_probing_size = probe_mtu;
    conn->pmtud_probe_pending_id = id;
  }

  // Start the probe timer
  if(conn->pmtud_time_cb) {
    conn->pmtud_time_cb(conn, PMTUD_PROBE_TIMEOUT_MS, conn->data);
  }
  return res;
}

he_return_code_t he_internal_pmtud_handle_probe_ack(he_conn_t *conn, uint16_t probe_id) {
  if(!conn) {
    return HE_ERR_NULL_POINTER;
  }
  if(conn->pmtud_probe_pending_id != probe_id) {
    // Receives an outdated probe id, ignore.
    return HE_SUCCESS;
  }

  // Reset the pending probe id
  conn->pmtud_probe_pending_id = 0;

  // Handle the ack based on current state
  switch(conn->pmtud_state) {}
  return HE_SUCCESS;
}

he_return_code_t he_internal_pmtud_handle_probe_timeout(he_conn_t *conn) {
  if(!conn) {
    return HE_ERR_NULL_POINTER;
  }

  // Increment PROBE_COUNT
  conn->pmtud_probe_count++;

  // Try again with the same probe size
  if(conn->pmtud_probe_count < MAX_PROBES) {
    return he_internal_pmtud_send_probe(conn, conn->pmtud_probing_size);
  }

  // PROBE_COUNT reaches MAX_PROBES, decide what to do based on state
  switch(conn->pmtud_state) {
    case HE_PMTUD_STATE_BASE:
      // Unable to confirm the base PMTU, entering error state.
      // TODO: we could try confirming a smaller BASE_PMTU
      return he_internal_pmtud_confirm_base_failed(conn);
    case HE_PMTUD_STATE_SEARCHING:
      // Search completed
      return he_internal_pmtud_search_completed(conn);
    case HE_PMTUD_STATE_SEARCH_COMPLETE:
      // Black hole detected
      return he_internal_pmtud_blackhole_detected(conn);
    default:
      // Do nothing in DISABLED / ERROR states
      break;
  }
  return HE_SUCCESS;
}

he_return_code_t he_internal_pmtud_start_base_probing(he_conn_t *conn) {
  if(!conn) {
    return HE_ERR_NULL_POINTER;
  }

  // Check current state
  switch(conn->pmtud_state) {
    case HE_PMTUD_STATE_DISABLED:
    case HE_PMTUD_STATE_SEARCHING:
    case HE_PMTUD_STATE_SEARCH_COMPLETE:
      // Valid states
      break;
    default:
      // Invalid states
      return HE_ERR_INVALID_CONN_STATE;
  }

  // Change state
  he_internal_pmtud_change_state(conn, HE_PMTUD_STATE_BASE);

  // Initialize PMTUD internal state
  conn->pmtud_base = MAX(MIN_PLPMTU, conn->effective_pmtu);
  conn->pmtud_probe_count = 0;

  // Start probing base mtu
  return he_internal_pmtud_send_probe(conn, conn->pmtud_base);
}

he_return_code_t he_internal_pmtud_confirm_base_failed(he_conn_t *conn) {
  if(!conn) {
    return HE_ERR_NULL_POINTER;
  }
  // Check current state
  switch(conn->pmtud_state) {
    case HE_PMTUD_STATE_BASE:
      // Valid states
      break;
    default:
      // Invalid states
      return HE_ERR_INVALID_CONN_STATE;
  }

  // Change state
  he_internal_pmtud_change_state(conn, HE_PMTUD_STATE_ERROR);

  // TODO: try continue probe with MIN_PLPMTU here
  return HE_SUCCESS;
}

he_return_code_t he_internal_pmtud_search_completed(he_conn_t *conn) {
  if(!conn) {
    return HE_ERR_NULL_POINTER;
  }
  // Check current state
  switch(conn->pmtud_state) {
    case HE_PMTUD_STATE_SEARCHING:
      // Valid states
      break;
    default:
      // Invalid states
      return HE_ERR_INVALID_CONN_STATE;
  }
  // Change state
  he_internal_pmtud_change_state(conn, HE_PMTUD_STATE_SEARCH_COMPLETE);

  // Set the effective pmtu
  conn->effective_pmtu = conn->pmtud_probing_size;

  // TODO: stay in this state and check for black hole regularly
  return HE_SUCCESS;
}

he_return_code_t he_internal_pmtud_blackhole_detected(he_conn_t *conn) {
  if(!conn) {
    return HE_ERR_NULL_POINTER;
  }
  // Check current state
  switch(conn->pmtud_state) {
    case HE_PMTUD_STATE_SEARCHING:
    case HE_PMTUD_STATE_SEARCH_COMPLETE:
      // Valid states
      break;
    default:
      // Invalid states
      return HE_ERR_INVALID_CONN_STATE;
  }

  // Change state
  he_internal_pmtud_change_state(conn, HE_PMTUD_STATE_BASE);

  // Set the base pmtu
  conn->pmtud_base = MIN_PLPMTU;
  conn->pmtud_probe_count = 0;

  // Start probing base mtu
  return he_internal_pmtud_send_probe(conn, conn->pmtud_base);
}
