#include "he.h"
#include "conn.h"
#include "conn_internal.h"
#include "he_internal.h"

#include "pmtud.h"

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

  // Craft a PING message
  uint8_t buf[HE_MAX_WIRE_MTU] = {0};
  he_msg_ping_t *ping = (he_msg_ping_t *)buf;
  ping->msg_header.msgid = HE_MSGID_PING;

  // Set identifier
  uint16_t id = conn->ping_next_id++;
  ping->id = htons(id);

  // Set payload for keepalive
  uint16_t payload_size = probe_mtu + sizeof(he_msg_data_t) - sizeof(he_msg_ping_t);
  ping->length = payload_size;

  // TODO: fill payload with random data

  // Send it
  he_return_code_t res = he_internal_send_message(conn, buf, sizeof(he_msg_ping_t) + payload_size);
  if(res == HE_SUCCESS) {
    conn->ping_pending_id = id;
  }
  return res;
}

void he_internal_pmtud_pong_received(he_conn_t *conn) {
}

void he_internal_change_pmtud_state(he_conn_t *conn, he_pmtud_state_t state) {
  if(conn == NULL || conn->pmtud_state == state) {
    return;
  }

  switch(conn->pmtud_state) {
    case HE_PMTUD_STATE_DISABLED:
      switch(state) {
        case HE_PMTUD_STATE_BASE:
          // DISABLED -> BASE
          he_internal_generate_event(conn, HE_EVENT_PMTU_DISCOVERY_STARTED);

          // Initialize PMTU internal data
          conn->pmtud_base = HE_MAX_MTU;
          conn->pmtud_is_using_big_step = true;
          conn->pmtud_probe_count = 0;

          // TODO: start timers?
          break;
        default:
          // Invalid state transition, do nothing
          return;
      }
      break;
    case HE_PMTUD_STATE_BASE:
      switch(state) {
        case HE_PMTUD_STATE_SEARCHING:
          // TODO: enter searching state
          break;
        case HE_PMTUD_STATE_ERROR:
          // TODO: enter error state
          break;
        case HE_PMTUD_STATE_SEARCH_COMPLETE:
          // TODO: enter search complete state
          break;
        default:
          // Invalid state transition, do nothing
          return;
      }
      break;
    case HE_PMTUD_STATE_SEARCHING:
      switch(state) {
        case HE_PMTUD_STATE_BASE:
          // TODO: Return to Base when blackhole is detected
          break;
        case HE_PMTUD_STATE_SEARCH_COMPLETE:
          // TODO: Probe acked
          break;
        default:
          // Invalid state transition, do nothing
          return;
      }
      break;
    case HE_PMTUD_STATE_ERROR:
      switch(state) {
        case HE_PMTUD_STATE_SEARCHING:
          // TODO: Enter Searching state when probe succeeds
          break;
        default:
          // Invalid state transition, do nothing
          return;
      }
      break;
    case HE_PMTUD_STATE_SEARCH_COMPLETE:
      switch(state) {
        case HE_PMTUD_STATE_BASE:
          // TODO: enter Base state if MAX_PROBES successive PLPMTUD-sized probes fail to be
          // acknowledged
          break;

        default:
          break;
      }
      break;
  }

  // State changed
  conn->pmtud_state = state;
}

void he_internal_pmtud_update(he_conn_t *conn) {
  if(conn == NULL || conn->pmtud_state == HE_PMTUD_STATE_DISABLED) {
    // Invalid state, do nothing
    return;
  }
  switch(conn->pmtud_state) {
    case HE_PMTUD_STATE_BASE:
      break;
    case HE_PMTUD_STATE_SEARCHING:
      break;
    case HE_PMTUD_STATE_SEARCH_COMPLETE:
      break;
    case HE_PMTUD_STATE_ERROR:
      break;
    default:
      break;
  }
}
