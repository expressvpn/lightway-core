/**
 * Lightway Core
 * Copyright (C) 2023 Express VPN International Ltd.
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

#include <assert.h>

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
  conn->pmtud.state = state;
  if(conn->pmtud_state_change_cb) {
    conn->pmtud_state_change_cb(conn, state, conn->data);
  }
}

he_return_code_t he_internal_pmtud_send_probe(he_conn_t *conn, uint16_t probe_mtu) {
  if(!conn) {
    return HE_ERR_NULL_POINTER;
  }

  if(conn->state != HE_STATE_ONLINE) {
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
  uint16_t id = conn->ping_next_id++;
  probe->id = htons(id);

  // Set payload for the probe message
  uint16_t payload_size = probe_mtu + sizeof(he_msg_data_t) - sizeof(he_msg_ping_t);
  probe->length = htons(payload_size);

  conn->pmtud.probe_count++;
  conn->pmtud.probing_size = probe_mtu;

  // Send it
  he_return_code_t res = he_internal_send_message(conn, buf, sizeof(he_msg_ping_t) + payload_size);
  int timeout_ms = PMTUD_PROBE_TIMEOUT_MS;
  if(res != HE_SUCCESS) {
    // If he_internal_send_message failed to send the probe message, trigger the pmtud timeout with
    // a tiny delay
    timeout_ms = 10;
  } else {
    // Set the probe pending id for verifying the ack message
    conn->pmtud.probe_pending_id = id;
  }

  // Start the probe timer
  if(conn->pmtud_time_cb) {
    conn->pmtud_time_cb(conn, timeout_ms, conn->data);
  }

  return HE_SUCCESS;
}

he_return_code_t he_internal_pmtud_handle_probe_ack(he_conn_t *conn, uint16_t probe_id) {
  if(!conn) {
    return HE_ERR_NULL_POINTER;
  }
  if(conn->pmtud.probe_pending_id != probe_id) {
    // Receives an outdated probe id, ignore.
    return HE_SUCCESS;
  }

  // Stop the timer
  if(conn->pmtud_time_cb) {
    conn->pmtud_time_cb(conn, 0, conn->data);
  }

  // Reset the pending probe id
  conn->pmtud.probe_pending_id = 0;

  // Reset the probe count for each ack
  conn->pmtud.probe_count = 0;

  // Handle the ack based on current state
  switch(conn->pmtud.state) {
    case HE_PMTUD_STATE_BASE:
      // Base MTU confirmed
      return he_internal_pmtud_base_confirmed(conn);
    case HE_PMTUD_STATE_SEARCHING:
      // Current probe acked
      if(conn->pmtud.probing_size >= MAX_PLPMTU) {
        // Search completed if the MAX_PLPMTU acked
        return he_internal_pmtud_search_completed(conn);
      } else {
        // Increment probing size and send next probe
        uint16_t probe_size = conn->pmtud.probing_size;
        probe_size +=
            (conn->pmtud.is_using_big_step) ? PMTUD_PROBE_BIG_STEP : PMTUD_PROBE_SMALL_STEP;
        probe_size = MIN(probe_size, MAX_PLPMTU);
        he_internal_pmtud_send_probe(conn, probe_size);
      }
      break;
    case HE_PMTUD_STATE_ERROR:
      // Base PMTU probe acked, enter Searching state now
      return he_internal_pmtud_base_confirmed(conn);
    case HE_PMTUD_STATE_SEARCH_COMPLETE:
      // Set a timer to retry probe
      return he_internal_pmtud_retry_probe(conn, PMTUD_SUCCESSFUL_SEARCH_RETRY_TIMEOUT_MS);
    default:
      // Do nothing
      break;
  }
  return HE_SUCCESS;
}

he_return_code_t he_internal_pmtud_handle_probe_timeout(he_conn_t *conn) {
  if(!conn) {
    return HE_ERR_NULL_POINTER;
  }

  // Try again with the same probe size
  if(conn->pmtud.probe_count < MAX_PROBES) {
    return he_internal_pmtud_send_probe(conn, conn->pmtud.probing_size);
  }

  // Reset probe count
  conn->pmtud.probe_pending_id = 0;
  conn->pmtud.probe_count = 0;

  // PROBE_COUNT reaches MAX_PROBES, decide what to do based on state
  switch(conn->pmtud.state) {
    case HE_PMTUD_STATE_BASE:
      if(conn->pmtud.probing_size == INITIAL_PLPMTU) {
        // Try again using MIN_PLPMTU
        conn->pmtud.base = MIN_PLPMTU;
        return he_internal_pmtud_send_probe(conn, MIN_PLPMTU);
      } else {
        // Unable to confirm the base PMTU, entering error state.
        return he_internal_pmtud_confirm_base_failed(conn);
      }
      break;
    case HE_PMTUD_STATE_SEARCHING:
      if(conn->pmtud.is_using_big_step) {
        // Try probing with small step
        conn->pmtud.is_using_big_step = false;
        uint16_t probe_size = conn->pmtud.probing_size;
        probe_size -= PMTUD_PROBE_BIG_STEP;
        probe_size += PMTUD_PROBE_SMALL_STEP;
        return he_internal_pmtud_send_probe(conn, probe_size);
      } else {
        // Search completed
        // Set the probing size to the previous successful one
        assert(conn->pmtud.probing_size > conn->pmtud.base);
        conn->pmtud.probing_size -= PMTUD_PROBE_SMALL_STEP;
        return he_internal_pmtud_search_completed(conn);
      }
      break;
    case HE_PMTUD_STATE_SEARCH_COMPLETE:
      // Black hole detected
      return he_internal_pmtud_blackhole_detected(conn);
    case HE_PMTUD_STATE_ERROR:
      // Retry if the base probe failed again
      return he_internal_pmtud_retry_probe(conn, PMTUD_ERROR_RETRY_TIMEOUT_MS);
    default:
      // Do nothing in DISABLED state
      break;
  }
  return HE_SUCCESS;
}

he_return_code_t he_internal_pmtud_start_base_probing(he_conn_t *conn) {
  if(!conn) {
    return HE_ERR_NULL_POINTER;
  }

  // Check current state
  switch(conn->pmtud.state) {
    case HE_PMTUD_STATE_DISABLED:
    case HE_PMTUD_STATE_SEARCHING:
    case HE_PMTUD_STATE_SEARCH_COMPLETE:
      // Valid states
      break;
    case HE_PMTUD_STATE_BASE:
      // Already in base state, do nothing
      return HE_SUCCESS;
    default:
      // Invalid states
      return HE_ERR_INVALID_CONN_STATE;
  }

  // Change state
  he_internal_pmtud_change_state(conn, HE_PMTUD_STATE_BASE);

  // Initialize PMTUD internal state
  conn->pmtud.base = INITIAL_PLPMTU;
  conn->pmtud.probe_count = 0;

  // Start probing base mtu
  return he_internal_pmtud_send_probe(conn, conn->pmtud.base);
}

he_return_code_t he_internal_pmtud_base_confirmed(he_conn_t *conn) {
  if(!conn) {
    return HE_ERR_NULL_POINTER;
  }
  // Check current state
  switch(conn->pmtud.state) {
    case HE_PMTUD_STATE_BASE:
    case HE_PMTUD_STATE_ERROR:
      // Valid states
      break;
    default:
      // Invalid states
      return HE_ERR_INVALID_CONN_STATE;
  }

  // Change to Searching state
  he_internal_pmtud_change_state(conn, HE_PMTUD_STATE_SEARCHING);

  // Start searching
  conn->pmtud.probe_count = 0;
  conn->pmtud.is_using_big_step = true;
  uint16_t probe_size = conn->pmtud.base + PMTUD_PROBE_BIG_STEP;

  return he_internal_pmtud_send_probe(conn, probe_size);
}

he_return_code_t he_internal_pmtud_confirm_base_failed(he_conn_t *conn) {
  if(!conn) {
    return HE_ERR_NULL_POINTER;
  }
  // Check current state
  switch(conn->pmtud.state) {
    case HE_PMTUD_STATE_BASE:
      // Valid states
      break;
    default:
      // Invalid states
      return HE_ERR_INVALID_CONN_STATE;
  }

  // Change state
  he_internal_pmtud_change_state(conn, HE_PMTUD_STATE_ERROR);

  return he_internal_pmtud_retry_probe(conn, PMTUD_ERROR_RETRY_TIMEOUT_MS);
}

he_return_code_t he_internal_pmtud_search_completed(he_conn_t *conn) {
  if(!conn) {
    return HE_ERR_NULL_POINTER;
  }
  // Check current state
  switch(conn->pmtud.state) {
    case HE_PMTUD_STATE_SEARCHING:
      // Valid states
      break;
    default:
      // Invalid states
      return HE_ERR_INVALID_CONN_STATE;
  }

  // Set the effective pmtu
  conn->pmtud.effective_pmtu = MIN(conn->pmtud.probing_size, MAX_PLPMTU);

  // Change state
  he_internal_pmtud_change_state(conn, HE_PMTUD_STATE_SEARCH_COMPLETE);

  // Set a timer to retry probe
  return he_internal_pmtud_retry_probe(conn, PMTUD_SUCCESSFUL_SEARCH_RETRY_TIMEOUT_MS);
}

he_return_code_t he_internal_pmtud_blackhole_detected(he_conn_t *conn) {
  if(!conn) {
    return HE_ERR_NULL_POINTER;
  }
  // Check current state
  switch(conn->pmtud.state) {
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
  conn->pmtud.base = MIN_PLPMTU;
  conn->pmtud.probe_count = 0;

  // Start probing base mtu
  return he_internal_pmtud_send_probe(conn, conn->pmtud.base);
}

he_return_code_t he_internal_pmtud_retry_probe(he_conn_t *conn, int delay_ms) {
  he_return_code_t ret = HE_ERR_PMTUD_CALLBACKS_NOT_SET;

  // Retry PMTUD after a delay
  if(conn->pmtud_time_cb) {
    ret = conn->pmtud_time_cb(conn, delay_ms, conn->data);
  }

  conn->pmtud.probe_count = 0;
  return ret;
}
