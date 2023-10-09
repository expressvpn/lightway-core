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

/**
 * @file pmtud.h
 * @brief Path MTU Discovery functions
 *
 */

#ifndef PMTUD_H
#define PMTUD_H

typedef enum he_pmtud_state {
  // The DISABLED state is the initial state before probing has started.
  // It is also entered from any other state, when the PL indicates loss of
  // connectivity. This state is left once the PL indicates connectivity to the
  // remote PL. When transitioning to the BASE state, a probe packet of size
  // BASE_PLPMTU can be sent immediately
  HE_PMTUD_STATE_DISABLED = 0,

  // The BASE state is used to confirm that the BASE_PLPMTU size is supported by
  // the network path and is designed to allow an application to continue working
  // when there are transient reductions in the actual PMTU. It also seeks to avoid
  // long periods when a sender searching for a larger PLPMTU is unaware that
  // packets are not being delivered due to a packet or ICMP black hole.
  HE_PMTUD_STATE_BASE = 1,

  // The SEARCHING state is the main probing state. This state is entered when
  // probing for the BASE_PLPMTU completes.
  HE_PMTUD_STATE_SEARCHING = 2,

  // The SEARCH_COMPLETE state indicates that a search has completed. This is the
  // normal maintenance state, where the PL is not probing to update the PLPMTU.
  // DPLPMTUD remains in this state until either the PMTU_RAISE_TIMER expires or a
  // black hole is detected.
  HE_PMTUD_STATE_SEARCH_COMPLETE = 3,

  // The ERROR state represents the case where either the network path is not known
  // to support a PLPMTU of at least the BASE_PLPMTU size or when there is
  // contradictory information about the network path that would otherwise result
  // in excessive variation in the MPS signaled to the higher layer. The state
  // implements a method to mitigate oscillation in the state-event engine.
  HE_PMTUD_STATE_ERROR = 4,
} he_pmtud_state_t;

#endif  // PMTUD_H
