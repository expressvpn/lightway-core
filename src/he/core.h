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

/**
 * @file core.h
 * @brief Utility functions
 *
 */

#ifndef CORE_H
#define CORE_H

#include <he.h>

/**
 * @brief Setup the pointers and counters for reading from a TCP stream
 */
he_return_code_t he_internal_setup_stream_state(he_conn_t *conn, uint8_t *data, size_t length);

/**
 * Out of the box, Unity doesn't allow us to mock intra-module function calls.
 * This is generally OK but is *very* annoying for the packet lifecycle functions,
 * where we pass control to a bunch of various functions in a pipeline, so
 * instead of artificially breaking these functions into different modules we
 * just mock the "handover" here with a dispatch macro.
 *
 * If TEST isn't defined this just compiles down to a function call, so there's
 * zero performance penalty AND we would get compile errors if the function is
 * called incorrectly.
 */
#ifdef TEST
#include "fake_dispatch.h"  // Never implemented, only used as a mock
#define HE_DISPATCH(func, ...) dispatch("" #func "", ##__VA_ARGS__);
#define HE_DISPATCH_CONN(func, conn) dispatch_conn("" #func "", conn);
#else
#define HE_DISPATCH(func, ...) func(__VA_ARGS__);
#define HE_DISPATCH_CONN(func, ...) func(__VA_ARGS__);
#endif  // TEST

#endif  // CORE_H
