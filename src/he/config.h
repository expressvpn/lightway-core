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
 * @file config.h
 * @brief Internal configuration conenvience functions
 *
 */

#ifndef CONFIG_H
#define CONFIG_H

#include <he.h>

// Helpers - internal only below this point

/**
 * @brief Checks to make sure the string does not exceed the maximum
 * @param string The string to test
 * @return Whether the length is okay
 */
bool he_internal_config_is_string_length_okay(const char *string);

bool he_internal_config_is_empty_string(const char *string);
bool he_internal_config_is_string_too_long(const char *string);

he_return_code_t he_internal_set_config_string(char *field, const char *value);
he_return_code_t he_internal_set_config_int(int *field, int value);

#endif  // CONFIG_H
