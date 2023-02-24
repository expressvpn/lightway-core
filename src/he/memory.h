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
 * @file memory.h
 * @brief Customisation of allocators if desired
 *
 */

#ifndef MEMORY_H
#define MEMORY_H

#include "he.h"
#include "he_internal.h"

/**
 * @brief Set allocators for use by libhelium
 * @param malloc A function that conforms to the signature of malloc(3)
 * @param calloc A function that conforms to the signature of calloc(3)
 * @param realloc A function that conforms to the signature of realloc(3)
 * @param free A function that conforms to the signature of free(3)
 *
 * @return HE_SUCCESS Currently this function cannot fail
 * @note If this function is not called, Helium will use system allocators by default
 */
he_return_code_t he_set_allocators(he_malloc_t malloc, he_calloc_t calloc, he_realloc_t realloc,
                                   he_free_t free);

/**
 * @brief Allocate memory using the internal malloc function set by he_set_allocators()
 * @note The caller must call he_free when the allocated memory is no longer used
 */
void *he_malloc(size_t size);

/**
 * @brief Allocate memory using the internal calloc function set by he_set_allocators()
 * @note The caller must call he_free when the allocated memory is no longer used
 */
void *he_calloc(size_t nmemb, size_t size);

/**
 * @brief Allocate memory using the internal realloc function set by he_set_allocators()
 * @note The caller must call he_free when the allocated memory is no longer used
 */
void *he_realloc(void *ptr, size_t size);

/**
 * @brief Free memory using the internal free function set by he_set_allocators()
 */
void he_free(void *ptr);

#endif  // MEMORY_H
