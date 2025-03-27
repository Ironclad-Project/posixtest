/*
    entrypoints.h: Entrypoints of the project's tests.
    Copyright (C) 2023 streaksu

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

void mmap_run_tests(void);

int test_dgram_simple(void);
int test_dgram_fd(void);
int test_stream_simple(void);

#define assert_errno(fail_func, expr) ((void)(((expr) ? 1 : 0) || (assert_errno_fail(fail_func, #expr, __FILE__, __PRETTY_FUNCTION__, __LINE__), 0)))

static inline void assert_errno_fail(const char *fail_func, const char *expr,
        const char *file, const char *func, int line) {
    int err = errno;
    fprintf(stderr, "In function %s, file %s:%d: Function %s failed with error '%s'; failing assertion: '%s'\n",
            func, file, line, fail_func, strerror(err), expr);
    abort();
    __builtin_unreachable();
}
