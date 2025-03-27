/*
    mmap.c: mmap-related tests.
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

#include <entrypoints.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <setjmp.h>
#include <signal.h>
#include <unistd.h>
#include <assert.h>
#include <sys/mman.h>
#include <sys/wait.h>

static size_t pageSize;

static sigjmp_buf restoreEnv;

static void *offsetBy(void *ptr, ptrdiff_t n) {
    return (void *)((uintptr_t)ptr + n);
}

static void signalHandler(int _1, siginfo_t *_2, void *_3) {
    (void)_1; (void)_2; (void)_3;
    siglongjmp(restoreEnv, 1);
}

static bool ensureReadable(void *ptr) {
    if (sigsetjmp(restoreEnv, 1)) {
        return false;
    }

    (void)(*(volatile uint8_t *)ptr);

    return true;
}

static bool ensureWritable(void *ptr) {
    if (sigsetjmp(restoreEnv, 1)) {
        return false;
    }

    *(volatile uint8_t *)ptr = 0;

    return true;
}

static bool ensureNotReadable(void *ptr) {
    if (sigsetjmp(restoreEnv, 1)) {
        return true;
    }

    (void)(*(volatile uint8_t *)ptr);

    return false;
}

static bool ensureNotWritable(void *ptr) {
    if (sigsetjmp(restoreEnv, 1)) {
        return true;
    }

    *(volatile uint8_t *)ptr = 0;

    return false;
}

#define RUNCHECKS(...) do { \
    pid_t pid = fork(); \
    assert_errno("fork", pid >= 0); \
    \
    struct sigaction sa, old_sa; \
    sigemptyset(&sa.sa_mask); \
    sa.sa_sigaction = signalHandler; \
    sa.sa_flags = SA_SIGINFO; \
    \
    int ret = sigaction(SIGSEGV, &sa, &old_sa); \
    assert_errno("sigaction", ret != -1); \
    \
    if (pid == 0) { \
        __VA_ARGS__ \
        exit(0); \
    } else { \
        int status = 0; \
        while (waitpid(pid, &status, 0) == -1) { \
            if (errno == EINTR) continue; \
            assert_errno("waitpid", false); \
        } \
        \
        if (WIFSIGNALED(status) || WEXITSTATUS(status) != 0) { \
            fprintf(stderr, "Test failed on subprocess!\n"); \
            abort(); \
        } \
        \
        __VA_ARGS__ \
    } \
    \
    ret = sigaction(SIGSEGV, &old_sa, NULL); \
    assert_errno("sigaction", ret != -1); \
} while (0)

static void fixed_replace_middle(void) {
    void *mem = mmap(NULL, pageSize * 3, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    assert_errno("mmap", mem != MAP_FAILED);

    void *newPtr = mmap(offsetBy(mem, pageSize), pageSize, PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
    assert_errno("mmap", newPtr != MAP_FAILED);
    assert(newPtr == offsetBy(mem, pageSize));

    RUNCHECKS(
        assert(ensureReadable(mem));
        assert(ensureWritable(mem));

        assert(ensureReadable(offsetBy(mem, pageSize)));
        assert(ensureNotWritable(offsetBy(mem, pageSize)));

        assert(ensureReadable(offsetBy(mem, pageSize * 2)));
        assert(ensureWritable(offsetBy(mem, pageSize * 2)));
    );

    int ret = munmap(mem, pageSize * 3);
    assert_errno("munmap", ret != -1);

    RUNCHECKS(
        assert(ensureNotReadable(mem));
        assert(ensureNotWritable(mem));

        assert(ensureNotReadable(offsetBy(mem, pageSize)));
        assert(ensureNotWritable(offsetBy(mem, pageSize)));

        assert(ensureNotReadable(offsetBy(mem, pageSize * 2)));
        assert(ensureNotWritable(offsetBy(mem, pageSize * 2)));
    );
}

static void fixed_replace_left(void) {
    void *mem = mmap(NULL, pageSize * 2, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    assert_errno("mmap", mem != MAP_FAILED);

    void *newPtr = mmap(mem, pageSize, PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
    assert_errno("mmap", newPtr != MAP_FAILED);
    assert(newPtr == mem);

    RUNCHECKS(
        assert(ensureReadable(mem));
        assert(ensureNotWritable(mem));

        assert(ensureReadable(offsetBy(mem, pageSize)));
        assert(ensureWritable(offsetBy(mem, pageSize)));
    );

    int ret = munmap(mem, pageSize * 2);
    assert_errno("munmap", ret != -1);

    RUNCHECKS(
        assert(ensureNotReadable(mem));
        assert(ensureNotWritable(mem));

        assert(ensureNotReadable(offsetBy(mem, pageSize)));
        assert(ensureNotWritable(offsetBy(mem, pageSize)));
    );
}

static void fixed_replace_right(void) {
    void *mem = mmap(NULL, pageSize * 2, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    assert_errno("mmap", mem != MAP_FAILED);

    void *newPtr = mmap(offsetBy(mem, pageSize), pageSize, PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
    assert_errno("mmap", newPtr != MAP_FAILED);
    assert(newPtr == offsetBy(mem, pageSize));

    RUNCHECKS(
        assert(ensureReadable(mem));
        assert(ensureWritable(mem));

        assert(ensureReadable(offsetBy(mem, pageSize)));
        assert(ensureNotWritable(offsetBy(mem, pageSize)));
    );

    int ret = munmap(mem, pageSize * 2);
    assert_errno("munmap", ret != -1);

    RUNCHECKS(
        assert(ensureNotReadable(mem));
        assert(ensureNotWritable(mem));

        assert(ensureNotReadable(offsetBy(mem, pageSize)));
        assert(ensureNotWritable(offsetBy(mem, pageSize)));
    );
}

static void partial_protect_middle(void) {
    void *mem = mmap(NULL, pageSize * 3, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    assert_errno("mmap", mem != MAP_FAILED);

    int ret = mprotect(offsetBy(mem, pageSize), pageSize, PROT_READ);
    assert_errno("mprotect", ret != -1);

    RUNCHECKS(
        assert(ensureReadable(mem));
        assert(ensureWritable(mem));

        assert(ensureReadable(offsetBy(mem, pageSize)));
        assert(ensureNotWritable(offsetBy(mem, pageSize)));

        assert(ensureReadable(offsetBy(mem, pageSize * 2)));
        assert(ensureWritable(offsetBy(mem, pageSize * 2)));
    );

    ret = munmap(mem, pageSize * 3);
    assert_errno("munmap", ret != -1);

    RUNCHECKS(
        assert(ensureNotReadable(mem));
        assert(ensureNotWritable(mem));

        assert(ensureNotReadable(offsetBy(mem, pageSize)));
        assert(ensureNotWritable(offsetBy(mem, pageSize)));

        assert(ensureNotReadable(offsetBy(mem, pageSize * 2)));
        assert(ensureNotWritable(offsetBy(mem, pageSize * 2)));
    );
}

static void partial_protect_left(void) {
    void *mem = mmap(NULL, pageSize * 2, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    assert_errno("mmap", mem != MAP_FAILED);

    int ret = mprotect(mem, pageSize, PROT_READ);
    assert_errno("mprotect", ret != -1);

    RUNCHECKS(
        assert(ensureReadable(mem));
        assert(ensureNotWritable(mem));

        assert(ensureReadable(offsetBy(mem, pageSize)));
        assert(ensureWritable(offsetBy(mem, pageSize)));
    );

    ret = munmap(mem, pageSize * 2);
    assert_errno("munmap", ret != -1);

    RUNCHECKS(
        assert(ensureNotReadable(mem));
        assert(ensureNotWritable(mem));

        assert(ensureNotReadable(offsetBy(mem, pageSize)));
        assert(ensureNotWritable(offsetBy(mem, pageSize)));
    );
}

static void partial_protect_right(void) {
    void *mem = mmap(NULL, pageSize * 2, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    assert_errno("mmap", mem != MAP_FAILED);

    int ret = mprotect(offsetBy(mem, pageSize), pageSize, PROT_READ);
    assert_errno("mprotect", ret != -1);

    RUNCHECKS(
        assert(ensureReadable(mem));
        assert(ensureWritable(mem));

        assert(ensureReadable(offsetBy(mem, pageSize)));
        assert(ensureNotWritable(offsetBy(mem, pageSize)));
    );

    ret = munmap(mem, pageSize * 2);
    assert_errno("munmap", ret != -1);

    RUNCHECKS(
        assert(ensureNotReadable(mem));
        assert(ensureNotWritable(mem));

        assert(ensureNotReadable(offsetBy(mem, pageSize)));
        assert(ensureNotWritable(offsetBy(mem, pageSize)));
    );
}

static void partial_unmap_middle(void) {
    void *mem = mmap(NULL, pageSize * 3, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    assert_errno("mmap", mem != MAP_FAILED);

    int ret = munmap(offsetBy(mem, pageSize), pageSize);
    assert_errno("munmap", ret != -1);

    RUNCHECKS(
        assert(ensureReadable(mem));
        assert(ensureWritable(mem));

        assert(ensureNotReadable(offsetBy(mem, pageSize)));
        assert(ensureNotWritable(offsetBy(mem, pageSize)));

        assert(ensureReadable(offsetBy(mem, pageSize * 2)));
        assert(ensureWritable(offsetBy(mem, pageSize * 2)));
    );

    ret = munmap(mem, pageSize * 3);
    assert_errno("munmap", ret != -1);

    RUNCHECKS(
        assert(ensureNotReadable(mem));
        assert(ensureNotWritable(mem));

        assert(ensureNotReadable(offsetBy(mem, pageSize)));
        assert(ensureNotWritable(offsetBy(mem, pageSize)));

        assert(ensureNotReadable(offsetBy(mem, pageSize * 2)));
        assert(ensureNotWritable(offsetBy(mem, pageSize * 2)));
    );
}

static void partial_unmap_left(void) {
    void *mem = mmap(NULL, pageSize * 2, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    assert_errno("mmap", mem != MAP_FAILED);

    int ret = munmap(mem, pageSize);
    assert_errno("munmap", ret != -1);

    RUNCHECKS(
        assert(ensureNotReadable(mem));
        assert(ensureNotWritable(mem));

        assert(ensureReadable(offsetBy(mem, pageSize)));
        assert(ensureWritable(offsetBy(mem, pageSize)));
    );

    ret = munmap(mem, pageSize * 2);
    assert_errno("munmap", ret != -1);

    RUNCHECKS(
        assert(ensureNotReadable(mem));
        assert(ensureNotWritable(mem));

        assert(ensureNotReadable(offsetBy(mem, pageSize)));
        assert(ensureNotWritable(offsetBy(mem, pageSize)));
    );
}

static void partial_unmap_right(void) {
    void *mem = mmap(NULL, pageSize * 2, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    assert_errno("mmap", mem != MAP_FAILED);

    int ret = munmap(offsetBy(mem, pageSize), pageSize);
    assert_errno("munmap", ret != -1);

    RUNCHECKS(
        assert(ensureReadable(mem));
        assert(ensureWritable(mem));

        assert(ensureNotReadable(offsetBy(mem, pageSize)));
        assert(ensureNotWritable(offsetBy(mem, pageSize)));
    );

    ret = munmap(mem, pageSize * 2);
    assert_errno("munmap", ret != -1);

    RUNCHECKS(
        assert(ensureNotReadable(mem));
        assert(ensureNotWritable(mem));

        assert(ensureNotReadable(offsetBy(mem, pageSize)));
        assert(ensureNotWritable(offsetBy(mem, pageSize)));
    );
}

static void unmap_range_before_first(void) {
    pageSize = getpagesize();

    void *mem = mmap((void *)(0x100000 + pageSize * 2), pageSize,
            PROT_READ | PROT_WRITE, MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    assert_errno("mmap", mem != MAP_FAILED);

    int ret = munmap((void *)(0x100000 + pageSize), pageSize * 2);
    assert_errno("munmap", ret != -1);

    RUNCHECKS(
        assert(ensureNotReadable(mem));
        assert(ensureNotWritable(mem));
    );
}

static void check_whether_split_mappings_get_protected_correctly(void) {
    void *mem = mmap(NULL, 0x6000, PROT_READ | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    assert_errno("mmap", mem != MAP_FAILED);
    int ret = mprotect(mem, 0x1000, PROT_READ | PROT_WRITE);
    assert_errno("mprotect", ret != -1);
    ret = mprotect(mem, 0x1000, PROT_READ | PROT_EXEC);
    assert_errno("mprotect", ret != -1);
    ret = mprotect(mem, 0x5000, PROT_READ | PROT_WRITE);
    assert_errno("mprotect", ret != -1);

    RUNCHECKS(
        assert(ensureWritable(mem));
    );
}

static void check_whether_three_way_split_mappings_are_handled_correctly(void) {
    void *mem = mmap(NULL, pageSize * 3, PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    assert_errno("mmap", mem != MAP_FAILED);
    int ret = mprotect(offsetBy(mem, pageSize), pageSize, PROT_READ | PROT_WRITE);
    assert_errno("mprotect", ret != -1);

    RUNCHECKS(
        assert(ensureNotWritable(mem));
        assert(ensureWritable(offsetBy(mem, pageSize)));
        assert(ensureNotWritable(offsetBy(mem, pageSize * 2)));
    );
}

void mmap_run_tests(void) {
    pageSize = getpagesize();

    fixed_replace_middle();
    fixed_replace_left();
    fixed_replace_right();
    partial_protect_middle();
    partial_protect_left();
    partial_protect_right();
    partial_unmap_middle();
    partial_unmap_left();
    partial_unmap_right();
    unmap_range_before_first();
    check_whether_split_mappings_get_protected_correctly();
    check_whether_three_way_split_mappings_are_handled_correctly();
}
