/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2023 SRI International
 * Copyright (c) 2026 Paul Metzger
 *
 * This software was developed by the CHERI Research Centre (CRC) in the
 * Department of Computer Science and Technology at the University of
 * Cambridge under the EPSRC grant "UKRI3001: CHERI Research Centre".
 *
 * This software was developed by SRI International, the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology), and Capabilities Limited under Defense Advanced Research
 * Projects Agency (DARPA) Contract No. HR001123C0031 ("MTSS").
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifdef __FreeBSD__
#include <sys/mount.h>
#include <sys/procctl.h>

#include <malloc_np.h>
#endif

#include <sys/param.h>
#include <sys/wait.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

#include "cheriostest.h"

#define THE_CHERI_LINUX_PROJECT_DOES_NOT_SUPPORT_REVOC_MSG \
	"The CHERI Linux Project does not support revocation"

extern volatile void *eptr;
volatile void *eptr;

static const char *
skip_malloc_revocation_disabled(const struct cheri_test *ctp __attribute__((__unused__)))
{
#ifdef __FreeBSD__
	if (malloc_revoke_enabled())
		return (NULL);
	return ("malloc quarantine disabled");
#elif defined(__linux__)
	return (THE_CHERI_LINUX_PROJECT_DOES_NOT_SUPPORT_REVOC_MSG);
#endif
}

CHERIOSTEST(malloc_double_free, "malloc aborts on double free",
    .ct_flags = CT_FLAG_SIGEXIT,
    .ct_signum = SIGABRT,
#if defined(__linux__)
    .ct_xfail_reason = "Not supported",
#else
    .ct_check_skip = skip_malloc_revocation_disabled,
#endif
)
{
#ifdef __linux__
	cheriostest_failure_errx(THE_CHERI_LINUX_PROJECT_DOES_NOT_SUPPORT_REVOC_MSG);
#else
	volatile void *ptr;

	/* Externalize to prevent malloc() from being optimized away */
	eptr = ptr = malloc(2);

	free(__DEVOLATILE(void *, ptr));
	free(__DEVOLATILE(void *, ptr));

	cheriostest_failure_errx("malloc() did not abort");
#endif
}


CHERIOSTEST(malloc_revoke_basic,
    "verify that a free'd pointer is revoked by malloc_revoke",
#if defined(__linux__)
    .ct_xfail_reason = "Not supported",
#else
    .ct_check_skip = skip_malloc_revocation_disabled,
#endif
)
{
#ifdef __linux__
	cheriostest_failure_errx(THE_CHERI_LINUX_PROJECT_DOES_NOT_SUPPORT_REVOC_MSG);
#else
	volatile void *ptr __attribute__((__unused__));

	/*
	 * Try to get the compiler to spill the pointer to memory.
	 */
	eptr = ptr = malloc(1);

	free(__DEVOLATILE(void *, ptr));

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
	malloc_revoke();
#pragma GCC diagnostic pop
	CHERIOSTEST_VERIFY2(!cheri_tag_get(ptr),
	    "revoked ptr not revoked %#lp", ptr);
	CHERIOSTEST_VERIFY2(!cheri_tag_get(eptr),
	    "revoked eptr not revoked %#lp", eptr);

	cheriostest_success();
#endif
}

#ifdef __FreeBSD__
CHERIOSTEST(malloc_revoke_quarantine_force_flush_basic,
    "verify that a free'd pointer is revoked by malloc_revoke_quarantine_force_flush",
    .ct_check_skip = skip_malloc_revocation_disabled)
{
	volatile void *ptr __attribute__((__unused__));
	int ret;

	/*
	 * Try to get the compiler to spill the pointer to memory.
	 */
	eptr = ptr = malloc(1);

	free(__DEVOLATILE(void *, ptr));

	CHERIOSTEST_VERIFY2((ret = malloc_revoke_quarantine_force_flush()) == 0,
	    "malloc_revoke_quarantine_force_flush returned %d", ret);
	CHERIOSTEST_VERIFY2(!cheri_tag_get(ptr),
	    "revoked ptr not revoked %#lp", ptr);
	CHERIOSTEST_VERIFY2(!cheri_tag_get(eptr),
	    "revoked eptr not revoked %#lp", eptr);

	cheriostest_success();
}

extern volatile void *eptr1, *eptr2;
volatile void *eptr1, *eptr2;

CHERIOSTEST(malloc_revoke_quarantine_force_flush_twice,
    "flush the quarantine twice back to back",
    .ct_check_skip = skip_malloc_revocation_disabled)
{
	volatile void *ptr1, *ptr2;
	int ret;

	/*
	 * Try to get the compiler to spill the pointers to memory.
	 */
	eptr1 = ptr1 = malloc(1);
	eptr2 = ptr2 = malloc(1);

	free(__DEVOLATILE(void *, ptr1));

	CHERIOSTEST_VERIFY2((ret = malloc_revoke_quarantine_force_flush()) == 0,
	    "malloc_revoke_quarantine_force_flush returned %d", ret);
	CHERIOSTEST_VERIFY2(!cheri_tag_get(ptr1),
	    "revoked ptr1 not revoked %#lp", ptr1);
	CHERIOSTEST_VERIFY2(!cheri_tag_get(eptr1),
	    "revoked eptr1 not revoked %#lp", eptr1);

	free(__DEVOLATILE(void *, ptr2));

	CHERIOSTEST_VERIFY2((ret = malloc_revoke_quarantine_force_flush()) == 0,
	    "malloc_revoke_quarantine_force_flush returned %d", ret);
	CHERIOSTEST_VERIFY2(!cheri_tag_get(ptr2),
	    "revoked ptr2 not revoked %#lp", ptr2);
	CHERIOSTEST_VERIFY2(!cheri_tag_get(eptr2),
	    "revoked eptr2 not revoked %#lp", eptr2);

	cheriostest_success();
}
#elif defined(__linux__)
#pragma message "The CHERI Linux Project does not support revocation"
#endif

CHERIOSTEST(malloc_zero_size,
    "Check that allocators return non-NULL for size=0")
{
	void *ptr, *ptr2;

	CHERIOSTEST_VERIFY((ptr = malloc(0)) != NULL);
	free(ptr);

	CHERIOSTEST_VERIFY((ptr = calloc(0, 1)) != NULL);
	free(ptr);
	CHERIOSTEST_VERIFY((ptr = calloc(1, 0)) != NULL);
	free(ptr);
	CHERIOSTEST_VERIFY((ptr = calloc(0, 0)) != NULL);
	free(ptr);

	CHERIOSTEST_VERIFY((ptr = realloc(NULL, 0)) != NULL);
	CHERIOSTEST_VERIFY((ptr2 = realloc(ptr, 0)) != NULL);
	/*
	 * XXX: POSIX requires that: "A pointer to the allocated space
	 * shall be returned, and the memory object pointed to by ptr
	 * shall be freed."  Unfortunately that's impractical to check as
	 * even with revocation the same storage could be allocated if
	 * revocation is triggered internally.
	 */
	free(ptr2);

	/*
	 * C/POSIX require that aligned_alloc/posix_memalign take
	 * alignements that are a power-of-2 multiple of sizeof(void *).
	 */
	CHERIOSTEST_VERIFY((ptr = aligned_alloc(sizeof(void *), 0)) != NULL);
	free(ptr);

	CHERIOSTEST_VERIFY2(posix_memalign(&ptr, sizeof(void *), 0) == 0,
	    "posix_memalign failed, errno %d", errno);
	CHERIOSTEST_VERIFY2(ptr != NULL, "posix_memalign returned NULL");
	free(ptr);

	CHERIOSTEST_VERIFY((ptr = memalign(sizeof(void *), 0)) != NULL);
	free(ptr);

	cheriostest_success();
}

/*
 * No else branch because the CHERI Linux Project does not support
 * revocation yet.
 */
#ifdef __FreeBSD__
static bool
child_is_revoking(int pid)
{
	int res;

	waitpid(pid, &res, 0);
	if (WIFEXITED(res)) {
		if (WEXITSTATUS(res) == 0)
			return (true);
		else
			return (false);
	} else
		cheriostest_failure_errx("child exec failed");
}

/*
 * The suid_*_protctl_* tests rely on exec()ing a setuid helper dropping the
 * revocation setting inherited via procctl(). p9fs does not honour the setuid
 * bit, so when running straight from a build directory shared with the host
 * (as cheribuild's --test does) there is no privilege transition and those
 * tests would report bogus failures.
 */
static const char *
skip_need_suid_helpers_and_cheri_revoke(const struct cheri_test *ctp)
{
	struct statfs sb;
	const char *reason;

	reason = skip_need_cheri_revoke(ctp);
	if (reason != NULL)
		return (reason);

	if (statfs(cheriostest_get_helper_dir(), &sb) != 0)
		return ("could not statfs the helper directory");
	if (strcmp(sb.f_fstypename, "p9fs") == 0)
		return ("helpers are on p9fs, which ignores the setuid bit");
	return (NULL);
}

static void
malloc_revocation_ctl_common_procctl(const char *progname,
    bool should_be_revoking, int *procctl_arg)
{
	int pid;

	pid = fork();
	CHERIOSTEST_VERIFY(pid >= 0);
	if (pid == 0) {
		char *progpath;
		char *argv[2];

		if (procctl_arg != NULL)
			CHERIOSTEST_CHECK_SYSCALL(procctl(P_PID, getpid(),
			    PROC_CHERI_REVOKE_CTL, procctl_arg));

		asprintf(&progpath, "%s/%s", cheriostest_get_helper_dir(),
		    progname);
		argv[0] = progpath;
		argv[1] = NULL;
		execve(argv[0], argv, NULL);
		abort();
	} else {
		if (child_is_revoking(pid) == should_be_revoking)
			cheriostest_success();
		else {
			if (should_be_revoking)
				cheriostest_failure_errx(
				    "child is not revoking and should be");
			else
				cheriostest_failure_errx(
				    "child is revoking and should not be");
		}
	}
}

static void
malloc_revocation_ctl_common(const char *progname, bool should_be_revoking)
{
	malloc_revocation_ctl_common_procctl(progname, should_be_revoking,
	    NULL);
}

CHERIOSTEST(malloc_revocation_ctl_baseline,
    "A base binary reports revocation is enabled",
    .ct_check_skip = skip_need_default_cheri_revoke)
{
	malloc_revocation_ctl_common("malloc_revoke_enabled", true);
}

CHERIOSTEST(malloc_revocation_ctl_elfnote_disable,
    "A binary with elfnote disabling reports revocation is disable",
    .ct_check_skip = skip_need_cheri_revoke)
{
	malloc_revocation_ctl_common("malloc_revoke_enabled_elfnote_disable",
	    false);
}

CHERIOSTEST(malloc_revocation_ctl_elfnote_enable,
    "A binary with elfnote enabling reports revocation is enabled",
    .ct_check_skip = skip_need_cheri_revoke)
{
	malloc_revocation_ctl_common("malloc_revoke_enabled_elfnote_enable",
	    true);
}

CHERIOSTEST(malloc_revocation_ctl_elfnote_disable_protctl_enable,
    "A binary with elfnote disabling reports revocation is disable",
    .ct_check_skip = skip_need_cheri_revoke)
{
	int arg = PROC_CHERI_REVOKE_FORCE_ENABLE;

	malloc_revocation_ctl_common_procctl(
	    "malloc_revoke_enabled_elfnote_disable", true, &arg);
}

CHERIOSTEST(malloc_revocation_ctl_elfnote_enable_protctl_disable,
    "A binary with elfnote enabling reports revocation is enabled",
    .ct_check_skip = skip_need_cheri_revoke)
{
	int arg = PROC_CHERI_REVOKE_FORCE_DISABLE;

	malloc_revocation_ctl_common_procctl(
	    "malloc_revoke_enabled_elfnote_enable", false, &arg);
}

CHERIOSTEST(malloc_revocation_ctl_suid_baseline,
    "A suid binary reports revocation is enabled",
    .ct_check_skip = skip_need_default_cheri_revoke)
{
	malloc_revocation_ctl_common("malloc_revoke_enabled_suid", true);
}

CHERIOSTEST(malloc_revocation_ctl_suid_elfnote_disable,
    "A suid binary with elfnote disabling reports revocation is disable",
    .ct_check_skip = skip_need_cheri_revoke)
{
	malloc_revocation_ctl_common("malloc_revoke_enabled_elfnote_disable",
	    false);
}

CHERIOSTEST(malloc_revocation_ctl_suid_elfnote_enable,
    "A suid binary with elfnote enabling reports revocation is enabled",
    .ct_check_skip = skip_need_cheri_revoke)
{
	malloc_revocation_ctl_common("malloc_revoke_enabled_elfnote_enable",
	    true);
}

CHERIOSTEST(malloc_revocation_ctl_suid_elfnote_disable_protctl_enable,
    "A binary with elfnote disabling reports revocation is disable",
    .ct_check_skip = skip_need_suid_helpers_and_cheri_revoke)
{
	int arg = PROC_CHERI_REVOKE_FORCE_ENABLE;

	malloc_revocation_ctl_common_procctl(
	    "malloc_revoke_enabled_suid_elfnote_disable", false, &arg);
}

CHERIOSTEST(malloc_revocation_ctl_suid_elfnote_enable_protctl_disable,
    "A binary with elfnote enabling reports revocation is enabled",
    .ct_check_skip = skip_need_suid_helpers_and_cheri_revoke)
{
	int arg = PROC_CHERI_REVOKE_FORCE_DISABLE;

	malloc_revocation_ctl_common_procctl(
	    "malloc_revoke_enabled_suid_elfnote_enable", true, &arg);
}
#endif

CHERIOSTEST(malloc_early_constructor,
    "invoke malloc in an early constructor",
    .ct_check_skip = cheriostest_skip_no_helper)
{
	pid_t pid;
	int res;
	char *helper_path = strdup(cheriostest_get_helper_path());

	pid = fork();
	CHERIOSTEST_VERIFY(pid >= 0);
	if (pid == 0) {
		char *argv[2];

		argv[0] = helper_path;
		argv[1] = NULL;
		execve(argv[0], argv, NULL);
		abort();
	} else {
		waitpid(pid, &res, 0);
		if (WIFEXITED(res) && WEXITSTATUS(res) == 0)
			cheriostest_success();
		else
			cheriostest_failure_errx("child %s exited improperly",
			    helper_path);
	}
}

#ifdef __FreeBSD__
static void
check_mallocx(size_t size)
{
	void *data;

	data = mallocx(size, MALLOCX_ALIGN(size));
	CHERIOSTEST_VERIFY2(__builtin_is_aligned(data, size),
	    "mallocx(%#zx, MALLOCX_ALIGN(%#zx (%#x))) -> %#lp: "
	    "Not correctly aligned! offset: %#zx\n",
	    size, size, MALLOCX_ALIGN(size), data, (ptraddr_t)data -
	    (ptraddr_t)__builtin_align_down(data, size));
	free(data);
}

CHERIOSTEST(mallocx_alignment, "Check that mallocx aligns allocations")
{
	size_t sizes[] = {0x400, 0x800, 0x1000, 0x2000, 0x4000, 0x8000,
	    0x10000};

	for (size_t i = 0; i < cheritest_nitems(sizes); i++)
		check_mallocx(sizes[i]);

	cheriostest_success();
}

static void
check_rallocx(size_t size)
{
	void *data = malloc(1);

	data = rallocx(data, size, MALLOCX_ALIGN(size));
	CHERIOSTEST_VERIFY2(__builtin_is_aligned(data, size),
	    "rallocx(%#zx, MALLOCX_ALIGN(%#zx (%#x))) -> %#lp: "
	    "Not correctly aligned! offset: %#zx\n",
	    size, size, MALLOCX_ALIGN(size), data, (ptraddr_t)data -
	    (ptraddr_t)__builtin_align_down(data, size));
}

CHERIOSTEST(rallocx_alignment, "Check that rallocx aligns allocations")
{
	size_t sizes[] = {0x400, 0x800, 0x1000, 0x2000, 0x4000, 0x8000,
	    0x10000};

	for (size_t i = 0; i < cheritest_nitems(sizes); i++)
		check_rallocx(sizes[i]);

	cheriostest_success();
}
#endif
