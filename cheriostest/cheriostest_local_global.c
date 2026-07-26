/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2021 SRI International
 * Copyright (c) 2025-2026 Paul Metzger
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
 * DARPA SSITH research programme.
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

#if !__has_feature(capabilities)
#error "This code requires a CHERI-aware compiler"
#endif

#if __linux__
#include <signal.h>
#endif

#include <sys/param.h>

#include <cheri/cheric.h>
#ifdef __FreeBSD__
#include <cheri/cheri.h>
#endif

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cheriostest.h"

#ifdef __linux__
#include "cheriostest_compat.h"
#endif

#define	NOT_IMPL_MSG "This test hasn't been fully implemented for RISC-V yet"

#define	STR_VAL	"123"

static const char *
skip_local_global_required(const struct cheri_test *test __attribute__((__unused__)))
{
#if defined(__riscv_zcheripurecap)
	FILE *f;
	ssize_t buf_size = 4096;
	char *line = malloc(buf_size);

	f = fopen("/proc/cpuinfo", "r");
	if (f == NULL)
		cheriostest_failure_errx("Couldn't open /proc/cpuinfo");

	while (getline(&line, &buf_size, f) != -1) {
		if (strstr(line, "isa") != NULL) {
			if (strstr(line, "zcherilevels") != NULL) {
				free(line);
				return NULL;
			}
		}
	}
	free(line);
	return ("zcherilevels required");
#else
	return NULL;
#endif
}

CHERIOSTEST(store_local_allowed,
    "Checks local capabilities can be stored via default capabilities",
    .ct_check_skip = skip_local_global_required,)
{
	char str[] = STR_VAL;
	char * __capability cap = str;
	char * __capability target;
	char * __capability * __capability targetp = &target;

	CHERIOSTEST_VERIFY(strcmp(STR_VAL, str) == 0);
	*targetp = cap;
	CHERIOSTEST_VERIFY(
	    strcmp(STR_VAL, (__cheri_fromcap char *)target) == 0);

	/* Make cap local */
	cap = cheri_perms_and(cap, ~CHERI_PERM_GLOBAL);

	/* Store local cap through cap with store-local permission */
	*targetp = cap;
	CHERIOSTEST_VERIFY(
	    strcmp(STR_VAL, (__cheri_fromcap char *)target) == 0);

	cheriostest_success();
}

#ifndef __riscv_zcherilevels
CHERIOSTEST(store_local_disallowed,
    "Checks local capabilities can not be stored via non-store-local capabilities",
#ifdef __FreeBSD__
    .ct_flags = CT_FLAG_SIGNAL | CT_FLAG_SI_CODE | CT_FLAG_SI_TRAPNO,
    .ct_signum = SIGPROT,
    .ct_si_code = SI_CODE_STORELOCAL,
    .ct_si_trapno = TRAPNO_LOAD_STORE,
#elif defined(__linux__)
    .ct_flags = CT_FLAG_SIGNAL | CT_FLAG_SI_CODE,
    .ct_signum = SIGSEGV,
#if defined(__aarch64__) && defined(SEGV_CAPPERMERR)
    .ct_si_code = SEGV_CAPPERMERR,
#elif defined(__riscv)
    .ct_si_code = SEGV_CAPTAGERR,
#endif
#endif
)
#else
CHERIOSTEST(store_local_disallowed,
    "Checks tag is stripped when local capabilities are stored via non-store-local capabilities")
#endif
{
	char str[] = STR_VAL;
	char * __capability cap = str;
	char * __capability volatile target;
	char * __capability volatile * __capability targetp = &target;

	CHERIOSTEST_VERIFY(strcmp(STR_VAL, str) == 0);
	*targetp = cap;
	CHERIOSTEST_VERIFY(
	    strcmp(STR_VAL, (__cheri_fromcap char *)target) == 0);

	/*
	 * Make cap local, and then store local cap through cap without
	 * store-local permission.
	 */
	cap = cheri_perms_and(cap, ~CHERI_PERM_GLOBAL);
	targetp = cheri_perms_and(targetp, ~CHERI_PERM_STORE_LOCAL_CAP);
	/* This should fault on Morello */
	*targetp = cap;

	/* RVY just strips tags. */
#ifdef __riscv_zcherilevels
	CHERIOSTEST_VERIFY(cheri_tag_get(*targetp) == 0);
	cheriostest_success();
#else
	cheriostest_failure_errx(
	    "No fault after storing local cap via non-store-local cap");
#endif
}
