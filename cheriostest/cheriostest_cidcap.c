/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2023 SRI International
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
#include <stdint.h>
#include <sys/sysctl.h>
#include <cheri/cidcap.h>
#endif

#include <sys/types.h>
#include "cheriostest.h"

#if defined(CHERI_PERM_COMPARTMENT_ID)
static void
check_cidcap(uintcap_t cidcap, size_t base, size_t length, size_t offset)
{
	uint64_t v;

	if (base != (size_t)-1) {
		/* Base. */
		v = cheri_base_get(cidcap);
		if (v != base)
			cheriostest_failure_errx("base %jx (expected %jx)", v,
			    (uintmax_t)base);
	}

	/* Length. */
	v = cheri_length_get(cidcap);
	if (v != length)
		cheriostest_failure_errx("length 0x%jx (expected 0x%jx)", v,
		    (uintmax_t)length);

	/* Offset. */
	v = cheri_offset_get(cidcap);
	if (v != offset)
		cheriostest_failure_errx("offset %jx (expected %jx)", v,
		    (uintmax_t)offset);

	/* Type -- should have unsealed type. */
	v = cheri_type_get(cidcap);
	if (v != (u_register_t)CHERI_OTYPE_UNSEALED)
		cheriostest_failure_errx("otype %jx (expected %jx)", v,
		    (uintmax_t)CHERI_OTYPE_UNSEALED);

	/* Permissions. */
	v = cheri_perms_get(cidcap);
	if (v != CHERI_COMPARTMENT_ID_USERSPACE_PERMS)
		cheriostest_failure_errx("perms %jx (expected %jx)", v,
		    (uintmax_t)CHERI_COMPARTMENT_ID_USERSPACE_PERMS);

	/* Sealed bit. */
	v = cheri_is_sealed(cidcap);
	if (v != 0)
		cheriostest_failure_errx("sealed %jx (expected 0)", v);

	/* Tag bit. */
	v = cheri_tag_get(cidcap);
	if (v != 1)
		cheriostest_failure_errx("tag %jx (expected 1)", v);
}

#ifdef __FreeBSD__
static uintcap_t
get_cidcap_sysctl(void)
{
	uintcap_t cidcap;
	size_t cidcap_size;

	cidcap_size = sizeof(cidcap);
	CHERIOSTEST_CHECK_SYSCALL(sysctlbyname("security.cheri.cidcap",
		&cidcap, &cidcap_size, NULL, 0));

	return (cidcap);
}

# XXXPM: Add tests for CHERI Alliance's AT_CHERI_CID_CAP
CHERIOSTEST(cidcap_sysctl, "Retrieve cidcap using sysctl(3)")
{
	uintcap_t cidcap;

	cidcap = get_cidcap_sysctl();

	check_cidcap(cidcap, CHERI_COMPARTMENT_ID_USERSPACE_BASE,
	    CHERI_COMPARTMENT_ID_USERSPACE_LENGTH,
	    CHERI_COMPARTMENT_ID_USERSPACE_OFFSET);

	cheriostest_success();
}
#endif
#endif

#if defined(CHERI_PERM_COMPARTMENT_ID) \
	|| (defined(__linux__) && defined(__aarch64__))
CHERIOSTEST(cidcap_alloc,
	"Retrieve cidcap using cheri_cidcap_alloc(2)",
#ifdef __linux__
	.ct_xfail_reason = "Not supported"
#endif
)
{
#ifdef __linux__
	cheriostest_failure_errx("Linux on Morello does not use compartment IDs");
#else
	uintcap_t cidcap1, cidcap2;

	/*
	 * XXX: there's no inherent reason why the allocator should
	 * return seqential CID's from 1. This is an artifact of the
	 * counter based implementation and the fact that RTLD and CSU
	 * bits don't currently request any CIDs.  Should that happen,
	 * we'll probably want to stop validating the base and just pass
	 * -1 for the base.
	 */
	CHERIOSTEST_CHECK_SYSCALL(cheri_cidcap_alloc(&cidcap1));
	check_cidcap(cidcap1, 1, 1, 0);

	CHERIOSTEST_CHECK_SYSCALL(cheri_cidcap_alloc(&cidcap2));
	check_cidcap(cidcap2, 2, 1, 0);

	CHERIOSTEST_VERIFY(cidcap1 != cidcap2);

	cheriostest_success();
#endif
}
#endif
