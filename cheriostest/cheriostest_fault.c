/*-
 * Copyright (c) 2012-2018 Robert N. M. Watson
 * Copyright (c) 2014 SRI International
 * Copyright (c) 2025-2026 Paul Metzger
 * All rights reserved.
 *
 * This software was developed by the CHERI Research Centre (CRC) in the
 * Department of Computer Science and Technology at the University of
 * Cambridge under the EPSRC grant "UKRI3001: CHERI Research Centre".
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract (FA8750-10-C-0237)
 * ("CTSRD"), as part of the DARPA CRASH research programme.
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

#include <sys/types.h>
#include <sys/time.h>

#ifdef __FreeBSD__
#include <cheri/cheric.h>
#include <sys/sysctl.h>

#include <machine/frame.h>
#include <machine/trap.h>

#include <cheri/cheri.h>
#elif defined(__linux__)
#include "cheri/cheric.h"

#include <sys/auxv.h>
#endif

#include <err.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include "cheriostest.h"

#if defined(__linux__) && defined(__aarch64__)
/*
 * Morello Linux's muslc does not define these in signal.h.
 * XXXPM: Create a PR to add these to the header.
 */
#if !defined(SEGV_CAPTAGERR)
#define SEGV_CAPTAGERR		10
#define SEGV_CAPTAGERR_DEF_MISSING
#endif

#if !defined(SEGV_CAPBOUNDSERR)
#define SEGV_CAPBOUNDSERR	12
#define SEGV_CAPBOUNDSERR_DEF_MISSING
#endif

#if !defined(SEGV_CAPPERMERR)
#define SEGV_CAPPERMERR		13
#define SEGV_CAPPERMERR_DEF_MISSING
#endif
#endif

/*
 * Exercises CHERI faults outside of sandboxes.
 */

#if CHERI_SEAL_VIOLATION_EXCEPTION
#define	CT_SEAL_VIOLATION_EXCEPTION	\
    .ct_flags = CT_FLAG_SIGNAL,		\
    .ct_signum = SIGPROT,
#else
#define	CT_SEAL_VIOLATION_EXCEPTION
#endif

#define	ARRAY_LEN	2
static char array[ARRAY_LEN];
static char sink;

CHERIOSTEST(fault_bounds, "Exercise capability bounds check failure",
#ifdef __FreeBSD__
    .ct_flags = CT_FLAG_SIGNAL | CT_FLAG_SI_CODE | CT_FLAG_SI_TRAPNO,
    .ct_signum = SIGPROT,
    .ct_si_code = PROT_CHERI_BOUNDS,
    .ct_si_trapno = TRAPNO_LOAD_STORE
#elif defined(__linux__)
    .ct_flags = CT_FLAG_SIGNAL | CT_FLAG_SI_CODE,
    .ct_signum = SIGSEGV,
    .ct_si_code = SEGV_CAPBOUNDSERR
#endif
)
{
#ifdef SEGV_CAPBOUNDSERR_DEF_MISSING
	cheriostest_failure_errx("SEGV_CAPBOUNDSERR is not defined");
#endif
	char * __capability arrayp = cheri_ptr(array, sizeof(array));
	int i;

	for (i = 0; i < ARRAY_LEN; i++)
		arrayp[i] = 0;
	arrayp[i] = 0;

	cheriostest_failure_errx("out of bounds access did not fault");
}

CHERIOSTEST(fault_perm_load,
    "Exercise capability load permission failure",
#ifdef __FreeBSD__
    .ct_flags = CT_FLAG_SIGNAL | CT_FLAG_SI_CODE | CT_FLAG_SI_TRAPNO,
    .ct_signum = SIGPROT,
    .ct_si_code = PROT_CHERI_PERM,
    .ct_si_trapno = TRAPNO_LOAD_STORE
#elif defined(__linux__)
    .ct_flags = CT_FLAG_SIGNAL | CT_FLAG_SI_CODE,
    .ct_signum = SIGSEGV,
    .ct_si_code = SEGV_CAPPERMERR
#endif
)
{
#ifdef SEGV_CAPPERMERR_DEF_MISSING
	cheriostest_failure_errx("SEGV_CAPPERMERR is not defined");
#endif
	char * __capability arrayp = cheri_ptrperm(array, sizeof(array), 0);

	sink = arrayp[0];

	cheriostest_failure_errx("access without required permissions did not fault");
}

CHERIOSTEST(nofault_perm_load,
    "Exercise capability load permission success")
{
	char * __capability arrayp = cheri_ptrperm(array, sizeof(array),
#if defined(__riscv)
	    CHERI_PERM_READ);
#else
	    CHERI_PERM_LOAD);
#endif

	sink = arrayp[0];
	cheriostest_success();
}

#ifdef HAS_CHERI_PERM_SEAL
CHERIOSTEST(illegal_perm_seal,
    "Exercise capability seal permission failure",
    CT_SEAL_VIOLATION_EXCEPTION)
{
	int i;
	void * __capability ip = &i;
	void * __capability sealcap;
	void * __capability sealed;
#ifdef __FreeBSD__
	size_t sealcap_size;

	sealcap_size = sizeof(sealcap);
	if (sysctlbyname("security.cheri.sealcap", &sealcap, &sealcap_size,
	    NULL, 0) < 0)
		cheriostest_failure_err("sysctlbyname(security.cheri.sealcap)");
#elif defined(__linux__)
	sealcap = getauxptr(AT_CHERI_SEAL_CAP);
	sealcap = (void *) (((char *) sealcap) + 1);
	if (!cheri_tag_get(sealcap) || !(cheri_perms_get(sealcap) & CHERI_PERM_SEAL))
		cheriostest_failure_err("getauxptr failed");
#else
#error "Unsupported OS"
#endif

	sealcap = cheri_perms_and(sealcap, ~CHERI_PERM_SEAL);
	sealed = cheri_seal(ip, sealcap);
	/* cheri_seal() should tag-clear on failure on all architectures. */
	if (!cheri_tag_get(sealed)) {
#if CHERI_SEAL_VIOLATION_EXCEPTION
		/*
		 * For the transition period from trapping to tag-clearing
		 * semantics for CHERI-RISC-V, we report a SIGPROT here for CI.
		 * TODO: remove this once we require tag-clearing.
		 */
		if (csr_read(uccsr) & SCCSR_TAG_CLEARING)
			raise(SIGPROT);
#endif
		cheriostest_success();
	}
	cheriostest_failure_errx("cheri_seal() performed successfully "
	    "%#lp with bad sealcap %#lp", sealed, sealcap);
}
#endif

#ifdef HAS_CHERI_PERM_SEAL
CHERIOSTEST(illegal_perm_unseal,
    "Exercise capability unseal permission failure",
    CT_SEAL_VIOLATION_EXCEPTION)
{
	int i;
	void * __capability ip = &i;
	void * __capability sealcap;
	void * __capability sealed;
	void * __capability unsealed;
#ifdef __FreeBSD__
	size_t sealcap_size;

	sealcap_size = sizeof(sealcap);
	if (sysctlbyname("security.cheri.sealcap", &sealcap, &sealcap_size,
	    NULL, 0) < 0)
		cheriostest_failure_err("sysctlbyname(security.cheri.sealcap)");
#elif defined(__linux__)
	sealcap = getauxptr(AT_CHERI_SEAL_CAP);
	sealcap = (void *) (((char *) sealcap) + 1);
	if (!cheri_tag_get(sealcap))
		cheriostest_failure_err("getauxptr failed");
#else
#error "Unsupported OS"
#endif
	if ((cheri_perms_get(sealcap) & CHERI_PERM_SEAL) == 0)
		cheriostest_failure_errx("unexpected !seal perm on sealcap");
	sealed = cheri_seal(ip, sealcap);
	sealcap = cheri_perms_and(sealcap, ~CHERI_PERM_UNSEAL);
	unsealed = cheri_unseal(sealed, sealcap);
	/* cheri_unseal() should tag-clear on failure on all architectures. */
	if (!cheri_tag_get(unsealed)) {
#if CHERI_SEAL_VIOLATION_EXCEPTION
		/*
		 * For the transition period from trapping to tag-clearing
		 * semantics for CHERI-RISC-V, we report a SIGPROT here for CI.
		 * TODO: remove this once we require tag-clearing.
		 */
		if (csr_read(uccsr) & SCCSR_TAG_CLEARING)
			raise(SIGPROT);
#endif
		cheriostest_success();
	}
	cheriostest_failure_errx("cheri_unseal() performed successfully "
	    "%#lp with bad unsealcap %#lp", unsealed, sealcap);
}
#endif // HAS_CHERI_PERM_SEAL

CHERIOSTEST(fault_perm_store,
    "Exercise capability store permission failure",
#ifdef __FreeBSD__
    .ct_flags = CT_FLAG_SIGNAL | CT_FLAG_SI_CODE | CT_FLAG_SI_TRAPNO,
    .ct_signum = SIGPROT,
    .ct_si_code = PROT_CHERI_PERM,
    .ct_si_trapno = TRAPNO_LOAD_STORE
#elif defined(__linux__)
    .ct_flags = CT_FLAG_SIGNAL | CT_FLAG_SI_CODE,
    .ct_signum = SIGSEGV,
    .ct_si_code = SEGV_CAPPERMERR
#endif
)
{
#ifdef SEGV_CAPPERMERR_DEF_MISSING
	cheriostest_failure_errx("SEGV_CAPPERMERR is not defined");
#endif
	char * __capability arrayp = cheri_ptrperm(array, sizeof(array), 0);

	arrayp[0] = sink;
}

CHERIOSTEST(nofault_perm_store,
    "Exercise capability store permission success")
{
	char * __capability arrayp = cheri_ptrperm(array, sizeof(array),
#ifdef __riscv
	    CHERI_PERM_WRITE);
#else
	    CHERI_PERM_STORE);
#endif

	arrayp[0] = sink;
	cheriostest_success();
}

CHERIOSTEST(fault_tag, "Store via untagged capability",
#ifdef __FreeBSD__
    .ct_flags = CT_FLAG_SIGNAL | CT_FLAG_SI_CODE | CT_FLAG_SI_TRAPNO,
    .ct_signum = SIGPROT,
    .ct_si_code = PROT_CHERI_TAG,
    .ct_si_trapno = TRAPNO_LOAD_STORE
#elif defined(__linux__)
    .ct_flags = CT_FLAG_SIGNAL | CT_FLAG_SI_CODE,
    .ct_signum = SIGSEGV,
    .ct_si_code = SEGV_CAPTAGERR
#endif
)
{
#ifdef SEGV_CAPTAGERR_DEF_MISSING
	cheriostest_failure_errx("Signal code SEGV_CAPTAGERR missing");
#endif
	char ch;
	char * __capability chp = cheri_ptr(&ch, sizeof(ch));

	chp = cheri_tag_clear(chp);
	*chp = '\0';
}

CHERIOSTEST(nofault_cfromptr, "Exercise CFromPtr success")
{
	char buf[256];
	void * __capability cb; /* derived from here */
	char * __capability cd; /* stored into here */

	cb = cheri_ptr(buf, 256);
	cd = __builtin_cheri_cap_from_pointer(cb, (ptraddr_t)buf + 10);
	*cd = '\0';
	cheriostest_success();
}
