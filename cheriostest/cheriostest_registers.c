/*-
 * Copyright (c) 2012-2018 Robert N. M. Watson
 * Copyright (c) 2014 SRI International
 * Copyright (c) 2026 Paul Metzger
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

/*
 * Exercise CHERI functions without an expectation of a signal.
 */

#if !__has_feature(capabilities)
#error "This code requires a CHERI-aware compiler"
#endif

#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>

#include <err.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include <cheri/cheric.h>
#include <cheri/cherireg.h>

#include "cheriostest.h"

#if defined(__FreeBSD__)
#include <sys/sysctl.h>

#include <machine/pte.h>
#include <machine/vmparam.h>

#include <cheri/cheri.h>

#elif defined(__linux__)
#include <sys/cheri.h>
#include <sys/resource.h>
#endif

#if defined(__linux__)
#define	CHERI_CAP_USER_DATA_BASE	get_minuser_address()
#define	MAXSSIZ						get_max_stack_size()

static unsigned long get_minuser_address(void) {
	FILE *f;
	unsigned long minaddr;

	f = fopen("/proc/sys/vm/mmap_min_addr", "r");
	if (fscanf(f, "%lu", &minaddr) != 1)
		cheriostest_failure_errx("fscanf call failed");
	fclose(f);

	return minaddr;
}

static unsigned long get_max_stack_size(void) {
	struct rlimit rl;

	if (getrlimit(RLIMIT_STACK, &rl) != 0)
		cheriostest_failure_errx("getrlimit call failed");

	return rl.rlim_max;
}
#endif /* defined(__linux__) */

/*
 * These tests assume that the compiler and run-time libraries won't muck with
 * the global registers in question -- which is true at the time of writing.
 *
 * However, in the future, it could be that they are modified -- e.g., to
 * differentiate memory capabilities from class-type capabilities.  In that
 * case, these tests would need to check the original capability values saved
 * during process startup -- and also the new expected values.
 */
static void
check_initreg_code(void * __capability c)
{
	uintmax_t v, expect;

#if defined(__CHERI_PURE_CAPABILITY__) && !defined(__ARM_MORELLO_PURECAP_BENCHMARK_ABI)
	/*
	 * Dynamically linked pure-capability code should have a program
	 * counter that is bounded to the current DSO/executable (or function).
	 */
	CHERIOSTEST_VERIFY2(cheri_base_get(c) != 0, "code base should be nonzero");
	/*
	 * Check that PCC ends at the end of the current DSO (or executable in
	 * the statically linked case). Since we don't know the real value here,
	 * just check that it is less than PCC plus a constant that should be
	 * large enough for this binary (rounded to the next representable
	 * length).
	 */
	ptraddr_t upper_bound =
	    cheri_representable_length(cheri_address_get(c) + 0x1000000);
	CHERIOSTEST_VERIFY2(cheri_length_get(c) < upper_bound,
	    "code length 0x%jx should be < than 0x%jx)", cheri_length_get(c),
	    upper_bound);
#else
	/*
	 * In hybrid mode PCC should start at zero and extend to the end of the
	 * user address space.
	 */
	CHERIOSTEST_VERIFY2(cheri_base_get(c) == CHERI_CAP_USER_CODE_BASE,
	    "code base 0x%jx (expected 0x%jx)", cheri_base_get(c),
	    (uintmax_t)CHERI_CAP_USER_CODE_BASE);
	CHERIOSTEST_VERIFY2(cheri_length_get(c) == CHERI_CAP_USER_CODE_LENGTH,
	    "code length 0x%jx should be 0x%jx", cheri_length_get(c),
	    (uintmax_t)CHERI_CAP_USER_CODE_LENGTH);
#endif
	/* Offset. */
	CHERIOSTEST_VERIFY(cheri_offset_get(c) == 0);

#ifdef HAS_CHERI_PERM_SEAL
	/* Type -- should have unsealed type. */
	v = cheri_type_get(c);
	if (v != (uintmax_t)CHERI_OTYPE_UNSEALED)
		cheriostest_failure_errx("otype %jx (expected %jx)", v,
		    (uintmax_t)CHERI_OTYPE_UNSEALED);
#endif

	/* Sealed bit. */
	v = cheri_is_sealed(c);
	if (v != 0)
		cheriostest_failure_errx("sealed %jx (expected 0)", v);

	/* Tag bit. */
	v = cheri_tag_get(c);
	if (v != 1)
		cheriostest_failure_errx("tag %jx (expected 1)", v);

	/* Permissions. */
	v = cheri_perms_get(c);
	/*
	 * More overt tests for permissions that should -- or should not -- be
	 * there, regardless of consistency with the kernel headers.
	 */
	if ((v & CHERI_PERM_GLOBAL) == 0)
		cheriostest_failure_errx("perms %jx (global missing)", v);

	if ((v & CHERI_PERM_EXECUTE) == 0)
		cheriostest_failure_errx("perms %jx (execute missing)", v);

	if ((v & CHERI_PERM_LOAD) == 0)
		cheriostest_failure_errx("perms %jx (load missing)", v);

	if ((v & CHERI_PERM_STORE) != 0)
		cheriostest_failure_errx("perms %jx (store present)", v);

#ifdef HAS_CHERI_PERM_LOAD_STORE_CAP
	if ((v & CHERI_PERM_LOAD_CAP) == 0)
		cheriostest_failure_errx("perms %jx (loadcap missing)", v);
	if ((v & CHERI_PERM_STORE_CAP) != 0)
		cheriostest_failure_errx("perms %jx (storecap present)", v);
#endif
#ifdef HAS_CHERI_PERM_CAP
	if ((v & CHERI_PERM_CAP) == 0)
			cheriostest_failure_errx("perms %jx (cap missing)", v);
#endif

	if ((v & CHERI_PERM_STORE_LOCAL_CAP) != 0)
		cheriostest_failure_errx("perms %jx (store_local_cap present)",
		    v);

#ifdef HAS_CHERI_PERM_LOAD_MUTABLE
	if ((v & CHERI_PERM_LOAD_MUTABLE) == 0)
		cheriostest_failure_errx("perms %jx (load mutable missing)", v);
#endif
#ifdef HAS_CHERI_PERM_SEAL
	if ((v & CHERI_PERM_SEAL) != 0)
		cheriostest_failure_errx("perms %jx (seal present)", v);

#if defined(__FreeBSD__)
	if ((v & CHERI_PERM_INVOKE) == 0)
		cheriostest_failure_errx("perms %jx (invoke missing)", v);
#elif defined(__linux__)
	/*
	 * XXXPM: This might need to be changed for RISC-V
	 * CPUs with the Zyseal extension.
	 */
	if ((v & CHERI_PERM_INVOKE) == 1)
		cheriostest_failure_errx("perms %jx (invoke set)", v);
#endif

	if ((v & CHERI_PERM_UNSEAL) != 0)
		cheriostest_failure_errx("perms %jx (unseal present)", v);
#endif

	if ((v & CHERI_PERM_SYSTEM_REGS) != 0)
		cheriostest_failure_errx("perms %jx (system_regs present)", v);

#if defined(__FreeBSD__)
	expect = CHERITEST_CHERI_PERMS_SWALL & ~CHERI_PERM_SW_VMEM;
#elif defined(__linux__)
	expect = 0;
#endif

#ifdef CHERIOSTEST_C18N_TESTS
#ifndef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
#ifndef __linux__
	expect &= ~CHERI_PERM_SYSCALL;
#endif
#endif
#endif
	if ((v & CHERITEST_CHERI_PERMS_SWALL) != expect)
		cheriostest_failure_errx("swperms %jx (expected swperms %jx)",
		    v & CHERITEST_CHERI_PERMS_SWALL, expect);

	/* Check that the raw permission bits match the kernel header: */
	expect = CHERITEST_CHERI_PERMS_USERSPACE_CODE;
#ifdef CHERIOSTEST_C18N_TESTS
#ifndef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
#ifndef __linux__
	expect &= ~CHERI_PERM_SYSCALL;
#endif
#ifdef __aarch64__
	expect &= ~ARM_CAP_PERMISSION_EXECUTIVE;
#endif
#endif
#endif
	if (v != expect)
		cheriostest_failure_errx("perms %jx (expected %jx)", v, expect);

	cheriostest_success();
}

#ifndef __CHERI_PURE_CAPABILITY__
static void
check_initreg_data_full_addrspace(void * __capability c)
{
	uintmax_t v;

	/* Base. */
	v = cheri_base_get(c);
	if (v != CHERI_CAP_USER_DATA_BASE)
		cheriostest_failure_errx("base %jx (expected %jx)", v,
		    (uintmax_t)CHERI_CAP_USER_DATA_BASE);

	/* Length. */
	v = cheri_length_get(c);
	if (v > CHERI_CAP_USER_DATA_LENGTH)
		cheriostest_failure_errx("length 0x%jx (expected <= 0x%jx)", v,
		    CHERI_CAP_USER_DATA_LENGTH);

	/* Offset. */
	v = cheri_offset_get(c);
	if (v != CHERI_CAP_USER_DATA_OFFSET)
		cheriostest_failure_errx("offset %jx (expected %jx)", v,
		    (uintmax_t)CHERI_CAP_USER_DATA_OFFSET);

#ifdef HAS_CHERI_PERM_SEAL
	/* Type -- should have unsealed type. */
	v = cheri_type_get(c);
	if (v != (uintmax_t)CHERI_OTYPE_UNSEALED)
		cheriostest_failure_errx("otype %jx (expected %jx)", v,
		    (uintmax_t)CHERI_OTYPE_UNSEALED);
#endif

	/* Permissions. */
	v = cheri_perms_get(c);
	if (v != (CHERITEST_CHERI_CAP_USER_DATA_PERMS | CHERI_PERM_SW_VMEM |
		CHERI_PERM_SYSCALL))
		cheriostest_failure_errx("perms %jx (expected %jx)", v,
		    (uintmax_t)CHERITEST_CHERI_CAP_USER_DATA_PERMS |
		    CHERI_PERM_SW_VMEM | CHERI_PERM_SYSCALL);

	/*
	 * More overt tests for permissions that should -- or should not -- be
	 * there, regardless of consistency with the kernel headers.
	 */
	if ((v & CHERI_PERM_GLOBAL) == 0)
		cheriostest_failure_errx("perms %jx (global missing)", v);

	if ((v & CHERI_PERM_EXECUTE) != 0)
		cheriostest_failure_errx("perms %jx (execute present)", v);

	if ((v & CHERI_PERM_LOAD) == 0)
		cheriostest_failure_errx("perms %jx (load missing)", v);

	if ((v & CHERI_PERM_STORE) == 0)
		cheriostest_failure_errx("perms %jx (store missing)", v);

#ifdef HAS_CHERI_PERM_LOAD_STORE_CAP
	if ((v & CHERI_PERM_LOAD_CAP) == 0)
		cheriostest_failure_errx("perms %jx (loadcap missing)", v);
	if ((v & CHERI_PERM_STORE_CAP) == 0)
		cheriostest_failure_errx("perms %jx (storecap missing)", v);
#endif
#ifdef HAS_CHERI_PERM_CAP
	if ((v & CHERI_PERM_CAP) == 0)
		cheriostest_failure_errx("perms %jx (cap missing)", v);
#endif

	if ((v & CHERI_PERM_STORE_LOCAL_CAP) == 0)
		cheriostest_failure_errx("perms %jx (store_local_cap missing)",
		    v);

#ifdef HAS_CHERI_PERM_LOAD_MUTABLE
	if ((v & CHERI_PERM_LOAD_MUTABLE) == 0)
		cheriostest_failure_errx("perms %jx (load mutable missing)", v);
#endif
#ifdef HAS_CHERI_PERM_SEAL
	if ((v & CHERI_PERM_SEAL) != 0)
		cheriostest_failure_errx("perms %jx (seal present)", v);

	if ((v & CHERI_PERM_INVOKE) == 0)
		cheriostest_failure_errx("perms %jx (invoke missing)", v);

	if ((v & CHERI_PERM_UNSEAL) != 0)
		cheriostest_failure_errx("perms %jx (unseal present)", v);
#endif

	if ((v & CHERI_PERM_SYSTEM_REGS) != 0)
		cheriostest_failure_errx("perms %jx (system_regs present)", v);

	if ((v & CHERITEST_CHERI_PERMS_SWALL) != CHERITEST_CHERI_PERMS_SWALL)
		cheriostest_failure_errx("swperms %jx (expected swperms %x)",
		    v & CHERITEST_CHERI_PERMS_SWALL, CHERITEST_CHERI_PERMS_SWALL);

	/* Sealed bit. */
	v = cheri_is_sealed(c);
	if (v != 0)
		cheriostest_failure_errx("sealed %jx (expected 0)", v);

	/* Tag bit. */
	v = cheri_tag_get(c);
	if (v != 1)
		cheriostest_failure_errx("tag %jx (expected 1)", v);
	cheriostest_success();
}
#endif

CHERIOSTEST(initregs_default, "Test initial value of default capability")
{

#ifdef __CHERI_PURE_CAPABILITY__
	if (cheri_ddc_get() == NULL)
		cheriostest_success();
	else
		cheriostest_failure_errx("Expected NULL $ddc but was %-#p",
		    cheri_ddc_get());

#else
	check_initreg_data_full_addrspace(cheri_ddc_get());
#endif
}

/*
 * Outside of CheriABI, the stack pointer ($sp) is evaluated relative to the
 * default data capability, so no separate stack capability is defined.
 *
 * Inside CheriABI, the stack capability should contain only the specific
 * address range used for the stack.  We could try to capture the same logic
 * here as used in the kernel to select the stack -- but it seems more
 * sensible to simply assert that the capability is not the same as the
 * default capability for the legacy ABI.
 */
#ifdef __CHERI_PURE_CAPABILITY__

/*
 * We require our stack offset to be somewhere in the first 256KiB.  That
 * should be plenty of room for the aux vector and args and all that.
 */

#define	CHERI_STACK_USE_MAX	(256 * 1024)
#define	CHERI_STACK_SWPERMS	CHERITEST_CHERI_PERMS_SW_USERSPACE

CHERIOSTEST(initregs_stack_user_perms,
    "Test user permissions of stack capability")
{
	register_t v;

	v = cheri_perms_get(__builtin_cheri_stack_get());
	if ((v & CHERITEST_CHERI_PERMS_SWALL) != CHERI_STACK_SWPERMS)
		cheriostest_failure_errx("swperms %jx (expected swperms %x)",
		    (uintmax_t) v & CHERITEST_CHERI_PERMS_SWALL,
		    CHERI_STACK_SWPERMS);
	cheriostest_success();
}

CHERIOSTEST(initregs_stack,
    "Test initial value of stack capability")
{
	void * __capability c = __builtin_cheri_stack_get();
	register_t v;

	/* Base. */
	if (cheri_base_get(c) == CHERI_CAP_USER_DATA_BASE)
		cheriostest_failure_errx("base 0x%jx (did not expect 0x%jx)",
		    cheri_base_get(c), (uintmax_t)CHERI_CAP_USER_DATA_BASE);

	/* Length. */
	/* Technically dynamic, but defaults to MAXSSIZ. */
	if (cheri_length_get(c) > MAXSSIZ)
		cheriostest_failure_errx("length 0x%jx (> MAXSSIZ 0x%jx)",
		    cheri_length_get(c), (uintmax_t)MAXSSIZ);

	/* Offset. */
	/* If we're running len > offset... */
	if (cheri_length_get(c) - cheri_offset_get(c) > CHERI_STACK_USE_MAX)
		cheriostest_failure_errx("offset more then 0x%jx from top "
		    "(0x%jx)", (intmax_t)CHERI_STACK_USE_MAX,
		    cheri_length_get(c) - cheri_offset_get(c));

#ifdef HAS_CHERI_PERM_SEAL
	/* Type -- should have unsealed type. */
	if (cheri_type_get(c) != CHERI_OTYPE_UNSEALED)
		cheriostest_failure_errx("otype 0x%jx (expected 0x%jx)",
		    cheri_type_get(c), (uintmax_t)CHERI_OTYPE_UNSEALED);
#endif

	/* Permissions. */
	v = cheri_perms_get(c);

	/*
	 * More overt tests for permissions that should -- or should not -- be
	 * there, regardless of consistency with the kernel headers.
	 */
	if ((v & CHERI_PERM_EXECUTE) != 0)
		cheriostest_failure_errx("perms %jx (execute present)", (uintmax_t) v);

	if ((v & CHERI_PERM_LOAD) == 0)
		cheriostest_failure_errx("perms %jx (load missing)", (uintmax_t) v);
	if ((v & CHERI_PERM_STORE) == 0)
		cheriostest_failure_errx("perms %jx (store missing)", (uintmax_t) v);

#ifdef HAS_CHERI_PERM_LOAD_STORE_CAP
	if ((v & CHERI_PERM_LOAD_CAP) == 0)
		cheriostest_failure_errx("perms %jx (loadcap missing)", (uintmax_t) v);
	if ((v & CHERI_PERM_STORE_CAP) == 0)
		cheriostest_failure_errx("perms %jx (storecap missing)", (uintmax_t) v);
#endif
#ifdef HAS_CHERI_PERM_CAP
	if ((v & CHERI_PERM_CAP) == 0)
		cheriostest_failure_errx("perms %jx (cap missing)", (uintmax_t) v);
#endif
	if ((v & CHERI_PERM_GLOBAL) == 0)
		cheriostest_failure_errx("perms %jx (global missing)", (uintmax_t) v);

	if ((v & CHERI_PERM_STORE_LOCAL_CAP) == 0)
		cheriostest_failure_errx("perms %jx (store_local_cap missing)",
		    (uintmax_t) v);
#ifdef HAS_CHERI_PERM_LOAD_MUTABLE
	if ((v & CHERI_PERM_LOAD_MUTABLE) == 0)
		cheriostest_failure_errx("perms %jx (load mutable missing)", (uintmax_t) v);
#endif
#ifdef HAS_CHERI_PERM_SEAL
	if ((v & CHERI_PERM_SEAL) != 0)
		cheriostest_failure_errx("perms %jx (seal present)", (uintmax_t) v);

	if ((v & CHERI_PERM_INVOKE) == 0)
		cheriostest_failure_errx("perms %jx (invoke missing)", (uintmax_t) v);

	if ((v & CHERI_PERM_UNSEAL) != 0)
		cheriostest_failure_errx("perms %jx (unseal present)", (uintmax_t) v);
#endif
	if ((v & CHERI_PERM_SYSTEM_REGS) != 0)
		cheriostest_failure_errx("perms %jx (system_regs present)", (uintmax_t) v);

	if (v != CHERITEST_CHERI_CAP_USER_DATA_PERMS)
		cheriostest_failure_errx("perms %jx (expected %jx)", (uintmax_t) v,
		    (uintmax_t)(CHERITEST_CHERI_CAP_USER_DATA_PERMS));

	/* Sealed bit. */
	v = cheri_is_sealed(c);
	if (v != 0)
		cheriostest_failure_errx("sealed %jx (expected 0)", (uintmax_t) v);

	/* Tag bit. */
	v = cheri_tag_get(c);
	if (v != 1)
		cheriostest_failure_errx("tag %jx (expected 1)", (uintmax_t) v);
	cheriostest_success();
}

CHERIOSTEST(initregs_returncap, "Test value of return capability")
{
	void *c;
	uintmax_t v;
	
	/* The return capability should always be a sentry capability */
	c = __builtin_return_address(0);
	v = cheri_perms_get(c);

	CHERIOSTEST_VERIFY(cheri_tag_get(c));
	/* Check that execute is present and store permissions aren't */
	CHERIOSTEST_VERIFY2((v & CHERI_PERM_EXECUTE) == CHERI_PERM_EXECUTE,
	    "perms %jx (execute missing)", v);
	CHERIOSTEST_VERIFY2((v & CHERI_PERM_STORE) == 0,
	    "perms %jx (store present)", v);
#ifdef HAS_CHERI_PERM_LOAD_STORE_CAP
	CHERIOSTEST_VERIFY2((v & CHERI_PERM_STORE_CAP) == 0,
	    "perms %jx (storecap present)", v);
#endif
#ifdef HAS_CHERI_PERM_CAP
	CHERIOSTEST_VERIFY2((v & CHERI_PERM_CAP) != 0,
	    "perms %jx (cap missing)", v);
#endif
	CHERIOSTEST_VERIFY2((v & CHERI_PERM_STORE_LOCAL_CAP) == 0,
	    "perms %jx (store_local_cap present)", v);

	v = cheri_type_get(c);
	CHERIOSTEST_VERIFY2(v == (uintmax_t)CHERI_OTYPE_SENTRY,
	    "otype %jx (expected %jx)", v, (uintmax_t)CHERI_OTYPE_SENTRY);

	/* __builtin_extract_return_addr() should be a no-op */
	CHERIOSTEST_CHECK_EQ_CAP(c, __builtin_extract_return_addr(c));

	cheriostest_success();
}
#endif

CHERIOSTEST(initregs_pcc,
    "Test initial value of program-counter capability")
{
	void * __capability c;

	/* $pcc includes $pc, so clear that for the purposes of the check. */
	c = cheri_pcc_get();
	c = cheri_offset_set(c, 0);
	check_initreg_code(c);
}

#ifdef __aarch64__
#ifndef CHERIOSTEST_C18N_TESTS
CHERIOSTEST(initregs_restricted_default,
    "Test initial value of restricted default capability")
{
	void * __capability c;

	/* XXX: There don't seem to be intrisics; use once they exist */
	__asm__ ("mrs %0, rddc_el0" : "=C"(c));
	CHERIOSTEST_CHECK_EQ_CAP(c, NULL);

	cheriostest_success();
}

CHERIOSTEST(initregs_restricted_stack,
    "Test initial value of restricted stack capability")
{
	void * __capability c;

	/* XXX: There don't seem to be intrisics; use once they exist */
	__asm__ ("mrs %0, rcsp_el0" : "=C"(c));
	CHERIOSTEST_CHECK_EQ_CAP(c, NULL);

	cheriostest_success();
}

CHERIOSTEST(initregs_restricted_thread,
    "Test initial value of restricted thread capability")
{
	void * __capability c;

	/* XXX: There don't seem to be intrisics; use once they exist */
	__asm__ ("mrs %0, rctpidr_el0" : "=C"(c));
	CHERIOSTEST_CHECK_EQ_CAP(c, NULL);

	cheriostest_success();
}
#endif
#endif
