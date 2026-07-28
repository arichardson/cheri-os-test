/*-
 * Copyright (c) 2014, 2016 Robert N. M. Watson
 * Copyright (c) 2021 Microsoft Corp.
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

/*
 * A few non-faulting CHERI-related virtual-memory tests.
 */

#if !__has_feature(capabilities)
#error "This code requires a CHERI-aware compiler"
#endif

#if defined(__FreeBSD__)
#include <cheri/cheric.h>
#elif defined(__linux__)
#define _GNU_SOURCE

#include "cheri/cheric.h"
#endif

#include <sys/types.h>
#include <sys/param.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/ucontext.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#ifdef CHERIBSD_THREAD_TESTS
#include <pthread.h>
#endif

#if defined(__FreeBSD__)
#include <sys/event.h>
#include <sys/queue.h>
#include <sys/sysctl.h>

#include <machine/frame.h>
#include <machine/trap.h>
#include <machine/vmparam.h>

#include <cheri/cheri.h>
#include <cheri/revoke.h>

#include <libprocstat.h>
#elif defined(__linux__)
#include <bits/syscall.h>
#include <bsd/sys/queue.h>
#include <linux/sched.h>
#include <sys/cheri.h>

#include <dirent.h>
#include <math.h>
#endif

#include "cheriostest.h"

static void
gen_shm_obj_name(char *shm_obj_name, size_t len)
{
	CHERIOSTEST_VERIFY2(len >= 32, "Buffer for shm object name too small");
	memset(shm_obj_name, 0, len);
	const char *charset = "abcdefghijklmnopqrstuvwxyz0123456789";
	strcpy(shm_obj_name, "/cheriostest_shm-");
	for (size_t i = 18; i < len - 1; i++)
		shm_obj_name[i] = charset[random() % (sizeof(charset) - 1)];
	shm_obj_name[len - 1] = '\0';
}

static int
create_named_shm_obj(char *name, size_t len)
{
	bool created = false;
	int fd;
	int attempts = 0;

	while (!created) {
		gen_shm_obj_name(name, len);
		fd = shm_open(name, O_CREAT | O_EXCL | O_RDWR, 0600);
		if (fd != -1) created = true;
		attempts++;
		if (attempts == 10)
			cheriostest_failure_errx("Couldn't create shared memory object");

	}

	return fd;
}

static const char *
skip_need_writable_tmp(const struct cheri_test *ctp __attribute__((__unused__)))
{
	static const char *reason = NULL;
	static int checked = 0;
	char template[] = "/tmp/cheriostest.XXXXXXXX";
	int fd;

	if (checked)
		return (reason);

	checked = 1;
	fd = mkstemp(template);
	if (fd >= 0) {
		close(fd);
		unlink(template);
		return (NULL);
	}
	reason = "/tmp is not writable";
	return (reason);
}

/*
 * Tests to check that tags are ... or aren't ... preserved for various page
 * types.  Pages from the filesystem should not preserve tags -- unless they are
 * mapped MAP_PRIVATE, in which case they should, since they are effectively
 * anonymous pages.  Or so I claim.
 *
 * Most test cases only differ in the mmap flags and the file descriptor, this
 * function does all the shared checks
 *
 * Storing a capability without capability-write permissions strips the tag on
 * RVY instead of raising a CHERI exception. Set expected_tag_loss accordingly.
 */
static void
mmap_and_check_tag_stored(int fd, int protflags, int mapflags,
    bool expect_tag_loss)
{
	void * __capability volatile *cp;
	void * __capability cp_value;
	int v;

	cp = CHERIOSTEST_CHECK_SYSCALL(mmap(fd == -1 ? NULL : fd,
		getpagesize(), protflags, mapflags, fd, 0));
	cp_value = cheri_ptr(&v, sizeof(v));
	*cp = cp_value;
	cp_value = *cp;
	if (expect_tag_loss)
		CHERIOSTEST_VERIFY2(cheri_tag_get(cp_value) == 0, "tag not lost");
	else
		CHERIOSTEST_VERIFY2(cheri_tag_get(cp_value) != 0, "tag lost");
	CHERIOSTEST_CHECK_SYSCALL(munmap(__DEVOLATILE(void *, cp), getpagesize()));
	if (fd != -1)
		CHERIOSTEST_CHECK_SYSCALL(close(fd));
}

CHERIOSTEST(vm_tag_mmap_anon,
    "check tags are stored for MAP_ANON pages")
{
#ifdef __FreeBSD__
	mmap_and_check_tag_stored(-1, PROT_READ | PROT_WRITE, MAP_ANON, false);
#elif defined(__linux__)
	/*
	 * Linux requires MAP_ANON to be used with either MAP_PRIVATE or MAP_SHARED.
	 */
	mmap_and_check_tag_stored(-1, PROT_READ | PROT_WRITE,
		MAP_ANON | MAP_PRIVATE, false);
#endif
	cheriostest_success();
}

CHERIOSTEST(vm_tag_mmap_anon_cap,
    "check tags are stored for MAP_ANON pages with explicit permissions")
{
	/* CHERI and Morello Linux do not have the flags PROT_NO_CAP and PROT_CAP. */
#ifdef PROT_CAP
	int flags;

#ifdef __FreeBSD__
	flags = MAP_ANON;
#elif defined(__linux__)
	flags = MAP_ANON | MAP_PRIVATE;
#endif

	mmap_and_check_tag_stored(-1, PROT_READ | PROT_WRITE | PROT_CAP,
	    flags, false);
	cheriostest_success();
#else
	cheriostest_failure_errx("PROT_CAP is not defined");
#endif
}

CHERIOSTEST(vm_notag_mmap_no_cap,
    "check tags are not stored if we request no capability permissions",
    .ct_flags = CT_FLAG_SIGNAL | CT_FLAG_SI_CODE | CT_FLAG_SI_TRAPNO | CT_FLAG_SI_ADDR,
    .ct_signum = SIGSEGV,
#ifdef __FreeBSD__
    .ct_si_code = SEGV_STORETAG,
    .ct_si_trapno = TRAPNO_STORE_CAP_PF,
#endif
    .ct_check_skip = skip_need_writable_tmp)
{
#ifdef PROT_NO_CAP
	void * __capability volatile *cp;
	void * __capability cp_value;
	int v;
	int flags;

#ifdef __FreeBSD__
	flags = MAP_ANON;
#elif defined(__linux__)
	flags = MAP_ANON | MAP_PRIVATE;
#endif

	cp = CHERIOSTEST_CHECK_SYSCALL(mmap(NULL, getpagesize(),
		PROT_MAX(PROT_READ | PROT_WRITE | PROT_CAP) |
		PROT_READ | PROT_WRITE | PROT_NO_CAP, flags, -1, 0));
	cheriostest_set_expected_si_addr(NULL_DERIVED_VOIDP(cp));
	cp_value = cheri_ptr(&v, sizeof(v));
	*cp = cp_value;
	cheriostest_failure_errx("tagged store succeeded");
#else
	cheriostest_failure_errx("PROT_NO_CAP is not defined");
#endif
}

CHERIOSTEST(vm_notag_mprotect_no_cap,
    "check tags are not stored if we remove capability page permissions",
    .ct_flags = CT_FLAG_SIGNAL | CT_FLAG_SI_CODE | CT_FLAG_SI_TRAPNO | CT_FLAG_SI_ADDR,
    .ct_signum = SIGSEGV,
#ifdef __FreeBSD__
    .ct_si_code = SEGV_STORETAG,
    .ct_si_trapno = TRAPNO_STORE_CAP_PF,
#endif
    .ct_check_skip = skip_need_writable_tmp)
{
#ifdef PROT_NO_CAP
	void * __capability volatile *cp;
	void * __capability cp_value;
	int v;
	int flags;

#ifdef __FreeBSD__
	flags = MAP_ANON;
#elif defined(__linux__)
	flags = MAP_ANON | MAP_PRIVATE;
#endif

	cp = CHERIOSTEST_CHECK_SYSCALL(mmap(NULL, getpagesize(),
	    PROT_READ | PROT_WRITE, flags, -1, 0));
	CHERIOSTEST_CHECK_SYSCALL(mprotect(__DEVOLATILE(void *, cp),
	    getpagesize(), PROT_READ | PROT_WRITE | PROT_NO_CAP));
	cheriostest_set_expected_si_addr(NULL_DERIVED_VOIDP(cp));
	cp_value = cheri_ptr(&v, sizeof(v));
	*cp = cp_value;
	cheriostest_failure_errx("tagged store succeeded");
#else
	cheriostest_failure_errx("PROT_NO_CAP is not defined");
#endif
}

static void
mmap_check_bad_protections(int prot, int expected_errno)
{
	CHERIOSTEST_CHECK_CALL_ERROR(mmap(NULL, getpagesize(),
#ifdef __FreeBSD__
	    prot, MAP_ANON, -1, 0), expected_errno);
#elif defined(__linux__)
	    prot, MAP_ANON | MAP_PRIVATE, -1, 0), expected_errno);
#endif
}

CHERIOSTEST(vm_mmap_disallowed_prot,
    "check that disallowed protection combinations are rejected")
{
	/* Max protections not a superset */
	mmap_check_bad_protections(PROT_READ | PROT_WRITE | PROT_MAX(PROT_READ),
	    ENOTSUP);

#ifdef PROT_CAP
	/* Mixing implied and explict protections */
	mmap_check_bad_protections(PROT_READ | PROT_CAP | PROT_MAX(PROT_READ),
	    ENOTSUP);

	/* Disallowed explicit capability protection combinations */
	mmap_check_bad_protections(PROT_CAP, ENOTSUP);
	mmap_check_bad_protections(PROT_MAX(PROT_CAP), ENOTSUP);
#endif

	cheriostest_success();
}

#ifdef __FreeBSD__
/* Linux doesn't have SHM_ANON */
CHERIOSTEST(vm_tag_shm_open_anon_shared,
    "check tags are stored for SHM_ANON MAP_SHARED pages when requested")
{
	int fd = CHERIOSTEST_CHECK_SYSCALL(shm_open(SHM_ANON, O_RDWR, 0600));
	CHERIOSTEST_CHECK_SYSCALL(ftruncate(fd, getpagesize()));
	mmap_and_check_tag_stored(fd, PROT_READ | PROT_WRITE | PROT_CAP,
		MAP_SHARED, false);
	cheriostest_success();
}
#endif

CHERIOSTEST(vm_tag_shm_open_named_shared_no_implied_cap,
    "check tags are stored for named MAP_SHARED pages",
    /*
     * RVY just silently drops the tags when trying to store capabilities
     * without capability-write permissions.
     */
#if !defined(__riscv_zcheripurecap)
    .ct_flags = CT_FLAG_SIGNAL,
    .ct_signum = SIGSEGV,
#ifdef __FreeBSD__
    /*
     * Linux is missing this SIGSEGV signal code.
     */
    .ct_flags = CT_FLAG_SIGNAL | CT_FLAG_SI_CODE,
    .ct_si_code = SEGV_STORETAG,
#endif
#endif
)
{
	char shm_name[32];

	int fd = create_named_shm_obj(shm_name, sizeof(shm_name));
	CHERIOSTEST_CHECK_SYSCALL(shm_unlink(shm_name));
	CHERIOSTEST_CHECK_SYSCALL(ftruncate(fd, getpagesize()));
#ifdef __riscv_zcheripurecap
	mmap_and_check_tag_stored(fd, PROT_READ | PROT_WRITE, MAP_SHARED, true);
	cheriostest_success();
#else
	mmap_and_check_tag_stored(fd, PROT_READ | PROT_WRITE, MAP_SHARED, false);
	cheriostest_failure_errx("tagged store succeeded");
#endif
}

#ifdef __FreeBSD__
CHERIOSTEST(vm_tag_shm_open_anon_shared_no_implied_cap,
    "check tags are not stored for SHM_ANON MAP_SHARED pages by default",
#if !defined(__riscv_zcheripurecap)
    .ct_flags = CT_FLAG_SIGNAL | CT_FLAG_SI_CODE | CT_FLAG_SI_TRAPNO,
    .ct_signum = SIGSEGV,
    .ct_si_code = SEGV_STORETAG,
    .ct_si_trapno = TRAPNO_STORE_CAP_PF,
    .ct_check_skip = skip_need_writable_tmp
#endif
)
{
	int fd = CHERIOSTEST_CHECK_SYSCALL(shm_open(SHM_ANON, O_RDWR, 0600));
	CHERIOSTEST_CHECK_SYSCALL(ftruncate(fd, getpagesize()));
#ifdef __riscv_zcheripurecap
	mmap_and_check_tag_stored(fd, PROT_READ | PROT_WRITE, MAP_SHARED, true);
	cheriostest_success();
#else
	mmap_and_check_tag_stored(fd, PROT_READ | PROT_WRITE, MAP_SHARED, false);
	cheriostest_failure_errx("store succeeded");
#endif
}
#endif

CHERIOSTEST(vm_tag_anon_shared_no_implied_cap,
    "check tags are not stored for anonymous MAP_SHARED pages by default",
#if !defined(__riscv_zcheripurecap)
    .ct_flags = CT_FLAG_SIGNAL,
    .ct_signum = SIGSEGV,
#ifdef __FreeBSD__
    .ct_flags = CT_FLAG_SIGNAL | CT_FLAG_SI_CODE | CT_FLAG_SI_TRAPNO,
    .ct_si_code = SEGV_STORETAG,
    .ct_si_trapno = TRAPNO_STORE_CAP_PF,
#endif
#endif
    .ct_check_skip = skip_need_writable_tmp)
{

#ifdef __riscv_zcheripurecap
	mmap_and_check_tag_stored(-1, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON,
		true);
	cheriostest_success();
#else
	mmap_and_check_tag_stored(-1, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON,
		false);
	cheriostest_failure_errx("store succeeded");
#endif
}

CHERIOSTEST(vm_tag_memfd_create_shared,
    "check tags are stored for SHM_ANON MAP_SHARED pages",
#if !defined(__riscv_zcheripurecap)
    .ct_flags = CT_FLAG_SIGNAL,
    .ct_signum = SIGSEGV,
#ifdef __FreeBSD__
    /*
     * Linux is missing this SIGSEGV signal code.
     */
    .ct_flags = CT_FLAG_SIGNAL | CT_FLAG_SI_CODE,
    .ct_si_code = SEGV_STORETAG,
#endif
#endif
)
{
	int fd = CHERIOSTEST_CHECK_SYSCALL(memfd_create(__func__, 0));
	CHERIOSTEST_CHECK_SYSCALL(ftruncate(fd, getpagesize()));
#if defined (__riscv_zcheripurecap)
	mmap_and_check_tag_stored(fd, PROT_READ | PROT_WRITE, MAP_SHARED, true);
	cheriostest_success();
#else
	mmap_and_check_tag_stored(fd, PROT_READ | PROT_WRITE, MAP_SHARED, false);
	cheriostest_failure_errx("tagged store succeeded");
#endif
}

#ifdef __FreeBSD__
CHERIOSTEST(vm_tag_shm_open_anon_private,
    "check tags are stored for SHM_ANON MAP_PRIVATE pages")
{
	int fd = CHERIOSTEST_CHECK_SYSCALL(shm_open(SHM_ANON, O_RDWR, 0600));
	CHERIOSTEST_CHECK_SYSCALL(ftruncate(fd, getpagesize()));
	mmap_and_check_tag_stored(fd, PROT_READ | PROT_WRITE, MAP_PRIVATE, false);
	cheriostest_success();
}
#endif

CHERIOSTEST(vm_tag_shm_open_named_private,
    "check tags are stored for named MAP_PRIVATE pages")
{
	char shm_name[32];
	int fd = create_named_shm_obj(shm_name, sizeof(shm_name));
	CHERIOSTEST_CHECK_SYSCALL(shm_unlink(shm_name));
	CHERIOSTEST_CHECK_SYSCALL(ftruncate(fd, getpagesize()));
	mmap_and_check_tag_stored(fd, PROT_READ | PROT_WRITE, MAP_PRIVATE, false);
	cheriostest_success();
}


static void
vm_tag_shm_open_shared2x(int fd)
{
	void * __capability volatile * map2;
	void * __capability c2;

#ifdef PROT_CAP
	map2 = CHERIOSTEST_CHECK_SYSCALL(mmap(NULL, getpagesize(),
		PROT_READ | PROT_CAP, MAP_SHARED, fd, 0));

	/* Verify that no capability present */
	c2 = *map2;
	CHERIOSTEST_VERIFY2(cheri_tag_get(c2) == 0, "tag exists on first read");
	CHERIOSTEST_VERIFY2(c2 == NULL, "Initial read NULL");

	mmap_and_check_tag_stored(fd, PROT_READ | PROT_WRITE | PROT_CAP,
		MAP_SHARED, false);
#else
	cheriostest_failure_errx("PROT_CAP is not defined");
#endif

	/* And now verify that it is, thanks to the aliased maps */
	c2 = *map2;
	CHERIOSTEST_VERIFY2(cheri_tag_get(c2) != 0, "tag lost on second read");
	CHERIOSTEST_VERIFY2(c2 != NULL, "Second read not NULL");
}

#ifdef __FreeBSD__
/*
 * Test aliasing of SHM_ANON objects
 */
CHERIOSTEST(vm_tag_shm_open_anon_shared2x,
    "test multiply-mapped SHM_ANON objects")
{
	int fd = CHERIOSTEST_CHECK_SYSCALL(shm_open(SHM_ANON, O_RDWR, 0600));
	CHERIOSTEST_CHECK_SYSCALL(ftruncate(fd, getpagesize()));
	vm_tag_shm_open_shared2x(fd);
	cheriostest_success();
}
#endif

CHERIOSTEST(vm_tag_shm_open_named_shared2x,
    "test multiply-mapped named objects")
{
	char shm_name[32];
	int fd = create_named_shm_obj(shm_name, sizeof(shm_name));
	CHERIOSTEST_CHECK_SYSCALL(shm_unlink(shm_name));
	CHERIOSTEST_CHECK_SYSCALL(ftruncate(fd, getpagesize()));
	vm_tag_shm_open_shared2x(fd);
	cheriostest_success();
}

static void
vm_shm_open_unix_surprise(const char *shm_obj_name)
{
	int sv[2];
	int pid;

	CHERIOSTEST_CHECK_SYSCALL(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) != 0);

	pid = fork();
	if (pid == -1)
		cheriostest_failure_errx("Fork failed; errno=%d", errno);

	if (pid == 0) {
		void * __capability *map;
		void * __capability c;
		int fd, tag;
		struct msghdr msg = { 0 };
		struct cmsghdr * cmsg;
		char cmsgbuf[CMSG_SPACE(sizeof(fd))] = { 0 } ;
		char iovbuf[16];
		struct iovec iov = {
			.iov_base = iovbuf,
			.iov_len = sizeof(iovbuf)
		};

		close(sv[1]);

		/* Read from socket */
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = cmsgbuf;
		msg.msg_controllen = sizeof(cmsgbuf);
		CHERIOSTEST_CHECK_SYSCALL(recvmsg(sv[0], &msg, 0));

		/* Deconstruct cmsg */
		cmsg = CMSG_FIRSTHDR(&msg);
		memcpy(&fd, CMSG_DATA(cmsg), sizeof(fd));

		CHERIOSTEST_VERIFY2(fd >= 0, "fd read OK");

#ifdef PROT_CAP
		map = CHERIOSTEST_CHECK_SYSCALL(mmap(NULL, getpagesize(),
		    PROT_READ | PROT_CAP, MAP_SHARED, fd, 0));
#else
		cheriostest_failure_errx("PROT_CAP is not defined");
#endif
		c = *map;

		if (verbose)
			fprintf(stderr, "rx cap: %#lp\n", c);

		tag = cheri_tag_get(c);
		CHERIOSTEST_VERIFY2(tag == 0, "tag read");

		CHERIOSTEST_CHECK_SYSCALL(munmap(map, getpagesize()));
		close(sv[0]);
		close(fd);

		exit(tag);
	} else {
		void * __capability *map;
		void * __capability c;
		int fd, res;
		struct msghdr msg = { 0 };
		struct cmsghdr * cmsg;
		char cmsgbuf[CMSG_SPACE(sizeof(fd))] = { 0 };
		char iovbuf[16] = { 0 };
		struct iovec iov = {
			.iov_base = iovbuf,
			.iov_len = sizeof(iovbuf)
		};
		int flags = O_RDWR;

		close(sv[0]);

#if defined(__FreeBSD__)
		if (shm_obj_name != SHM_ANON)
			flags |= O_CREAT | O_EXCL;
#elif defined(__linux__)
		flags |= O_CREAT | O_EXCL;
#endif

		fd = CHERIOSTEST_CHECK_SYSCALL(shm_open(shm_obj_name, flags, 0600));
#if defined(__FreeBSD__)
		if (shm_obj_name != SHM_ANON)
			CHERIOSTEST_CHECK_SYSCALL(shm_unlink(shm_obj_name));
#elif defined(__linux__)
		CHERIOSTEST_CHECK_SYSCALL(shm_unlink(shm_obj_name));
#endif
		CHERIOSTEST_CHECK_SYSCALL(ftruncate(fd, getpagesize()));

#ifdef PROT_CAP
		map = CHERIOSTEST_CHECK_SYSCALL(mmap(NULL, getpagesize(),
						PROT_READ | PROT_WRITE | PROT_CAP,
						MAP_SHARED, fd, 0));
#else
		cheriostest_failure_errx("PROT_CAP is not defined");
#endif

		/* Just some pointer */
		*map = &fd;
		c = *map;
		CHERIOSTEST_VERIFY2(cheri_tag_get(c) != 0, "tag not written");

		if (verbose)
			fprintf(stderr, "tx cap: %#lp\n", c);

		CHERIOSTEST_CHECK_SYSCALL(munmap(map, getpagesize()));

		/* Construct control message */
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = cmsgbuf;
		msg.msg_controllen = sizeof(cmsgbuf);
		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN(sizeof fd);
		memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));
		msg.msg_controllen = cmsg->cmsg_len;

		/* Send! */
		CHERIOSTEST_CHECK_SYSCALL(sendmsg(sv[1], &msg, 0));

		close(sv[1]);
		close(fd);

		waitpid(pid, &res, 0);
		if (res == 0) {
			cheriostest_failure_errx("tags failed to transfer");
		} else {
			cheriostest_success();
		}
	}
}

#ifdef __FreeBSD__
CHERIOSTEST(vm_shm_open_anon_unix_surprise,
    "test SHM_ANON vs SCM_RIGHTS",
    .ct_xfail_reason =
	    "Tags currently survive cross-AS aliasing of SHM_ANON objects")
{
	vm_shm_open_unix_surprise(SHM_ANON);
}
#endif

CHERIOSTEST(vm_shm_open_named_unix_surprise,
    "test SHM_ANON vs SCM_RIGHTS",
/*
 * XXXPM: The intended behaviour needs to be discussed on the
 *        OS portability mailing list.
 */
#if defined(__FreeBSD__)
    .ct_xfail_reason = "Tags currently survive cross-AS "
					   "aliasing of SHM_ANON objects")
#elif defined(__linux__)
    .ct_flags = CT_FLAG_SIGNAL,
    .ct_signum = SIGSEGV)
#endif
{
	char shm_name[32];
	gen_shm_obj_name(shm_name, sizeof(shm_name));
	vm_shm_open_unix_surprise(shm_name);
}

static void
shm_open_read_nocaps(int shm_fd)
{
	void * __capability *map;
	void * __capability c;
	size_t rv;

	CHERIOSTEST_CHECK_SYSCALL(ftruncate(shm_fd, getpagesize()));

#if PROT_CAP
	map = CHERIOSTEST_CHECK_SYSCALL(mmap(NULL, getpagesize(),
	    PROT_READ | PROT_WRITE | PROT_CAP, MAP_SHARED, shm_fd, 0));
#else
	cheriostest_failure_errx("PROT_CAP is not defined");
#endif

	/* Just some pointer */
	*map = &shm_fd;
	c = *map;
	CHERIOSTEST_VERIFY2(cheri_tag_get(c) != 0, "tag written");

	rv = CHERIOSTEST_CHECK_SYSCALL(read(shm_fd, &c, sizeof(c)));
	CHERIOSTEST_CHECK_EQ_SIZE(rv, sizeof(c));

	CHERIOSTEST_VERIFY2(cheri_tag_get(c) == 0, "tag read");
	CHERIOSTEST_VERIFY2(cheri_is_equal_exact(cheri_tag_clear(*map), c),
	    "untagged value not read");

	CHERIOSTEST_CHECK_SYSCALL(close(shm_fd));
	cheriostest_success();
}

#ifdef __FreeBSD__
CHERIOSTEST(shm_open_anon_read_nocaps,
    "check that read(2) of a shm_open fd does not return tags")
{
	int fd = CHERIOSTEST_CHECK_SYSCALL(shm_open(SHM_ANON, O_RDWR, 0600));
	shm_open_read_nocaps(fd);
}
#endif

CHERIOSTEST(shm_open_named_read_nocaps,
    "check that read(2) of a shm_open fd does not return tags")
{
#ifdef PROT_CAP
	char shm_name[32];
	int fd = create_named_shm_obj(shm_name, sizeof(shm_name));
	CHERIOSTEST_CHECK_SYSCALL(shm_unlink(shm_name));
	shm_open_read_nocaps(fd);
#else
	cheriostest_failure_errx("PROT_CAP is not defined");
#endif
}

static void
shm_open_write_nocaps(int shm_fd)
{
	void * __capability *map;
	void * __capability c;
	size_t rv;

	CHERIOSTEST_CHECK_SYSCALL(ftruncate(shm_fd, getpagesize()));

#ifdef PROT_CAP
	map = CHERIOSTEST_CHECK_SYSCALL(mmap(NULL, getpagesize(),
	    PROT_READ | PROT_WRITE | PROT_CAP, MAP_SHARED, shm_fd, 0));
#else
	cheriostest_failure_errx("PROT_CAP is not defined");
#endif

	/* Just some pointer */
	c = &shm_fd;
	CHERIOSTEST_VERIFY2(cheri_tag_get(c) != 0, "tag set on source");

	rv = CHERIOSTEST_CHECK_SYSCALL(write(shm_fd, &c, sizeof(c)));
	CHERIOSTEST_CHECK_EQ_SIZE(rv, sizeof(c));

	CHERIOSTEST_VERIFY2(cheri_tag_get(*map) == 0, "tag written");
	CHERIOSTEST_VERIFY2(cheri_is_equal_exact(cheri_tag_clear(c), *map),
	    "untagged value not written");

	CHERIOSTEST_CHECK_SYSCALL(close(shm_fd));
	cheriostest_success();
}

#ifdef __FreeBSD__
CHERIOSTEST(shm_open_anon_write_nocaps,
    "check that write(2) of a shm_open fd does not set tags")
{
	int fd = CHERIOSTEST_CHECK_SYSCALL(shm_open(SHM_ANON, O_RDWR, 0600));
	shm_open_write_nocaps(fd);
}
#endif

CHERIOSTEST(shm_open_anon_shm,
    "check that write(2) of a named shm_open fd does not set tags")
{
	char shm_name[32];
	int fd = create_named_shm_obj(shm_name, sizeof(shm_name));
	CHERIOSTEST_CHECK_SYSCALL(shm_unlink(shm_name));
	shm_open_write_nocaps(fd);
}

CHERIOSTEST(memfd_create_anon_write_nocaps,
    "check that write(2) of a memfd_create fd does not set tags")
{
	int fd = CHERIOSTEST_CHECK_SYSCALL(memfd_create(__func__, 0));
	shm_open_write_nocaps(fd);
}

#ifdef __CHERI_PURE_CAPABILITY__

#ifdef __FreeBSD__
/*
 * We can fork processes with shared file descriptor tables, including
 * shared access to a kqueue, which can hoard capabilities for us, allowing
 * them to flow between address spaces.  It is difficult to know what to do
 * about this case, but it seems important to acknowledge.
 */
CHERIOSTEST(vm_cap_share_fd_kqueue,
    "Demonstrate capability passing via shared FD table",
    .ct_xfail_reason = "Tags currently survive cross-AS shared FD tables")
{
	int kq, pid;

	kq = CHERIOSTEST_CHECK_SYSCALL(kqueue());
	pid = rfork(RFPROC);
	if (pid == -1)
		cheriostest_failure_errx("Fork failed; errno=%d", errno);

	if (pid == 0) {
		struct kevent oke;
		/*
		 * Wait for receipt of the user event, and witness the
		 * capability received from the parent.
		 */
		oke.udata = NULL;
		CHERIOSTEST_CHECK_SYSCALL(kevent(kq, NULL, 0, &oke, 1, NULL));
		CHERIOSTEST_VERIFY2(oke.ident == 0x2BAD, "Bad identifier from kqueue");
		CHERIOSTEST_VERIFY2(oke.filter == EVFILT_USER, "Bad filter from kqueue");

		exit(cheri_tag_get(oke.udata));
	} else {
		int res;
		struct kevent ike;
		void * __capability passme;

		/*
		 * Generate a capability to a new mapping to pass to the
		 * child, who will not have this region mapped.
		 */
		passme = CHERIOSTEST_CHECK_SYSCALL(mmap(0, CHERITEST_PAGE_SIZE,
				PROT_READ | PROT_WRITE, MAP_ANON, -1, 0));

		EV_SET(&ike, 0x2BAD, EVFILT_USER, EV_ADD|EV_ONESHOT,
			NOTE_FFNOP, 0, passme);
		CHERIOSTEST_CHECK_SYSCALL(kevent(kq, &ike, 1, NULL, 0, NULL));

		EV_SET(&ike, 0x2BAD, EVFILT_USER, EV_KEEPUDATA,
			NOTE_FFNOP|NOTE_TRIGGER, 0, NULL);
		CHERIOSTEST_CHECK_SYSCALL(kevent(kq, &ike, 1, NULL, 0, NULL));

		waitpid(pid, &res, 0);
		if (res == 0) {
			cheriostest_success();
		} else {
			cheriostest_failure_errx("tag transfer");
		}
	}
}

extern int __sys_sigaction(int, const struct sigaction *, struct sigaction *);

/*
 * We can rfork and share the sigaction table across parent and child, which
 * again allows for capability passing across address spaces.
 *
 * An equivalent test case on Linux cannot be created, because the CLONE_SIGHAND
 * flag of the clone syscall requires CLONE_VM to be also set.
 *
 * XXXPM: We should check if we need other test cases for Linux's clone() syscall.
 */
CHERIOSTEST(vm_cap_share_sigaction,
    "Demonstrate capability passing via shared sigaction table",
    .ct_xfail_reason = "Tags currently survive cross-AS shared sigaction table")
{
	int pid;

	pid = rfork(RFPROC | RFSIGSHARE);
	if (pid == -1)
		cheriostest_failure_errx("Fork failed; errno=%d", errno);

	/*
	 * Note: we call __sys_sigaction directly here, since the libthr
	 * _thr_sigaction has a shadow list for the sigaction values
	 * (per-process) and therefore does not read the new value installed by
	 * the child process forked with RFSIGSHARE.
	 */
	if (pid == 0) {
		void *__capability passme;
		struct sigaction sa;

		bzero(&sa, sizeof(sa));

		/* This is a little abusive, but shows the point, I think */

		passme = CHERIOSTEST_CHECK_SYSCALL(mmap(0, CHERITEST_PAGE_SIZE,
		    PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANON, -1, 0));
		sa.sa_handler = passme;

		CHERIOSTEST_CHECK_SYSCALL(__sys_sigaction(SIGUSR1, &sa, NULL));

		/* Read it again and check that we get the same value back. */
		CHERIOSTEST_CHECK_SYSCALL(__sys_sigaction(SIGUSR1, NULL, &sa));
		CHERIOSTEST_CHECK_EQ_CAP(sa.sa_handler, passme);

		exit(0);
	} else {
		struct sigaction sa;

		waitpid(pid, NULL, 0);

		bzero(&sa, sizeof(sa));
		sa.sa_flags = 1;

		CHERIOSTEST_CHECK_SYSCALL(__sys_sigaction(SIGUSR1, NULL, &sa));
		/* Flags should be zero on read */
		CHERIOSTEST_CHECK_EQ_LONG(sa.sa_flags, 0);

		if (cheri_tag_get(sa.sa_handler)) {
			cheriostest_failure_errx("tag transfer");
		} else {
			cheriostest_success();
		}
	}
}
#endif
#endif

CHERIOSTEST(vm_tag_dev_zero_shared,
    "check tags are stored for /dev/zero MAP_SHARED pages")
{
#ifdef PROT_CAP
	int fd = CHERIOSTEST_CHECK_SYSCALL(open("/dev/zero", O_RDWR));
	mmap_and_check_tag_stored(fd, PROT_READ | PROT_WRITE | PROT_CAP, MAP_SHARED,
		false);
	cheriostest_success();
#else
	cheriostest_failure_errx("PROT_CAP is not defined");
#endif
}

CHERIOSTEST(vm_tag_dev_zero_private,
    "check tags are stored for /dev/zero MAP_PRIVATE pages")
{
	int fd = CHERIOSTEST_CHECK_SYSCALL(open("/dev/zero", O_RDWR));
	mmap_and_check_tag_stored(fd, PROT_READ | PROT_WRITE,
		MAP_PRIVATE, false);
	cheriostest_success();
}

static int
create_tempfile(void)
{
	char template[] = "/tmp/cheriostest.XXXXXXXX";
	int fd = CHERIOSTEST_CHECK_SYSCALL2(mkstemp(template),
	    "mkstemp %s", template);
	CHERIOSTEST_CHECK_SYSCALL(unlink(template));
	CHERIOSTEST_CHECK_SYSCALL(ftruncate(fd, getpagesize()));
	return fd;
}

/*
 * XXXRW: I wonder if we also need some sort of load-related test?
 */
CHERIOSTEST(vm_notag_tmpfile_shared,
    "check tags are not stored for tmpfile() MAP_SHARED pages",
#if !defined(__riscv_zcheripurecap)
    .ct_flags = CT_FLAG_SIGNAL | CT_FLAG_SI_ADDR,
    .ct_signum = SIGSEGV,
#ifdef __FreeBSD__
    .ct_flags |= CT_FLAG_SI_CODE | CT_FLAG_SI_TRAPNO,
    .ct_si_code = SEGV_STORETAG,
    .ct_si_trapno = TRAPNO_STORE_CAP_PF,
#endif
#endif
    .ct_check_skip = skip_need_writable_tmp)
{
	void * __capability volatile *cp;
	void * __capability cp_value;
	int fd, v;

	fd = create_tempfile();
	cp = CHERIOSTEST_CHECK_SYSCALL(mmap(NULL, getpagesize(),
	    PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0));
	cheriostest_set_expected_si_addr(NULL_DERIVED_VOIDP(cp));
	cp_value = cheri_ptr(&v, sizeof(v));
	*cp = cp_value;

#ifdef __riscv_zcheripurecap
	cp_value = *cp;
	CHERIOSTEST_VERIFY2(cheri_tag_get(cp_value) == 0, "tag not lost");
	cheriostest_success();
#else
	cheriostest_failure_errx("tagged store succeeded");
#endif
}

CHERIOSTEST(vm_tag_tmpfile_private,
    "check tags are stored for tmpfile() MAP_PRIVATE pages",
    .ct_check_skip = skip_need_writable_tmp)
{
	int fd = create_tempfile();
	mmap_and_check_tag_stored(fd, PROT_READ | PROT_WRITE,
		MAP_PRIVATE, false);
	cheriostest_success();
}

CHERIOSTEST(vm_tag_tmpfile_private_prefault,
    "check tags are stored for tmpfile() MAP_PRIVATE, MAP_PREFAULT_READ pages",
    .ct_check_skip = skip_need_writable_tmp)
{
	int fd = create_tempfile();
	mmap_and_check_tag_stored(fd, PROT_READ | PROT_WRITE,
#ifdef __FreeBSD__
	    MAP_PRIVATE | MAP_PREFAULT_READ, false);
#elif defined(__linux__)
	    MAP_PRIVATE | MAP_POPULATE, false);
#endif
	cheriostest_success();
}

/*
 * Exercise copy-on-write:
 *
 * 1) Create a new anonymous or named shared memory object, extend to page
 * size, map, and write a tagged capability to it.
 *
 * 2) Create a second copy-on-write mapping; read back the tagged value via
 * the second mapping, and confirm that it still has a tag.
 * (cheriostest_vm_cow_read)
 *
 * 3) Write an adjacent word in the second mapping, which should cause a
 * copy-on-write, then read back the capability and confirm that it still has
 * a tag.  (cheriostest_vm_cow_write)
 */
static void
vm_cow_read(int fd)
{
	void * __capability volatile *cp_copy;
	void * __capability volatile *cp_real;
	void * __capability cp;

	CHERIOSTEST_CHECK_SYSCALL(ftruncate(fd, getpagesize()));

	/*
	 * Create 'real' and copy-on-write mappings.
	 */
#ifdef PROT_CAP
	cp_real = CHERIOSTEST_CHECK_SYSCALL2(mmap(NULL, getpagesize(),
	    PROT_READ | PROT_WRITE | PROT_CAP, MAP_SHARED, fd, 0), "mmap cp_real");
	cp_copy = CHERIOSTEST_CHECK_SYSCALL2(mmap(NULL, getpagesize(),
	    PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0), "mmap cp_copy");
#else
	cheriostest_failure_errx("PROT_CAP is not defined");
#endif

	/*
	 * Write out a tagged capability to 'real' mapping -- doesn't really
	 * matter what it points at.  Confirm it has a tag.
	 */
	cp = cheri_ptr(&fd, sizeof(fd));
	cp_real[0] = cp;
	cp = cp_real[0];
	CHERIOSTEST_VERIFY2(cheri_tag_get(cp) != 0, "pretest: tag missing");

	/*
	 * Read in tagged capability via copy-on-write mapping.  Confirm it
	 * has a tag.
	 */
	cp = cp_copy[0];
	CHERIOSTEST_VERIFY2(cheri_tag_get(cp) != 0, "tag missing, cp_real");

	/*
	 * Clean up.
	 */
	CHERIOSTEST_CHECK_SYSCALL2(munmap(__DEVOLATILE(void *, cp_real),
	    getpagesize()), "munmap cp_real");
	CHERIOSTEST_CHECK_SYSCALL2(munmap(__DEVOLATILE(void *, cp_copy),
	    getpagesize()), "munmap cp_copy");

}

#ifdef __FreeBSD__
CHERIOSTEST(vm_cow_anon_read,
    "read capabilities from a copy-on-write page")
{
	/*
	 * Create anonymous shared memory object.
	 */
	int fd = CHERIOSTEST_CHECK_SYSCALL(shm_open(SHM_ANON, O_RDWR, 0600));
	vm_cow_read(fd);
	CHERIOSTEST_CHECK_SYSCALL(close(fd));
	cheriostest_success();
}
#endif

CHERIOSTEST(vm_cow_named_read,
    "read capabilities from a copy-on-write page")
{
	/*
	 * Create anonymous shared memory object.
	 */
	char shm_name[32];
	int fd = create_named_shm_obj(shm_name, sizeof(shm_name));
	CHERIOSTEST_CHECK_SYSCALL(shm_unlink(shm_name));
	vm_cow_read(fd);
	CHERIOSTEST_CHECK_SYSCALL(close(fd));
	cheriostest_success();
}

static void
vm_cow_write(int fd)
{
	void * __capability volatile *cp_copy;
	void * __capability volatile *cp_real;
	void * __capability cp;

	CHERIOSTEST_CHECK_SYSCALL(ftruncate(fd, getpagesize()));

	/*
	 * Create 'real' and copy-on-write mappings.
	 */
#ifdef PROT_CAP
	cp_real = CHERIOSTEST_CHECK_SYSCALL2(mmap(NULL, getpagesize(),
	    PROT_READ | PROT_WRITE | PROT_CAP, MAP_SHARED, fd, 0), "mmap cp_real");
	cp_copy = CHERIOSTEST_CHECK_SYSCALL2(mmap(NULL, getpagesize(),
	    PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0), "mmap cp_copy");
#else
	cheriostest_failure_errx("PROT_CAP is not defined");
#endif

	/*
	 * Write out a tagged capability to 'real' mapping -- doesn't really
	 * matter what it points at.  Confirm it has a tag.
	 */
	cp = cheri_ptr(&fd, sizeof(fd));
	cp_real[0] = cp;
	cp = cp_real[0];
	CHERIOSTEST_VERIFY2(cheri_tag_get(cp) != 0, "pretest: tag missing");

	/*
	 * Read in tagged capability via copy-on-write mapping.  Confirm it
	 * has a tag.
	 */
	cp = cp_copy[0];
	CHERIOSTEST_VERIFY2(cheri_tag_get(cp) != 0, "tag missing, cp_real");

	/*
	 * Diverge from cheriostest_vm_cow_read(): write via the second mapping
	 * to force a copy-on-write rather than continued sharing of the page.
	 */
	cp = cheri_ptr(&fd, sizeof(fd));
	cp_copy[1] = cp;

	/*
	 * Confirm that the tag is still present on the 'real' page.
	 */
	cp = cp_real[0];
	CHERIOSTEST_VERIFY2(cheri_tag_get(cp) != 0, "tag missing after COW, cp_real");

	cp = cp_copy[0];
	CHERIOSTEST_VERIFY2(cheri_tag_get(cp) != 0, "tag missing after COW, cp_copy");

	/*
	 * Clean up.
	 */
	CHERIOSTEST_CHECK_SYSCALL2(munmap(__DEVOLATILE(void *, cp_real),
	    getpagesize()), "munmap cp_real");
	CHERIOSTEST_CHECK_SYSCALL2(munmap(__DEVOLATILE(void *, cp_copy),
	    getpagesize()), "munmap cp_copy");
}

#ifdef __FreeBSD__
CHERIOSTEST(vm_cow_anon_write,
    "read capabilities from a faulted copy-on-write page")
{
	/*
	 * Create anonymous shared memory object.
	 */
	int fd = CHERIOSTEST_CHECK_SYSCALL(shm_open(SHM_ANON, O_RDWR, 0600));
	vm_cow_write(fd);
	CHERIOSTEST_CHECK_SYSCALL(close(fd));
	cheriostest_success();
}
#endif

CHERIOSTEST(vm_cow_named_write,
    "read capabilities from a faulted copy-on-write page")
{
	/*
	 * Create anonymous shared memory object.
	 */
	char shm_name[32];
	int fd = create_named_shm_obj(shm_name, sizeof(shm_name));
	CHERIOSTEST_CHECK_SYSCALL(shm_unlink(shm_name));
	vm_cow_write(fd);
	CHERIOSTEST_CHECK_SYSCALL(close(fd));
	cheriostest_success();
}

#ifdef __CHERI_PURE_CAPABILITY__

static int __attribute__((__used__)) sink;

static size_t
get_unrepresentable_length(void)
{
	int shift = 0;
	size_t len;

	/*
	 * Generate the shortest unrepresentable length, for which rounding
	 * up to CHERITEST_PAGE_SIZE is still unrepresentable.
	 */
	do {
		len = (1 << (CHERITEST_PAGE_SHIFT + shift)) + 1;
		shift++;
	} while (cheritest_round_page(len) ==
	    __builtin_cheri_round_representable_length(cheritest_round_page(len)));
	return (len);
}

/*
 * Check that globals do not have the SW_VMEM permission bit after
 * capability relocation.
 */
static char test_buffer[64];
static void *test_bufferp = (void *)&test_buffer;

CHERIOSTEST(vm_sw_perm_on_capreloc,
	    "Check that the SW_VMEM permission is not present on globals.")
{
	CHERIOSTEST_VERIFY(cheri_tag_get(test_bufferp));
	CHERIOSTEST_VERIFY((cheri_perms_get(test_bufferp) & CHERI_PERM_SW_VMEM) == 0);

	cheriostest_success();
}

/*
 * Check that the padding of a reservation faults on access
 */
CHERIOSTEST(vm_reservation_access_fault,
    "check that we fault when accessing padding of a reservation",
    .ct_flags = CT_FLAG_SIGNAL | CT_FLAG_SI_CODE,
    .ct_signum = SIGSEGV,
    .ct_si_code = SEGV_ACCERR)
{
	size_t len = get_unrepresentable_length();
	size_t expected_len;
	void *map;
	int *padding;

	expected_len = __builtin_cheri_round_representable_length(len);
	CHERIOSTEST_VERIFY2(expected_len > cheritest_round_page(len),
	    "test precondition failed: padding for length (%lx) must "
	    "exceed one page, found %lx", len, expected_len);
	map = CHERIOSTEST_CHECK_SYSCALL(mmap(NULL, len, PROT_READ | PROT_WRITE,
#ifdef __FreeBSD__
	    MAP_ANON, -1, 0));
#elif defined(__linux__)
	    MAP_ANON | MAP_PRIVATE, -1, 0));
#endif
	CHERIOSTEST_VERIFY2(cheri_tag_get(map) != 0, "mmap() failed to return "
	    "a pointer when given unrepresentable length (%zu)", len);
	CHERIOSTEST_VERIFY2(cheri_length_get(map) == expected_len,
	    "mmap() returned a pointer with an unrepresentable length "
	    "(%zu vs %zu): %#p", cheri_length_get(map), expected_len, map);

	padding = (int *)((uintcap_t)map + expected_len - sizeof(int));
	sink = *padding;

	cheriostest_failure_errx("reservation padding access allowed");
}

/*
 * Check that a reserved range can not be reused for another mapping,
 * until the whole mapping is freed.
 */
CHERIOSTEST(vm_reservation_reuse,
    "check that we can not remap over a partially-unmapped reservation")
{
	void *map;
	void *map2;
#ifdef __FreeBSD__
	int flags = MAP_ANON;
#elif defined(__linux__)
	int flags = MAP_ANON | MAP_PRIVATE;
#endif

	map = CHERIOSTEST_CHECK_SYSCALL(mmap(NULL, CHERITEST_PAGE_SIZE * 2,
	    PROT_READ | PROT_WRITE, flags, -1, 0));
	CHERIOSTEST_VERIFY2(cheri_tag_get(map) != 0, "mmap() failed to return "
	    "a pointer");

	CHERIOSTEST_CHECK_SYSCALL(munmap((char *)map + CHERITEST_PAGE_SIZE, CHERITEST_PAGE_SIZE));
	/*
	 * XXX-AM: is this checking the right thing?
	 * We may be failing because the reservation length is not enough.
	 */
	map2 = mmap((void *)(uintptr_t)((ptraddr_t)map + CHERITEST_PAGE_SIZE), CHERITEST_PAGE_SIZE * 2,
		PROT_READ | PROT_WRITE, flags | MAP_FIXED, -1, 0);
	if (map2 == MAP_FAILED) {
		CHERIOSTEST_VERIFY2(errno == ENOMEM,
		    "Unexpected errno %d instead of ENOMEM", errno);
		cheriostest_success();
	}

	cheriostest_failure_errx("mmap over reservation succeeded");
}

/*
 * Check that alignment is promoted automatically to the first
 * representable boundary.
 */
CHERIOSTEST(vm_reservation_align,
    "check that mmap correctly aligns mappings")
{
	void *map;
	size_t len = get_unrepresentable_length();
	size_t align_mask = CHERITEST_CHERI_ALIGN_MASK(len);
#ifdef __FreeBSD__
	size_t align_shift = CHERI_ALIGN_SHIFT(len);
#endif

	/* No alignment */
	map = CHERIOSTEST_CHECK_SYSCALL(mmap(NULL, len,
#ifdef __FreeBSD__
	    PROT_READ | PROT_WRITE, MAP_ANON, -1, 0));
#elif defined(__linux__)
	    PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0));
#endif
	CHERIOSTEST_VERIFY2(((ptraddr_t)(map) & align_mask) == 0,
	    "mmap failed to align representable region for %p", map);

#ifdef __FreeBSD__
	/* Underaligned */
	map = CHERIOSTEST_CHECK_SYSCALL(mmap(NULL, len,
	    PROT_READ | PROT_WRITE, MAP_ANON | MAP_ALIGNED(align_shift - 1),
	    -1, 0));
	CHERIOSTEST_VERIFY2(((ptraddr_t)(map) & align_mask) == 0,
	    "mmap failed to align representable region with requested "
	    "alignment %lx for %p", align_shift - 1, map);

	/* Overaligned */
	map = CHERIOSTEST_CHECK_SYSCALL(mmap(NULL, len,
	    PROT_READ | PROT_WRITE, MAP_ANON | MAP_ALIGNED(align_shift + 1),
	    -1, 0));
	CHERIOSTEST_VERIFY2(
	    ((ptraddr_t)(map) & ((1 << (align_shift + 1)) - 1)) == 0,
	    "mmap failed to align representable region with requested "
	    "alignment %lx for %p", align_shift + 1, map);
#endif

	cheriostest_success();
}

#ifdef __FreeBSD__
/*
 * These tests use revocation which is currently not supported by CHERI and
 * Morello Linux.
 */
static bool
reservations_are_quarantined(void)
{
	uint8_t quarantine_unmapped_reservations;
	size_t quarantine_unmapped_reservations_sz =
	    sizeof(quarantine_unmapped_reservations);

	if (sysctlbyname("vm.cheri_revoke.quarantine_unmapped_reservations",
	    &quarantine_unmapped_reservations,
	    &quarantine_unmapped_reservations_sz, NULL, 0) != 0) {
		if (errno == ENOENT)
			return (false);
		cheriostest_failure_err(
		    "sysctlbyname(vm.cheri_revoke.quarantine_unmapped_reservations)");
	}

	return (quarantine_unmapped_reservations != 0);
}

/*
 * Check that after a reservation is unmapped, it is not possible to
 * reuse the old capability to create new fixed mappings.
 * This is an attempt to reuse a capability prior to a revocation pass.
 * As this capability may be revoked at some arbitrary point in the
 * future, we always disallow use.
 */
CHERIOSTEST(vm_reservation_mmap_after_free_fixed,
    "check that an old capability can not be used to mmap with MAP_FIXED "
    "after the reservation has been deleted",
    .ct_check_skip = skip_need_cheri_revoke)
{
	void *map;
	const volatile struct cheri_revoke_info *cri;

	/* Make sure this process is revoking */
	CHERIOSTEST_CHECK_SYSCALL(cheri_revoke_get_shadow(
	    CHERI_REVOKE_SHADOW_INFO_STRUCT, NULL, __DEQUALIFY(void **, &cri)));

	map = CHERIOSTEST_CHECK_SYSCALL(mmap(NULL, CHERITEST_PAGE_SIZE,
	    PROT_READ | PROT_WRITE, MAP_ANON, -1, 0));

	CHERIOSTEST_CHECK_SYSCALL(munmap((char *)map, CHERITEST_PAGE_SIZE));

	map = mmap(map, CHERITEST_PAGE_SIZE, PROT_READ | PROT_WRITE,
	    MAP_ANON | MAP_FIXED, -1, 0);
	CHERIOSTEST_VERIFY2(map == MAP_FAILED, "mmap after free succeeded");

	if (reservations_are_quarantined()) {
		/*
		 * There's nothing to cause the quarantined reservation to be
		 * revoked between the munmap and mmap calls so we'll get an
		 * ENOMEM here.
		 *
		 * XXX: ideally we'd trigger a revocation of this specific
		 * reservation before the mmap call to test the same case with
		 * and without revocation.
		 */
		CHERIOSTEST_VERIFY2(errno == ENOMEM,
		    "mmap after free failed with %d instead of ENOMEM", errno);
	} else
		CHERIOSTEST_VERIFY2(errno == EPROT,
		    "mmap after free failed with %d instead of EPROT", errno);

	cheriostest_success();
}

/*
 * Check that after a reservation is unmapped, it is not possible to
 * reuse the old capability to create new non-fixed mappings.
 * This is an attempt of reusing a capability before revocation, in
 * a proper temporal-safety implementation will lead to failures so
 * we catch these early.
 */
CHERIOSTEST(vm_reservation_mmap_after_free,
    "check that an old capability can not be used to mmap after the "
    "reservation has been deleted",
    .ct_check_skip = skip_need_cheri_revoke)
{
	void *map;
	map = CHERIOSTEST_CHECK_SYSCALL(mmap(NULL, CHERITEST_PAGE_SIZE,
	    PROT_READ | PROT_WRITE, MAP_ANON, -1, 0));

	CHERIOSTEST_CHECK_SYSCALL(munmap((char *)map, CHERITEST_PAGE_SIZE));

	map = mmap(map, CHERITEST_PAGE_SIZE, PROT_READ | PROT_WRITE,
	    MAP_ANON, -1, 0);
	CHERIOSTEST_VERIFY2(map == MAP_FAILED, "mmap after free succeeded");
	CHERIOSTEST_VERIFY2(errno == EPROT,
	    "mmap after free failed with %d instead of EPROT", errno);
	cheriostest_success();
}
#endif

/*
 * Check that reservations are aligned and padded correctly for shared mappings.
 */
static void
vm_reservation_mmap_shared(int fd)
{
	void *map;
	size_t len = get_unrepresentable_length();
	size_t expected_len;
	size_t align_mask = CHERITEST_CHERI_ALIGN_MASK(len);

	expected_len = __builtin_cheri_round_representable_length(len);
	CHERIOSTEST_CHECK_SYSCALL(ftruncate(fd, len));

	map = CHERIOSTEST_CHECK_SYSCALL(mmap(NULL, len,
	    PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0));

	CHERIOSTEST_VERIFY2(((ptraddr_t)(map) & align_mask) == 0,
	    "mmap failed to align shared regiont for representability");
	CHERIOSTEST_VERIFY2(cheri_length_get(map) == expected_len,
	    "mmap returned pointer with unrepresentable length");

	cheriostest_success();
}

#ifdef __FreeBSD__
CHERIOSTEST(vm_reservation_mmap_shared_shm_open,
	"check reservation alignment and bounds for shared mappings created with shm_open")
{
	int fd = CHERIOSTEST_CHECK_SYSCALL(shm_open(SHM_ANON, O_RDWR, 0600));
	vm_reservation_mmap_shared(fd);
}
#endif

CHERIOSTEST(vm_reservation_mmap_shared_memfd_open,
	"check reservation alignment and bounds for shared mappings created with memfd_create")
{
	int fd = CHERIOSTEST_CHECK_SYSCALL(memfd_create(__func__, 0));
	vm_reservation_mmap_shared(fd);
}

/*
 * Check that we require NULL-derived capabilities when mmap().
 * Test mmap() with an invalid capability and no backing reservation.
 */
CHERIOSTEST(vm_mmap_invalid_cap,
    "check that mmap with invalid capability hint fails")
{
	void *invalid = cheri_tag_clear(cheri_address_set(
	    cheri_pcc_get(), 0x4300beef));
	void *map;

	map = mmap(invalid, CHERITEST_PAGE_SIZE, PROT_READ | PROT_WRITE,
	    MAP_ANON, -1, 0);
	CHERIOSTEST_VERIFY2(map == MAP_FAILED,
	    "mmap with invalid capability succeeded");
	CHERIOSTEST_VERIFY2(errno == EINVAL,
	    "mmap with invalid capability failed with %d instead "
	    "of EINVAL", errno);

	cheriostest_success();
}

/*
 * Check that we require NULL-derived capabilities when mmap().
 * Test mmap() MAP_FIXED with an invalid capability and no backing reservation.
 */
CHERIOSTEST(vm_mmap_invalid_cap_fixed,
    "check that mmap MAP_FIXED with invalid capability hint fails")
{
	void *invalid = cheri_tag_clear(cheri_address_set(
	    cheri_pcc_get(), 0x4300beef));
	void *map;
#ifdef __FreeBSD__
	int flags = MAP_ANON | MAP_FIXED;
#elif defined(__linux__)
	int flags = MAP_ANON | MAP_PRIVATE | MAP_FIXED;
#endif

	map = mmap(invalid, CHERITEST_PAGE_SIZE, PROT_READ | PROT_WRITE, flags, -1, 0);
	CHERIOSTEST_VERIFY2(map == MAP_FAILED,
	    "mmap with invalid capability succeeded");
	CHERIOSTEST_VERIFY2(errno == EINVAL,
	    "mmap with invalid capability failed with %d instead "
	    "of EINVAL", errno);

	cheriostest_success();
}

/*
 * Check that we require NULL-derived capabilities when mmap().
 * Test mmap() MAP_FIXED with an invalid capability and existing
 * backing reservation.
 */
CHERIOSTEST(vm_reservation_mmap_invalid_cap,
    "check that mmap over existing reservation with invalid "
    "capability hint fails")
{
	void *invalid;
	void *map;
#ifdef __FreeBSD__
	int flags = MAP_ANON;
#elif defined(__linux__)
	int flags = MAP_ANON | MAP_PRIVATE;
#endif

	map = CHERIOSTEST_CHECK_SYSCALL(mmap(NULL, CHERITEST_PAGE_SIZE,
	    PROT_READ | PROT_WRITE, flags, -1, 0));

	invalid = cheri_tag_clear(map);

	map = mmap(invalid, CHERITEST_PAGE_SIZE, PROT_READ | PROT_WRITE,
	    flags, -1, 0);
	CHERIOSTEST_VERIFY2(map == MAP_FAILED,
	    "mmap with invalid capability succeeded");
	CHERIOSTEST_VERIFY2(errno == EINVAL,
	    "mmap with invalid capability failed with %d instead "
	    "of EINVAL", errno);

	cheriostest_success();
}

/*
 * Check that mmap() with a null-derived hint address succeeds.
 */
CHERIOSTEST(vm_reservation_mmap,
    "check mmap with NULL-derived hint address")
{
	uintptr_t hint;
	void *map;
#ifdef __FreeBSD__
	int flags = MAP_ANON;
#elif defined(__linux__)
	int flags = MAP_ANON | MAP_PRIVATE;
#endif

	hint = find_address_space_gap(CHERITEST_PAGE_SIZE, 0);
	map = CHERIOSTEST_CHECK_SYSCALL(mmap((void *)hint, CHERITEST_PAGE_SIZE,
	    PROT_READ | PROT_WRITE, flags, -1, 0));
	CHERIOSTEST_VERIFY2(cheri_tag_get(map) != 0,
	    "mmap with null-derived hint failed to return valid capability");

	cheriostest_success();
}

/*
 * Check that mapping with a NULL-derived capability hint at a fixed
 * address, with no existing reservation at the target region, succeeds.
 * Check that this fails if a mapping already exists at the target address
 * as MAP_FIXED implies MAP_EXCL in this case.
 */
CHERIOSTEST(vm_reservation_mmap_fixed_unreserved,
    "check mmap MAP_FIXED with NULL-derived hint address")
{
	uintptr_t hint;
	void *map;
#ifdef __FreeBSD__
	int flags = MAP_ANON | MAP_FIXED;
#elif defined(__linux__)
	int flags = MAP_ANON | MAP_PRIVATE | MAP_FIXED;
#endif

	hint = find_address_space_gap(CHERITEST_PAGE_SIZE * 2, 0);
	map = CHERIOSTEST_CHECK_SYSCALL(mmap((void *)(hint + CHERITEST_PAGE_SIZE),
	    CHERITEST_PAGE_SIZE, PROT_MAX(PROT_READ | PROT_WRITE), flags, -1, 0));
	CHERIOSTEST_VERIFY2(cheri_tag_get(map) != 0,
	    "mmap fixed with NULL-derived hint failed to return "
	    "valid capability");

	map = mmap((void *)hint, 2 * CHERITEST_PAGE_SIZE, PROT_READ | PROT_WRITE,
	    flags, -1, 0);
	CHERIOSTEST_VERIFY2(map == MAP_FAILED,
	    "mmap fixed with NULL-derived hint does not imply MAP_EXCL");
	CHERIOSTEST_VERIFY2(errno == ENOMEM,
	    "mmap fixed with NULL-derived hint failed with %d instead "
	    "of ENOMEM", errno);

	cheriostest_success();
}

/*
 * Check that mmap at fixed address with NULL-derived hint fails if
 * a reservation already exists at the target address.
 */
CHERIOSTEST(vm_reservation_mmap_insert_null_derived,
    "check that mmap with NULL-derived hint address over existing "
    "reservation fails")
{
	void *map;

#ifdef __FreeBSD__
	map = CHERIOSTEST_CHECK_SYSCALL(mmap(NULL, 3 * CHERITEST_PAGE_SIZE,
	    PROT_MAX(PROT_READ | PROT_WRITE), MAP_GUARD, -1, 0));
#elif defined(__linux__)
	map = CHERIOSTEST_CHECK_SYSCALL(mmap(NULL, 3 * CHERITEST_PAGE_SIZE, PROT_NONE |
	    PROT_MAX(PROT_READ | PROT_WRITE), MAP_ANON | MAP_PRIVATE, -1, 0));
#endif
	CHERIOSTEST_VERIFY2(cheri_tag_get(map) != 0,
	    "mmap failed to return valid capability");

	map = mmap((void *)(uintptr_t)(ptraddr_t)map, CHERITEST_PAGE_SIZE,
	    PROT_READ | PROT_WRITE, MAP_ANON | MAP_FIXED | MAP_PRIVATE, -1, 0);
	CHERIOSTEST_VERIFY2(map == MAP_FAILED,
	    "mmap fixed with NULL-derived hint succeded");
	CHERIOSTEST_VERIFY2(errno == ENOMEM,
	    "mmap fixed with NULL-derived hint failed with %d instead "
	    "of ENOMEM", errno);

	cheriostest_success();
}

CHERIOSTEST(vm_reservation_mmap_fixed_insert,
    "check mmap MAP_FIXED into an existing reservation with a "
    "SW_VMEM perm capability")
{
	void *map;

#ifdef __FreeBSD__
	map = CHERIOSTEST_CHECK_SYSCALL(mmap(NULL, 3 * CHERITEST_PAGE_SIZE,
	    PROT_MAX(PROT_READ | PROT_WRITE), MAP_GUARD, -1, 0));
#elif defined(__linux__)
	map = CHERIOSTEST_CHECK_SYSCALL(mmap(NULL, 3 * CHERITEST_PAGE_SIZE, PROT_NONE |
		PROT_MAX(PROT_READ | PROT_WRITE), MAP_ANON | MAP_PRIVATE, -1, 0));
#endif
	CHERIOSTEST_VERIFY2(cheri_tag_get(map) != 0,
	    "mmap failed to return valid capability");
	CHERIOSTEST_VERIFY2(cheri_perms_get(map) & CHERI_PERM_SW_VMEM,
	    "mmap failed to return capability with VMEM perm");

	CHERIOSTEST_CHECK_SYSCALL(mmap((char *)(map) + CHERITEST_PAGE_SIZE, CHERITEST_PAGE_SIZE,
	    PROT_READ | PROT_WRITE, MAP_ANON | MAP_FIXED | MAP_PRIVATE, -1, 0));
	CHERIOSTEST_VERIFY2(cheri_tag_get(map) != 0,
	    "mmap fixed failed to return valid capability");

	cheriostest_success();
}

CHERIOSTEST(vm_reservation_mmap_fixed_insert_noperm,
    "check that mmap MAP_FIXED into an existing reservation "
    "with a capability missing SW_VMEM permission fails")
{
	void *map;
	void *map2;
	void *not_enough_perm;

#ifdef __FreeBSD__
	map = CHERIOSTEST_CHECK_SYSCALL(mmap(NULL, 3 * CHERITEST_PAGE_SIZE,
	    PROT_MAX(PROT_READ | PROT_WRITE), MAP_GUARD, -1, 0));
#elif defined(__linux__)
	map = CHERIOSTEST_CHECK_SYSCALL(mmap(NULL, 3 * CHERITEST_PAGE_SIZE, PROT_NONE |
		PROT_MAX(PROT_READ | PROT_WRITE), MAP_ANON | MAP_PRIVATE, -1, 0));
#endif
	CHERIOSTEST_VERIFY2(cheri_tag_get(map) != 0,
	    "mmap failed to return valid capability");
	CHERIOSTEST_VERIFY2(cheri_perms_get(map) & CHERI_PERM_SW_VMEM,
	    "mmap failed to return capability with VMEM perm");

	not_enough_perm = cheri_perms_and(map, ~CHERI_PERM_SW_VMEM);
	map2 = mmap((char *)(not_enough_perm) + CHERITEST_PAGE_SIZE, CHERITEST_PAGE_SIZE,
	    PROT_READ | PROT_WRITE, MAP_ANON | MAP_FIXED | MAP_PRIVATE, -1, 0);
	CHERIOSTEST_VERIFY2(map2 == MAP_FAILED,
	    "mmap fixed with capability missing VMEM perm succeeds");
	CHERIOSTEST_VERIFY2(errno == EACCES,
	    "mmap fixed with capability missing VMEM perm failed "
	    "with %d instead of EACCES", errno);

	cheriostest_success();
}

#if (defined(PMAP_HAS_LARGEPAGES) && defined(__FreeBSD__)) || defined(__linux__)
#ifdef __FreeBSD__
static int
get_pagesizes(size_t ps[static MAXPAGESIZES])
{
	int count;

	count = getpagesizes(ps, MAXPAGESIZES);
	CHERIOSTEST_VERIFY2(count != -1, "failed to get pagesizes");
	CHERIOSTEST_VERIFY2(ps[0] == CHERITEST_PAGE_SIZE, "psind 0 is not CHERITEST_PAGE_SIZE");
	return (count);
}
#elif defined(__linux__)
static int
get_pagesizes(size_t **p_sizes)
{
	int count = 0;
	const char* sys_huge_page_dir = "/sys/kernel/mm/hugepages";
	struct dirent *de;
	size_t kb;
	const int max_size = 512;

	*p_sizes = malloc(max_size * sizeof(**p_sizes));
	DIR *hp = opendir(sys_huge_page_dir);
	while((de = readdir(hp)) != NULL) {
		if (sscanf(de->d_name, "hugepages-%lukB", &kb) == 1) {
			CHERIOSTEST_VERIFY2(count <= max_size, "Maximum number of huge"
			    "page sizes exceeded.");
			(*p_sizes)[count++] = kb * 1024;
		}
	}

	closedir(hp);
	return count;
}

static void
check_hugepages_pool(size_t *p_sizes, int count) {
	const int max_path_len = 100;
	char path[max_path_len];
	size_t pool_pages = 0;

	for (int i = 0; i < count; i++) {
		size_t kb = p_sizes[i] / 1024;
		memset(path, 0, max_path_len);
		snprintf(path, max_path_len - 1, "/sys/kernel/mm/hugepages/"
		    "hugepages-%zukB/nr_hugepages", kb);
		FILE *f = fopen(path, "r");
		CHERIOSTEST_VERIFY2(f != 0, "Couldn't open nr_hugepages");
		CHERIOSTEST_VERIFY2(fscanf(f, "%zu", &pool_pages) == 1, "Couldn't "
		    "read page count in hugepages pool");
		CHERIOSTEST_VERIFY2(pool_pages != 0, "No pages in the hugepages pool "
		    "for size %zukB (\"echo <pages> > /sys/kernel/mm/hugepages/"
		    "hugepages-<size>kB/nr_hugepages\" set the number of pages in "
		    "the pool)", kb);
		fclose(f);
	}
}
#endif

/*
 * Builds on FreeBSD testsuite posixshm_test:largepage_basic.
 */
CHERIOSTEST(vm_large_pages_basic,
    "Test basic largepage SHM mapping setup and teardown")
{
	void *addr;
#ifdef __FreeBSD__
	size_t ps[MAXPAGESIZES];
	int fd;
#elif defined(__linux__)
	size_t *ps;
#endif
	int psind, psmax;
	unsigned int perms = (CHERI_PERM_LOAD | CHERI_PERM_STORE);
	void * volatile *map_buffer;
	int v;

#ifdef __FreeBSD__
	psmax = get_pagesizes(ps);
	for (psind = 1; psind < psmax; psind++) {
#elif defined(__linux__)
	psmax = get_pagesizes(&ps);
	check_hugepages_pool(ps, psmax);
	for (psind = 0; psind < psmax; psind++) {
#endif

		/* Skip very large pagesizes */
		if (ps[psind] >= (1 << 30))
			continue;

#ifdef __FreeBSD__
		fd = shm_create_largepage(SHM_ANON, O_CREAT | O_RDWR, psind,
		    SHM_LARGEPAGE_ALLOC_DEFAULT, /*mode*/0);
		CHERIOSTEST_VERIFY2(fd >= 0, "Failed to create largepage SHM fd "
		    "psind=%d errno=%d", psind, errno);
		CHERIOSTEST_CHECK_SYSCALL(ftruncate(fd, ps[psind]));
		addr = CHERIOSTEST_CHECK_SYSCALL(mmap(NULL, ps[psind],
		    PROT_READ | PROT_WRITE | PROT_CAP, MAP_SHARED, fd, 0));
#elif defined(__linux__)
#if PROT_CAP
		addr = CHERIOSTEST_CHECK_SYSCALL(mmap(NULL, ps[psind],
		    PROT_READ | PROT_WRITE | PROT_CAP,
		    MAP_ANON | MAP_SHARED | MAP_HUGETLB |
		    (__builtin_ctzll(ps[psind]) << MAP_HUGE_SHIFT), -1, 0));
#else
		cheriostest_failure_errx("PROT_CAP is not defined");
#endif
#endif

		/* Verify mmap output */
		CHERIOSTEST_VERIFY2(cheri_tag_get(addr) != 0,
		    "mmap invalid capability for psind=%d", psind);
		CHERIOSTEST_VERIFY2(cheri_length_get(addr) == ps[psind],
		    "mmap wrong capability length for psind=%d "
		    "expected %jx found %jx",
		    psind, ps[psind], cheri_length_get(addr));
		CHERIOSTEST_VERIFY2((cheri_perms_get(addr) & perms) == perms,
		    "mmap missing permission expected %jx found %jx",
		    (uintmax_t)perms, (uintmax_t) cheri_perms_get(addr));

		/* Try to store capabilities in the SHM region */
		map_buffer = (void * volatile *)addr;
		*map_buffer = &v;
		CHERIOSTEST_VERIFY2(cheri_tag_get(*map_buffer) != 0, "tag lost");

		map_buffer = (void * volatile *)((uintptr_t)addr +
		    ps[psind] / 2);
		*map_buffer = &v;
		CHERIOSTEST_VERIFY2(cheri_tag_get(*map_buffer) != 0, "tag lost");

		map_buffer = (void * volatile *)((uintptr_t)addr +
		    ps[psind] - CHERITEST_PAGE_SIZE);
		*map_buffer = &v;
		CHERIOSTEST_VERIFY2(cheri_tag_get(*map_buffer) != 0, "tag lost");

		CHERIOSTEST_CHECK_SYSCALL(munmap(addr, ps[psind]));
#ifdef __FreeBSD__
		CHERIOSTEST_CHECK_SYSCALL(close(fd));
#endif
	}
#if defined(__linux__)
	free(ps);
#endif

	cheriostest_success();
}
#endif /* PMAP_HAS_LARGEPAGES */

#ifdef __FreeBSD__
/*
 * Store a cap to a page and check that mincore reports it CAPSTORE.
 *
 * Due to a shortage of bits in mincore()'s uint8_t reporting bit vector, this
 * particular test is not able to distinguish CAPSTORE and CAPDIRTY and so is
 * not sensitive to the vm.pmap.enter_capstore_as_capdirty sysctl.
 *
 * On the other hand, this test is sensitive to the vm.capstore_on_alloc sysctl:
 * if that is asserted, our cap-capable anonymous memory will be installed
 * CAPSTORE (and possibly even CAPDIRTY, in light of the above) whereas, if this
 * sysctl is clear, our initial view of said memory will be !CAPSTORE.
 */
CHERIOSTEST(vm_capdirty, "verify capdirty marking and mincore")
{
#define CHERIOSTEST_VM_CAPDIRTY_NPG	2
	size_t sz = CHERIOSTEST_VM_CAPDIRTY_NPG * getpagesize();
	uint8_t capstore_on_alloc;
	size_t capstore_on_alloc_sz = sizeof(capstore_on_alloc);

	void * __capability *pg0;
	unsigned char mcv[CHERIOSTEST_VM_CAPDIRTY_NPG] = { 0 };

	CHERIOSTEST_CHECK_SYSCALL(
	    sysctlbyname("vm.capstore_on_alloc", &capstore_on_alloc,
	        &capstore_on_alloc_sz, NULL, 0));

	pg0 = CHERIOSTEST_CHECK_SYSCALL(
	    mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_ANON, -1, 0));

	void * __capability *pg1 = (void *)&((char *)pg0)[getpagesize()];

	/*
	 * Pages are ZFOD and so will not be CAPSTORE, or, really, anything
	 * else, either.
	 */
	CHERIOSTEST_CHECK_SYSCALL(mincore(pg0, sz, &mcv[0]));
	CHERIOSTEST_VERIFY2(mcv[0] == 0, "page 0 status 0");
	CHERIOSTEST_VERIFY2(mcv[1] == 0, "page 1 status 0");

	/*
	 * Write data to page 0, causing it to become allocated and MODIFIED.
	 * If vm.capstore_on_alloc, then it should be CAPSTORE as well, despite
	 * having never been the target of a capability store.
	 */
	*(char *)pg0 = 0x42;

	CHERIOSTEST_CHECK_SYSCALL(mincore(pg0, sz, &mcv[0]));
	CHERIOSTEST_VERIFY2(
	    (mcv[0] & MINCORE_MODIFIED) != 0, "page 0 modified 1");
	CHERIOSTEST_VERIFY2(
	    !(mcv[0] & MINCORE_CAPSTORE) == !capstore_on_alloc,
	    "page 0 capstore 1");

	/*
	 * Write a capability to page 1 and check that it is MODIFIED and
	 * CAPSTORE regardless of vm.capstore_on_alloc.
	 */
	*pg1 = (__cheri_tocap void * __capability)pg0;

	CHERIOSTEST_CHECK_SYSCALL(mincore(pg0, sz, &mcv[0]));
	CHERIOSTEST_VERIFY2(
	    (mcv[1] & MINCORE_MODIFIED) != 0, "page 1 modified 2");
	CHERIOSTEST_VERIFY2(
	    (mcv[1] & MINCORE_CAPSTORE) != 0, "page 1 capstore 2");

	CHERIOSTEST_CHECK_SYSCALL(munmap(pg0, sz));
	cheriostest_success();
#undef CHERIOSTEST_VM_CAPDIRTY_NPG
}
#endif

#ifdef CHERIOSTEST_CHERI_REVOKE_TESTS
/*
 * Revocation tests
 */

static int
check_revoked(void *r)
{
	return (cheri_tag_get(r) == 0) ||
		((cheri_type_get(r) == -1L) && (cheri_perms_get(r) == 0));
}

#if defined(__FreeBSD__)
static const char *
skip_need_quarantine_unmapped_reservations(
    const struct cheri_test *ctp __attribute__((__unused__)))
{
	if (!feature_present("cheri_revoke"))
		return ("Kernel does not support revocation");
	if (!reservations_are_quarantined())
		return ("unmapped reservations are not being quarantined");
	return (NULL);
}

/*
 * Install a couple of knotes into the queue, one identified by a file
 * descriptor and one not, to exercise different code paths in the kernel.
 * The knotes will contain a user capability which should be detected and
 * handled by the kernel's caprevoke machinery.
 */
static void
install_kqueue_cap(int kq, int pfd[2], void *revme)
{
	struct kevent ike;
	ssize_t rv;
	char b;

	EV_SET(&ike, (uintptr_t)&install_kqueue_cap,
	    EVFILT_USER, EV_ADD | EV_ONESHOT | EV_DISABLE, NOTE_FFNOP, 0,
	    revme);
	CHERIOSTEST_CHECK_SYSCALL(kevent(kq, &ike, 1, NULL, 0, NULL));
	EV_SET(&ike, (uintptr_t)&install_kqueue_cap, EVFILT_USER, EV_KEEPUDATA,
	    NOTE_FFNOP | NOTE_TRIGGER, 0, NULL);
	CHERIOSTEST_CHECK_SYSCALL(kevent(kq, &ike, 1, NULL, 0, NULL));

	EV_SET(&ike, (uintptr_t)pfd[0], EVFILT_READ, EV_ADD | EV_DISABLE, 0, 0,
	    revme);
	CHERIOSTEST_CHECK_SYSCALL(kevent(kq, &ike, 1, NULL, 0, NULL));
	b = 42;
	rv = CHERIOSTEST_CHECK_SYSCALL(write(pfd[1], &b, sizeof(b)));
	CHERIOSTEST_VERIFY(rv == 1);
}

static void
check_kqueue_cap(int kq, int pfd[2], unsigned int valid)
{
	struct kevent ike, oke = { 0 };
	ssize_t rv;
	char b;

	EV_SET(&ike, (uintptr_t)&install_kqueue_cap,
	    EVFILT_USER, EV_ENABLE|EV_KEEPUDATA, NOTE_FFNOP, 0, NULL);
	CHERIOSTEST_CHECK_SYSCALL(kevent(kq, &ike, 1, NULL, 0, NULL));
	CHERIOSTEST_CHECK_SYSCALL(kevent(kq, NULL, 0, &oke, 1, NULL));
	CHERIOSTEST_VERIFY2(
	    cheri_is_equal_exact(oke.ident, &install_kqueue_cap),
	    "Bad identifier from kqueue");
	CHERIOSTEST_VERIFY2(oke.filter == EVFILT_USER,
	    "Bad filter from kqueue");
	CHERIOSTEST_VERIFY2(check_revoked(oke.udata) == !valid,
	    "kqueue-held cap not as expected");

	memset(&oke, 0, sizeof(0));
	EV_SET(&ike, pfd[0], EVFILT_READ, EV_ENABLE | EV_KEEPUDATA, 0, 0, NULL);
	CHERIOSTEST_CHECK_SYSCALL(kevent(kq, &ike, 1, NULL, 0, NULL));
	CHERIOSTEST_CHECK_SYSCALL(kevent(kq, NULL, 0, &oke, 1, NULL));
	CHERIOSTEST_VERIFY2(oke.ident == (uintptr_t)pfd[0],
	    "Bad identifier from kqueue");
	CHERIOSTEST_VERIFY2(oke.filter == EVFILT_READ,
	    "Bad filter from kqueue");
	CHERIOSTEST_VERIFY2(check_revoked(oke.udata) == !valid,
	    "kqueue-held cap not as expected");
	rv = CHERIOSTEST_CHECK_SYSCALL(read(pfd[0], &b, sizeof(b)));
	CHERIOSTEST_VERIFY(rv == 1);
	CHERIOSTEST_VERIFY(b == 42);
}
#endif

CHERIOSTEST(cheri_revoke_lightly, "A gentle test of capability revocation",
#if defined(__linux__)
    .ct_xfail_reason = "Not supported"
#else
    .ct_check_skip = skip_need_cheri_revoke
#endif
)
{
#ifdef __linux__
	cheriostest_failure_errx("The CHERI Linux Project does not support revocation");
#else
	void **mb;
	void *sh;
	const volatile struct cheri_revoke_info *cri;
	void *revme;
	struct cheri_revoke_syscall_info crsi;
	int ekq, kq, pfd[2];

	/*
	 * Set up our descriptors.  Keep an empty kqueue around to help exercise
	 * extra code paths in the kernel.
	 */
	ekq = CHERIOSTEST_CHECK_SYSCALL(kqueue());
	kq = CHERIOSTEST_CHECK_SYSCALL(kqueue());
	CHERIOSTEST_CHECK_SYSCALL(pipe(pfd));

	mb = CHERIOSTEST_CHECK_SYSCALL(
	    mmap(0, CHERITEST_PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANON, -1, 0));
	CHERIOSTEST_CHECK_SYSCALL(
	    cheri_revoke_get_shadow(CHERI_REVOKE_SHADOW_NOVMEM, mb, &sh));

	CHERIOSTEST_CHECK_SYSCALL(cheri_revoke_get_shadow(
	    CHERI_REVOKE_SHADOW_INFO_STRUCT, NULL, __DEQUALIFY(void **, &cri)));

	/*
	 * OK, armed with the shadow mapping... generate a capability to
	 * the 0th granule of the map, spill it to the 1st granule,
	 * stash it in the kqueue, and mark it as revoked in the shadow.
	 */
	revme = cheri_perms_and(mb, ~CHERI_PERM_SW_VMEM);
	((void **)mb)[1] = revme;
	install_kqueue_cap(kq, pfd, revme);

	((uint8_t *)sh)[0] = 1;

	crsi.epochs.enqueue = 0xC0FFEE;
	crsi.epochs.dequeue = 0xB00;

	CHERIOSTEST_CHECK_SYSCALL(
	    cheri_revoke(CHERI_REVOKE_LAST_PASS | CHERI_REVOKE_IGNORE_START |
	    CHERI_REVOKE_TAKE_STATS , 0, &crsi));

	CHERIOSTEST_VERIFY2(
	    cri->epochs.dequeue == crsi.epochs.dequeue,
	    "Bad shared clock");

	CHERIOSTEST_VERIFY2(check_revoked(mb[1]), "Memory tag persists");
	check_kqueue_cap(kq, pfd, 0);

	/* Clear the revocation bit and do that again */
	((uint8_t *)sh)[0] = 0;

	/*
	 * We don't derive exactly the same thing, to prevent CSE from
	 * firing.  More specifically, we adjust the offset first, taking
	 * the path through the commutation diagram that doesn't share an
	 * edge with the derivation above.
	 */
	revme = cheri_perms_and(mb + 1, ~CHERI_PERM_SW_VMEM);
	CHERIOSTEST_VERIFY2(!check_revoked(revme), "Tag clear on 2nd revme?");
	((void **)mb)[1] = revme;
	install_kqueue_cap(kq, pfd, revme);

	CHERIOSTEST_CHECK_SYSCALL(cheri_revoke(CHERI_REVOKE_IGNORE_START |
	    CHERI_REVOKE_TAKE_STATS, 0, &crsi));

	CHERIOSTEST_VERIFY2(
	    crsi.epochs.enqueue >= crsi.epochs.dequeue + 1,
	    "Bad epoch clock state");

	CHERIOSTEST_VERIFY2(
	    cri->epochs.dequeue == crsi.epochs.dequeue,
	    "Bad shared clock");

	CHERIOSTEST_CHECK_SYSCALL(
	    cheri_revoke(CHERI_REVOKE_LAST_PASS | CHERI_REVOKE_TAKE_STATS,
	    crsi.epochs.enqueue, &crsi));

	CHERIOSTEST_VERIFY2(
	    cri->epochs.dequeue == crsi.epochs.dequeue,
	    "Bad shared clock");

	CHERIOSTEST_VERIFY2(!check_revoked(mb[1]), "Memory tag cleared");

	check_kqueue_cap(kq, pfd, 1);

	munmap(mb, CHERITEST_PAGE_SIZE);
	close(kq);
	close(ekq);
	close(pfd[0]);
	close(pfd[1]);

	cheriostest_success();
#endif
}

CHERIOSTEST(cheri_revoke_loadside, "Test load-side revoker",
#if defined(__linux__)
    .ct_xfail_reason = "Not supported"
#else
    .ct_check_skip = skip_need_cheri_revoke
#endif
)
{
#ifdef __linux__
	cheriostest_failure_errx("The CHERI Linux Project does not support revocation");
#else

#define CHERIOSTEST_VM_CHERI_REVOKE_LOADSIDE_NPG	3

	void **mb;
	void *sh;
	const volatile struct cheri_revoke_info *cri;
	void *revme;
	struct cheri_revoke_syscall_info crsi;
	unsigned char mcv[CHERIOSTEST_VM_CHERI_REVOKE_LOADSIDE_NPG] = { 0 };
	const size_t asz = CHERIOSTEST_VM_CHERI_REVOKE_LOADSIDE_NPG *
	    CHERITEST_PAGE_SIZE;

	mb = CHERIOSTEST_CHECK_SYSCALL(
	    mmap(0, asz, PROT_READ | PROT_WRITE, MAP_ANON, -1, 0));
	CHERIOSTEST_CHECK_SYSCALL(
	    cheri_revoke_get_shadow(CHERI_REVOKE_SHADOW_NOVMEM, mb, &sh));

	CHERIOSTEST_CHECK_SYSCALL(cheri_revoke_get_shadow(
	    CHERI_REVOKE_SHADOW_INFO_STRUCT, NULL,
	    __DEQUALIFY_CAP(void **, &cri)));

	revme = cheri_perms_and(mb, ~CHERI_PERM_SW_VMEM);
	((void **)mb)[1] = revme;
	((uint8_t *)sh)[0] = 1;

	/* Write and clear a capability one page up */
	size_t capsperpage = CHERITEST_PAGE_SIZE/sizeof(void *);
	((void * volatile *)mb)[capsperpage] = revme;
	((volatile uintptr_t *)mb)[capsperpage] = 0;

	CHERIOSTEST_CHECK_SYSCALL(mincore(mb, asz, &mcv[0]));
	CHERIOSTEST_VERIFY2(
	    (mcv[0] & MINCORE_CAPSTORE) != 0, "page 0 capstore 1");
	CHERIOSTEST_VERIFY2(
	    (mcv[1] & MINCORE_CAPSTORE) != 0, "page 1 capstore 1");
	CHERIOSTEST_VERIFY2(
	    (mcv[2] & MINCORE_CAPSTORE) == 0, "page 2 capstore 1");

	/*
	 * Begin load side.  This should be pretty speedy since we do no VM
	 * walks.
	 */
	CHERIOSTEST_CHECK_SYSCALL(cheri_revoke(CHERI_REVOKE_IGNORE_START |
	    CHERI_REVOKE_TAKE_STATS, 0, &crsi));

	/*
	 * Try to induce a read fault and check that the read result is revoked.
	 * Unfortunately, we can't check its capdirty status, but it should
	 * still be CAPSTORED, since not enough time has elapsed for the state
	 * machine to declare it clean.
	 */
	revme = ((void **)mb)[1];
	CHERIOSTEST_VERIFY2(check_revoked(revme), "Fault didn't stop me!");

	CHERIOSTEST_CHECK_SYSCALL(mincore(mb, asz, &mcv[0]));
	CHERIOSTEST_VERIFY2(
	    (mcv[0] & MINCORE_CAPSTORE) != 0, "page 0 capstore 2.0");
	CHERIOSTEST_VERIFY2(
	    (mcv[1] & MINCORE_CAPSTORE) != 0, "page 1 capstore 2.0");

	/*
	 * This might redirty the 0th page, if we're keeping tags around on
	 * revoked caps.  If it does, we expect the dirty bit to stay set
	 * through the revoker sweep (though that's not strictly essential)
	 */
	((void **)mb)[2] = revme;

	/*
	 * Now do the background sweep and wait for everything to finish
	 */
	CHERIOSTEST_CHECK_SYSCALL(
	    cheri_revoke(CHERI_REVOKE_LAST_PASS | CHERI_REVOKE_IGNORE_START |
		CHERI_REVOKE_TAKE_STATS, 0, &crsi));

	CHERIOSTEST_CHECK_SYSCALL(mincore(mb, asz, &mcv[0]));
	CHERIOSTEST_VERIFY2(
	    (mcv[0] & MINCORE_CAPSTORE) != 0, "page 0 capstore 2.1");
	CHERIOSTEST_VERIFY2(
	    (mcv[1] & MINCORE_CAPSTORE) != 0, "page 1 capstore 2.1");

	/* Re-dirty page 0 but not page 1 */
	revme = cheri_perms_and(mb + 1, ~CHERI_PERM_SW_VMEM);
	CHERIOSTEST_VERIFY2(!check_revoked(revme), "Tag clear on 2nd revme?");
	((void **)mb)[1] = revme;

	CHERIOSTEST_CHECK_SYSCALL(mincore(mb, asz, &mcv[0]));
	CHERIOSTEST_VERIFY2(
	    (mcv[0] & MINCORE_CAPSTORE) != 0, "page 0 capstore 2.2");
	CHERIOSTEST_VERIFY2(
	    (mcv[1] & MINCORE_CAPSTORE) != 0, "page 1 capstore 2.2");

	/*
	 * Do another revocation, both parts at once this time.  This should
	 * transition page 0 from capdirty to capstore, since all capabilities
	 * on it are revoked.  Page 1, having previously been capstore, is now
	 * capclean.
	 */
	CHERIOSTEST_CHECK_SYSCALL(
	    cheri_revoke(CHERI_REVOKE_LAST_PASS | CHERI_REVOKE_IGNORE_START |
		CHERI_REVOKE_TAKE_STATS, 0, &crsi));

	CHERIOSTEST_VERIFY2(check_revoked(mb[1]),
	    "Revoker failure in full pass");

	CHERIOSTEST_CHECK_SYSCALL(mincore(mb, asz, &mcv[0]));
	CHERIOSTEST_VERIFY2(
	    (mcv[0] & MINCORE_CAPSTORE) != 0, "page 0 capstore 3");
	CHERIOSTEST_VERIFY2(
	    (mcv[1] & MINCORE_CAPSTORE) == 0, "page 1 capstore 3");

	/*
	 * Do that again so that we end with an odd CLG.
	 */
	CHERIOSTEST_CHECK_SYSCALL(
	    cheri_revoke(CHERI_REVOKE_LAST_PASS | CHERI_REVOKE_IGNORE_START |
	        CHERI_REVOKE_TAKE_STATS, 0, &crsi));

	CHERIOSTEST_CHECK_SYSCALL(mincore(mb, asz, &mcv[0]));
	CHERIOSTEST_VERIFY2(
	    (mcv[0] & MINCORE_CAPSTORE) == 0, "page 0 capstore 4");
	CHERIOSTEST_VERIFY2(
	    (mcv[1] & MINCORE_CAPSTORE) == 0, "page 1 capstore 4");
	/*
	 * TODO:
	 *
	 * - check that we can store to a page at any point in that transition.
	 */

	cheriostest_success();

#undef CHERIOSTEST_VM_CHERI_REVOKE_LOADSIDE_NPG
#endif
}

CHERIOSTEST(cheri_revoke_async,
    "A gentle test of asynchronous capability revocation",
#if defined(__linux__)
    .ct_xfail_reason = "Not supported"
#else
    .ct_check_skip = skip_need_cheri_revoke
#endif
)
{
#if defined(__linux__)
	cheriostest_failure_errx("The CHERI Linux Project does not support revocation");
#else
	struct cheri_revoke_syscall_info crsi;
	const volatile struct cheri_revoke_info *cri;
	cheri_revoke_epoch_t epoch;
	void **mb;
	void *sh;

	mb = CHERIOSTEST_CHECK_SYSCALL(
	    mmap(0, CHERITEST_PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANON, -1, 0));

	CHERIOSTEST_CHECK_SYSCALL(
	    cheri_revoke_get_shadow(CHERI_REVOKE_SHADOW_NOVMEM, mb, &sh));
	CHERIOSTEST_CHECK_SYSCALL(cheri_revoke_get_shadow(
	    CHERI_REVOKE_SHADOW_INFO_STRUCT, NULL, __DEQUALIFY(void **, &cri)));

	mb[1] = cheri_perms_and(mb, ~CHERI_PERM_SW_VMEM);
	((uint8_t *)sh)[0] = 1;
	epoch = cri->epochs.dequeue;

	memset(&crsi, 0, sizeof(crsi));
	CHERIOSTEST_CHECK_SYSCALL(
	    cheri_revoke(CHERI_REVOKE_ASYNC | CHERI_REVOKE_IGNORE_START, 0,
	    &crsi));

	CHERIOSTEST_VERIFY2(
	    cri->epochs.enqueue == crsi.epochs.enqueue,
	    "Bad shared enqueue clock (%lu %lu)",
	    cri->epochs.enqueue, crsi.epochs.enqueue);
	CHERIOSTEST_VERIFY2(
	    cri->epochs.dequeue == crsi.epochs.dequeue,
	    "Bad shared dequeue clock (%lu %lu)",
	    cri->epochs.dequeue, crsi.epochs.dequeue);
	CHERIOSTEST_VERIFY2(
	    cri->epochs.enqueue == cri->epochs.dequeue + 1,
	    "Bad shared clock (%lu %lu)",
	    cri->epochs.enqueue, cri->epochs.dequeue);

	while (!cheri_revoke_epoch_clears(cri->epochs.dequeue, epoch)) {
		CHERIOSTEST_CHECK_SYSCALL(
		    cheri_revoke(CHERI_REVOKE_ASYNC | CHERI_REVOKE_IGNORE_START,
		    0, NULL));
		usleep(1000);
	}

	CHERIOSTEST_VERIFY2(
	    cri->epochs.enqueue == cri->epochs.dequeue,
	    "Bad shared post-revocation clock (%lu %lu)",
	    cri->epochs.enqueue, cri->epochs.dequeue);
	CHERIOSTEST_VERIFY2(
	    cri->epochs.dequeue == crsi.epochs.dequeue + 2,
	    "Unexpected clock jump (%lu %lu)",
	    cri->epochs.dequeue, crsi.epochs.dequeue);

	CHERIOSTEST_VERIFY2(check_revoked(mb[1]), "Memory tag persists");

	cheriostest_success();
#endif
}

#ifdef CHERIBSD_THREAD_TESTS
static void *
forker(void *arg)
{
	atomic_int *p = arg;

	while (*p == 0) {
		pid_t child = fork();
		CHERIOSTEST_VERIFY2(child > 0, "fork failed");
		if (child == 0)
			_exit(0);
		(void)waitpid(child, NULL, 0);
	}

	return (NULL);
}

CHERIOSTEST(cheri_revoke_async_fork,
    "A test of asynchronous capability revocation with concurrent forks",
#if defined(__linux__)
    .ct_xfail_reason = "Not supported"
#else
    .ct_check_skip = skip_need_cheri_revoke
#endif
)
{
#ifdef __linux__
	cheriostest_failure_errx("The CHERI Linux Project does not support revocation");
#else
	struct cheri_revoke_syscall_info crsi;
	const volatile struct cheri_revoke_info *cri;
	cheri_revoke_epoch_t epoch;
	pthread_t thr;
	void **mb;
	void *sh;
	atomic_int forker_res;
	int error;

	forker_res = 0;
	error = pthread_create(&thr, NULL, forker, &forker_res);
	if (error != 0)
		cheriostest_failure_errc(error, "pthread_create");

	mb = CHERIOSTEST_CHECK_SYSCALL(
	    mmap(0, CHERITEST_PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANON, -1, 0));

	CHERIOSTEST_CHECK_SYSCALL(
	    cheri_revoke_get_shadow(CHERI_REVOKE_SHADOW_NOVMEM, mb, &sh));
	CHERIOSTEST_CHECK_SYSCALL(cheri_revoke_get_shadow(
	    CHERI_REVOKE_SHADOW_INFO_STRUCT, NULL, __DEQUALIFY(void **, &cri)));

	mb[1] = cheri_perms_and(mb, ~CHERI_PERM_SW_VMEM);
	((uint8_t *)sh)[0] = 1;
	epoch = cri->epochs.dequeue;

	memset(&crsi, 0, sizeof(crsi));
	CHERIOSTEST_CHECK_SYSCALL(
	    cheri_revoke(CHERI_REVOKE_ASYNC | CHERI_REVOKE_IGNORE_START, 0,
	    &crsi));

	CHERIOSTEST_VERIFY2(
	    cri->epochs.enqueue == crsi.epochs.enqueue,
	    "Bad shared enqueue clock (%lu %lu)",
	    cri->epochs.enqueue, crsi.epochs.enqueue);
	CHERIOSTEST_VERIFY2(
	    cri->epochs.dequeue == crsi.epochs.dequeue,
	    "Bad shared dequeue clock (%lu %lu)",
	    cri->epochs.dequeue, crsi.epochs.dequeue);
	CHERIOSTEST_VERIFY2(
	    cri->epochs.enqueue == cri->epochs.dequeue + 1,
	    "Bad shared clock (%lu %lu)",
	    cri->epochs.enqueue, cri->epochs.dequeue);

	while (!cheri_revoke_epoch_clears(cri->epochs.dequeue, epoch)) {
		CHERIOSTEST_CHECK_SYSCALL(
		    cheri_revoke(CHERI_REVOKE_ASYNC | CHERI_REVOKE_IGNORE_START,
		    0, NULL));
		usleep(1000);
	}

	CHERIOSTEST_VERIFY2(
	    cri->epochs.enqueue == cri->epochs.dequeue,
	    "Bad shared post-revocation clock (%lu %lu)",
	    cri->epochs.enqueue, cri->epochs.dequeue);
	CHERIOSTEST_VERIFY2(
	    cri->epochs.dequeue == crsi.epochs.dequeue + 2,
	    "Unexpected clock jump (%lu %lu)",
	    cri->epochs.dequeue, crsi.epochs.dequeue);

	CHERIOSTEST_VERIFY2(check_revoked(mb[1]), "Memory tag persists");

	forker_res = 1;
	error = pthread_join(thr, NULL);
	if (error != 0)
		cheriostest_failure_errc(error, "pthread_join");

	cheriostest_success();
#endif
}
#endif /* CHERIBSD_THREAD_TESTS */

#if defined(__FreeBSD__)
/*
 * Repeatedly invoke libcheri_caprevoke logic.
 * Using a bump the pointer allocator, repeatedly grab rand()-omly sized
 * objects and fill them with capabilities to themselves, mark them for
 * revocation, revoke, and validate.
 *
 */

#include <cheri/libcaprevoke.h>

static void
cheriostest_cheri_revoke_lib_init(size_t bigblock_caps, void *** obigblock,
    void ** oshadow, const volatile struct cheri_revoke_info ** ocri)
{
	void **bigblock;

	bigblock = CHERIOSTEST_CHECK_SYSCALL(
	    mmap(0, bigblock_caps * sizeof(void *), PROT_READ | PROT_WRITE,
	    MAP_ANON, -1, 0));

	for (size_t ix = 0; ix < bigblock_caps; ix++) {
		/* Create self-referential SW_VMEM-free capabilities */

		bigblock[ix] = cheri_perms_and(cheri_bounds_set(&bigblock[ix], 16),
		    ~CHERI_PERM_SW_VMEM);
	}
	*obigblock = bigblock;

	CHERIOSTEST_CHECK_SYSCALL(
	    cheri_revoke_get_shadow(CHERI_REVOKE_SHADOW_NOVMEM, bigblock,
	    oshadow));

	CHERIOSTEST_CHECK_SYSCALL(
	    cheri_revoke_get_shadow(CHERI_REVOKE_SHADOW_INFO_STRUCT, NULL,
	    __DEQUALIFY(void **, ocri)));
}

enum {
	TCLR_MODE_NONE = 0,
	TCLR_MODE_LOAD_ONCE = 1,
	TCLR_MODE_LOAD_SPLIT = 2,
	TCLR_MODE_LOAD_SPLIT_INIT = 3,
	TCLR_MODE_LOAD_SPLIT_FINI = 4,
};

static void
cheriostest_cheri_revoke_lib_run(int paranoia, int mode, size_t bigblock_caps,
    void **bigblock, void *shadow, const volatile struct cheri_revoke_info *cri)
{
	size_t bigblock_offset = 0;
	const ptraddr_t sbase = cri->base_mem_nomap;

	if (verbose > 1)
		fprintf(stderr, "test_cheri_revoke_lib_run mode %d\n", mode);

	while (bigblock_offset < bigblock_caps) {
		struct cheri_revoke_syscall_info crsi;
		size_t csz;

		switch (mode) {
		case TCLR_MODE_LOAD_SPLIT_INIT:
		case TCLR_MODE_LOAD_SPLIT_FINI:
			/*
			 * Just do one big block so we can
			 * call this function once to open the
			 * epoch and once to close it.
			 */
			csz = bigblock_caps - bigblock_offset;
			break;
		default:
			csz = rand() % 1024 + 1;
			csz = MIN(csz, bigblock_caps - bigblock_offset);
			break;
		}

		if (verbose > 1) {
			fprintf(stderr, "left=%zd csz=%zd\n",
			    bigblock_caps - bigblock_offset, csz);
		}

		void **chunk = cheri_bounds_set(bigblock + bigblock_offset,
		    csz * sizeof(void *));

		if (verbose > 1) {
			fprintf(stderr, "chunk: %#.16lp\n", chunk);
		}

		size_t chunk_offset = bigblock_offset;
		bigblock_offset += csz;

		if (mode == TCLR_MODE_LOAD_SPLIT_FINI)
			goto load_split_fini;

		if (verbose > 3) {
			ptrdiff_t fwo, lwo;
			uint64_t fwm, lwm;
			caprev_shadow_nomap_offsets((ptraddr_t)chunk,
			    csz * sizeof(void *), &fwo, &lwo);
			caprev_shadow_nomap_masks((ptraddr_t)chunk,
			    csz * sizeof(void *), &fwm, &lwm);

			fprintf(stderr,
			    "premrk fwo=%lx lwo=%lx fw=%p *fw=%016lx "
			    "(fwm=%016lx) *lw=%016lx (lwm=%016lx)\n",
			    fwo, lwo, cheri_address_set(shadow, sbase + fwo),
			    *(uint64_t *)(cheri_address_set(shadow, sbase + fwo)), fwm,
			    *(uint64_t *)(cheri_address_set(shadow, sbase + lwo)), lwm);
		}

		/* Mark the chunk for revocation */
		CHERIOSTEST_VERIFY2(caprev_shadow_nomap_set(
		    cri->base_mem_nomap, shadow, chunk, chunk) == 0,
		    "Shadow update collision");

		__atomic_thread_fence(__ATOMIC_RELEASE);

		if (verbose > 3) {
			ptrdiff_t fwo, lwo;
			caprev_shadow_nomap_offsets((ptraddr_t)chunk,
			    csz * sizeof(void *), &fwo, &lwo);

			fprintf(stderr,
			    "marked fwo=%lx lwo=%lx fw=%p *fw=%016lx "
			    "*lw=%016lx\n",
			    fwo, lwo, cheri_address_set(shadow, sbase + fwo),
			    *(uint64_t *)(cheri_address_set(shadow, sbase + fwo)),
			    *(uint64_t *)(cheri_address_set(shadow, sbase + lwo)));
		}

		{
			int crflags = CHERI_REVOKE_IGNORE_START |
			    CHERI_REVOKE_TAKE_STATS;

			switch(mode) {
			case TCLR_MODE_LOAD_ONCE:
				crflags |= CHERI_REVOKE_LAST_PASS;
				break;
			}

			CHERIOSTEST_CHECK_SYSCALL(cheri_revoke(crflags, 0,
			    &crsi));
			CHERIOSTEST_VERIFY2(cri->epochs.dequeue ==
			    crsi.epochs.dequeue, "Bad shared clock");
		}

		/* Check the surroundings */
		if (paranoia > 1) {
			for (size_t ix = 0; ix < chunk_offset; ix++) {
				CHERIOSTEST_VERIFY2(
				    !check_revoked(bigblock[ix]),
				    "Revoked cap incorrectly below object, "
				    "at ix=%zd", ix);
			}
			for (size_t ix = chunk_offset + csz; ix < bigblock_caps;
			    ix++) {
				CHERIOSTEST_VERIFY2(
				    !check_revoked(bigblock[ix]),
				    "Revoked cap incorrectly above object, "
				    "at ix=%zd", ix);
			}
		}

		if (paranoia > 0) {
			for (size_t ix = 0; ix < csz; ix++) {
				if (!check_revoked(chunk[ix])) {
					fprintf(stderr, "c %#.16lp\n",
					    chunk[ix]);
					cheriostest_failure_errx(
					    "Unrevoked at ix=%zd after revoke",
					    ix);
				}
			}
		}
		if (mode == TCLR_MODE_LOAD_SPLIT_INIT)
			return;

		if (mode == TCLR_MODE_LOAD_SPLIT) {
load_split_fini:
			CHERIOSTEST_CHECK_SYSCALL(cheri_revoke(
			    CHERI_REVOKE_LAST_PASS | CHERI_REVOKE_IGNORE_START |
			    CHERI_REVOKE_TAKE_STATS, 0, &crsi));
			CHERIOSTEST_VERIFY2(cri->epochs.dequeue ==
			    crsi.epochs.dequeue, "Bad shared clock");
		}

		caprev_shadow_nomap_clear(cri->base_mem_nomap, shadow, chunk);
		__atomic_thread_fence(__ATOMIC_RELEASE);

		for (size_t ix = 0; ix < csz; ix++) {
			/* Put everything back */
			chunk[ix] = cheri_perms_and(
			    cheri_bounds_set(&chunk[ix], 16),
			    ~CHERI_PERM_SW_VMEM);
		}
	}
}
#endif

CHERIOSTEST(cheri_revoke_lib, "Test libcheri_caprevoke internals",
#if defined(__linux__)
    .ct_xfail_reason = "Not supported"
#else
    .ct_check_skip = skip_need_cheri_revoke
#endif
)
{
#ifdef __linux__
	cheriostest_failure_errx("The CHERI Linux Project does not support revocation");
#else
	/*
	 * Tweaking paranoia can turn this test into more of a
	 * benchmark than a correctness test.  At 0, no checks
	 * will be performed; at 1, only the revoked object is
	 * investigated, and at 2, the entire allocation arena
	 * is tested.
	 */
	static const int paranoia = 2;

	static const size_t bigblock_caps = 4096;

	void **bigblock;
	void *shadow;
	const volatile struct cheri_revoke_info *cri;

	srand(1337);

	cheriostest_cheri_revoke_lib_init(bigblock_caps, &bigblock, &shadow,
	    &cri);

	if (verbose > 0) {
		fprintf(stderr, "bigblock: %#.16lp\n", bigblock);
		fprintf(stderr, "shadow: %#.16lp\n", shadow);
	}

	cheriostest_cheri_revoke_lib_run(paranoia,
	    TCLR_MODE_LOAD_ONCE, bigblock_caps, bigblock, shadow, cri);

	cheriostest_cheri_revoke_lib_run(paranoia,
	    TCLR_MODE_LOAD_SPLIT, bigblock_caps, bigblock, shadow, cri);

	munmap(bigblock, bigblock_caps * sizeof(void *));

	cheriostest_success();
#endif
}

CHERIOSTEST(cheri_revoke_lib_fork, "Test libcheri_caprevoke with fork",
#if defined(__linux__)
    .ct_xfail_reason = "Not supported"
#else
    .ct_check_skip = skip_need_cheri_revoke
#endif
)
{
#ifdef __linux__
	cheriostest_failure_errx("The CHERI Linux Project does not support revocation");
#else
	static const int paranoia = 2;

	static const size_t bigblock_caps = 4096;

	void **bigblock;
	void *shadow;
	const volatile struct cheri_revoke_info *cri;

	int pid;

	srand(1337);

	cheriostest_cheri_revoke_lib_init(bigblock_caps, &bigblock, &shadow,
	    &cri);

	if (verbose > 0) {
		fprintf(stderr, "bigblock: %#.16lp\n", bigblock);
		fprintf(stderr, "shadow: %#.16lp\n", shadow);
	}

	pid = fork();
	if (pid == 0) {
		cheriostest_cheri_revoke_lib_run(paranoia,
		    TCLR_MODE_LOAD_ONCE, bigblock_caps, bigblock, shadow, cri);

		cheriostest_cheri_revoke_lib_run(paranoia,
		    TCLR_MODE_LOAD_SPLIT, bigblock_caps, bigblock, shadow, cri);
	} else {
		int res;

		CHERIOSTEST_VERIFY2(pid > 0, "fork failed");
		waitpid(pid, &res, 0);
		if (res == 0) {
			cheriostest_success();
		} else {
			cheriostest_failure_errx("Bad child process exit");
		}
	}

	munmap(bigblock, bigblock_caps * sizeof(void *));

	cheriostest_success();
#endif
}

CHERIOSTEST(cheri_revoke_lib_fork_split,
    "Test libcheri_caprevoke split across fork",
#if defined(__linux__)
    .ct_xfail_reason = "Not supported",
#else
    .ct_check_skip = skip_need_cheri_revoke
#endif
)
{
#ifdef __linux__
	cheriostest_failure_errx("The CHERI Linux Project does not support revocation");
#else
	static const int paranoia = 2;

	static const size_t bigblock_caps = 4096;

	void **bigblock;
	void *shadow;
	const volatile struct cheri_revoke_info *cri;

	int pid;

	srand(1337);

	cheriostest_cheri_revoke_lib_init(bigblock_caps, &bigblock, &shadow,
	    &cri);

	if (verbose > 0) {
		fprintf(stderr, "bigblock: %#.16lp\n", bigblock);
		fprintf(stderr, "shadow: %#.16lp\n", shadow);
	}

	/* Open the epoch and begin revocation */
	cheriostest_cheri_revoke_lib_run(paranoia,
	    TCLR_MODE_LOAD_SPLIT_INIT, bigblock_caps, bigblock, shadow, cri);

	pid = fork();
	if (pid == 0) {
		/* Finish revocation */
		cheriostest_cheri_revoke_lib_run(paranoia,
		    TCLR_MODE_LOAD_SPLIT_FINI, bigblock_caps, bigblock,
		    shadow, cri);
	} else {
		int res;

		CHERIOSTEST_VERIFY2(pid > 0, "fork failed");
		waitpid(pid, &res, 0);
		if (res == 0) {
			cheriostest_success();
		} else {
			cheriostest_failure_errx("Bad child process exit");
		}
	}

	munmap(bigblock, bigblock_caps * sizeof(void *));

	cheriostest_success();
#endif
}

#if defined(__FreeBSD__)
/*
 * cheri_revoke_lib_child_* - test that execed children can revoke
 *
 * We selectively test along three axes:
 *   spawn method: fork+execve, rfork+execve, vfork+execve, posix_spawn
 *   pre-fork revoke: none, once, opened
 *   revoke type: once, split
 *
 * Testing all 24 cases is seems excessive so we limit rfork+execve to a
 * single test (posix_spawn being built on rfork) and alternate between
 * once and split as the difference has not previously resulted in bugs.
 */

static void
cheri_revoke_lib_child_spawn_common(enum spawn_child_mode sc_mode,
    int pre_fork_tclr_mode)
{
	static const int paranoia = 2;
	static const size_t bigblock_caps = 4096;
	void **bigblock;
	void *shadow;
	const volatile struct cheri_revoke_info *cri;
	int res;
	pid_t pid;

	/*
	 * Optionally exercise the revocation machinery before spawing a
	 * child process.
	 */
	if (pre_fork_tclr_mode != TCLR_MODE_NONE) {
		srand(1337);

		cheriostest_cheri_revoke_lib_init(bigblock_caps, &bigblock,
		    &shadow, &cri);
		cheriostest_cheri_revoke_lib_run(paranoia, pre_fork_tclr_mode,
		    bigblock_caps, bigblock, shadow, cri);
	}

	pid = cheriostest_spawn_child(sc_mode);

	CHERIOSTEST_VERIFY2(pid > 0, "spawning child process failed");
	waitpid(pid, &res, 0);
	if (res != 0)
		cheriostest_failure_errx("Bad child process exit");

	cheriostest_success();
}


static void
cheri_revoke_lib_child_common(int tclr_mode)
{
	static const int paranoia = 2;
	static const size_t bigblock_caps = 4096;
	void **bigblock;
	void *shadow;
	const volatile struct cheri_revoke_info *cri;

	srand(1337);

	cheriostest_cheri_revoke_lib_init(bigblock_caps, &bigblock, &shadow,
	    &cri);

	/*
	 * Technically the epoch doesn't have to be 0 when a new vmspace is
	 * created, but that's the most logical init value so assert it.
	 *
	 * XXX: check the state
	 */
	CHERIOSTEST_VERIFY(cri->epochs.enqueue == 0);
	CHERIOSTEST_VERIFY(cri->epochs.dequeue == 0);

	if (verbose > 0) {
		fprintf(stderr, "bigblock: %#.16lp\n", bigblock);
		fprintf(stderr, "shadow: %#.16lp\n", shadow);
	}

	cheriostest_cheri_revoke_lib_run(paranoia, tclr_mode, bigblock_caps,
	    bigblock, shadow, cri);

	munmap(bigblock, bigblock_caps * sizeof(void *));

	exit(0);
}

static void
cheri_revoke_lib_child_once(void)
{
	cheri_revoke_lib_child_common(TCLR_MODE_LOAD_ONCE);
}

static void
cheri_revoke_lib_child_split(void)
{
	cheri_revoke_lib_child_common(TCLR_MODE_LOAD_SPLIT);
}

/*
 *	These tests are surrounded by #ifdef __FreeBSD__ instead of
 *	emitting an XFAIL on Linux to not spam the test suite output
 *	with too many 'The CHERI Linux Project does not support revocation'
 *	messages.
 */
CHERIOSTEST(cheri_revoke_lib_child_fork_exec_once,
    "revoke in a fork+exec'd child",
    .ct_child_func = cheri_revoke_lib_child_once,
    .ct_check_skip = skip_need_cheri_revoke)
{
	cheri_revoke_lib_child_spawn_common(SC_MODE_FORK,
	    TCLR_MODE_NONE);
}

CHERIOSTEST(cheri_revoke_lib_child_fork_exec_split_prior,
    "split revoke in a fork+exec'd child after revoking once",
    .ct_child_func = cheri_revoke_lib_child_split,
    .ct_check_skip = skip_need_cheri_revoke)
{
	cheri_revoke_lib_child_spawn_common(SC_MODE_FORK,
	    TCLR_MODE_LOAD_ONCE);
}

CHERIOSTEST(cheri_revoke_lib_child_fork_exec_once_opened,
    "revoke in a fork+exec'd child after opening epoch",
    .ct_child_func = cheri_revoke_lib_child_once,
    .ct_check_skip = skip_need_cheri_revoke)
{
	cheri_revoke_lib_child_spawn_common(SC_MODE_FORK,
	    TCLR_MODE_LOAD_SPLIT_INIT);
}

CHERIOSTEST(cheri_revoke_lib_child_rfork_exec_split,
    "split revoke in a rfork+exec'd child",
    .ct_child_func = cheri_revoke_lib_child_split,
    .ct_check_skip = skip_need_cheri_revoke)
{
	cheri_revoke_lib_child_spawn_common(SC_MODE_RFORK,
	    TCLR_MODE_NONE);
}

CHERIOSTEST(cheri_revoke_lib_child_vfork_exec_once,
    "revoke in a vfork+exec'd child",
    .ct_child_func = cheri_revoke_lib_child_once,
    .ct_check_skip = skip_need_cheri_revoke)
{
	cheri_revoke_lib_child_spawn_common(SC_MODE_VFORK,
	    TCLR_MODE_NONE);
}

CHERIOSTEST(cheri_revoke_lib_child_vfork_exec_split_prior,
    "split revoke in a vfork+exec'd child after revoking once",
    .ct_child_func = cheri_revoke_lib_child_split,
    .ct_check_skip = skip_need_cheri_revoke)
{
	cheri_revoke_lib_child_spawn_common(SC_MODE_VFORK,
	    TCLR_MODE_LOAD_ONCE);
}

CHERIOSTEST(cheri_revoke_lib_child_vfork_exec_once_opened,
    "revoke in a vfork+exec'd child after opening epoch",
    .ct_child_func = cheri_revoke_lib_child_once,
    .ct_check_skip = skip_need_cheri_revoke)
{
	cheri_revoke_lib_child_spawn_common(SC_MODE_VFORK,
	    TCLR_MODE_LOAD_SPLIT_INIT);
}

CHERIOSTEST(cheri_revoke_lib_child_posix_spawn_split,
    "split revoke in a posix_spawn'd child",
    .ct_child_func = cheri_revoke_lib_child_split,
    .ct_check_skip = skip_need_cheri_revoke)
{
	cheri_revoke_lib_child_spawn_common(SC_MODE_POSIX_SPAWN,
	    TCLR_MODE_NONE);
}

CHERIOSTEST(cheri_revoke_lib_child_posix_spawn_once_prior,
    "revoke in a posix_spawn'd child after revoking once",
    .ct_child_func = cheri_revoke_lib_child_once,
    .ct_check_skip = skip_need_cheri_revoke)
{
	cheri_revoke_lib_child_spawn_common(SC_MODE_POSIX_SPAWN,
	    TCLR_MODE_LOAD_ONCE);
}

CHERIOSTEST(cheri_revoke_lib_child_posix_spawn_split_opened,
    "split revoke in a posix_spawn'd child after revoking once",
    .ct_child_func = cheri_revoke_lib_child_split,
    .ct_check_skip = skip_need_cheri_revoke)
{
	cheri_revoke_lib_child_spawn_common(SC_MODE_POSIX_SPAWN,
	    TCLR_MODE_LOAD_SPLIT_INIT);
}
#endif

CHERIOSTEST(revoke_largest_quarantined_reservation,
    "Verify that the largest quarantined reservation is revoked",
#if defined(__linux__)
    .ct_xfail_reason = "Not supported",
#else
    .ct_check_skip = skip_need_quarantine_unmapped_reservations
#endif
)
{
#ifdef __linux__
	cheriostest_failure_errx("The CHERI Linux Project does not support revocation");
#else
	const size_t res_size = 0x100000000;
	void *res;
	ptraddr_t res_addr;
	struct procstat *psp;
	struct kinfo_proc *kipp;
	struct kinfo_vmentry *kivp;
	const volatile struct cheri_revoke_info *cri;
	uint pcnt, vmcnt;
	bool found_res;

	/* Make sure this process is revoking */
	CHERIOSTEST_CHECK_SYSCALL(cheri_revoke_get_shadow(
	    CHERI_REVOKE_SHADOW_INFO_STRUCT, NULL, __DEQUALIFY(void **, &cri)));

	res = CHERIOSTEST_CHECK_SYSCALL(mmap(NULL, res_size, PROT_READ,
	    MAP_ANON, -1, 0));
	res_addr = (ptraddr_t)res;
	CHERIOSTEST_CHECK_SYSCALL(munmap(res, res_size));

	psp = procstat_open_sysctl();
	CHERIOSTEST_VERIFY(psp != NULL);
	kipp = procstat_getprocs(psp, KERN_PROC_PID, getpid(), &pcnt);
	CHERIOSTEST_VERIFY(kipp != NULL);
	CHERIOSTEST_VERIFY(pcnt == 1);
	kivp = procstat_getvmmap(psp, kipp, &vmcnt);
	CHERIOSTEST_VERIFY(kivp != NULL);

	found_res = false;
	for (u_int i = 0; i < vmcnt; i++) {
		/*
		 * Look for an entry containing our reservation.  It
		 * may have been merged with a previously quarantined
		 * region so don't expect an exact match.
		 */
		if (kivp[i].kve_start <= res_addr &&
		    kivp[i].kve_end >= res_addr + res_size) {
			found_res = true;
			CHERIOSTEST_VERIFY(kivp[i].kve_type ==
			    KVME_TYPE_QUARANTINED);
		}
	}
	CHERIOSTEST_VERIFY2(found_res, "reservation not found in vmmap");

	procstat_freevmmap(psp, kivp);

	/*
	 * XXX: Assume that the revoker will revoke the largest
	 * quarantined reservation.
	 */
	CHERIOSTEST_CHECK_SYSCALL(cheri_revoke(
	    CHERI_REVOKE_LAST_PASS | CHERI_REVOKE_IGNORE_START, 0, NULL));

	kivp = procstat_getvmmap(psp, kipp, &vmcnt);
	CHERIOSTEST_VERIFY(kivp != NULL);

	for (u_int i = 0; i < vmcnt; i++) {
		/*
		 * Look for an entry containing our reservation.  We
		 * assuming res_size is large enough that it's the
		 * reservation we revoke, we shouldn't find it.
		 *
		 * XXX: It's possible procstat_getvmmap() could trigger
		 * reuse of this space, but probably not since we'll
		 * have just flushed malloc()'s quarantine list so
		 * there should be plenty of objects on the free list(s).
		 */
		if (kivp[i].kve_start <= res_addr &&
		    kivp[i].kve_end >= res_addr + res_size) {
			cheriostest_failure_errx(
			    "reservation still in memory map");
		}
	}

	procstat_freevmmap(psp, kivp);
	procstat_freeprocs(psp, kipp);
	procstat_close(psp);
	cheriostest_success();
#endif
}

#define	NRES	3
CHERIOSTEST(revoke_merge_quarantined,
    "Verify that adjacent non-neighbor reservations are revoked",
#if defined(__linux__)
    .ct_xfail_reason = "Not supported",
#else
    .ct_check_skip = skip_need_quarantine_unmapped_reservations
#endif
)
{
#ifdef __linux__
	cheriostest_failure_errx("The CHERI Linux Project does not support revocation");
#else
	const size_t big_res_size = 0x100000000;
	const size_t res_sizes[NRES] =
	    { CHERITEST_PAGE_SIZE, big_res_size, CHERITEST_PAGE_SIZE };
	const size_t res_offsets[NRES] =
	    { CHERITEST_PAGE_SIZE, big_res_size, 3 * big_res_size };
	void *res;
	ptraddr_t res_addrs[NRES], working_space;
	struct procstat *psp;
	struct kinfo_proc *kipp;
	struct kinfo_vmentry *kivp;
	const volatile struct cheri_revoke_info *cri;
	uint pcnt, vmcnt;
	bool found_res[NRES] = {};

	/* Make sure this process is revoking */
	CHERIOSTEST_CHECK_SYSCALL(cheri_revoke_get_shadow(
	    CHERI_REVOKE_SHADOW_INFO_STRUCT, NULL, __DEQUALIFY(void **, &cri)));

	/*
	 * Create a single large quarantined reservation with three
	 * non-adjacent, quarantined neighbors inside it (the edges are
	 * padded to prevent merging with neighbors are creation time).
	 *
	 * The three quarantined regions are:
	 *  - A CHERITEST_PAGE_SIZE entry at offset CHERITEST_PAGE_SIZE.
	 *  - A large (big_res_size) allocation at offset big_res_size.
	 *  - A CHERITEST_PAGE_SIZE reservation at offset 3*big_res_size.
	 */
	working_space = find_address_space_gap(big_res_size * 4, 0);
	for (int r = 0; r < NRES; r++) {
		res = CHERIOSTEST_CHECK_SYSCALL(mmap(
		    (void *)(uintptr_t)(working_space + res_offsets[r]),
		    res_sizes[r], PROT_READ, MAP_ANON, -1, 0));
		res_addrs[r] = (ptraddr_t)res;
		CHERIOSTEST_CHECK_SYSCALL(munmap(res, res_sizes[r]));
	}

	psp = procstat_open_sysctl();
	CHERIOSTEST_VERIFY(psp != NULL);
	kipp = procstat_getprocs(psp, KERN_PROC_PID, getpid(), &pcnt);
	CHERIOSTEST_VERIFY(kipp != NULL);
	CHERIOSTEST_VERIFY(pcnt == 1);
	kivp = procstat_getvmmap(psp, kipp, &vmcnt);
	CHERIOSTEST_VERIFY(kivp != NULL);

	/*
	 * Check that there are quarantines resevations at each expected
	 * location.
	 */
	for (u_int i = 0; i < vmcnt; i++) {
		for (int r = 0; r < NRES; r++) {
			if (kivp[i].kve_start == res_addrs[r]) {
				found_res[r] = true;
				CHERIOSTEST_VERIFY(kivp[i].kve_type ==
				    KVME_TYPE_QUARANTINED);
			}
		}
	}
	for (int r = 0; r < NRES; r++)
		CHERIOSTEST_VERIFY2(found_res[r],
		    "reservation not found in vmmap");

	procstat_freevmmap(psp, kivp);

	/*
	 * XXX: Assume that the revoker will revoke the largest
	 * quarantined reservation and merge it with it's neighbors.
	 */
	CHERIOSTEST_CHECK_SYSCALL(cheri_revoke(
	    CHERI_REVOKE_LAST_PASS | CHERI_REVOKE_IGNORE_START, 0, NULL));

	kivp = procstat_getvmmap(psp, kipp, &vmcnt);
	CHERIOSTEST_VERIFY(kivp != NULL);

	for (u_int i = 0; i < vmcnt; i++) {
		/*
		 * Check that no entries overlap our working space.
		 */
		if ((kivp[i].kve_start >= working_space &&
		    kivp[i].kve_start < working_space + (4 * big_res_size)) ||
		    (kivp[i].kve_end - 1 >= working_space &&
		    kivp[i].kve_end - 1 < working_space + (4 * big_res_size))) {
			cheriostest_failure_errx(
			    "reservation(s) still in memory map");
		}
	}

	procstat_freevmmap(psp, kivp);
	procstat_freeprocs(psp, kipp);
	procstat_close(psp);
	cheriostest_success();
#endif
}
#undef NRES

/*
 * A simple test to confirm that revocation of a capability in a COW mapping
 * affects only the caller's mapping.
 */
CHERIOSTEST(cheri_revoke_cow_mapping,
    "verify that revocation of a COW page triggers a copy",
#if defined(__linux__)
    .ct_xfail_reason = "Not supported",
#else
    .ct_check_skip = skip_need_cheri_revoke
#endif
)
{
#ifdef __linux__
	cheriostest_failure_errx("The CHERI Linux Project does not support revocation");
#else
	void **block, **cap1, **cap2;
	void *shadow, *torev;
	ssize_t n;
	size_t blocksz;
	pid_t child;
	int pd[2], res;
	char ch, st[2];

	/*
	 * Use three pages for our heap.  The last page will be revoked.  The
	 * first two pages contain a pointer into the third page; the first
	 * page will be unmapped before revocation, while the second will remain
	 * mapped.  This difference exercises different code paths in the
	 * revoker.
	 */
	blocksz = 3 * CHERITEST_PAGE_SIZE;
	block = mmap(NULL, blocksz, PROT_READ | PROT_WRITE, MAP_ANON, -1, 0);
	CHERIOSTEST_VERIFY(block != MAP_FAILED);

	torev = cheri_bounds_set(block + 2 * CHERITEST_PAGE_SIZE / sizeof(void *),
	    CHERITEST_PAGE_SIZE);
	cap1 = cheri_bounds_set(&block[0], CHERITEST_PAGE_SIZE);
	cap2 = cheri_bounds_set(&block[CHERITEST_PAGE_SIZE / sizeof(void *)], CHERITEST_PAGE_SIZE);
	*cap1 = *cap2 = cheri_perms_and(torev, ~CHERI_PERM_SW_VMEM);

	child = fork();
	if (child == -1)
		cheriostest_failure_errx("Fork failed; errno=%d", errno);
	if (child == 0) {
		/*
		 * Quarantine the third page.
		 */
		if (cheri_revoke_get_shadow(CHERI_REVOKE_SHADOW_NOVMEM,
		    torev, &shadow) != 0)
			_exit(1);
		memset(shadow, 0xff, cheri_length_get(shadow));

		/*
		 * Remove the first page from our page tables without modifying
		 * the logical mapping (i.e., without using munmap(2)).  This
		 * means that the revoker will visit the page, but cannot use
		 * the page tables to find it, so helps exercise different code
		 * paths.
		 */
		if (msync(cap1, CHERITEST_PAGE_SIZE, MS_INVALIDATE) != 0)
			_exit(2);
		if (mincore(block, 2 * CHERITEST_PAGE_SIZE, st) != 0)
			_exit(3);
		if ((st[0] & MINCORE_INCORE) != 0)
			_exit(4);

		/*
		 * Revoke the third page of our heap.
		 */
		if (cheri_revoke(CHERI_REVOKE_IGNORE_START |
		    CHERI_REVOKE_LAST_PASS, 0, NULL) != 0)
			_exit(6);

		if (!check_revoked(*cap1))
			_exit(7);
		if (!check_revoked(*cap2))
			_exit(8);
		_exit(0);
	}

	waitpid(child, &res, 0);
	if (!WIFEXITED(res) || WEXITSTATUS(res) != 0) {
		cheriostest_failure_errx("Bad child process exit: %d",
		    WEXITSTATUS(res));
	}

	/*
	 * Make sure our copies of the capability were preserved.
	 */
	CHERIOSTEST_VERIFY(!check_revoked(*cap1));
	CHERIOSTEST_VERIFY(!check_revoked(*cap2));

	/*
	 * Repeat the test, this time revoking in the parent.
	 */
	CHERIOSTEST_CHECK_SYSCALL(pipe(pd));
	child = fork();
	if (child == -1)
		cheriostest_failure_errx("Fork failed; errno=%d", errno);
	if (child == 0) {
		/*
		 * Block until the parent revokes the capability.
		 */
		n = read(pd[0], &ch, 1);
		if (n != 1)
			_exit(1);

		/*
		 * Make sure the child's copies of the capability were
		 * preserved.
		 */
		if (check_revoked(*cap1))
			_exit(5);
		if (check_revoked(*cap2))
			_exit(6);
		_exit(0);
	}

	/*
	 * Quarantine the third page.
	 */
	CHERIOSTEST_CHECK_SYSCALL(cheri_revoke_get_shadow(
	    CHERI_REVOKE_SHADOW_NOVMEM, torev, &shadow));
	memset(shadow, 0xff, cheri_length_get(shadow));

	/*
	 * Remove the first page from our page tables without modifying the
	 * logical mapping (i.e., without using munmap(2)).  This means that the
	 * revoker will visit the page, but cannot use the page tables to find
	 * it, so helps exercise different code paths.
	 */
	CHERIOSTEST_CHECK_SYSCALL(msync(cap1, CHERITEST_PAGE_SIZE, MS_INVALIDATE));
	CHERIOSTEST_CHECK_SYSCALL(mincore(block, 2 * CHERITEST_PAGE_SIZE, st));
	CHERIOSTEST_VERIFY((st[0] & MINCORE_INCORE) == 0);
	CHERIOSTEST_VERIFY((st[1] & MINCORE_INCORE) != 0);

	/*
	 * Revoke the third page of our heap.
	 */
	CHERIOSTEST_CHECK_SYSCALL(cheri_revoke(
	    CHERI_REVOKE_IGNORE_START | CHERI_REVOKE_LAST_PASS, 0, NULL));

	CHERIOSTEST_VERIFY(check_revoked(*cap1));
	CHERIOSTEST_VERIFY(check_revoked(*cap2));

	/*
	 * Wake up our child and wait for it to verify its copy of the
	 * capability.
	 */
	n = write(pd[1], &ch, 1);
	CHERIOSTEST_VERIFY(n == 1);

	waitpid(child, &res, 0);
	if (!WIFEXITED(res) || WEXITSTATUS(res) != 0) {
		cheriostest_failure_errx("Bad child 2 process exit: %d",
		    WEXITSTATUS(res));
	}

	CHERIOSTEST_CHECK_SYSCALL(munmap(block, blocksz));
	CHERIOSTEST_CHECK_SYSCALL(close(pd[0]));
	CHERIOSTEST_CHECK_SYSCALL(close(pd[1]));

	cheriostest_success();
#endif
}

CHERIOSTEST(cheri_revoke_shm_anon_hoard_unmapped,
    "Capability is revoked within an unmapped shm object",
#if defined(__linux__)
    .ct_xfail_reason = "Not supported",
#else
    .ct_xfail_reason = "unmapped part of shm objects aren't revoked"
#endif
)
{
#ifdef __linux__
	cheriostest_failure_errx("The CHERI Linux Project does not support revocation");
#else
	int fd, ret;
	void * volatile to_revoke;
	void * volatile *map;

	fd = CHERIOSTEST_CHECK_SYSCALL(shm_open(SHM_ANON, O_RDWR, 0600));
	CHERIOSTEST_CHECK_SYSCALL(ftruncate(fd, getpagesize()));

	map = CHERIOSTEST_CHECK_SYSCALL(mmap(NULL, getpagesize(),
	    PROT_READ | PROT_WRITE | PROT_CAP, MAP_SHARED, fd, 0));

	to_revoke = malloc(1);
	*map = to_revoke;
	CHERIOSTEST_VERIFY(cheri_tag_get(*map));

	munmap(__DEVOLATILE(void *, map), getpagesize());

	free(to_revoke);
	CHERIOSTEST_VERIFY2((ret = malloc_revoke_quarantine_force_flush()) == 0,
	   "malloc_revoke_quarantine_force_flush returned %d", ret);
	CHERIOSTEST_VERIFY(check_revoked(to_revoke));

	map = CHERIOSTEST_CHECK_SYSCALL(mmap(NULL, getpagesize(),
	    PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0));

	CHERIOSTEST_VERIFY(to_revoke == *map);
	CHERIOSTEST_VERIFY(check_revoked(*map));

	cheriostest_success();
#endif
}

CHERIOSTEST(cheri_revoke_shm_anon_hoard_closed,
    "Capability is revoked within an unmapped and closed shm object",
#if defined(__linux__)
    .ct_xfail_reason = "Not supported",
#else
    .ct_xfail_reason = "unmapped part of shm objects aren't revoked"
#endif
)
{
#ifdef __linux__
	cheriostest_failure_errx("The CHERI Linux Project does not support revocation");
#else
	int sv[2];
	int pid;

	CHERIOSTEST_CHECK_SYSCALL(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) != 0);

	pid = fork();
	if (pid == -1)
		cheriostest_failure_errx("Fork failed; errno=%d", errno);

	if (pid == 0) {
		int fd;
		struct msghdr msg = { 0 };
		struct cmsghdr * cmsg;
		char cmsgbuf[CMSG_SPACE(sizeof(fd))] = { 0 } ;
		char iovbuf[16];
		struct iovec iov = {
			.iov_base = iovbuf,
			.iov_len = sizeof(iovbuf)
		};

		close(sv[1]);

		/* Read from socket */
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = cmsgbuf;
		msg.msg_controllen = sizeof(cmsgbuf);
		CHERIOSTEST_CHECK_SYSCALL(recvmsg(sv[0], &msg, 0));

		/* Deconstruct cmsg */
		cmsg = CMSG_FIRSTHDR(&msg);
		memcpy(&fd, CMSG_DATA(cmsg), sizeof(fd));

		CHERIOSTEST_VERIFY2(fd >= 0, "fd read OK");

		/* Send the fd back. */
		CHERIOSTEST_CHECK_SYSCALL(sendmsg(sv[0], &msg, 0));

		close(sv[0]);
		close(fd);

		exit(0);
	} else {
		void * volatile to_revoke;
		void * volatile * map;
		int fd, res, ret;
		struct msghdr msg = { 0 };
		struct cmsghdr * cmsg;
		char cmsgbuf[CMSG_SPACE(sizeof(fd))] = { 0 };
		char iovbuf[16] = { 0 };
		struct iovec iov = {
			.iov_base = iovbuf,
			.iov_len = sizeof(iovbuf)
		};

		close(sv[0]);

		fd = CHERIOSTEST_CHECK_SYSCALL(shm_open(SHM_ANON, O_RDWR, 0600));
		CHERIOSTEST_CHECK_SYSCALL(ftruncate(fd, getpagesize()));

		map = CHERIOSTEST_CHECK_SYSCALL(mmap(NULL, getpagesize(),
		    PROT_READ | PROT_WRITE | PROT_CAP, MAP_SHARED, fd, 0));

		to_revoke = malloc(1);
		*map = to_revoke;
		CHERIOSTEST_VERIFY(cheri_tag_get(*map));

		CHERIOSTEST_CHECK_SYSCALL(munmap(__DEVOLATILE(void *, map),
		    getpagesize()));

		/* Construct control message */
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = cmsgbuf;
		msg.msg_controllen = sizeof(cmsgbuf);
		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN(sizeof fd);
		memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));
		msg.msg_controllen = cmsg->cmsg_len;

		/* Send! */
		CHERIOSTEST_CHECK_SYSCALL(sendmsg(sv[1], &msg, 0));
		close(fd);

		/* Revoke the pointer */
		free(to_revoke);
		CHERIOSTEST_VERIFY2(
		    (ret = malloc_revoke_quarantine_force_flush()) == 0,
		    "malloc_revoke_quarantine_force_flush returned %d", ret);
		CHERIOSTEST_VERIFY(check_revoked(to_revoke));

		/* Receive the fd back */
		msg.msg_controllen = sizeof(cmsgbuf);
		CHERIOSTEST_CHECK_SYSCALL(recvmsg(sv[1], &msg, 0));

		/* Deconstruct cmsg */
		cmsg = CMSG_FIRSTHDR(&msg);
		memcpy(&fd, CMSG_DATA(cmsg), sizeof(fd));

		CHERIOSTEST_VERIFY2(fd >= 0, "fd read OK");

		map = CHERIOSTEST_CHECK_SYSCALL(mmap(NULL, getpagesize(),
		    PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0));

		CHERIOSTEST_VERIFY(to_revoke == *map);
		CHERIOSTEST_VERIFY(check_revoked(*map));

		close(sv[1]);
		close(fd);

		waitpid(pid, &res, 0);
		if (res == 0) {
			cheriostest_success();
		} else {
			cheriostest_failure_errx("child failed");
		}
	}
#endif
}

#endif /* CHERIOSTEST_CHERI_REVOKE_TESTS */

/*
 * This test is derived from a syskiller panic.  Bugs in
 * vm_map_stack_locked() when the stack was being inserted into an
 * existing reservation (why would anyone do this in the real world?)
 * caused a panic.
 * https://github.com/CTSRD-CHERI/cheribsd/issues/2252
 */
CHERIOSTEST(mmap_insert_stack,
    "try to insert a stack mapping in a reservation")
{
	void *p;

	p = CHERIOSTEST_CHECK_SYSCALL(mmap((void *)(intptr_t)0x20000000,
	    0x1000000, PROT_WRITE | PROT_READ,
	    MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0));

	/*
	 * Historically would fail, but leave the map in a broken state
	 * due to trying to insert a reservation inside an existing one.
	 * This is now rejected outright.
	 */
	CHERIOSTEST_CHECK_CALL_ERROR(mmap(cheri_address_set(p, 0x20ffc000),
	    0x2000, PROT_WRITE | PROT_READ, MAP_STACK | MAP_FIXED, -1, 0),
	    ENOMEM);

	/*
	 * This would trigger a panic by trying to remove an unmapped
	 * entry left by the previous mmap.
	 */
	CHERIOSTEST_CHECK_SYSCALL(munmap(cheri_address_set(p, 0x20ffc000),
	    0x3000));

	cheriostest_success();
}

#endif /* __CHERI_PURE_CAPABILITY__ */
