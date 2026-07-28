/*-
 * Copyright (c) 2021, 2022 SRI International
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

#include <sys/param.h>
#include <sys/user.h>

#ifdef __FreeBSD__
#include <libprocstat.h>

#include <sys/sysctl.h>

#include <cheri/cheric.h>
#elif defined(__linux__)
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bsd/sys/queue.h>
#endif

#include "cheri/cheric.h"

#include <unistd.h>

#include "cheriostest.h"

#ifdef __FreeBSD__
/*
 * Find a region of address space unoccupied by any memory mappings.
 *
 * Caveats:
 * - This is not concurency safe and the found region could be disrupted
 *   by any non-MAP_FIXED mmap() call.  This includes anything that
 *   allocates heap memory.
 * - The region between CHERITEST_CHERITEST_PAGE_SIZE and the first mapping is not currently
 *   searched.
 * - The top of the address space will be searched due to the shared
 *   page at the topmost address.
 * - If an alignment of 0 is pased, the address of a region representable as a
 *   capability will be returned.  It a non-zero alignment is passed it
 *   will be honored even if that results in an address that is
 *   under-aligned relative to a representable capability.
 */
ptraddr_t
find_address_space_gap(size_t len, size_t align)
{
	struct procstat *psp;
	struct kinfo_proc *kipp;
	struct kinfo_vmentry *kivp;
	unsigned int pcnt, vmcnt;
	ptraddr_t addr = 0;

	psp = procstat_open_sysctl();
	CHERIOSTEST_VERIFY(psp != NULL);
	kipp = procstat_getprocs(psp, KERN_PROC_PID, getpid(), &pcnt);
	CHERIOSTEST_VERIFY(kipp != NULL);
	CHERIOSTEST_VERIFY(pcnt == 1);
	kivp = procstat_getvmmap(psp, kipp, &vmcnt);
	CHERIOSTEST_VERIFY(kivp != NULL);

	if (align == 0) {
		len = cheri_representable_length(len);
		align = CHERITEST_CHERI_REPRESENTABLE_ALIGNMENT(len);
	}

	for (unsigned int i = 1; i < vmcnt; i++) {
		ptraddr_t aligned_start = __builtin_align_up(kivp[i-1].kve_end, align);
		ptraddr_t end = kivp[i].kve_start;
		if (aligned_start > end)
			continue;
		if (end - aligned_start >= len) {
			addr = aligned_start;
			break;
		}
	}
	if (addr == 0) {
		cheriostest_failure_errx("no free region of length %#jx\n",
		    len);
	}

	procstat_freevmmap(psp, kivp);
	procstat_freeprocs(psp, kipp);
	procstat_close(psp);
	return (addr);
}
#elif defined(__linux__)

struct vma_attr_t {
	unsigned long long start;
	unsigned long long end;
	LIST_ENTRY(vma_attr_t) link;
};

LIST_HEAD(vma_attr_list, vma_attr_t);

ptraddr_t
find_address_space_gap(size_t len, size_t align)
{
	ptraddr_t addr = 0;
	struct vma_attr_t *cur_vma_attr;
	FILE *f = NULL;
	char *line = NULL;
	size_t line_len = 0;
	struct vma_attr_list lh;
	unsigned int vmcnt = 0;

	LIST_INIT(&lh);

	// Create a list of VMAs based on /proc/self/stat
	f = fopen("/proc/self/maps", "r");
	if (f == NULL) {
		cheriostest_failure_errx("fopen: %s", strerror(errno)); // TODO: Improve this
	}

	while(getline(&line, &line_len, f) != -1) {
		cur_vma_attr = malloc(sizeof(struct vma_attr_t));
		sscanf(line, "%llx-%llx", &cur_vma_attr->start, &cur_vma_attr->end);
		LIST_INSERT_HEAD(&lh, cur_vma_attr, link);
		vmcnt++;
	}
	free(line);
	fclose(f);

	if (align == 0) {
		len = cheri_representable_length(len);
		align = CHERITEST_CHERI_REPRESENTABLE_ALIGNMENT(len);
	}

	// Search for gap in the address space
	struct vma_attr_t *it = LIST_FIRST(&lh);
	for (unsigned int i = 0; i < vmcnt - 1; i++) {
		ptraddr_t end = it->start;
		it = LIST_NEXT(it, link);
		ptraddr_t aligned_start = __builtin_align_up(it->end, align);
		if (aligned_start > end)
			continue;
		if (end - aligned_start >= len) {
			addr = aligned_start;
			break;
		}
	}

	if (addr == 0) {
		cheriostest_failure_errx("no free region of length %#jx\n", len);
	}

	return addr;
}
#else
#error "Unsupported OS"
#endif
