/*
 *  Multi2Sim
 *  Copyright (C) 2012  Rafael Ubal (ubal@ece.neu.edu)
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef ARCH_FPGA_EMU_EMU_H
#define ARCH_FPGA_EMU_EMU_H

#include <pthread.h>
#include <stdio.h>

#include <arch/common/emu.h>
#include <lib/util/class.h>

/* Forward declarations */
struct config_t;

/*
 * Class 'FPGAEmu'
 */

CLASS_BEGIN(FPGAEmu, Emu)

/* PID assignment */
	int current_pid;

	/* Schedule next call to 'X86EmuProcessEvents()'.
	 * The call will only be effective if 'process_events_force' is set.
	 * This flag should be accessed thread-safely locking 'process_events_mutex'. */
	pthread_mutex_t process_events_mutex;
	int process_events_force;

	/* Counter of times that a context has been suspended in a
	 * futex. Used for FIFO wakeups. */
	long long futex_sleep_count;

	/* Flag set to force a call to the scheduler 'x86_cpu_schedule()' in the
	 * beginning of next cycle. This flag is set any time a context changes its
	 * state in any bit other than 'spec_mode'. It can be set anywhere in the
	 * code by directly assigning a value to 1. E.g.: when a system call is
	 * executed to change the context's affinity. */
	int schedule_signal;

	/* List of kernels */
	FPGAKernel *kernel_list_head;
	FPGAKernel *kernel_list_tail;
	int kernel_list_count;
	int kernel_list_max;

	/* List of running kernels */
	FPGAKernel *running_list_head;
	FPGAKernel *running_list_tail;
	int running_list_count;
	int running_list_max;

	/* List of suspended kernels */
	FPGAKernel *suspended_list_head;
	FPGAKernel *suspended_list_tail;
	int suspended_list_count;
	int suspended_list_max;

	/* List of zombie kernels */
	FPGAKernel *zombie_list_head;
	FPGAKernel *zombie_list_tail;
	int zombie_list_count;
	int zombie_list_max;

	/* Table of tasks associated with each kernel */
	FPGATask **kernel_task_table;
	int *task_count_of_kernel;

CLASS_END(FPGAEmu)

void FPGAEmuCreate(FPGAEmu *self);
void FPGAEmuDestroy(FPGAEmu *self);

int FPGAEmuRun(Emu *self);

void FPGAEmuDump(Object *self, FILE *f);
void FPGAEmuDumpSummary(Emu *self, FILE *f);

void FPGAEmuProcessEvents(FPGAEmu *self);
void FPGAEmuProcessEventsSchedule(FPGAEmu *self);

FPGAContext *FPGAEmuGetContext(FPGAEmu *self, int pid);

void FPGAEmuLoadContextsFromConfig(FPGAEmu *self, struct config_t *config,
		char *section);
/*
 * Non-Class
 */

extern FPGAEmu *fpga_emu;

extern long long fpga_emu_max_cycles;
extern long long fpga_emu_max_inst;
extern char fpga_emu_last_inst_bytes[20];
extern int fpga_emu_last_inst_size;
extern int fpga_emu_process_prefetch_hints;

void fpga_emu_init(void);
void fpga_emu_done(void);

#endif

