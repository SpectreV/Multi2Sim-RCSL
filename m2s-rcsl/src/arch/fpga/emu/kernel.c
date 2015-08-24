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

#include <poll.h>
#include <unistd.h>

#include <arch/fpga/timing/fpga.h>
#include <lib/esim/esim.h>
#include <lib/mhandle/mhandle.h>
#include <lib/util/bit-map.h>
#include <lib/util/debug.h>
#include <lib/util/misc.h>
#include <lib/util/string.h>
#include <lib/util/timer.h>
#include <mem-system/memory.h>
#include <mem-system/mmu.h>
#include <mem-system/spec-mem.h>

#include "kernel.h"
#include "emu.h"
#include "file-desc.h"
#include "isa.h"
#include "loader.h"
#include "regs.h"
#include "signal.h"
#include "syscall.h"

/*
 * Class 'FPGAKernel'
 */

CLASS_IMPLEMENTATION(FPGAKernel);

static void FPGAKernelDoCreate(FPGAKernel *self, FPGAEmu *emu) {
	int num_nodes;
	int i;

	/* Initialize */
	self->emu = emu;
	self->kid = emu->current_pid++;

	/* Update state so that the context is inserted in the
	 * corresponding lists. The fpga_ctx_running parameter has no
	 * effect, since it will be updated later. */
	FPGAKernelSetState(self, FPGAKernelOnchip);
	DOUBLE_LINKED_LIST_INSERT_HEAD(emu, kernel, self);

	/* Structures
	 self->regs = fpga_regs_create();
	 self->backup_regs = fpga_regs_create();
	 self->signal_mask_table = fpga_signal_mask_table_create();

	 Thread affinity mask, used only for timing simulation. It is
	 * initialized to all 1's.
	 num_nodes = fpga_cpu_num_cores * fpga_cpu_num_threads;
	 self->affinity = bit_map_create(num_nodes);
	 for (i = 0; i < num_nodes; i++)
	 bit_map_set(self->affinity, i, 1, 1);*/

	/* Virtual functions */
	asObject(self)->Dump = FPGAKernelDump;
}

void FPGAKernelCreate(FPGAKernel *self, FPGAEmu *emu) {
	/* Baseline initialization */
	FPGAKernelDoCreate(self, emu);

	/* Loader */
	self->loader = fpga_loader_create();

}

void FPGAKernelDestroy(FPGAKernel *self) {
	FPGAEmu *emu = self->emu;

	/* If context is not finished/zombie, finish it first.
	 * This removes all references to current freed context. */
	if (!FPGAKernelGetState(self, FPGAKernelFinished | FPGAKernelZombie))
		FPGAKernelFinish(self, 0);

	/* Remove context from finished contexts list. This should
	 * be the only list the context is in right now. */
	assert(!DOUBLE_LINKED_LIST_MEMBER(emu, running, self));
	assert(!DOUBLE_LINKED_LIST_MEMBER(emu, suspended, self));
	assert(!DOUBLE_LINKED_LIST_MEMBER(emu, zombie, self));
	assert(DOUBLE_LINKED_LIST_MEMBER(emu, finished, self));
	DOUBLE_LINKED_LIST_REMOVE(emu, finished, self);

	/* Free private structures */
	fpga_regs_free(self->regs);
	fpga_regs_free(self->backup_regs);
	fpga_signal_mask_table_free(self->signal_mask_table);
	spec_mem_free(self->spec_mem);
	bit_map_free(self->affinity);

	/* Unlink shared structures */
	fpga_loader_unlink(self->loader);
	fpga_signal_handler_table_unlink(self->signal_handler_table);
	fpga_file_desc_table_unlink(self->file_desc_table);
	mem_unlink(self->mem);

	/* Remove context from contexts list and free */
	DOUBLE_LINKED_LIST_REMOVE(emu, context, self);
	FPGAKernelDebug("inst %lld: context %d freed\n", asEmu(emu)->instructions, self->pid);
}

void FPGAKernelDump(Object *self, FILE *f) {
	FPGAKernel *context = asFPGAKernel(self);
	char state_str[MAX_STRING_SIZE];

	/* Title */
	fprintf(f, "------------\n");
	fprintf(f, "Context %d\n", context->pid);
	fprintf(f, "------------\n\n");

	str_map_flags(&fpga_context_state_map, context->state, state_str, sizeof state_str);
	fprintf(f, "State = %s\n", state_str);

	/* End */
	fprintf(f, "\n\n");
}

void FPGAKernelProceed(FPGAKernel *self) {
	FPGAEmu *emu = self->emu;

	if (FPGAKernelGetState(self) != FPGAKernelRunning)
		return;

	FPGATask *task = self.waiting_list_head;
	FPGATaskExecute(task);

}

int FPGAKernelGetState(FPGAKernel *self, FPGAKernelState state) {
	return (self->state & state) > 0;
}

static void FPGAKernelUpdateState(FPGAKernel *self, FPGAKernelState state) {
	FPGAEmu *emu = self->emu;

	FPGAKernelState status_diff;
	char state_str[MAX_STRING_SIZE];

	/* Remove contexts from the following lists:
	 *   running, suspended, zombie */
	if (DOUBLE_LINKED_LIST_MEMBER(emu, running, self))
		DOUBLE_LINKED_LIST_REMOVE(emu, running, self);
	if (DOUBLE_LINKED_LIST_MEMBER(emu, suspended, self))
		DOUBLE_LINKED_LIST_REMOVE(emu, suspended, self);
	if (DOUBLE_LINKED_LIST_MEMBER(emu, zombie, self))
		DOUBLE_LINKED_LIST_REMOVE(emu, zombie, self);
	if (DOUBLE_LINKED_LIST_MEMBER(emu, finished, self))
		DOUBLE_LINKED_LIST_REMOVE(emu, finished, self);

	/* If the difference between the old and new state lies in other
	 * states other than 'fpga_ctx_specmode', a reschedule is marked. */
	status_diff = self->state ^ state;
	if (status_diff & ~FPGAKernelSpecMode)
		emu->schedule_signal = 1;

	/* Update state */
	self->state = state;
	if (self->state & FPGAKernelFinished)
		self->state = FPGAKernelFinished | (state & FPGAKernelAlloc) | (state & FPGAKernelMapped);
	if (self->state & FPGAKernelZombie)
		self->state = FPGAKernelZombie | (state & FPGAKernelAlloc) | (state & FPGAKernelMapped);
	if (!(self->state & FPGAKernelSuspended) && !(self->state & FPGAKernelFinished)
			&& !(self->state & FPGAKernelZombie) && !(self->state & FPGAKernelLocked))
		self->state |= FPGAKernelRunning;
	else
		self->state &= ~FPGAKernelRunning;

	/* Insert context into the corresponding lists. */
	if (self->state & FPGAKernelRunning)
		DOUBLE_LINKED_LIST_INSERT_HEAD(emu, running, self);
	if (self->state & FPGAKernelZombie)
		DOUBLE_LINKED_LIST_INSERT_HEAD(emu, zombie, self);
	if (self->state & FPGAKernelFinished)
		DOUBLE_LINKED_LIST_INSERT_HEAD(emu, finished, self);
	if (self->state & FPGAKernelSuspended)
		DOUBLE_LINKED_LIST_INSERT_HEAD(emu, suspended, self);

	/* Dump new state (ignore 'fpga_ctx_specmode' state, it's too frequent) */
	if (debug_status(fpga_context_debug_category) && (status_diff & ~FPGAKernelSpecMode)) {
		str_map_flags(&fpga_context_state_map, self->state, state_str, sizeof state_str);
		FPGAKernelDebug("inst %lld: ctx %d changed state to %s\n", asEmu(emu)->instructions,
				self->pid, state_str);
	}

	/* Start/stop fpga timer depending on whether there are any contexts
	 * currently running. */
	if (emu->running_list_count)
		m2s_timer_start(asEmu(emu)->timer);
	else
		m2s_timer_stop(asEmu(emu)->timer);
}

void FPGAKernelSetState(FPGAKernel *self, FPGAKernelState state) {
	FPGAKernelUpdateState(self, self->state | state);
}

void FPGAKernelClearState(FPGAKernel *self, FPGAKernelState state) {
	FPGAKernelUpdateState(self, self->state & ~state);
}

/* Finish a context. If the context has no parent, its state will be set
 * to 'fpga_ctx_finished'. If it has, its state is set to 'fpga_ctx_zombie', waiting for
 * a call to 'waitpid'.
 * The children of the finished context will set their 'parent' attribute to NULL.
 * The zombie children will be finished. */
void FPGAKernelFinish(FPGAKernel *self, int state) {
	FPGAEmu *emu = self->emu;
	FPGAKernel *aux;

	/* Context already finished */
	if (FPGAKernelGetState(self, FPGAKernelFinished | FPGAKernelZombie))
		return;

	/* If context is waiting for host events, cancel spawned host threads. */
	FPGAKernelHostThreadSuspendCancel(self);
	FPGAKernelHostThreadTimerCancel(self);

	/* From now on, all children have lost their parent. If a child is
	 * already zombie, finish it, since its parent won't be able to waitpid it
	 * anymore. */
	DOUBLE_LINKED_LIST_FOR_EACH(emu, context, aux)
	{
		if (aux->parent == self) {
			aux->parent = NULL;
			if (FPGAKernelGetState(aux, FPGAKernelZombie))
				FPGAKernelSetState(aux, FPGAKernelFinished);
		}
	}

	/* Send finish signal to parent */
	if (self->exit_signal && self->parent) {
		fpga_sys_debug("  sending signal %d to pid %d\n", self->exit_signal, self->parent->pid);
		fpga_sigset_add(&self->parent->signal_mask_table->pending, self->exit_signal);
		FPGAEmuProcessEventsSchedule(emu);
	}

	/* If clear_child_tid was set, a futex() call must be performed on
	 * that pointer. Also wake up futexes in the robust list. */
	if (self->clear_child_tid) {
		unsigned int zero = 0;
		mem_write(self->mem, self->clear_child_tid, 4, &zero);
		FPGAKernelFutexWake(self, self->clear_child_tid, 1, -1);
	}
	FPGAKernelExitRobustList(self);

	/* If we are in a signal handler, stop it. */
	if (FPGAKernelGetState(self, FPGAKernelHandler))
		FPGAKernelReturnFromSignalHandler(self);

	/* Finish context */
	FPGAKernelSetState(self, self->parent ? FPGAKernelZombie : FPGAKernelFinished);
	self->exit_code = state;
	FPGAEmuProcessEventsSchedule(emu);
}

/*
 * Non-Class
 */

int fpga_kernel_debug_category;

struct str_map_t fpga_context_state_map = { 5, { { "onchip", FPGAKernelOnchip }, { "ready",
		FPGAKernelReady }, { "blocked", FPGAKernelBlocked }, { "running", FPGAKernelRunning }, {
		"offchip", FPGAKernelOffchip } } };
