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

#include <arch/x86/emu/context.h>

#include "task.h"
#include "emu.h"
#include "kernel.h"

/*
 * Class 'FPGATask'
 */

CLASS_IMPLEMENTATION(FPGATask);

static void FPGATaskDoCreate(FPGATask *self, FPGAEmu *emu, FPGAKernel *kernel, X86Context *ctx) {
	int num_nodes;
	int i;

	/* Initialize */
	self->emu = emu;
	self->kernel = kernel;
	self->pid = emu->current_pid++;
	self->ctx = ctx;

	/* Update state so that the context is inserted in the
	 * corresponding lists. The fpga_ctx_running parameter has no
	 * effect, since it will be updated later. */
	FPGATaskSetState(self, FPGATaskReady);
	DOUBLE_LINKED_LIST_INSERT_TAIL(kernel, task, self);

	/* Virtual functions */
	asObject(self)->Dump = FPGATaskDump;
}

void FPGATaskCreate(FPGATask *self, FPGAKernel *kernel, X86Context *ctx, int task_ready_idx,
		int task_done_idx) {
	/* Baseline initialization */
	FPGATaskDoCreate(self, kernel->emu, kernel, ctx);

	int srcsize;
	int dstsize;

	self->state = FPGATaskReady;
	DOUBLE_LINKED_LIST_INSERT_TAIL(kernel, task, self);
	if (kernel->sharedmem) {
		mem_read_copy(self->ctx->realmem, kernel->srcsize, 4, &srcsize);
		self->input = (void *) xcalloc(1, srcsize);
		self->input_size = srcsize;
		mem_read_copy(self->ctx->realmem, kernel->dstsize, 4, &dstsize);
		self->output = (void *) xcalloc(1, dstsize);
		self->output_size = dstsize;
	} else {
		self->input = (void *) xcalloc(1, kernel->srcsize);
		self->input_size = kernel->srcsize;
		self->output = (void *) xcalloc(1, kernel->dstsize);
		self->output_size = kernel->dstsize;
	}
}

void FPGATaskDestroy(FPGATask *self) {
	FPGAEmu *emu = self->emu;
	FPGAKernel *kernel = self->kernel;

	/* If context is not finished/zombie, finish it first.
	 * This removes all references to current freed context. */
	if (!FPGATaskGetState(self, FPGATaskFinished))
		FPGATaskFinish(self, 0);

	/* Remove context from finished contexts list. This should
	 * be the only list the context is in right now. */
	DOUBLE_LINKED_LIST_REMOVE(kernel, task, self);

	FPGATaskDebug("inst %lld: context %d freed\n", asEmu(emu)->instructions, self->pid);
}

void FPGATaskDump(Object *self, FILE *f) {
	FPGATask *task = asFPGATask(self);
	char state_str[MAX_STRING_SIZE];

	/* Title */
	fprintf(f, "------------\n");
	fprintf(f, "Task %d\n", task->pid);
	fprintf(f, "------------\n\n");

	/* End */
	fprintf(f, "\n\n");
}

void FPGATaskExecute(FPGATask *self) {
	FPGAEmu *emu = self->emu;
	FPGAKernel *kernel = self->kernel;

}

int FPGATaskGetState(FPGATask *self, FPGATaskState state) {
	return (self->state & state) > 0;
}


static void FPGATaskUpdateState(FPGATask *self, FPGATaskState state) {

	/* Remove contexts from the following lists:

	 if (emu->running_list_count)
	 m2s_timer_start(asEmu(emu)->timer);
	 else
	 m2s_timer_stop(asEmu(emu)->timer);
	 }

	 void FPGATaskSetState(FPGATask *self, FPGATaskState state) {
	 FPGATaskUpdateState(self, self->state | state);
	 }

	 void FPGATaskClearState(FPGATask *self, FPGATaskState state) {
	 FPGATaskUpdateState(self, self->state & ~state);
	 }

	 /* Finish a context. If the context has no parent, its state will be set
	 * to 'fpga_ctx_finished'. If it has, its state is set to 'fpga_ctx_zombie', waiting for
	 * a call to 'waitpid'.
	 * The children of the finished context will set their 'parent' attribute to NULL.
	 * The zombie children will be finished. */
}

void FPGATaskSetState(FPGATask *self, FPGATaskState state) {
	FPGATaskUpdateState(self, self->state | state);
}


void FPGATaskFinish(FPGATask *self, int state) {

}

/*
 * Non-Class
 */

int fpga_task_debug_category;

struct str_map_t fpga_task_state_map = { 3, { { "running", FPGATaskRunning }, { "waiting",
		FPGATaskReady }, { "finished", FPGATaskFinished } } };
