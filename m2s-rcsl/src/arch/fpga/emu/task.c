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

#include <arch/fpga/timing/cpu.h>
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

#include "task.h"
#include "emu.h"
#include "file-desc.h"
#include "isa.h"
#include "loader.h"
#include "regs.h"
#include "signal.h"
#include "syscall.h"

/*
 * Class 'FPGATask'
 */

CLASS_IMPLEMENTATION(FPGATask);

static void FPGATaskDoCreate(FPGATask *self, FPGAEmu *emu, FPGAKernel *kernel) {
	int num_nodes;
	int i;

	/* Initialize */
	self->emu = emu;
	self->kernel = kernel;
	self->pid = emu->current_pid++;

	/* Update state so that the context is inserted in the
	 * corresponding lists. The fpga_ctx_running parameter has no
	 * effect, since it will be updated later. */
	FPGATaskSetState(self, FPGATaskReady);
	DOUBLE_LINKED_LIST_INSERT_TAIL(kernel, task, self);

	/* Virtual functions */
	asObject(self)->Dump = FPGATaskDump;
}

void FPGATaskCreate(FPGATask *self, FPGAEmu *emu, FPGAKernel *kernel, int input_size,
		int output_size, void *input, void *output, int task_ready_idx, int task_done_idx) {
	/* Baseline initialization */
	FPGATaskDoCreate(self, emu, kernel);

	self->input_size = input_size;
	self->output_size = output_size;

	assert(task_ready_idx > 0 && task_done_idx > 0);
	assert(input_size >= task_ready_idx && output_size >= task_done_idx);

	self->input = xcalloc(input_size, sizeof(bool));
	self->output = xcalloc(output_size, sizeof(bool));

	memcpy(self->input, input, input_size*sizeof(bool));
	memcpy(self->output, output, output_size*sizeof(bool));

	self->task_done_idx = task_done_idx;
	self->task_ready_idx = task_ready_idx;
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
void FPGATaskFinish(FPGATask *self, int state) {



}



/*
 * Non-Class
 */

int fpga_task_debug_category;

struct str_map_t fpga_task_state_map = { 3, { { "running", FPGATaskRunning }, { "waiting",
		FPGATaskWaiting }, { "finished", FPGATaskFinished } } };
