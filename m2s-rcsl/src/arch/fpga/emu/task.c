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
#include <stdio.h>

#include <lib/esim/esim.h>
#include <lib/mhandle/mhandle.h>
#include <lib/util/bit-map.h>
#include <lib/util/debug.h>
#include <lib/util/misc.h>
#include <lib/util/list.h>
#include <lib/util/string.h>
#include <lib/util/timer.h>
#include <mem-system/memory.h>
#include <mem-system/mmu.h>
#include <mem-system/spec-mem.h>

#include <arch/x86/emu/context.h>

#include "task.h"
#include "emu.h"
#include "kernel.h"

int EV_FPGA_TASK_FINISH;

/*
 * Class 'FPGATask'
 */

CLASS_IMPLEMENTATION(FPGATask);

static void FPGATaskDoCreate(FPGATask *self, FPGAEmu *emu, FPGAKernel *kernel,
		X86Context *ctx) {
	/*int num_nodes;*/
	/*int i;*/

	/* Initialize */
	self->emu = emu;
	self->kernel = kernel;
	self->pid = emu->current_pid++;
	self->ctx = ctx;

	if (kernel->state == FPGAKernelOffchip
			|| kernel->state == FPGAKernelBlocked) {
		printf("Task rejected, kernel %s currently not available\n",
				kernel->kernel_name);
		return;
	}
	/* Update state so that the context is inserted in the
	 * corresponding lists. The fpga_ctx_running parameter has no
	 * effect, since it will be updated later. */
	FPGATaskSetState(self, FPGATaskReady);
	DOUBLE_LINKED_LIST_INSERT_TAIL(kernel, task, self);

	/* Virtual functions */
	asObject(self)->Dump = FPGATaskDump;
}

void FPGATaskCreate(FPGATask *self, FPGAKernel *kernel, X86Context *ctx) {
	/* Baseline initialization */
	FPGATaskDoCreate(self, kernel->emu, kernel, ctx);

	int srcsize;
	int dstsize;

	if (kernel->sharedmem) {
		mem_read_copy(self->ctx->realmem, kernel->srcsize, 4, &srcsize);
		self->input = (void *) xcalloc(1, srcsize);
		self->input_size = srcsize;

		void * data = (void *) xcalloc(1, srcsize);

		mem_read_copy(self->ctx->realmem, kernel->srcbase, 4, self->input);
		mem_read_copy(self->ctx->realmem, self->input, self->input_size, data);

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
		FPGATaskFinish(self);

	assert(FPGATaskGetState(self, FPGATaskFinished));
	DOUBLE_LINKED_LIST_REMOVE(kernel, finished, self);

	/* Remove context from finished contexts list. This should
	 * be the only list the context is in right now. */
	DOUBLE_LINKED_LIST_REMOVE(kernel, task, self);

	FPGAKernelDebug("task %d freed on kernel %d\n", self->pid,
			self->kernel->kid);
}

void FPGATaskDump(Object *self, FILE *f) {
	FPGATask *task = asFPGATask(self);
	/*char state_str[MAX_STRING_SIZE];*/

	/* Title */
	fprintf(f, "------------\n");
	fprintf(f, "Task %d\n", task->pid);
	fprintf(f, "------------\n\n");

	/* End */
	fprintf(f, "\n\n");
}

static int FPGATaskVerilate(FPGATask *self, struct mem_t *mem,
		unsigned int addr, int size, void *buf) {

	mem_read_copy(mem, addr, size, buf);
	int i, j, delay;
	char *input = "input.txt";
	char *output = "output.txt";
	FILE *verilate_input = fopen(input, "w");
	fprintf(verilate_input,
			"8\n1\n100\n5\n200\n6\n300\n7\n700\n8\n900\n9\n250\n10\n400\n11\n600\n12\n800\n13\n1500\n14\n1200\n15\n110\n16\n140\n17\n133\n18\n10");
	fclose(verilate_input);

	char verilate_command[256];
	strcpy(verilate_command, self->kernel->sim_file);
	strcat(verilate_command, " ");
	strcat(verilate_command, input);
	strcat(verilate_command, " ");
	strcat(verilate_command, output);
	system(verilate_command);

	char line[256];
	FILE *verilate_output = fopen(output, "r");
	if(fgets(line, sizeof(line), verilate_output))
		sscanf(line, "%d", &delay);
	else
		fatal("Verilation of %s failed!\n", self->kernel->sim_file);
	return delay;
}

void FPGATaskExecute(FPGATask *self) {
	FPGAKernel *kernel = self->kernel;

	assert(FPGATaskGetState(self, FPGATaskReady));

	FPGATaskSetState(self, FPGATaskRunning);

	int i, j, delay;
	void *data;
	int data_size;

	if (kernel->folding) {
		kernel->delay = *(int*) list_get(kernel->heights,
				kernel->current_implement);
	}

	if (kernel->delay) {
		esim_schedule_event(EV_FPGA_TASK_FINISH, self, kernel->delay);
	} else {
		/* Read Input Data */
		delay = FPGATaskVerilate(self, self->ctx->realmem, kernel->srcbase,
				self->input_size, self->input);
		esim_schedule_event(EV_FPGA_TASK_FINISH, self, delay);
	}

}

int FPGATaskGetState(FPGATask *self, FPGATaskState state) {
	return (self->state & state) > 0;
}

static void FPGATaskUpdateState(FPGATask *self, FPGATaskState state) {
	FPGAKernel *kernel = self->kernel;

	/* Remove contexts from the following lists:
	 * ready, finished
	 */

	if (DOUBLE_LINKED_LIST_MEMBER(kernel, ready, self))
		DOUBLE_LINKED_LIST_REMOVE(kernel, ready, self);
	if (DOUBLE_LINKED_LIST_MEMBER(kernel, finished, self))
		DOUBLE_LINKED_LIST_MEMBER(kernel, finished, self);

	self->state = state;
	if (self->state & FPGATaskReady) {
		DOUBLE_LINKED_LIST_INSERT_TAIL(kernel, ready, self);
	}
	if (self->state & FPGATaskFinished) {
		DOUBLE_LINKED_LIST_INSERT_TAIL(kernel, finished, self);
	}
	if (self->state & FPGATaskRunning) {
		DOUBLE_LINKED_LIST_INSERT_HEAD(kernel, ready, self);
		self->state |= FPGATaskReady;
	}

}

void FPGATaskSetState(FPGATask *self, FPGATaskState state) {
	FPGATaskUpdateState(self, state);
}

void FPGATaskClearState(FPGATask *self, FPGATaskState state) {
	FPGATaskUpdateState(self, self->state & ~state);
}

void FPGATaskFinish(FPGATask *self) {
	int finish = 1;
	mem_write_copy(self->ctx->realmem, self->kernel->finish, 4, &finish);
	mem_write_copy(self->ctx->mem, self->kernel->finish, 4, &finish);
	FPGATaskSetState(self, FPGATaskFinished);
}

/*
 * Non-Class
 */

int fpga_task_debug_category;

struct str_map_t fpga_task_state_map = { 3, { { "running", FPGATaskRunning }, {
		"ready", FPGATaskReady }, { "finished", FPGATaskFinished } } };
