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
#include "loader.h"

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

	/* Update state so that the kernel is inserted in the
	 * corresponding lists. The fpga_ctx_running parameter has no
	 * effect, since it will be updated later. */
	FPGAKernelSetState(self, FPGAKernelOnchip);
	DOUBLE_LINKED_LIST_INSERT_HEAD(emu, kernel, self);

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


	FPGAKernelDebug("inst %lld: context %d freed\n", asEmu(emu)->instructions, self->kid);
}

void FPGAKernelDump(Object *self, FILE *f) {
	FPGAKernel *context = asFPGAKernel(self);
	char state_str[MAX_STRING_SIZE];

	/* Title */
	fprintf(f, "------------\n");
	fprintf(f, "Context %d\n", context->kid);
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


}

/*
 * Non-Class
 */

int fpga_kernel_debug_category;

struct str_map_t fpga_context_state_map = { 5, { { "onchip", FPGAKernelOnchip }, { "ready",
		FPGAKernelReady }, { "blocked", FPGAKernelBlocked }, { "running", FPGAKernelRunning }, {
		"offchip", FPGAKernelOffchip } } };
