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

#ifndef ARCH_FPGA_EMU_KERNEL_H
#define ARCH_FPGA_EMU_KERNEL_H

#include <pthread.h>

#include <lib/util/class.h>

/* Forward declarations */
struct bit_map_t;

/*
 * Class 'FPGAKernel'
 */

typedef int (*FPGAKernelCanWakeupFunc)(FPGAKernel *self, void *data);
typedef void (*FPGAKernelWakeupFunc)(FPGAKernel *self, void *data);

typedef enum {
	FPGAKernelOnchip = 0x00001, /* it is placed on chip */
	FPGAKernelReady = 0x00002, /* it is ready to execute hardware tasks */
	FPGAKernelBlocked = 0x00004, /* it is blocked by an overlapping kernel currently running */
	FPGAKernelRunning = 0x00008, /* the kernel is currently running a hardware task */
	FPGAKernelOffchip = 0x00010, /* the kernle is currently not placed on chip, needs to be reloaded */
	FPGAKernelNone = 0x00000
} FPGAKernelState;

CLASS_BEGIN(FPGAKernel, Object)

/* Emulator it belongs to */
	FPGAEmu *emu;

	/* Kernel properties */
	int state;
	int kid; /* Kernel ID */

	char* kernel_name;
	int folding;

	/* Implementations */
	int num_implements;
	int *widths, *lengths, *heights;

	/* Placement Information */
	int coordinate_x, coordinate_y;
	/* Placement Affinity */
	int affinity_x, affinity_y, affinity_imp;

	int exit_signal; /* Signal to send host when finished */
	int exit_code; /* For zombie kernels */

	/* Instruction pointers */
	unsigned int last_stage; /* Address of last emulated instruction */
	unsigned int curr_stage; /* Address of currently emulated instruction */

	/* Cycle when the kernel was allocated and evicted to a node (core/thread),
	 * respectively. */
	long long activate_cycle;
	long long eviction_cycle;

	/* The kernel is mapped and allocated, but its eviction is in progress.
	 * It will be effectively evicted once the last instruction reaches the
	 * commit stage. This value is set by 'fpga_cpu_kernel_evict_signal'. */
	int evict_signal;

	/* Links to kernels forming a linked list. */
	FPGAKernel *kernel_list_next, *kernel_list_prev;
	FPGAKernel *running_list_next, *running_list_prev;
	FPGAKernel *blocked_list_next, *blocked_list_prev;
	FPGAKernel *onchip_list_next, *onchip_list_prev;
	FPGAKernel *offchip_list_next, *offchip_list_prev;
	FPGAKernel *ready_list_next, *ready_list_prev;

	/* List of tasks assigned to a kernel. This list is
	 * managed by the timing simulator for scheduling purposes. */
	FPGATask *task_list_head, *task_list_tail;
	int task_list_count, task_list_max;

	FPGATask *waiting_list_head, *waiting_list_tail;
	int waiting_list_count, waiting_list_max;

	FPGATask *finished_list_head, *finished_list_tail;
	int finished_list_count, finished_list_max;

	/* Substructures */
	struct fpga_loader_t *loader;
	/* Thread affinity mask */
	struct bit_map_t *affinity;

	struct bounds {
		unsigned int low;
		unsigned int high;
	} HW_bounds;

	unsigned int srcbase;
	unsigned int dstbase;
	unsigned int srcsize;
	unsigned int dstsize;

	unsigned int start;
	unsigned int finish;
	int delay;
	int sharedmem;

CLASS_END(FPGAKernel)

void FPGAKernelCreate(FPGAKernel *self, FPGAEmu *emu);

void FPGAKernelDestroy(FPGAKernel *self);

void FPGAKernelDump(Object *self, FILE *f);

void FPGAKernelFinish(FPGAKernel *self, int state);
void FPGAKernelExecute(FPGAKernel *self);

int FPGAKernelGetState(FPGAKernel *self, FPGAKernelState state);
void FPGAKernelSetState(FPGAKernel *self, FPGAKernelState state);
void FPGAKernelClearState(FPGAKernel *self, FPGAKernelState state);

/*
 * Non-Class
 */

#define FPGAKernelDebug(...) debug(fpga_kernel_debug_category, __VA_ARGS__)
extern int fpga_kernel_debug_category;

extern struct str_map_t fpga_kernel_state_map;

#endif

