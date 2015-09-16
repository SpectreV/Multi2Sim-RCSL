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

#ifndef ARCH_FPGA_EMU_TASK_H
#define ARCH_FPGA_EMU_TASK_H

#include <pthread.h>

#include <lib/util/class.h>

/* Forward declarations */
struct bit_map_t;

/*
 * Class 'FPGATask'
 */

typedef int (*FPGATaskCanWakeupFunc)(FPGATask *self, void *data);
typedef void (*FPGATaskWakeupFunc)(FPGATask *self, void *data);

typedef enum {
	FPGATaskRunning = 0x00001, /* it is running */
	FPGATaskReady = 0x00002, /* waiting in a kernel queue */
	FPGATaskRejected = 0x00004,
	FPGATaskFinished = 0x00008, /* no more inst to execute */
	FPGATaskNone = 0x00000
} FPGATaskState;

CLASS_BEGIN(FPGATask, Object)

/* Emulator it belongs to */
	FPGAEmu *emu;

	/* Task properties */
	int state;
	int pid; /* Task ID */

	/* Host kernel */
	FPGAKernel *kernel;

	FPGATask *task_list_next, *task_list_prev;
	FPGATask *waiting_list_next, *waiting_list_prev;
	FPGATask *finished_list_next, *finished_list_prev;

	/* If task is in state 'mapped', these two variables represent the
	 * node (core/thread) associated with the task. */
	int kernel_index;

	int task_ready_idx, task_done_idx;
	int input_size, output_size;
	void *input, *output;

	X86Context *ctx;

	long long start_cycle;

CLASS_END(FPGATask)

void FPGATaskCreate(FPGATask *self, FPGAEmu *emu, FPGAKernel *kernel, int input_size,
		int output_size, void *input, void *output, int task_ready_idx, int task_done_idx);

void FPGATaskDestroy(FPGATask *self);

void FPGATaskDump(Object *self, FILE *f);

/* Thread safe/unsafe versions */
void FPGATaskHostThreadSuspendCancelUnsafe(FPGATask *self);
void FPGATaskHostThreadSuspendCancel(FPGATask *self);
void FPGATaskHostThreadTimerCancelUnsafe(FPGATask *self);
void FPGATaskHostThreadTimerCancel(FPGATask *self);

void FPGATaskSuspend(FPGATask *self, FPGATaskCanWakeupFunc can_wakeup_callback_func,
		void *can_wakeup_callback_data, FPGATaskWakeupFunc wakeup_callback_func,
		void *wakeup_callback_data);

void FPGATaskFinish(FPGATask *self, int state);
void FPGATaskFinishGroup(FPGATask *self, int state);
void FPGATaskExecute(FPGATask *self);

void FPGATaskSetEip(FPGATask *self, unsigned int eip);
void FPGATaskRecover(FPGATask *self);

FPGATask *FPGATaskGetZombie(FPGATask *parent, int pid);

int FPGATaskGetState(FPGATask *self, FPGATaskState state);
void FPGATaskSetState(FPGATask *self, FPGATaskState state);
void FPGATaskClearState(FPGATask *self, FPGATaskState state);

int FPGATaskFutexWake(FPGATask *self, unsigned int futex, unsigned int count, unsigned int bitset);
void FPGATaskExitRobustList(FPGATask *self);

void FPGATaskProcSelfMaps(FPGATask *self, char *path, int size);
void FPGATaskProcCPUInfo(FPGATask *self, char *path, int size);

/* Function that suspends the host thread waiting for an event to occur.
 * When the event finally occurs (i.e., before the function finishes, a
 * call to 'FPGAEmuProcessEvents' is scheduled.
 * The argument 'arg' is the associated guest task. */
void *FPGAEmuHostThreadSuspend(void *self);

/* Function that suspends the host thread waiting for a timer to expire,
 * and then schedules a call to 'FPGAEmuProcessEvents'. */
void *FPGATaskHostThreadTimer(void *self);

/*
 * Non-Class
 */

#define FPGATaskDebug(...) debug(fpga_task_debug_category, __VA_ARGS__)
extern int fpga_task_debug_category;

extern struct str_map_t fpga_task_state_map;

#endif

