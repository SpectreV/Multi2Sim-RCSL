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

static void FPGATaskDoCreate(FPGATask *self, FPGAEmu *emu)
{
	int num_nodes;
	int i;
	
	/* Initialize */
	self->emu = emu;
	self->pid = emu->current_pid++;

	/* Update state so that the context is inserted in the
	 * corresponding lists. The fpga_ctx_running parameter has no
	 * effect, since it will be updated later. */
	FPGATaskSetState(self, FPGATaskRunning);
	DOUBLE_LINKED_LIST_INSERT_HEAD(emu, task, self);

	/* Structures */
	self->regs = fpga_regs_create();
	self->backup_regs = fpga_regs_create();
	self->signal_mask_table = fpga_signal_mask_table_create();

	/* Thread affinity mask, used only for timing simulation. It is
	 * initialized to all 1's. */
	num_nodes = fpga_cpu_num_cores * fpga_cpu_num_threads;
	self->affinity = bit_map_create(num_nodes);
	for (i = 0; i < num_nodes; i++)
		bit_map_set(self->affinity, i, 1, 1);

	/* Virtual functions */
	asObject(self)->Dump = FPGATaskDump;
}


void FPGATaskCreate(FPGATask *self, FPGAEmu *emu)
{
	/* Baseline initialization */
	FPGATaskDoCreate(self, emu);

	/* Loader */
	self->loader = fpga_loader_create();

	/* Memory */
	self->address_space_index = mmu_address_space_new();
	self->mem = mem_create();
	self->spec_mem = spec_mem_create(self->mem);

	/* Signal handlers and file descriptor table */
	self->signal_handler_table = fpga_signal_handler_table_create();
	self->file_desc_table = fpga_file_desc_table_create();
}


void FPGATaskCreateAndClone(FPGATask *self, FPGATask *cloned)
{
	/* Baseline initialization */
	FPGATaskDoCreate(self, cloned->emu);

	/* Register file contexts are copied from parent. */
	fpga_regs_copy(self->regs, cloned->regs);

	/* The memory image of the cloned context if the same.
	 * The memory structure must be only freed by the parent
	 * when all its children have been killed.
	 * The set of signal handlers is the same, too. */
	self->address_space_index = cloned->address_space_index;
	self->mem = mem_link(cloned->mem);
	self->spec_mem = spec_mem_create(self->mem);

	/* Loader */
	self->loader = fpga_loader_link(cloned->loader);

	/* Signal handlers and file descriptor table */
	self->signal_handler_table = fpga_signal_handler_table_link(cloned->signal_handler_table);
	self->file_desc_table = fpga_file_desc_table_link(cloned->file_desc_table);

	/* Libc segment */
	self->glibc_segment_base = cloned->glibc_segment_base;
	self->glibc_segment_limit = cloned->glibc_segment_limit;

	/* Update other fields. */
	self->parent = cloned;
}


void FPGATaskCreateAndFork(FPGATask *self, FPGATask *forked)
{
	/* Initialize baseline contect */
	FPGATaskDoCreate(self, forked->emu);

	/* Copy registers */
	fpga_regs_copy(self->regs, forked->regs);

	/* Memory */
	self->address_space_index = mmu_address_space_new();
	self->mem = mem_create();
	self->spec_mem = spec_mem_create(self->mem);
	mem_clone(self->mem, forked->mem);

	/* Loader */
	self->loader = fpga_loader_link(forked->loader);

	/* Signal handlers and file descriptor table */
	self->signal_handler_table = fpga_signal_handler_table_create();
	self->file_desc_table = fpga_file_desc_table_create();

	/* Libc segment */
	self->glibc_segment_base = forked->glibc_segment_base;
	self->glibc_segment_limit = forked->glibc_segment_limit;

	/* Set parent */
	self->parent = forked;
}


void FPGATaskDestroy(FPGATask *self)
{
	FPGAEmu *emu = self->emu;

	/* If context is not finished/zombie, finish it first.
	 * This removes all references to current freed context. */
	if (!FPGATaskGetState(self, FPGATaskFinished | FPGATaskZombie))
		FPGATaskFinish(self, 0);
	
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
	FPGATaskDebug("inst %lld: context %d freed\n",
			asEmu(emu)->instructions, self->pid);
}


void FPGATaskDump(Object *self, FILE *f)
{
	FPGATask *context = asFPGATask(self);
	char state_str[MAX_STRING_SIZE];

	/* Title */
	fprintf(f, "------------\n");
	fprintf(f, "Context %d\n", context->pid);
	fprintf(f, "------------\n\n");

	str_map_flags(&fpga_context_state_map, context->state, state_str, sizeof state_str);
	fprintf(f, "State = %s\n", state_str);
	if (!context->parent)
		fprintf(f, "Parent = None\n");
	else
		fprintf(f, "Parent = %d\n", context->parent->pid);
	fprintf(f, "Heap break: 0x%x\n", context->mem->heap_break);

	/* Bit masks */
	fprintf(f, "BlockedSignalMask = 0x%llx ", context->signal_mask_table->blocked);
	fpga_sigset_dump(context->signal_mask_table->blocked, f);
	fprintf(f, "\nPendingSignalMask = 0x%llx ", context->signal_mask_table->pending);
	fpga_sigset_dump(context->signal_mask_table->pending, f);
	fprintf(f, "\nAffinity = ");
	bit_map_dump(context->affinity, 0, fpga_cpu_num_cores * fpga_cpu_num_threads, f);
	fprintf(f, "\n");

	/* End */
	fprintf(f, "\n\n");
}


void FPGATaskExecute(FPGATask *self)
{
	FPGAEmu *emu = self->emu;

	struct fpga_regs_t *regs = self->regs;
	struct mem_t *mem = self->mem;

	unsigned char buffer[20];
	unsigned char *buffer_ptr;

	int spec_mode;

	/* Memory permissions should not be checked if the context is executing in
	 * speculative mode. This will prevent guest segmentation faults to occur. */
	spec_mode = FPGATaskGetState(self, FPGATaskSpecMode);
	mem->safe = spec_mode ? 0 : mem_safe_mode;

	/* Read instruction from memory. Memory should be accessed here in unsafe mode
	 * (i.e., allowing segmentation faults) if executing speculatively. */
	buffer_ptr = mem_get_buffer(mem, regs->eip, 20, mem_access_exec);
	if (!buffer_ptr)
	{
		/* Disable safe mode. If a part of the 20 read bytes does not belong to the
		 * actual instruction, and they lie on a page with no permissions, this would
		 * generate an undesired protection fault. */
		mem->safe = 0;
		buffer_ptr = buffer;
		mem_access(mem, regs->eip, 20, buffer_ptr, mem_access_exec);
	}
	mem->safe = mem_safe_mode;

	/* Disassemble */
	fpga_inst_decode(&self->inst, regs->eip, buffer_ptr);
	if (self->inst.opcode == fpga_inst_opcode_invalid && !spec_mode)
		fatal("0x%x: not supported fpga instruction (%02x %02x %02x %02x...)",
			regs->eip, buffer_ptr[0], buffer_ptr[1], buffer_ptr[2], buffer_ptr[3]);


	/* Stop if instruction matches last instruction bytes */
	if (fpga_emu_last_inst_size &&
		fpga_emu_last_inst_size == self->inst.size &&
		!memcmp(fpga_emu_last_inst_bytes, buffer_ptr, fpga_emu_last_inst_size))
		esim_finish = esim_finish_fpga_last_inst;

	/* Execute instruction */
	FPGATaskExecuteInst(self);
	
	/* Statistics */
	asEmu(emu)->instructions++;
}


/* Force a new 'eip' value for the context. The forced value should be the same as
 * the current 'eip' under normal circumstances. If it is not, speculative execution
 * starts, which will end on the next call to 'fpga_ctx_recover'. */
void FPGATaskSetEip(FPGATask *self, unsigned int eip)
{
	/* Entering specmode */
	if (self->regs->eip != eip && !FPGATaskGetState(self, FPGATaskSpecMode))
	{
		FPGATaskSetState(self, FPGATaskSpecMode);
		fpga_regs_copy(self->backup_regs, self->regs);
		self->regs->fpu_ctrl |= 0x3f; /* mask all FP exceptions on wrong path */
	}
	
	/* Set it */
	self->regs->eip = eip;
}


void FPGATaskRecover(FPGATask *self)
{
	assert(FPGATaskGetState(self, FPGATaskSpecMode));
	FPGATaskClearState(self, FPGATaskSpecMode);
	fpga_regs_copy(self->regs, self->backup_regs);
	spec_mem_clear(self->spec_mem);
}


int FPGATaskGetState(FPGATask *self, FPGATaskState state)
{
	return (self->state & state) > 0;
}


static void FPGATaskUpdateState(FPGATask *self, FPGATaskState state)
{
	FPGAEmu *emu = self->emu;

	FPGATaskState status_diff;
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
	if (status_diff & ~FPGATaskSpecMode)
		emu->schedule_signal = 1;
	
	/* Update state */
	self->state = state;
	if (self->state & FPGATaskFinished)
		self->state = FPGATaskFinished
				| (state & FPGATaskAlloc)
				| (state & FPGATaskMapped);
	if (self->state & FPGATaskZombie)
		self->state = FPGATaskZombie
				| (state & FPGATaskAlloc)
				| (state & FPGATaskMapped);
	if (!(self->state & FPGATaskSuspended) &&
		!(self->state & FPGATaskFinished) &&
		!(self->state & FPGATaskZombie) &&
		!(self->state & FPGATaskLocked))
		self->state |= FPGATaskRunning;
	else
		self->state &= ~FPGATaskRunning;
	
	/* Insert context into the corresponding lists. */
	if (self->state & FPGATaskRunning)
		DOUBLE_LINKED_LIST_INSERT_HEAD(emu, running, self);
	if (self->state & FPGATaskZombie)
		DOUBLE_LINKED_LIST_INSERT_HEAD(emu, zombie, self);
	if (self->state & FPGATaskFinished)
		DOUBLE_LINKED_LIST_INSERT_HEAD(emu, finished, self);
	if (self->state & FPGATaskSuspended)
		DOUBLE_LINKED_LIST_INSERT_HEAD(emu, suspended, self);
	
	/* Dump new state (ignore 'fpga_ctx_specmode' state, it's too frequent) */
	if (debug_status(fpga_context_debug_category) && (status_diff & ~FPGATaskSpecMode))
	{
		str_map_flags(&fpga_context_state_map, self->state, state_str, sizeof state_str);
		FPGATaskDebug("inst %lld: ctx %d changed state to %s\n",
			asEmu(emu)->instructions, self->pid, state_str);
	}

	/* Start/stop fpga timer depending on whether there are any contexts
	 * currently running. */
	if (emu->running_list_count)
		m2s_timer_start(asEmu(emu)->timer);
	else
		m2s_timer_stop(asEmu(emu)->timer);
}


void FPGATaskSetState(FPGATask *self, FPGATaskState state)
{
	FPGATaskUpdateState(self, self->state | state);
}


void FPGATaskClearState(FPGATask *self, FPGATaskState state)
{
	FPGATaskUpdateState(self, self->state & ~state);
}


/* Look for zombie child. If 'pid' is -1, the first finished child
 * in the zombie contexts list is return. Otherwise, 'pid' is the
 * pid of the child process. If no child has finished, return NULL. */
FPGATask *FPGATaskGetZombie(FPGATask *self, int pid)
{
	FPGAEmu *emu = self->emu;
	FPGATask *context;

	for (context = emu->zombie_list_head; context;
			context = context->zombie_list_next)
	{
		if (context->parent != self)
			continue;
		if (context->pid == pid || pid == -1)
			return context;
	}
	return NULL;
}


/* If the context is running a 'fpga_emu_host_thread_suspend' thread,
 * cancel it and schedule call to 'fpga_emu_process_events' */
void FPGATaskHostThreadSuspendCancelUnsafe(FPGATask *self)
{
	FPGAEmu *emu = self->emu;

	if (self->host_thread_suspend_active)
	{
		if (pthread_cancel(self->host_thread_suspend))
			fatal("%s: context %d: error canceling host thread",
				__FUNCTION__, self->pid);
		self->host_thread_suspend_active = 0;
		emu->process_events_force = 1;
	}
}


void FPGATaskHostThreadSuspendCancel(FPGATask *self)
{
	FPGAEmu *emu = self->emu;

	pthread_mutex_lock(&emu->process_events_mutex);
	FPGATaskHostThreadSuspendCancelUnsafe(self);
	pthread_mutex_unlock(&emu->process_events_mutex);
}


/* If the context is running a 'ke_host_thread_timer' thread,
 * cancel it and schedule call to 'fpga_emu_process_events' */
void FPGATaskHostThreadTimerCancelUnsafe(FPGATask *self)
{
	FPGAEmu *emu = self->emu;

	if (self->host_thread_timer_active)
	{
		if (pthread_cancel(self->host_thread_timer))
			fatal("%s: context %d: error canceling host thread",
				__FUNCTION__, self->pid);
		self->host_thread_timer_active = 0;
		emu->process_events_force = 1;
	}
}

void FPGATaskHostThreadTimerCancel(FPGATask *self)
{
	FPGAEmu *emu = self->emu;

	pthread_mutex_lock(&emu->process_events_mutex);
	FPGATaskHostThreadTimerCancelUnsafe(self);
	pthread_mutex_unlock(&emu->process_events_mutex);
}


/* Suspend a context, using the specified callback function and data to decide
 * whether the process can wake up every time the fpga emulation events are
 * processed. */
void FPGATaskSuspend(FPGATask *self, FPGATaskCanWakeupFunc can_wakeup_callback_func,
	void *can_wakeup_callback_data, FPGATaskWakeupFunc wakeup_callback_func,
	void *wakeup_callback_data)
{
	FPGAEmu *emu = self->emu;

	/* Checks */
	assert(!FPGATaskGetState(self, FPGATaskSuspended));
	assert(!self->can_wakeup_callback_func);
	assert(!self->can_wakeup_callback_data);

	/* Suspend context */
	self->can_wakeup_callback_func = can_wakeup_callback_func;
	self->can_wakeup_callback_data = can_wakeup_callback_data;
	self->wakeup_callback_func = wakeup_callback_func;
	self->wakeup_callback_data = wakeup_callback_data;
	FPGATaskSetState(self, FPGATaskSuspended | FPGATaskCallback);
	FPGAEmuProcessEventsSchedule(emu);
}


/* Finish a context group. This call does a subset of action of the 'fpga_ctx_finish'
 * call, but for all parent and child contexts sharing a memory map. */
void FPGATaskFinishGroup(FPGATask *self, int state)
{
	FPGAEmu *emu = self->emu;
	FPGATask *aux;

	/* Get group parent */
	if (self->group_parent)
		self = self->group_parent;
	assert(!self->group_parent);  /* Only one level */
	
	/* Context already finished */
	if (FPGATaskGetState(self, FPGATaskFinished | FPGATaskZombie))
		return;

	/* Finish all contexts in the group */
	DOUBLE_LINKED_LIST_FOR_EACH(emu, context, aux)
	{
		if (aux->group_parent != self && aux != self)
			continue;

		if (FPGATaskGetState(aux, FPGATaskZombie))
			FPGATaskSetState(aux, FPGATaskFinished);
		if (FPGATaskGetState(aux, FPGATaskHandler))
			FPGATaskReturnFromSignalHandler(aux);
		FPGATaskHostThreadSuspendCancel(aux);
		FPGATaskHostThreadTimerCancel(aux);

		/* Child context of 'ctx' goes to state 'finished'.
		 * Context 'ctx' goes to state 'zombie' or 'finished' if it has a parent */
		if (aux == self)
			FPGATaskSetState(aux, aux->parent ? FPGATaskZombie : FPGATaskFinished);
		else
			FPGATaskSetState(aux, FPGATaskFinished);
		aux->exit_code = state;
	}

	/* Process events */
	FPGAEmuProcessEventsSchedule(emu);
}


/* Finish a context. If the context has no parent, its state will be set
 * to 'fpga_ctx_finished'. If it has, its state is set to 'fpga_ctx_zombie', waiting for
 * a call to 'waitpid'.
 * The children of the finished context will set their 'parent' attribute to NULL.
 * The zombie children will be finished. */
void FPGATaskFinish(FPGATask *self, int state)
{
	FPGAEmu *emu = self->emu;
	FPGATask *aux;
	
	/* Context already finished */
	if (FPGATaskGetState(self, FPGATaskFinished | FPGATaskZombie))
		return;
	
	/* If context is waiting for host events, cancel spawned host threads. */
	FPGATaskHostThreadSuspendCancel(self);
	FPGATaskHostThreadTimerCancel(self);

	/* From now on, all children have lost their parent. If a child is
	 * already zombie, finish it, since its parent won't be able to waitpid it
	 * anymore. */
	DOUBLE_LINKED_LIST_FOR_EACH(emu, context, aux)
	{
		if (aux->parent == self)
		{
			aux->parent = NULL;
			if (FPGATaskGetState(aux, FPGATaskZombie))
				FPGATaskSetState(aux, FPGATaskFinished);
		}
	}

	/* Send finish signal to parent */
	if (self->exit_signal && self->parent)
	{
		fpga_sys_debug("  sending signal %d to pid %d\n",
			self->exit_signal, self->parent->pid);
		fpga_sigset_add(&self->parent->signal_mask_table->pending,
			self->exit_signal);
		FPGAEmuProcessEventsSchedule(emu);
	}

	/* If clear_child_tid was set, a futex() call must be performed on
	 * that pointer. Also wake up futexes in the robust list. */
	if (self->clear_child_tid)
	{
		unsigned int zero = 0;
		mem_write(self->mem, self->clear_child_tid, 4, &zero);
		FPGATaskFutexWake(self, self->clear_child_tid, 1, -1);
	}
	FPGATaskExitRobustList(self);

	/* If we are in a signal handler, stop it. */
	if (FPGATaskGetState(self, FPGATaskHandler))
		FPGATaskReturnFromSignalHandler(self);

	/* Finish context */
	FPGATaskSetState(self, self->parent ? FPGATaskZombie : FPGATaskFinished);
	self->exit_code = state;
	FPGAEmuProcessEventsSchedule(emu);
}


int FPGATaskFutexWake(FPGATask *self, unsigned int futex, unsigned int count,
		unsigned int bitset)
{
	FPGAEmu *emu = self->emu;
	FPGATask *wakeup_ctx;

	int wakeup_count = 0;

	/* Look for threads suspended in this futex */
	while (count)
	{
		wakeup_ctx = NULL;
		for (self = emu->suspended_list_head; self; self = self->suspended_list_next)
		{
			if (!FPGATaskGetState(self, FPGATaskFutex) || self->wakeup_futex != futex)
				continue;
			if (!(self->wakeup_futex_bitset & bitset))
				continue;
			if (!wakeup_ctx || self->wakeup_futex_sleep < wakeup_ctx->wakeup_futex_sleep)
				wakeup_ctx = self;
		}

		if (wakeup_ctx)
		{
			/* Wake up context */
			FPGATaskClearState(wakeup_ctx, FPGATaskSuspended | FPGATaskFutex);
			fpga_sys_debug("  futex 0x%x: thread %d woken up\n", futex, wakeup_ctx->pid);
			wakeup_count++;
			count--;

			/* Set system call return value */
			wakeup_ctx->regs->eax = 0;
		}
		else
		{
			break;
		}
	}
	return wakeup_count;
}


void FPGATaskExitRobustList(FPGATask *self)
{
	unsigned int next, lock_entry, offset, lock_word;

	/* Read the offset from the list head. This is how the structure is
	 * represented in the kernel:
	 * struct robust_list {
	 *      struct robust_list __user *next;
	 * }
	 * struct robust_list_head {
	 *	struct robust_list list;
	 *	long futex_offset;
	 *	struct robust_list __user *list_op_pending;
	 * }
	 * See linux/Documentation/robust-futex-ABI.txt for details
	 * about robust futex wake up at thread exit.
	 */

	lock_entry = self->robust_list_head;
	if (!lock_entry)
		return;
	
	fpga_sys_debug("ctx %d: processing robust futex list\n",
		self->pid);
	for (;;)
	{
		mem_read(self->mem, lock_entry, 4, &next);
		mem_read(self->mem, lock_entry + 4, 4, &offset);
		mem_read(self->mem, lock_entry + offset, 4, &lock_word);

		fpga_sys_debug("  lock_entry=0x%x: offset=%d, lock_word=0x%x\n",
			lock_entry, offset, lock_word);

		/* Stop processing list if 'next' points to robust list */
		if (!next || next == self->robust_list_head)
			break;
		lock_entry = next;
	}
}


/* Generate virtual file '/proc/self/maps' and return it in 'path'. */
void FPGATaskProcSelfMaps(FPGATask *self, char *path, int size)
{
	unsigned int start, end;
	enum mem_access_t perm, page_perm;
	struct mem_page_t *page;
	struct mem_t *mem = self->mem;
	int fd;
	FILE *f = NULL;

	/* Create temporary file */
	snprintf(path, size, "/tmp/m2s.XXXXXX");
	if ((fd = mkstemp(path)) == -1 || (f = fdopen(fd, "wt")) == NULL)
		fatal("ctx_gen_proc_self_maps: cannot create temporary file");

	/* Get the first page */
	end = 0;
	for (;;)
	{
		/* Get start of next range */
		page = mem_page_get_next(mem, end);
		if (!page)
			break;
		start = page->tag;
		end = page->tag;
		perm = page->perm & (mem_access_read | mem_access_write | mem_access_exec);

		/* Get end of range */
		for (;;)
		{
			page = mem_page_get(mem, end + MEM_PAGE_SIZE);
			if (!page)
				break;
			page_perm = page->perm & (mem_access_read | mem_access_write | mem_access_exec);
			if (page_perm != perm)
				break;
			end += MEM_PAGE_SIZE;
			perm = page_perm;
		}

		/* Dump range */ 
		fprintf(f, "%08x-%08x %c%c%c%c 00000000 00:00", start, end + MEM_PAGE_SIZE,
			perm & mem_access_read ? 'r' : '-',
			perm & mem_access_write ? 'w' : '-',
			perm & mem_access_exec ? 'x' : '-',
			'p');
		fprintf(f, "\n");
	}

	/* Close file */
	fclose(f);
}


/* Generate virtual file '/proc/cpuinfo' and return it in 'path'. */
void FPGATaskProcCPUInfo(FPGATask *self, char *path, int size)
{
	FILE *f = NULL;
	
	int i;
	int j;
	int node;
	int fd;

	/* Create temporary file */
	snprintf(path, size, "/tmp/m2s.XXXXXX");
	if ((fd = mkstemp(path)) == -1 || (f = fdopen(fd, "wt")) == NULL)
		fatal("ctx_gen_proc_self_maps: cannot create temporary file");

	for (i = 0; i < fpga_cpu_num_cores; i++)
	{
		for (j = 0; j < fpga_cpu_num_threads; j++)
		{
			node = i * fpga_cpu_num_threads + j;
			fprintf(f, "processor : %d\n", node);
			fprintf(f, "vendor_id : Multi2Sim\n");
			fprintf(f, "cpu family : 6\n");
			fprintf(f, "model : 23\n");
			fprintf(f, "model name : Multi2Sim\n");
			fprintf(f, "stepping : 6\n");
			fprintf(f, "microcode : 0x607\n");
			fprintf(f, "cpu MHz : 800.000\n");
			fprintf(f, "cache size : 3072 KB\n");
			fprintf(f, "physical id : 0\n");
			fprintf(f, "siblings : %d\n", fpga_cpu_num_cores * fpga_cpu_num_threads);
			fprintf(f, "core id : %d\n", i);
			fprintf(f, "cpu cores : %d\n", fpga_cpu_num_cores);
			fprintf(f, "apicid : %d\n", node);
			fprintf(f, "initial apicid : %d\n", node);
			fprintf(f, "fpu : yes\n");
			fprintf(f, "fpu_exception : yes\n");
			fprintf(f, "cpuid level : 10\n");
			fprintf(f, "wp : yes\n");
			fprintf(f, "flags : fpu vme de pse tsc msr pae mce cx8 apic sep mtrr "
					"pge mca cmov pat pse36 clflush dts acpi mmx fxsr sse "
					"sse2 ss ht tm pbe syscall nx lm constant_tsc arch_perfmon "
					"pebs bts rep_good nopl aperfmperf pni dtes64 monitor ds_cpl "
					"vmx est tm2 ssse3 cx16 xtpr pdcm sse4_1 lahf_lm ida dtherm "
					"tpr_shadow vnmi flexpriority\n");
			fprintf(f, "bogomips : 4189.40\n");
			fprintf(f, "clflush size : 32\n");
			fprintf(f, "cache_alignment : 32\n");
			fprintf(f, "address sizes : 32 bits physical, 32 bits virtual\n");
			fprintf(f, "power management :\n");
			fprintf(f, "\n");
		}
	}

	/* Close file */
	fclose(f);
}


void *FPGAEmuHostThreadSuspend(void *arg)
{
	FPGATask *self = asFPGATask(arg);
	FPGAEmu *emu = self->emu;

	long long now = esim_real_time();

	/* Detach this thread - we don't want the parent to have to join it to release
	 * its resources. The thread termination can be observed by atomically checking
	 * the 'self->host_thread_suspend_active' flag. */
	pthread_detach(pthread_self());

	/* Context suspended in 'poll' system call */
	if (FPGATaskGetState(self, FPGATaskNanosleep))
	{
		long long timeout;

		/* Calculate remaining sleep time in microseconds */
		timeout = self->wakeup_time > now ? self->wakeup_time - now : 0;
		usleep(timeout);

	}
	else if (FPGATaskGetState(self, FPGATaskPoll))
	{
		struct fpga_file_desc_t *fd;
		struct pollfd host_fds;
		int err, timeout;

		/* Get file descriptor */
		fd = fpga_file_desc_table_entry_get(self->file_desc_table, self->wakeup_fd);
		if (!fd)
			fatal("syscall 'poll': invalid 'wakeup_fd'");

		/* Calculate timeout for host call in milliseconds from now */
		if (!self->wakeup_time)
			timeout = -1;
		else if (self->wakeup_time < now)
			timeout = 0;
		else
			timeout = (self->wakeup_time - now) / 1000;

		/* Perform blocking host 'poll' */
		host_fds.fd = fd->host_fd;
		host_fds.events = ((self->wakeup_events & 4) ? POLLOUT : 0) | ((self->wakeup_events & 1) ? POLLIN : 0);
		err = poll(&host_fds, 1, timeout);
		if (err < 0)
			fatal("syscall 'poll': unexpected error in host 'poll'");
	}
	else if (FPGATaskGetState(self, FPGATaskRead))
	{
		struct fpga_file_desc_t *fd;
		struct pollfd host_fds;
		int err;

		/* Get file descriptor */
		fd = fpga_file_desc_table_entry_get(self->file_desc_table, self->wakeup_fd);
		if (!fd)
			fatal("syscall 'read': invalid 'wakeup_fd'");

		/* Perform blocking host 'poll' */
		host_fds.fd = fd->host_fd;
		host_fds.events = POLLIN;
		err = poll(&host_fds, 1, -1);
		if (err < 0)
			fatal("syscall 'read': unexpected error in host 'poll'");
	}
	else if (FPGATaskGetState(self, FPGATaskWrite))
	{
		struct fpga_file_desc_t *fd;
		struct pollfd host_fds;
		int err;

		/* Get file descriptor */
		fd = fpga_file_desc_table_entry_get(self->file_desc_table, self->wakeup_fd);
		if (!fd)
			fatal("syscall 'write': invalid 'wakeup_fd'");

		/* Perform blocking host 'poll' */
		host_fds.fd = fd->host_fd;
		host_fds.events = POLLOUT;
		err = poll(&host_fds, 1, -1);
		if (err < 0)
			fatal("syscall 'write': unexpected error in host 'write'");

	}

	/* Event occurred - thread finishes */
	pthread_mutex_lock(&emu->process_events_mutex);
	emu->process_events_force = 1;
	self->host_thread_suspend_active = 0;
	pthread_mutex_unlock(&emu->process_events_mutex);
	return NULL;
}


void *FPGATaskHostThreadTimer(void *arg)
{
	FPGATask *self = asFPGATask(arg);
	FPGAEmu *emu = self->emu;

	long long now = esim_real_time();
	struct timespec ts;
	long long sleep_time;  /* In usec */

	/* Detach this thread - we don't want the parent to have to join it to release
	 * its resources. The thread termination can be observed by thread-safely checking
	 * the 'self->host_thread_timer_active' flag. */
	pthread_detach(pthread_self());

	/* Calculate sleep time, and sleep only if it is greater than 0 */
	if (self->host_thread_timer_wakeup > now)
	{
		sleep_time = self->host_thread_timer_wakeup - now;
		ts.tv_sec = sleep_time / 1000000;
		ts.tv_nsec = (sleep_time % 1000000) * 1000;  /* nsec */
		nanosleep(&ts, NULL);
	}

	/* Timer expired, schedule call to 'FPGAEmuProcessEvents' */
	pthread_mutex_lock(&emu->process_events_mutex);
	emu->process_events_force = 1;
	self->host_thread_timer_active = 0;
	pthread_mutex_unlock(&emu->process_events_mutex);
	return NULL;
}




/*
 * Non-Class
 */

int fpga_context_debug_category;

struct str_map_t fpga_context_state_map =
{
	18, {
		{ "running",      FPGATaskRunning },
		{ "specmode",     FPGATaskSpecMode },
		{ "suspended",    FPGATaskSuspended },
		{ "finished",     FPGATaskFinished },
		{ "exclusive",    FPGATaskExclusive },
		{ "locked",       FPGATaskLocked },
		{ "handler",      FPGATaskHandler },
		{ "sigsuspend",   FPGATaskSigsuspend },
		{ "nanosleep",    FPGATaskNanosleep },
		{ "poll",         FPGATaskPoll },
		{ "read",         FPGATaskRead },
		{ "write",        FPGATaskWrite },
		{ "waitpid",      FPGATaskWaitpid },
		{ "zombie",       FPGATaskZombie },
		{ "futex",        FPGATaskFutex },
		{ "alloc",        FPGATaskAlloc },
		{ "callback",     FPGATaskCallback },
		{ "mapped",       FPGATaskMapped }
	}
};
