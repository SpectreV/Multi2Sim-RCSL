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

#include <errno.h>
#include <poll.h>
#include <unistd.h>

#include <arch/fpga/timing/cpu.h>
#include <driver/glew/glew.h>
#include <driver/glu/glu.h>
#include <driver/glut/glut.h>
#include <driver/opengl/opengl.h>
#include <lib/esim/esim.h>
#include <lib/mhandle/mhandle.h>
#include <lib/util/config.h>
#include <lib/util/debug.h>
#include <lib/util/linked-list.h>
#include <lib/util/misc.h>
#include <lib/util/string.h>
#include <mem-system/memory.h>

#include "context.h"
#include "emu.h"
#include "file-desc.h"
#include "loader.h"
#include "regs.h"
#include "signal.h"
#include "syscall.h"


/*
 * Global variables
 */

/* Configuration parameters */
long long fpga_emu_max_inst = 0;
long long fpga_emu_max_cycles = 0;
char fpga_emu_last_inst_bytes[20];
int fpga_emu_last_inst_size = 0;
int fpga_emu_process_prefetch_hints = 0;

FPGAEmu *fpga_emu;




/*
 * Class 'FPGAEmu'
 */

CLASS_IMPLEMENTATION(FPGAEmu);

void FPGAEmuCreate(FPGAEmu *self)
{
	/* Parent */
	EmuCreate(asEmu(self), "fpga");

	/* Initialize */
	self->current_pid = 100;
	pthread_mutex_init(&self->process_events_mutex, NULL);

	/* Virtual functions */
	asObject(self)->Dump = FPGAEmuDump;
	asEmu(self)->DumpSummary = FPGAEmuDumpSummary;
	asEmu(self)->Run = FPGAEmuRun;
}


void FPGAEmuDestroy(FPGAEmu *self)
{
	FPGAKernel *kernel;

	/* Finish all contexts */
	for (kernel = self->kernel_list_head; kernel; kernel = kernel->kernel_list_next)
		if (!FPGAKernelGetState(ctx, FPGAKernelFinished))
			FPGAKernelFinish(ctx, 0);

	/* Free contexts */
	while (self->kernel_list_head)
		delete(self->kernel_list_head);
	
}


void FPGAEmuDump(Object *self, FILE *f)
{
	FPGAKernel *kernel;
	FPGAEmu *emu = asFPGAEmu(self);

	/* Call parent */
	EmuDump(self, f);

	/* More */
	fprintf(f, "List of contexts (shows in any order)\n\n");
	DOUBLE_LINKED_LIST_FOR_EACH(emu, kernel, kernel)
		FPGAKernelDump(asObject(context), f);
}


void FPGAEmuDumpSummary(Emu *self, FILE *f)
{
	FPGAEmu *emu = asFPGAEmu(self);

	/* Call parent */
	EmuDumpSummary(self, f);

	/* More statistics */
	fprintf(f, "Kernels = %d\n", emu->running_list_max);
	fprintf(f, "Memory = %lu\n", mem_max_mapped_space);
}


/* Schedule a call to 'FPGAEmuProcessEvents' */
void FPGAEmuProcessEventsSchedule(FPGAEmu *self)
{
	pthread_mutex_lock(&self->process_events_mutex);
	self->process_events_force = 1;
	pthread_mutex_unlock(&self->process_events_mutex);
}


/* Check for events detected in spawned host threads, like waking up contexts or
 * sending signals.
 * The list is only processed if flag 'self->process_events_force' is set. */
void FPGAEmuProcessEvents(FPGAEmu *self)
{
	FPGAKernel *ctx, *next;
	long long now = esim_real_time();
	
	/* Check if events need actually be checked. */
	pthread_mutex_lock(&self->process_events_mutex);
	if (!self->process_events_force)
	{
		pthread_mutex_unlock(&self->process_events_mutex);
		return;
	}
	
	/* By default, no subsequent call to 'FPGAEmuProcessEvents' is assumed */
	self->process_events_force = 0;

	/*
	 * LOOP 1
	 * Look at the list of suspended contexts and try to find
	 * one that needs to be waken up.
	 */
	for (ctx = self->suspended_list_head; ctx; ctx = next)
	{
		/* Save next */
		next = ctx->suspended_list_next;

		/* Kernel is suspended in 'nanosleep' system call. */
		if (FPGAKernelGetState(ctx, FPGAKernelNanosleep))
		{
			unsigned int rmtp = ctx->regs->ecx;
			unsigned long long zero = 0;
			unsigned int sec, usec;
			unsigned long long diff;

			/* If 'FPGAEmuHostThreadSuspend' is still running for this context, do nothing. */
			if (ctx->host_thread_suspend_active)
				continue;

			/* Timeout expired */
			if (ctx->wakeup_time <= now)
			{
				if (rmtp)
					mem_write(ctx->mem, rmtp, 8, &zero);
				fpga_sys_debug("syscall 'nanosleep' - continue (pid %d)\n", ctx->pid);
				fpga_sys_debug("  return=0x%x\n", ctx->regs->eax);
				FPGAKernelClearState(ctx, FPGAKernelSuspended | FPGAKernelNanosleep);
				continue;
			}

			/* Kernel received a signal */
			if (ctx->signal_mask_table->pending & ~ctx->signal_mask_table->blocked)
			{
				if (rmtp)
				{
					diff = ctx->wakeup_time - now;
					sec = diff / 1000000;
					usec = diff % 1000000;
					mem_write(ctx->mem, rmtp, 4, &sec);
					mem_write(ctx->mem, rmtp + 4, 4, &usec);
				}
				ctx->regs->eax = -EINTR;
				fpga_sys_debug("syscall 'nanosleep' - interrupted by signal (pid %d)\n", ctx->pid);
				FPGAKernelClearState(ctx, FPGAKernelSuspended | FPGAKernelNanosleep);
				continue;
			}

			/* No event available, launch 'FPGAEmuHostThreadSuspend' again */
			ctx->host_thread_suspend_active = 1;
			if (pthread_create(&ctx->host_thread_suspend, NULL, FPGAEmuHostThreadSuspend, ctx))
				fatal("syscall 'poll': could not create child thread");
			continue;
		}

		/* Kernel suspended in 'rt_sigsuspend' system call */
		if (FPGAKernelGetState(ctx, FPGAKernelSigsuspend))
		{
			/* Kernel received a signal */
			if (ctx->signal_mask_table->pending & ~ctx->signal_mask_table->blocked)
			{
				FPGAKernelCheckSignalHandlerIntr(ctx);
				ctx->signal_mask_table->blocked = ctx->signal_mask_table->backup;
				fpga_sys_debug("syscall 'rt_sigsuspend' - interrupted by signal (pid %d)\n", ctx->pid);
				FPGAKernelClearState(ctx, FPGAKernelSuspended | FPGAKernelSigsuspend);
				continue;
			}

			/* No event available. The context will never awake on its own, so no
			 * 'FPGAEmuHostThreadSuspend' is necessary. */
			continue;
		}

		/* Kernel suspended in 'poll' system call */
		if (FPGAKernelGetState(ctx, FPGAKernelPoll))
		{
			uint32_t prevents = ctx->regs->ebx + 6;
			uint16_t revents = 0;
			struct fpga_file_desc_t *fd;
			struct pollfd host_fds;
			int err;

			/* If 'FPGAEmuHostThreadSuspend' is still running for this context, do nothing. */
			if (ctx->host_thread_suspend_active)
				continue;

			/* Get file descriptor */
			fd = fpga_file_desc_table_entry_get(ctx->file_desc_table, ctx->wakeup_fd);
			if (!fd)
				fatal("syscall 'poll': invalid 'wakeup_fd'");

			/* Kernel received a signal */
			if (ctx->signal_mask_table->pending & ~ctx->signal_mask_table->blocked)
			{
				FPGAKernelCheckSignalHandlerIntr(ctx);
				fpga_sys_debug("syscall 'poll' - interrupted by signal (pid %d)\n", ctx->pid);
				FPGAKernelClearState(ctx, FPGAKernelSuspended | FPGAKernelPoll);
				continue;
			}

			/* Perform host 'poll' call */
			host_fds.fd = fd->host_fd;
			host_fds.events = ((ctx->wakeup_events & 4) ? POLLOUT : 0) | ((ctx->wakeup_events & 1) ? POLLIN : 0);
			err = poll(&host_fds, 1, 0);
			if (err < 0)
				fatal("syscall 'poll': unexpected error in host 'poll'");

			/* POLLOUT event available */
			if (ctx->wakeup_events & host_fds.revents & POLLOUT)
			{
				revents = POLLOUT;
				mem_write(ctx->mem, prevents, 2, &revents);
				ctx->regs->eax = 1;
				fpga_sys_debug("syscall poll - continue (pid %d) - POLLOUT occurred in file\n", ctx->pid);
				fpga_sys_debug("  retval=%d\n", ctx->regs->eax);
				FPGAKernelClearState(ctx, FPGAKernelSuspended | FPGAKernelPoll);
				continue;
			}

			/* POLLIN event available */
			if (ctx->wakeup_events & host_fds.revents & POLLIN)
			{
				revents = POLLIN;
				mem_write(ctx->mem, prevents, 2, &revents);
				ctx->regs->eax = 1;
				fpga_sys_debug("syscall poll - continue (pid %d) - POLLIN occurred in file\n", ctx->pid);
				fpga_sys_debug("  retval=%d\n", ctx->regs->eax);
				FPGAKernelClearState(ctx, FPGAKernelSuspended | FPGAKernelPoll);
				continue;
			}

			/* Timeout expired */
			if (ctx->wakeup_time && ctx->wakeup_time < now)
			{
				revents = 0;
				mem_write(ctx->mem, prevents, 2, &revents);
				fpga_sys_debug("syscall poll - continue (pid %d) - time out\n", ctx->pid);
				fpga_sys_debug("  return=0x%x\n", ctx->regs->eax);
				FPGAKernelClearState(ctx, FPGAKernelSuspended | FPGAKernelPoll);
				continue;
			}

			/* No event available, launch 'FPGAEmuHostThreadSuspend' again */
			ctx->host_thread_suspend_active = 1;
			if (pthread_create(&ctx->host_thread_suspend, NULL, FPGAEmuHostThreadSuspend, ctx))
				fatal("syscall 'poll': could not create child thread");
			continue;
		}


		/* Kernel suspended in a 'write' system call  */
		if (FPGAKernelGetState(ctx, FPGAKernelWrite))
		{
			struct fpga_file_desc_t *fd;
			int count, err;
			uint32_t pbuf;
			void *buf;
			struct pollfd host_fds;

			/* If 'FPGAEmuHostThreadSuspend' is still running for this context, do nothing. */
			if (ctx->host_thread_suspend_active)
				continue;

			/* Kernel received a signal */
			if (ctx->signal_mask_table->pending & ~ctx->signal_mask_table->blocked)
			{
				FPGAKernelCheckSignalHandlerIntr(ctx);
				fpga_sys_debug("syscall 'write' - interrupted by signal (pid %d)\n", ctx->pid);
				FPGAKernelClearState(ctx, FPGAKernelSuspended | FPGAKernelWrite);
				continue;
			}

			/* Get file descriptor */
			fd = fpga_file_desc_table_entry_get(ctx->file_desc_table, ctx->wakeup_fd);
			if (!fd)
				fatal("syscall 'write': invalid 'wakeup_fd'");

			/* Check if data is ready in file by polling it */
			host_fds.fd = fd->host_fd;
			host_fds.events = POLLOUT;
			err = poll(&host_fds, 1, 0);
			if (err < 0)
				fatal("syscall 'write': unexpected error in host 'poll'");

			/* If data is ready in the file, wake up context */
			if (host_fds.revents) {
				pbuf = ctx->regs->ecx;
				count = ctx->regs->edx;
				buf = xmalloc(count);
				mem_read(ctx->mem, pbuf, count, buf);

				count = write(fd->host_fd, buf, count);
				if (count < 0)
					fatal("syscall 'write': unexpected error in host 'write'");

				ctx->regs->eax = count;
				free(buf);

				fpga_sys_debug("syscall write - continue (pid %d)\n", ctx->pid);
				fpga_sys_debug("  return=0x%x\n", ctx->regs->eax);
				FPGAKernelClearState(ctx, FPGAKernelSuspended | FPGAKernelWrite);
				continue;
			}

			/* Data is not ready to be written - launch 'FPGAEmuHostThreadSuspend' again */
			ctx->host_thread_suspend_active = 1;
			if (pthread_create(&ctx->host_thread_suspend, NULL, FPGAEmuHostThreadSuspend, ctx))
				fatal("syscall 'write': could not create child thread");
			continue;
		}

		/* Kernel suspended in 'read' system call */
		if (FPGAKernelGetState(ctx, FPGAKernelRead))
		{
			struct fpga_file_desc_t *fd;
			uint32_t pbuf;
			int count, err;
			void *buf;
			struct pollfd host_fds;

			/* If 'FPGAEmuHostThreadSuspend' is still running for this context, do nothing. */
			if (ctx->host_thread_suspend_active)
				continue;

			/* Kernel received a signal */
			if (ctx->signal_mask_table->pending & ~ctx->signal_mask_table->blocked)
			{
				FPGAKernelCheckSignalHandlerIntr(ctx);
				fpga_sys_debug("syscall 'read' - interrupted by signal (pid %d)\n", ctx->pid);
				FPGAKernelClearState(ctx, FPGAKernelSuspended | FPGAKernelRead);
				continue;
			}

			/* Get file descriptor */
			fd = fpga_file_desc_table_entry_get(ctx->file_desc_table, ctx->wakeup_fd);
			if (!fd)
				fatal("syscall 'read': invalid 'wakeup_fd'");

			/* Check if data is ready in file by polling it */
			host_fds.fd = fd->host_fd;
			host_fds.events = POLLIN;
			err = poll(&host_fds, 1, 0);
			if (err < 0)
				fatal("syscall 'read': unexpected error in host 'poll'");

			/* If data is ready, perform host 'read' call and wake up */
			if (host_fds.revents)
			{
				pbuf = ctx->regs->ecx;
				count = ctx->regs->edx;
				buf = xmalloc(count);
				
				count = read(fd->host_fd, buf, count);
				if (count < 0)
					fatal("syscall 'read': unexpected error in host 'read'");

				ctx->regs->eax = count;
				mem_write(ctx->mem, pbuf, count, buf);
				free(buf);

				fpga_sys_debug("syscall 'read' - continue (pid %d)\n", ctx->pid);
				fpga_sys_debug("  return=0x%x\n", ctx->regs->eax);
				FPGAKernelClearState(ctx, FPGAKernelSuspended | FPGAKernelRead);
				continue;
			}

			/* Data is not ready. Launch 'FPGAEmuHostThreadSuspend' again */
			ctx->host_thread_suspend_active = 1;
			if (pthread_create(&ctx->host_thread_suspend, NULL, FPGAEmuHostThreadSuspend, ctx))
				fatal("syscall 'read': could not create child thread");
			continue;
		}

		/* Kernel suspended in a 'waitpid' system call */
		if (FPGAKernelGetState(ctx, FPGAKernelWaitpid))
		{
			FPGAKernel *child;
			uint32_t pstatus;

			/* A zombie child is available to 'waitpid' it */
			child = FPGAKernelGetZombie(ctx, ctx->wakeup_pid);
			if (child)
			{
				/* Continue with 'waitpid' system call */
				pstatus = ctx->regs->ecx;
				ctx->regs->eax = child->pid;
				if (pstatus)
					mem_write(ctx->mem, pstatus, 4, &child->exit_code);
				FPGAKernelSetState(child, FPGAKernelFinished);

				fpga_sys_debug("syscall waitpid - continue (pid %d)\n", ctx->pid);
				fpga_sys_debug("  return=0x%x\n", ctx->regs->eax);
				FPGAKernelClearState(ctx, FPGAKernelSuspended | FPGAKernelWaitpid);
				continue;
			}

			/* No event available. Since this context won't wake up on its own, no
			 * 'FPGAEmuHostThreadSuspend' is needed. */
			continue;
		}

		/* Kernel suspended in a system call using a custom wake up check call-back
		 * function. NOTE: this is a new mechanism. It'd be nice if all other system
		 * calls started using it. It is nicer, since it allows for a check of wake up
		 * conditions together with the system call itself, without having distributed
		 * code for the implementation of a system call (e.g. 'read'). */
		if (FPGAKernelGetState(ctx, FPGAKernelCallback))
		{
			assert(ctx->can_wakeup_callback_func);
			if (ctx->can_wakeup_callback_func(ctx, ctx->can_wakeup_callback_data))
			{
				/* Set context status to 'running' again. */
				FPGAKernelClearState(ctx, FPGAKernelSuspended | FPGAKernelCallback);

				/* Call wake up function */
				if (ctx->wakeup_callback_func)
					ctx->wakeup_callback_func(ctx, ctx->wakeup_callback_data);

				/* Reset call-back info */
				ctx->wakeup_callback_func = NULL;
				ctx->wakeup_callback_data = NULL;
				ctx->can_wakeup_callback_func = NULL;
				ctx->can_wakeup_callback_data = NULL;
			}
			continue;
		}
	}


	/*
	 * LOOP 2
	 * Check list of all contexts for expired timers.
	 */
	for (ctx = self->context_list_head; ctx; ctx = ctx->context_list_next)
	{
		int sig[3] = { 14, 26, 27 };  /* SIGALRM, SIGVTALRM, SIGPROF */
		int i;

		/* If there is already a 'ke_host_thread_timer' running, do nothing. */
		if (ctx->host_thread_timer_active)
			continue;

		/* Check for any expired 'itimer': itimer_value < now
		 * In this case, send corresponding signal to process.
		 * Then calculate next 'itimer' occurrence: itimer_value = now + itimer_interval */
		for (i = 0; i < 3; i++ )
		{
			/* Timer inactive or not expired yet */
			if (!ctx->itimer_value[i] || ctx->itimer_value[i] > now)
				continue;

			/* Timer expired - send a signal.
			 * The target process might be suspended, so the host thread is canceled, and a new
			 * call to 'FPGAEmuProcessEvents' is scheduled. Since 'ke_process_events_mutex' is
			 * already locked, the thread-unsafe version of 'fpga_ctx_host_thread_suspend_cancel' is used. */
			FPGAKernelHostThreadSuspendCancelUnsafe(ctx);
			self->process_events_force = 1;
			fpga_sigset_add(&ctx->signal_mask_table->pending, sig[i]);

			/* Calculate next occurrence */
			ctx->itimer_value[i] = 0;
			if (ctx->itimer_interval[i])
				ctx->itimer_value[i] = now + ctx->itimer_interval[i];
		}

		/* Calculate the time when next wakeup occurs. */
		ctx->host_thread_timer_wakeup = 0;
		for (i = 0; i < 3; i++)
		{
			if (!ctx->itimer_value[i])
				continue;
			assert(ctx->itimer_value[i] >= now);
			if (!ctx->host_thread_timer_wakeup || ctx->itimer_value[i] < ctx->host_thread_timer_wakeup)
				ctx->host_thread_timer_wakeup = ctx->itimer_value[i];
		}

		/* If a new timer was set, launch ke_host_thread_timer' again */
		if (ctx->host_thread_timer_wakeup)
		{
			ctx->host_thread_timer_active = 1;
			if (pthread_create(&ctx->host_thread_timer, NULL, FPGAKernelHostThreadTimer, ctx))
				fatal("%s: could not create child thread", __FUNCTION__);
		}
	}


	/*
	 * LOOP 3
	 * Process pending signals in running contexts to launch signal handlers
	 */
	for (ctx = self->running_list_head; ctx; ctx = ctx->running_list_next)
	{
		FPGAKernelCheckSignalHandler(ctx);
	}

	
	/* Unlock */
	pthread_mutex_unlock(&self->process_events_mutex);
}


int FPGAEmuRun(Emu *self)
{
	FPGAEmu *emu = asFPGAEmu(self);
	FPGAKernel *kernel;

	/* Stop if there is no context running */
	if (emu->running_list_count <= 0)
		return FALSE;

	/* Run an instruction from every running process */
	for (kernel = emu->running_list_head; kernel; kernel = kernel->running_list_next)
		FPGAKernelExecute(kernel);

	/* Process list of suspended contexts */
	FPGAEmuProcessEvents(emu);

	/* Still running */
	return TRUE;
}


/* Search a context based on its PID */
FPGAKernel *FPGAEmuGetKernel(FPGAEmu *self, int pid)
{
	FPGAKernel *kernel;

	kernel = self->kernel_list_head;
	while (kernel && kernel->kid != pid)
		kernel = kernel->kernel_list_next;
	return kernel;
}


void FPGAEmuLoadKernelsFromConfig(FPGAEmu *self, struct config_t *config, char *section)
{
	FPGAKernel *kernel;
	struct fpga_loader_t *loader;

	char buf[MAX_STRING_SIZE];

	char *blif;
	char *imps;
	char *widths;
	char *lengths;
	char *heights;

	char *config_file_name;

	/* Get configuration file name for errors */
	config_file_name = config_get_file_name(config);

	/* Create new context */
	kernel = new(FPGAKernel, self);
	loader = kernel->loader;

	/* Executable */
	blif = config_read_string(config, section, "Blif", "");
	blif = str_set(NULL, blif);
	if (!*blif)
		fatal("%s: [%s]: invalid blif", config_file_name,
			section);

	/* Arguments */
	imps = config_read_string(config, section, "Implements", "");
	FPGAKernelSetSetNumImplements(kernel, imps);

	/* Environment variables */
	widths = config_read_string(config, section, "Widths", "");
	FPGAKernelAddImpsString(kernel, widths, WIDTH);
	lengths = config_read_string(config, section, "Lengths", "");
	FPGAKernelAddImpsString(kernel, lengths, LENGTH);
	heights = config_read_string(config, section, "Heights", "");
	FPGAKernelAddImpsString(kernel, heights, HEIGHT);

	/* Load executable */
	FPGAKernelLoadBlif(kernel, blif);
}

/*
 * Non-Class Functions
 */

void fpga_emu_init(void)
{
	/* Classes */
	CLASS_REGISTER(FPGAEmu);
	CLASS_REGISTER(FPGAKernel);

	/* Endian check */
	union
	{
		unsigned int as_uint;
		unsigned char as_uchar[4];
	} endian;
	endian.as_uint = 0x33221100;
	if (endian.as_uchar[0])
		fatal("%s: host machine is not little endian", __FUNCTION__);

	/* Host types */
	M2S_HOST_GUEST_MATCH(sizeof(long long), 8);
	M2S_HOST_GUEST_MATCH(sizeof(int), 4);
	M2S_HOST_GUEST_MATCH(sizeof(short), 2);

	/* Create fpga emulator */
	fpga_emu = new(FPGAEmu);

	/* Initialize */
	fpga_asm_init();
	fpga_uinst_init();

#ifdef HAVE_OPENGL
	/* GLUT */
	glut_init();
	/* GLEW */
	glew_init();
	/* GLU */
	glu_init();
#endif

	/* OpenGL */
	opengl_init();
}


/* Finalization */
void fpga_emu_done(void)
{

#ifdef HAVE_OPENGL
	glut_done();
	glew_done();
	glu_done();
#endif

	/* Finalize OpenGl */
	opengl_done();

	/* End */
	fpga_uinst_done();
	fpga_asm_done();

	/* Print system call summary */
	if (debug_status(fpga_sys_debug_category))
		fpga_sys_dump_stats(debug_file(fpga_sys_debug_category));

	/* Free emulator */
	delete(fpga_emu);
}

