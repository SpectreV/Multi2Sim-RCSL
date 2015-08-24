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

#include <arch/fpga/timing/fpga.h>
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

#include "kernel.h"
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

void FPGAEmuCreate(FPGAEmu *self) {
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

void FPGAEmuDestroy(FPGAEmu *self) {
	FPGAKernel *kernel;

	/* Finish all contexts */
	for (kernel = self->kernel_list_head; kernel; kernel = kernel->kernel_list_next)
		if (FPGAKernelGetState(kernel, FPGAKernelRunning))
			FPGAKernelFinish(kernel, 0);

	/* Free contexts */
	while (self->kernel_list_head)
		delete(self->kernel_list_head);

}

void FPGAEmuDump(Object *self, FILE *f) {
	FPGAKernel *kernel;
	FPGAEmu *emu = asFPGAEmu(self);

	/* Call parent */
	EmuDump(self, f);

	/* More */
	fprintf(f, "List of contexts (shows in any order)\n\n");
	DOUBLE_LINKED_LIST_FOR_EACH(emu, kernel, kernel)
		FPGAKernelDump(asObject(kernel), f);
}

void FPGAEmuDumpSummary(Emu *self, FILE *f) {
	FPGAEmu *emu = asFPGAEmu(self);

	/* Call parent */
	EmuDumpSummary(self, f);

	/* More statistics */
	fprintf(f, "Kernels = %d\n", emu->running_list_max);
	fprintf(f, "Memory = %lu\n", mem_max_mapped_space);
}

/* Schedule a call to 'FPGAEmuProcessEvents' */
void FPGAEmuProcessEventsSchedule(FPGAEmu *self) {
	pthread_mutex_lock(&self->process_events_mutex);
	self->process_events_force = 1;
	pthread_mutex_unlock(&self->process_events_mutex);
}

/* Check for events detected in spawned host threads, like waking up contexts or
 * sending signals.
 * The list is only processed if flag 'self->process_events_force' is set. */
void FPGAEmuProcessEvents(FPGAEmu *self) {
	FPGAKernel *kernel, *next;
	long long now = esim_real_time();

	/* Check if events need actually be checked. */
	pthread_mutex_lock(&self->process_events_mutex);
	if (!self->process_events_force) {
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
	for (kernel = self->suspended_list_head; kernel; kernel = next) {
		/* Save next */
		next = kernel->suspended_list_next;

		/* Kernel is suspended in 'nanosleep' system call. */
		if (FPGAKernelGetState(kernel, FPGAKernelNanosleep)) {
			unsigned int rmtp = kernel->regs->ecx;
			unsigned long long zero = 0;
			unsigned int sec, usec;
			unsigned long long diff;

			/* If 'FPGAEmuHostThreadSuspend' is still running for this context, do nothing. */
			if (kernel->host_thread_suspend_active)
				continue;

			/* Timeout expired */
			if (kernel->wakeup_time <= now) {
				if (rmtp)
					mem_write(kernel->mem, rmtp, 8, &zero);
				fpga_sys_debug("syscall 'nanosleep' - continue (pid %d)\n", kernel->pid);
				fpga_sys_debug("  return=0x%x\n", kernel->regs->eax);
				FPGAKernelClearState(kernel, FPGAKernelSuspended | FPGAKernelNanosleep);
				continue;
			}

			/* Kernel received a signal */
			if (kernel->signal_mask_table->pending & ~kernel->signal_mask_table->blocked) {
				if (rmtp) {
					diff = kernel->wakeup_time - now;
					sec = diff / 1000000;
					usec = diff % 1000000;
					mem_write(kernel->mem, rmtp, 4, &sec);
					mem_write(kernel->mem, rmtp + 4, 4, &usec);
				}
				kernel->regs->eax = -EINTR;
				fpga_sys_debug("syscall 'nanosleep' - interrupted by signal (pid %d)\n",
						kernel->pid);
				FPGAKernelClearState(kernel, FPGAKernelSuspended | FPGAKernelNanosleep);
				continue;
			}

			/* No event available, launch 'FPGAEmuHostThreadSuspend' again */
			kernel->host_thread_suspend_active = 1;
			if (pthread_create(&kernel->host_thread_suspend, NULL, FPGAEmuHostThreadSuspend,
					kernel))
				fatal("syscall 'poll': could not create child thread");
			continue;
		}

		/* Kernel suspended in 'rt_sigsuspend' system call */
		if (FPGAKernelGetState(kernel, FPGAKernelSigsuspend)) {
			/* Kernel received a signal */
			if (kernel->signal_mask_table->pending & ~kernel->signal_mask_table->blocked) {
				FPGAKernelCheckSignalHandlerIntr(kernel);
				kernel->signal_mask_table->blocked = kernel->signal_mask_table->backup;
				fpga_sys_debug("syscall 'rt_sigsuspend' - interrupted by signal (pid %d)\n",
						kernel->pid);
				FPGAKernelClearState(kernel, FPGAKernelSuspended | FPGAKernelSigsuspend);
				continue;
			}

			/* No event available. The context will never awake on its own, so no
			 * 'FPGAEmuHostThreadSuspend' is necessary. */
			continue;
		}

		/* Kernel suspended in 'poll' system call */
		if (FPGAKernelGetState(kernel, FPGAKernelPoll)) {
			uint32_t prevents = kernel->regs->ebx + 6;
			uint16_t revents = 0;
			struct fpga_file_desc_t *fd;
			struct pollfd host_fds;
			int err;

			/* If 'FPGAEmuHostThreadSuspend' is still running for this context, do nothing. */
			if (kernel->host_thread_suspend_active)
				continue;

			/* Get file descriptor */
			fd = fpga_file_desc_table_entry_get(kernel->file_desc_table, kernel->wakeup_fd);
			if (!fd)
				fatal("syscall 'poll': invalid 'wakeup_fd'");

			/* Kernel received a signal */
			if (kernel->signal_mask_table->pending & ~kernel->signal_mask_table->blocked) {
				FPGAKernelCheckSignalHandlerIntr(kernel);
				fpga_sys_debug("syscall 'poll' - interrupted by signal (pid %d)\n", kernel->pid);
				FPGAKernelClearState(kernel, FPGAKernelSuspended | FPGAKernelPoll);
				continue;
			}

			/* Perform host 'poll' call */
			host_fds.fd = fd->host_fd;
			host_fds.events = ((kernel->wakeup_events & 4) ? POLLOUT : 0)
					| ((kernel->wakeup_events & 1) ? POLLIN : 0);
			err = poll(&host_fds, 1, 0);
			if (err < 0)
				fatal("syscall 'poll': unexpected error in host 'poll'");

			/* POLLOUT event available */
			if (kernel->wakeup_events & host_fds.revents & POLLOUT) {
				revents = POLLOUT;
				mem_write(kernel->mem, prevents, 2, &revents);
				kernel->regs->eax = 1;
				fpga_sys_debug("syscall poll - continue (pid %d) - POLLOUT occurred in file\n",
						kernel->pid);
				fpga_sys_debug("  retval=%d\n", kernel->regs->eax);
				FPGAKernelClearState(kernel, FPGAKernelSuspended | FPGAKernelPoll);
				continue;
			}

			/* POLLIN event available */
			if (kernel->wakeup_events & host_fds.revents & POLLIN) {
				revents = POLLIN;
				mem_write(kernel->mem, prevents, 2, &revents);
				kernel->regs->eax = 1;
				fpga_sys_debug("syscall poll - continue (pid %d) - POLLIN occurred in file\n",
						kernel->pid);
				fpga_sys_debug("  retval=%d\n", kernel->regs->eax);
				FPGAKernelClearState(kernel, FPGAKernelSuspended | FPGAKernelPoll);
				continue;
			}

			/* Timeout expired */
			if (kernel->wakeup_time && kernel->wakeup_time < now) {
				revents = 0;
				mem_write(kernel->mem, prevents, 2, &revents);
				fpga_sys_debug("syscall poll - continue (pid %d) - time out\n", kernel->pid);
				fpga_sys_debug("  return=0x%x\n", kernel->regs->eax);
				FPGAKernelClearState(kernel, FPGAKernelSuspended | FPGAKernelPoll);
				continue;
			}

			/* No event available, launch 'FPGAEmuHostThreadSuspend' again */
			kernel->host_thread_suspend_active = 1;
			if (pthread_create(&kernel->host_thread_suspend, NULL, FPGAEmuHostThreadSuspend,
					kernel))
				fatal("syscall 'poll': could not create child thread");
			continue;
		}

		/* Kernel suspended in a 'write' system call  */
		if (FPGAKernelGetState(kernel, FPGAKernelWrite)) {
			struct fpga_file_desc_t *fd;
			int count, err;
			uint32_t pbuf;
			void *buf;
			struct pollfd host_fds;

			/* If 'FPGAEmuHostThreadSuspend' is still running for this context, do nothing. */
			if (kernel->host_thread_suspend_active)
				continue;

			/* Kernel received a signal */
			if (kernel->signal_mask_table->pending & ~kernel->signal_mask_table->blocked) {
				FPGAKernelCheckSignalHandlerIntr(kernel);
				fpga_sys_debug("syscall 'write' - interrupted by signal (pid %d)\n", kernel->pid);
				FPGAKernelClearState(kernel, FPGAKernelSuspended | FPGAKernelWrite);
				continue;
			}

			/* Get file descriptor */
			fd = fpga_file_desc_table_entry_get(kernel->file_desc_table, kernel->wakeup_fd);
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
				pbuf = kernel->regs->ecx;
				count = kernel->regs->edx;
				buf = xmalloc(count);
				mem_read(kernel->mem, pbuf, count, buf);

				count = write(fd->host_fd, buf, count);
				if (count < 0)
					fatal("syscall 'write': unexpected error in host 'write'");

				kernel->regs->eax = count;
				free(buf);

				fpga_sys_debug("syscall write - continue (pid %d)\n", kernel->pid);
				fpga_sys_debug("  return=0x%x\n", kernel->regs->eax);
				FPGAKernelClearState(kernel, FPGAKernelSuspended | FPGAKernelWrite);
				continue;
			}

			/* Data is not ready to be written - launch 'FPGAEmuHostThreadSuspend' again */
			kernel->host_thread_suspend_active = 1;
			if (pthread_create(&kernel->host_thread_suspend, NULL, FPGAEmuHostThreadSuspend,
					kernel))
				fatal("syscall 'write': could not create child thread");
			continue;
		}

		/* Kernel suspended in 'read' system call */
		if (FPGAKernelGetState(kernel, FPGAKernelRead)) {
			struct fpga_file_desc_t *fd;
			uint32_t pbuf;
			int count, err;
			void *buf;
			struct pollfd host_fds;

			/* If 'FPGAEmuHostThreadSuspend' is still running for this context, do nothing. */
			if (kernel->host_thread_suspend_active)
				continue;

			/* Kernel received a signal */
			if (kernel->signal_mask_table->pending & ~kernel->signal_mask_table->blocked) {
				FPGAKernelCheckSignalHandlerIntr(kernel);
				fpga_sys_debug("syscall 'read' - interrupted by signal (pid %d)\n", kernel->pid);
				FPGAKernelClearState(kernel, FPGAKernelSuspended | FPGAKernelRead);
				continue;
			}

			/* Get file descriptor */
			fd = fpga_file_desc_table_entry_get(kernel->file_desc_table, kernel->wakeup_fd);
			if (!fd)
				fatal("syscall 'read': invalid 'wakeup_fd'");

			/* Check if data is ready in file by polling it */
			host_fds.fd = fd->host_fd;
			host_fds.events = POLLIN;
			err = poll(&host_fds, 1, 0);
			if (err < 0)
				fatal("syscall 'read': unexpected error in host 'poll'");

			/* If data is ready, perform host 'read' call and wake up */
			if (host_fds.revents) {
				pbuf = kernel->regs->ecx;
				count = kernel->regs->edx;
				buf = xmalloc(count);

				count = read(fd->host_fd, buf, count);
				if (count < 0)
					fatal("syscall 'read': unexpected error in host 'read'");

				kernel->regs->eax = count;
				mem_write(kernel->mem, pbuf, count, buf);
				free(buf);

				fpga_sys_debug("syscall 'read' - continue (pid %d)\n", kernel->pid);
				fpga_sys_debug("  return=0x%x\n", kernel->regs->eax);
				FPGAKernelClearState(kernel, FPGAKernelSuspended | FPGAKernelRead);
				continue;
			}

			/* Data is not ready. Launch 'FPGAEmuHostThreadSuspend' again */
			kernel->host_thread_suspend_active = 1;
			if (pthread_create(&kernel->host_thread_suspend, NULL, FPGAEmuHostThreadSuspend,
					kernel))
				fatal("syscall 'read': could not create child thread");
			continue;
		}

		/* Kernel suspended in a 'waitpid' system call */
		if (FPGAKernelGetState(kernel, FPGAKernelWaitpid)) {
			FPGAKernel *child;
			uint32_t pstatus;

			/* A zombie child is available to 'waitpid' it */
			child = FPGAKernelGetZombie(kernel, kernel->wakeup_pid);
			if (child) {
				/* Continue with 'waitpid' system call */
				pstatus = kernel->regs->ecx;
				kernel->regs->eax = child->pid;
				if (pstatus)
					mem_write(kernel->mem, pstatus, 4, &child->exit_code);
				FPGAKernelSetState(child, FPGAKernelFinished);

				fpga_sys_debug("syscall waitpid - continue (pid %d)\n", kernel->pid);
				fpga_sys_debug("  return=0x%x\n", kernel->regs->eax);
				FPGAKernelClearState(kernel, FPGAKernelSuspended | FPGAKernelWaitpid);
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
		if (FPGAKernelGetState(kernel, FPGAKernelCallback)) {
			assert(kernel->can_wakeup_callback_func);
			if (kernel->can_wakeup_callback_func(kernel, kernel->can_wakeup_callback_data)) {
				/* Set context status to 'running' again. */
				FPGAKernelClearState(kernel, FPGAKernelSuspended | FPGAKernelCallback);

				/* Call wake up function */
				if (kernel->wakeup_callback_func)
					kernel->wakeup_callback_func(kernel, kernel->wakeup_callback_data);

				/* Reset call-back info */
				kernel->wakeup_callback_func = NULL;
				kernel->wakeup_callback_data = NULL;
				kernel->can_wakeup_callback_func = NULL;
				kernel->can_wakeup_callback_data = NULL;
			}
			continue;
		}
	}

	/*
	 * LOOP 2
	 * Check list of all contexts for expired timers.
	 */
	for (kernel = self->context_list_head; kernel; kernel = kernel->context_list_next) {
		int sig[3] = { 14, 26, 27 }; /* SIGALRM, SIGVTALRM, SIGPROF */
		int i;

		/* If there is already a 'ke_host_thread_timer' running, do nothing. */
		if (kernel->host_thread_timer_active)
			continue;

		/* Check for any expired 'itimer': itimer_value < now
		 * In this case, send corresponding signal to process.
		 * Then calculate next 'itimer' occurrence: itimer_value = now + itimer_interval */
		for (i = 0; i < 3; i++) {
			/* Timer inactive or not expired yet */
			if (!kernel->itimer_value[i] || kernel->itimer_value[i] > now)
				continue;

			/* Timer expired - send a signal.
			 * The target process might be suspended, so the host thread is canceled, and a new
			 * call to 'FPGAEmuProcessEvents' is scheduled. Since 'ke_process_events_mutex' is
			 * already locked, the thread-unsafe version of 'fpga_ctx_host_thread_suspend_cancel' is used. */
			FPGAKernelHostThreadSuspendCancelUnsafe(kernel);
			self->process_events_force = 1;
			fpga_sigset_add(&kernel->signal_mask_table->pending, sig[i]);

			/* Calculate next occurrence */
			kernel->itimer_value[i] = 0;
			if (kernel->itimer_interval[i])
				kernel->itimer_value[i] = now + kernel->itimer_interval[i];
		}

		/* Calculate the time when next wakeup occurs. */
		kernel->host_thread_timer_wakeup = 0;
		for (i = 0; i < 3; i++) {
			if (!kernel->itimer_value[i])
				continue;
			assert(kernel->itimer_value[i] >= now);
			if (!kernel->host_thread_timer_wakeup
					|| kernel->itimer_value[i] < kernel->host_thread_timer_wakeup)
				kernel->host_thread_timer_wakeup = kernel->itimer_value[i];
		}

		/* If a new timer was set, launch ke_host_thread_timer' again */
		if (kernel->host_thread_timer_wakeup) {
			kernel->host_thread_timer_active = 1;
			if (pthread_create(&kernel->host_thread_timer, NULL, FPGAKernelHostThreadTimer, kernel))
				fatal("%s: could not create child thread", __FUNCTION__);
		}
	}

	/*
	 * LOOP 3
	 * Process pending signals in running contexts to launch signal handlers
	 */
	for (kernel = self->running_list_head; kernel; kernel = kernel->running_list_next) {
		FPGAKernelCheckSignalHandler(kernel);
	}

	/* Unlock */
	pthread_mutex_unlock(&self->process_events_mutex);
}

int FPGAEmuRun(Emu *self) {
	FPGAEmu *emu = asFPGAEmu(self);
	FPGAKernel *kernel;

	/* Stop if there is no kernel running */
	if (emu->running_list_count <= 0)
		return FALSE;

	/* Run an instruction from every running process */
	for (kernel = emu->running_list_head; kernel; kernel = kernel->running_list_next)
		FPGAKernelProceed(kernel);

	/* Process list of suspended contexts */
	FPGAEmuProcessEvents(emu);

	/* Still running */
	return TRUE;
}

/* Search a context based on its PID */
FPGAKernel *FPGAEmuGetKernel(FPGAEmu *self, int pid) {
	FPGAKernel *kernel;

	kernel = self->kernel_list_head;
	while (kernel && kernel->kid != pid)
		kernel = kernel->kernel_list_next;
	return kernel;
}

void FPGAEmuLoadKernelsFromConfig(FPGAEmu *self, struct config_t *config, char *section) {
	FPGAKernel *kernel;
	struct fpga_loader_t *loader;

	char buf[MAX_STRING_SIZE];

	char *blif;
	char *imps;
	char *widths;
	char *lengths;
	char *heights;
	char *cwd;

	char *kernel_name;
	char *folding;

	char *config_file_name;

	/* Get configuration file name for errors */
	config_file_name = config_get_file_name(config);

	/* Create new kernel */
	kernel = new(FPGAKernel, self);
	loader = kernel->loader;

	/* Executable */
	blif = config_read_string(config, section, "Blif", "");
	blif = str_set(NULL, blif);
	if (!*blif)
		fatal("%s: [%s]: invalid blif", config_file_name, section);

	/* Current working directory */
	cwd = config_read_string(config, section, "Cwd", "");
	if (*cwd)
		loader->cwd = str_set(NULL, cwd);
	else {
		/* Get current directory */
		loader->cwd = getcwd(buf, sizeof buf);
		if (!loader->cwd)
			panic("%s: buffer too small", __FUNCTION__);

		/* Duplicate string */
		loader->cwd = str_set(NULL, loader->cwd);
	}

	/* Arguments */
	imps = config_read_string(config, section, "Implements", "");
	FPGAKernelSetNumImplements(kernel, imps);

	kernel_name = config_read_string(config, section, "Name", "");
	FPGAKernelSetName(kernel, kernel_name);

	folding = config_read_string(config, section, "Folding", "True");
	FPGAKernelSetFolding(kernel, folding);

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

void fpga_emu_init(void) {
	/* Classes */
	CLASS_REGISTER(FPGAEmu);
	CLASS_REGISTER(FPGAKernel);

	/* Endian check */
	union {
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
void fpga_emu_done(void) {

#ifdef HAVE_OPENGL
	glut_done();
	glew_done();
	glu_done();
#endif

	/* Finalize OpenGl */
	opengl_done();

	/* Print system call summary
	 if (debug_status(fpga_sys_debug_category))
	 fpga_sys_dump_stats(debug_file(fpga_sys_debug_category));*/

	/* Free emulator */
	delete(fpga_emu);
}

