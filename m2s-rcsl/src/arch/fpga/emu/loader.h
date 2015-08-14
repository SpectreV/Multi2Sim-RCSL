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

#ifndef ARCH_FPGA_EMU_LOADER_H
#define ARCH_FPGA_EMU_LOADER_H

/* Forward type declarations */
struct config_t;
struct elf_file_t;

typedef enum {
	WIDTH, LENGTH, HEIGHT
} implement_param;

/*
 * Class 'FPGAKernel'
 * Additional Functions
 */

void FPGAKernelAddArgsVector(FPGAKernel *self, int argc, char **argv);
void FPGAKernelAddArgsString(FPGAKernel *self, char *args);
void FPGAKernelSetNumImplements(FPGAKernel *self, char *num_implements);
void FPGAKernelAddImpsString(FPGAKernel *self, char *imps, implement_param type);

void FPGAKernelLoadELFSections(FPGAKernel *self, struct elf_file_t *elf_file);
void FPGAKernelLoadInterp(FPGAKernel *self);
void FPGAKernelLoadProgramHeaders(FPGAKernel *self);
unsigned int FPGAKernelLoadAV(FPGAKernel *self, unsigned int where);
void FPGAKernelLoadStack(FPGAKernel *self);

void FPGAKernelLoadExe(FPGAKernel *self, char *exe);
void FPGAKernelGetFullPath(FPGAKernel *self, char *file_name, char *full_path, int size);



/*
 * Object 'fpga_loader_t'
 */

struct fpga_loader_t
{
	/* Number of extra contexts using this loader */
	int num_implements;

	/* Program data */
	struct elf_file_t *elf_file;
	struct linked_list_t *widths;
	struct linked_list_t *lengths;
	struct linked_list_t *heights;

	char *blif;  /* Executable file name */

	char *stdin_file;  /* File name for stdin */
	char *stdout_file;  /* File name for stdout */

	/* Stack */
	unsigned int stack_base;
	unsigned int stack_top;
	unsigned int stack_size;
	unsigned int environ_base;

	/* Lowest address initialized */
	unsigned int bottom;

	/* Program entries */
	unsigned int prog_entry;
	unsigned int interp_prog_entry;

	/* Program headers */
	unsigned int phdt_base;
	unsigned int phdr_count;

	/* Random bytes */
	unsigned int at_random_addr;
	unsigned int at_random_addr_holder;
};


struct fpga_loader_t *fpga_loader_create(void);
void fpga_loader_free(struct fpga_loader_t *loader);

struct fpga_loader_t *fpga_loader_link(struct fpga_loader_t *loader);
void fpga_loader_unlink(struct fpga_loader_t *loader);




/*
 * Public
 */

#define fpga_loader_debug(...) debug(fpga_loader_debug_category, __VA_ARGS__)
extern int fpga_loader_debug_category;

extern char *fpga_loader_help;


#endif

