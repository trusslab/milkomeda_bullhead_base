/*
   Copyright (c) 2018, University of California, Irvine

   Authors: Zhihao Yao, Ardalan Amiri Sani

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

/*
 * Based on: https://cboard.cprogramming.com/linux-programming/112053-using-shared-libraries-dlopen-plus-dlsym.html
 */

#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <link.h>
#include <sched.h>
#include <android/dlext.h>

#include <sys/types.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/audit.h>

#include "shield.h"
#include "prints_android.h"

#if defined(__aarch64__)

#include <GLES2/gl2.h>
#include <GLES2/gl2ext.h>
#include <EGL/egl.h>
#include <EGL/eglext.h>

#define __NR_getaddrdom		279
#define __NR_activatedom	280
#define __NR_destroydom		281
#define __NR_enterdom		282
#define __NR_exitdom		283

unsigned long long addr1, addr2, addr3;
unsigned long libt_start, libt_end;
#define LIBC_SECURE_SIZE	0xcd000

/* Modified from: https://linux.die.net/man/3/dl_iterate_phdr */
/* TODO: remove. Just for debugging. */

void get_maps(void)
{
	FILE *fp = fopen("/proc/self/maps", "r");
	char line[2048];
	if (fp == nullptr) 
		return;
	while(fgets(line, 2048, fp) != NULL) {
		PRINTFM("%s", line);
	}
}

struct check_lib_struct {
	char *lib_name;
	uint64_t start_addr;
	uint64_t end_addr;
};

/* Modified from: https://linux.die.net/man/3/dl_iterate_phdr */
/* TODO: remove. Just for debugging. */

size_t dummy_size;

/* Modified from: https://linux.die.net/man/3/dl_iterate_phdr */
static int check_lib_addr(struct dl_phdr_info *info, size_t size, void *data)
{
	int j;
	struct check_lib_struct *cdata = (struct check_lib_struct *) data;
	
	if (!(info->dlpi_name && (strcmp(info->dlpi_name, cdata->lib_name) == 0))) {
		return 0;
	}
	dummy_size = size;

	/* TODO: Given that we check all the segments next, is this check still needed? */
	if ((uint64_t) info->dlpi_addr < cdata->start_addr ||
		    (uint64_t) info->dlpi_addr >= cdata->end_addr) {
			PRINTF_ERR("Library base address not in the domain: %s: address=%10p\n",
				cdata->lib_name, (void *) (info->dlpi_addr));
			exit(-1);
			return -1;
	}

	for (j = 0; j < info->dlpi_phnum; j++) {
		if ((uint64_t) (info->dlpi_addr + info->dlpi_phdr[j].p_vaddr) < cdata->start_addr ||
		    ((uint64_t) (info->dlpi_addr + info->dlpi_phdr[j].p_vaddr + info->dlpi_phdr[j].p_memsz) >= cdata->end_addr)) {
			PRINTF_ERR("Segment address not in the domain: %s header %2d: address=%10p (%10p, %10p), size = %#llx\n",
				cdata->lib_name, j, (void *) (info->dlpi_addr + info->dlpi_phdr[j].p_vaddr),
				(void *) info->dlpi_addr, (void *) info->dlpi_phdr[j].p_vaddr,
				(unsigned long long) info->dlpi_phdr[j].p_memsz);
			exit(-1);
			return -1;
		}
	}
	return 0;
}

typedef long (*dom_entry_proc)(uint64_t, uint64_t, uint64_t, uint64_t,
			       uint64_t, uint64_t, uint64_t, uint64_t);

struct shield_addr_info {
	void *hint_addr;
	size_t load_size;
};

static struct link_map *milkomeda_dlopen_ext(const char *filename, int flags,
					     const android_dlextinfo *ext_info)
{
	struct link_map *lib;
	struct shield_addr_info *shield_info = (struct shield_addr_info *) ext_info->reserved_addr;

	lib = (struct link_map *) android_dlopen_ext(filename, flags, ext_info);
	shield_info->hint_addr = (void *) ((unsigned long long) shield_info->hint_addr +
						shield_info->load_size);

	return lib;
}

char domain_print[1024] = "";

/* FIXME: use uint64_t for return type here. */
static long enter_domain(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4,
			 uint64_t arg5, uint64_t arg6, uint64_t arg7)
{
	long ret = 0;

	asm volatile("mov     x8, 282;" /* syscall number: __NR_enterdom */
		     "mov     x1, %[arg1];"
		     "mov     x2, %[arg2];"
		     "mov     x3, %[arg3];"
		     "mov     x4, %[arg4];"
		     "mov     x5, %[arg5];"
		     "mov     x6, %[arg6];"
		     "mov     x7, %[arg7];"
		     "svc     #0;"
		     "mov     %[ret], x1;"
		     :[ret] "=r" (ret)
		     :[arg1] "r" (arg1), [arg2] "r" (arg2), [arg3] "r" (arg3), [arg4] "r" (arg4),
		      [arg5] "r" (arg5), [arg6] "r" (arg6), [arg7] "r" (arg7)
		     :"x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8");

	PRINTF_ERR("%s\n", domain_print);

	return ret;
}

extern void *gl_stub_p;
extern void *gl_stub_long_p;
void *gl_stub_p_v3;
void *gl_stub_long_p_v3;

typedef long (*handle_gl_call_proc)(uint64_t, uint64_t, uint64_t, uint64_t,
		    uint64_t, uint64_t, uint64_t, uint64_t,
		    uint64_t, uint64_t, uint64_t, uint64_t,
		    uint64_t, uint64_t, uint64_t, uint64_t);
long (*handle_gl_call)(uint64_t api, uint64_t arg1, uint64_t arg2, uint64_t arg3,
		    uint64_t arg4, uint64_t arg5, uint64_t arg6, uint64_t arg7,
		    uint64_t arg8, uint64_t arg9, uint64_t arg10, uint64_t arg11,
		    uint64_t arg12, uint64_t arg13, uint64_t arg14, uint64_t arg15);

bool bottom_half_done = false;

int shield_bottom_half_one(void);
int shield_bottom_half_two(void);
int gl_op_count = 0;

uint64_t gl_stub(uint64_t gl_api, uint64_t arg1, uint64_t arg2, uint64_t arg3,
		 uint64_t arg4, uint64_t arg5)
{
	long ret;

	PRINTF_ERR("gl_api = %#lx\n", (unsigned long) gl_api);

	if (!bottom_half_done) {
		if (gl_op_count < 1) {
			ret = (long) (*handle_gl_call)(gl_api, arg1, arg2, arg3,
					arg4, arg5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
			gl_op_count++;
			goto exit;
		}
		shield_bottom_half_two();
		bottom_half_done = true;
	}

	ret = enter_domain(DOM_OP_GL, gl_api, arg1, arg2, arg3, arg4, arg5);

exit:	
	PRINTF_ERR("ret = %d\n", (int) ret);
	return (uint64_t) ret;
}

uint64_t gl_stub_long(uint64_t gl_api, uint64_t arg1, uint64_t arg2, uint64_t arg3,
		      uint64_t arg4, uint64_t arg5, uint64_t arg6, uint64_t arg7,
		      uint64_t arg8, uint64_t arg9, uint64_t arg10, uint64_t arg11,
		      uint64_t arg12, uint64_t arg13, uint64_t arg14, uint64_t arg15)
{
	long ret;
	uint64_t args[11];

	PRINTF_ERR("gl_api = %#lx\n", (unsigned long) gl_api);

	if (!bottom_half_done) {
		if (gl_op_count < 1) {
			ret = (long) handle_gl_call(gl_api, arg1, arg2, arg3, arg4, arg5, arg6,
				arg7, arg8, arg9, arg10, arg11, arg12, arg13, arg14, arg15);
			gl_op_count++;
			goto exit;
		}
		shield_bottom_half_two();
		bottom_half_done = true;
	}

	args[0] = arg5;
	args[1] = arg6;
	args[2] = arg7;
	args[3] = arg8;
	args[4] = arg9;
	args[5] = arg10;
	args[6] = arg11;
	args[7] = arg12;
	args[8] = arg13;
	args[9] = arg14;
	args[10] = arg15;

	ret = enter_domain(DOM_OP_GL_LONG, gl_api, arg1, arg2, arg3, arg4, (uint64_t) args);

exit:
	PRINTF_ERR("ret = %d\n", (int) ret);
	return (uint64_t) ret;
}

void set_up_domain_entry_stubs_one(void)
{
	gl_stub_p = (void *) gl_stub;
	gl_stub_long_p = (void *) gl_stub_long;
	gl_stub_p_v3 = (void *) gl_stub;
	gl_stub_long_p_v3 = (void *) gl_stub_long;
}

#define NUM_GLIBS	100
#define NUM_OLIBS	100

char *glibs[NUM_GLIBS];
char *olibs[NUM_OLIBS];

void *stack_mem = NULL;
uint64_t start_addr = 0, end_addr = 0, entry_addr = 0;

int shield_bottom_half_two(void)
{

	if (syscall(__NR_activatedom, start_addr, entry_addr, stack_mem, STACK_MEM_SIZE, NUM_STACKS)) {
		PRINTF_ERR("Could not activate the domain\n");
		return -1;
	}

	
	long dom_ret = enter_domain(DOM_OP_SET_DOMAIN_PARAMS, 0, (uint64_t) domain_print, 0, 0, 0, 0);
	if (dom_ret < 0) {
		PRINTF_ERR("Could not set up the domain params\n");
		exit(-1);
	}

    	PRINTFM("Domain enabled\n");
	
	/* For convenience of compatibility with existing code */

	return 0;
}

int set_up_milkomeda_shield(void) 
{
	struct link_map *lib;
	dom_entry_proc dom_entry;
	int i, j;
	android_dlextinfo ext_info;
	struct shield_addr_info shield_info;
	__u64 pr_code_start;
	__u64 pr_code_end;
	struct check_lib_struct cdata;

	syscall(__NR_getaddrdom, &start_addr, &end_addr);
	PRINTF_ERR("start_addr = %#lx\n", (unsigned long) start_addr);
	PRINTF_ERR("end_addr = %#lx\n", (unsigned long) end_addr);

	j = 0;

	olibs[j++] = (char *) "/system/lib65/libLLVM.so";
	olibs[j++] = (char *) "/system/lib65/libart.so";
	olibs[j++] = (char *) "/system/lib65/libsigchain.so";
	olibs[j++] = (char *) "/system/lib65/liblz4.so";
	olibs[j++] = (char *) "/system/lib65/libandroid.so";
	olibs[j++] = (char *) "/system/lib65/libcamera2ndk.so";
	olibs[j++] = (char *) "/system/lib65/libjnigraphics.so";
	olibs[j++] = (char *) "/system/lib65/libmediandk.so";
	olibs[j++] = (char *) "/system/lib65/libmediadrm.so";
	olibs[j++] = (char *) "/system/lib65/libOpenMAXAL.so";
	olibs[j++] = (char *) "/system/lib65/libOpenSLES.so";
	olibs[j++] = (char *) "/system/lib65/libwebviewchromium_plat_support.so";
	olibs[j++] = (char *) "/system/lib64/hw/memtrack.msm8992.so";
	olibs[j++] = (char *) "/system/lib65/libjavacore.so";
	olibs[j++] = (char *) "/system/lib65/libopenjdk.so";
	olibs[j++] = (char *) "/system/lib65/libart-compiler.so";
	olibs[j++] = (char *) "/system/lib65/libmedia_jni.so";
	olibs[j++] = (char *) "/system/lib65/libffmpeg_extractor.so";
	olibs[j++] = (char *) "/system/lib65/libjavacrypto.so";
	olibs[j++] = (char *) "/system/lib65/libcompiler_rt.so";
	olibs[j++] = (char *) "/system/lib65/libjnigraphics.so";
	olibs[j++] = (char *) "/system/lib65/libwebviewchromium_loader.so";
	olibs[j++] = (char *) "/data/local/lib64/libGLESv1_CM.so";
	olibs[j++] = (char *) "/data/local/lib64/libEGL.so";
	olibs[j++] = (char *) "/system/lib65/libGLESv2.so";
	olibs[j++] = (char *) "/data/app/com.android.gles3jni-1/lib/arm64/libgles3jni.so";
	olibs[j++] = (char *) "libRS.so";

	/* FIXME: use NUM_OLIBS for bound, and not j */
	for (i = 0; i < j; i++) {
		lib = (struct link_map *) dlopen(olibs[i], RTLD_NOW | RTLD_NODELETE);
		if (!lib) {
  			PRINTF_ERR("Couldn't open shared lib. Error: %s\n", dlerror());
  			return -1;
		}
	}

	lib = (struct link_map *) dlopen("/data/local/lib64/libGLESv3.so",
					RTLD_NOW | RTLD_NODELETE);
	if (!lib) {
  		PRINTF_ERR("Couldn't open shared lib. Error: %s\n", dlerror());
  		return -1;
	}

	gl_stub_p_v3 = (void *) dlsym(lib, "gl_stub_p");
	if (!gl_stub_p_v3) {
  		PRINTF_ERR("Couldn't find the gl_stub_p symbol in libGLESv3. Error: %s\n",
				dlerror());
		return -1;
	}

	gl_stub_long_p_v3 = (void *) dlsym(lib, "gl_stub_long_p");
	if (!gl_stub_long_p_v3) {
  		PRINTF_ERR("Couldn't find the gl_stub_long_p symbol in libGLESv3. Error: %s\n",
				dlerror());
		return -1;
	}

	memset(&ext_info, 0x0, sizeof(ext_info));
	ext_info.flags |= 0x400;
	ext_info.reserved_addr = &shield_info;
	shield_info.hint_addr = (void *) start_addr;

	/* allocate secure stack */
	stack_mem = mmap(shield_info.hint_addr, STACK_MEM_SIZE,
			PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
			-1, 0);
	if (stack_mem != shield_info.hint_addr) {
		PRINTF_ERR("Could not allocate the secure stack or address "
			   "wrong (%p)\n", stack_mem);
		return -1;
	}
	memset(stack_mem, 0x0, STACK_MEM_SIZE);
	shield_info.hint_addr = (void *) ((unsigned long long) shield_info.hint_addr +
						STACK_MEM_SIZE);

	cdata.start_addr = start_addr;
	cdata.end_addr = end_addr;

	/* FIXME: libt does some mmaps at load time. Either disable them or make sure they are within
	 * the domain memory */
	cdata.lib_name = (char *) "/data/local/lib64/libt.so";
	lib = milkomeda_dlopen_ext(cdata.lib_name, RTLD_NOW | RTLD_NODELETE, &ext_info);
	if (!lib) {
  		PRINTF_ERR("Couldn't open shared libt.so. Error: %s\n", dlerror());
  		return -1;
	}
	/* verify that the lib is within the domain address range. */
	dl_iterate_phdr(check_lib_addr, &cdata);

	/* FIXME: how about these graphics libs? done. */

	j = 0;
	glibs[j++] = (char *) "/vendor/lib65/libgsl.so";
	glibs[j++] = (char *) "/vendor/lib65/libadreno_utils.so";
	glibs[j++] = (char *) "/vendor/lib65/libllvm-glnext.so";
	glibs[j++] = (char *) "/vendor/lib64/egl/libGLESv2_adreno.so";
	glibs[j++] = (char *) "/vendor/lib65/egl/libEGL_adreno.so";
	glibs[j++] = (char *) "/vendor/lib65/egl/libGLESv1_CM_adreno.so";
	glibs[j++] = (char *) "/vendor/lib65/egl/eglSubDriverAndroid.so";
	glibs[j++] = (char *) "/system/lib65/hw/tralloc.msm8992.so";
	glibs[j++] = (char *) "/system/lib65/litgui.so";
	glibs[j++] = (char *) "/data/local/lib64/libc++_shared.so";
	glibs[j++] = (char *) "/data/local/lib64/libbase.cr.so";
	glibs[j++] = (char *) "/data/local/lib64/libgles2_utils.cr.so";
	glibs[j++] = (char *) "/data/local/lib64/libmojo_public_system.cr.so";
	glibs[j++] = (char *) "/data/local/lib64/libmojo_public_system_cpp.cr.so";
	glibs[j++] = (char *) "/data/local/lib64/libicuuc.cr.so";
	glibs[j++] = (char *) "/data/local/lib64/libfreetype_harfbuzz.cr.so";
	glibs[j++] = (char *) "/data/local/lib64/libskia.cr.so";
	glibs[j++] = (char *) "/data/local/lib64/libcolor_space.cr.so";
	glibs[j++] = (char *) "/data/local/lib64/libgeometry.cr.so";
	glibs[j++] = (char *) "/data/local/lib64/libgeometry_skia.cr.so";
	glibs[j++] = (char *) "/data/local/lib64/libgfx_switches.cr.so";
	glibs[j++] = (char *) "/data/local/lib64/libanimation.cr.so";
	glibs[j++] = (char *) "/data/local/lib64/libcodec.cr.so";
	glibs[j++] = (char *) "/data/local/lib64/librange.cr.so";
	glibs[j++] = (char *) "/data/local/lib64/libicui18n.cr.so";
	glibs[j++] = (char *) "/data/local/lib64/libbase_i18n.cr.so";
	glibs[j++] = (char *) "/data/local/lib64/libcc_base.cr.so";
	glibs[j++] = (char *) "/data/local/lib64/libcc_debug.cr.so";
	glibs[j++] = (char *) "/data/local/lib64/libcc_paint.cr.so";
	glibs[j++] = (char *) "/data/local/lib64/libgfx.cr.so";
	glibs[j++] = (char *) "/data/local/lib64/libprotobuf_lite.cr.so";
	glibs[j++] = (char *) "/data/local/lib64/libgl_wrapper.cr.so";
	glibs[j++] = (char *) "/data/local/lib64/libgl_init.cr.so";
	glibs[j++] = (char *) "/data/local/lib64/libmessage_support.cr.so";
	glibs[j++] = (char *) "/data/local/lib64/libbindings.cr.so";
	glibs[j++] = (char *) "/data/local/lib64/libipc_mojom_shared.cr.so";
	glibs[j++] = (char *) "/data/local/lib64/libipc_mojom.cr.so";
	glibs[j++] = (char *) "/data/local/lib64/libipc.cr.so";
	glibs[j++] = (char *) "/data/local/lib64/libgfx_ipc_geometry.cr.so";
	glibs[j++] = (char *) "/data/local/lib64/libgfx_ipc_color.cr.so";
	glibs[j++] = (char *) "/data/local/lib64/libipc.cr.so";
	glibs[j++] = (char *) "/data/local/lib64/libmessage_support.cr.so";
	glibs[j++] = (char *) "/data/local/lib64/libgfx_ipc.cr.so";
	glibs[j++] = (char *) "/data/local/lib64/libgfx_ipc_geometry.cr.so";
	glibs[j++] = (char *) "/data/local/lib64/liburl.cr.so";
	glibs[j++] = (char *) "/data/local/lib64/liburl_ipc.cr.so";
	glibs[j++] = (char *) "/data/local/lib64/libgpu.cr.so";
	glibs[j++] = (char *) "/data/local/lib64/libEGL_Secure.so";
	glibs[j++] = (char *) "/data/local/lib64/libGLESv2_Secure.so";

	/* FIXME: use NUM_GLIBS for bound, and not j */
	for (i = 0; i < j; i++) {
		cdata.lib_name = glibs[i];
		/* FIXME */
		lib = milkomeda_dlopen_ext(glibs[i], RTLD_NOW, &ext_info);
		if (!lib) {
  			PRINTF_ERR("Couldn't open shared %s. Error: %s\n", glibs[i], dlerror());
  			return -1;
		}
		/* FIXME */
		/* verify that the lib is within the domain address range. */
	}

	handle_gl_call = (handle_gl_call_proc) dlsym(lib, "handle_gl_call");
	if (!handle_gl_call) {
  		PRINTF_ERR("Couldn't find the handle_gl_call symbol. Error: %s\n", dlerror());
		return -1;
	}

	cdata.lib_name = (char *) "/data/local/lib64/libmilkomeda_shim.so";
	lib = milkomeda_dlopen_ext(cdata.lib_name, RTLD_NOW | RTLD_NODELETE, &ext_info);
	if (!lib) {
  		PRINTF_ERR("Couldn't open shared libmilkomeda_shim.so. Error: %s\n", dlerror());
  		return -1;
	}
	/* verify that the lib is within the domain address range. */
	dl_iterate_phdr(check_lib_addr, &cdata);

	dom_entry = (dom_entry_proc) dlsym(lib, "dom_entry");
	if (!dom_entry) {
  		PRINTF_ERR("Couldn't find the dom_entry symbol. Error: %s\n", dlerror());
		return -1;
	}

	pr_code_start = (__u64) start_addr;
	/* FIXME: Is g_pr_code_end exclusive? end_addr is. */
	pr_code_end = (__u64) end_addr;
	
    	/* set up the restricted environment */

	entry_addr = (uint64_t) (*dom_entry);

	/* For convenience of compatibility with existing code */
	set_up_domain_entry_stubs_one();

	/* For convenience of compatibility with existing code */

	get_maps();

	return 0;
}
#endif /* defined(__aarch64__) */
