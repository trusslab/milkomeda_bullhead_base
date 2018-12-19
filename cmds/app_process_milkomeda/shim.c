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

#include <stdio.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include "shield.h"
#include "prints.h"

#if defined(__aarch64__)

char *dom_str = NULL;
#define PRINTFD0(fmt, args...)		sprintf(dom_str, "Domain print: " fmt, ##args)

/* Implemented in libGLESv2_Secure */
extern long handle_gl_call(uint64_t api, uint64_t arg1, uint64_t arg2, uint64_t arg3,
		    uint64_t arg4, uint64_t arg5, uint64_t arg6, uint64_t arg7,
		    uint64_t arg8, uint64_t arg9, uint64_t arg10, uint64_t arg11,
		    uint64_t arg12, uint64_t arg13, uint64_t arg14, uint64_t arg15);

long handle_call(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4,
		 uint64_t arg5, uint64_t arg6, uint64_t arg7)
{
	long ret = -1;

	switch(arg1) {

	case DOM_OP_GL:
		ret = (long) handle_gl_call(arg2, arg3, arg4, arg5, arg6, arg7, 0, 0, 0,
					    0, 0, 0, 0, 0, 0, 0);
		break;

	case DOM_OP_GL_LONG:
	{
		uint64_t *args = (uint64_t *) arg7;
		ret = (long) handle_gl_call(arg2, arg3, arg4, arg5, arg6, args[0], args[1],
					    args[2], args[3], args[4], args[5], args[6],
					    args[7], args[8], args[9], args[10]);
		break;
	}
	default:
		ret = -1;
		break;
	}
	
	return ret;
}

uint64_t dummy;

void dom_entry(uint64_t unused, uint64_t arg1, uint64_t arg2, uint64_t arg3,
	       uint64_t arg4, uint64_t arg5, uint64_t arg6, uint64_t arg7)
{
	uint64_t ret;

	/* To get rid of compiler warning. */
	dummy = unused;

	if (arg1 == DOM_OP_SET_DOMAIN_PARAMS) {
		dom_str = (char *) arg3;
		ret = 0;
		goto exit;
	}

	ret = (uint64_t) handle_call(arg1, arg2, arg3, arg4, arg5, arg6, arg7);
exit:

	asm volatile("mov     x8, 283;" /* syscall number: __NR_exitdom */
		     "mov     x1, %[ret];"
		     "svc     #0;"
		     :
		     :[ret] "r" (ret)
		     :"x1", "x8");
}
#endif /* defined(__aarch64__) */
