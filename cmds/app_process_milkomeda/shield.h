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

#define DOM_OP_SET_DOMAIN_PARAMS	100
#define DOM_OP_OPENAT			101
#define DOM_OP_CLOSE			102
#define DOM_OP_CHDIR			103
#define DOM_OP_FCHDIR			104
#define DOM_OP_GL			105
#define DOM_OP_GL_LONG			106

#define NUM_STACKS	8
#define STACK_MEM_SIZE	0x61000

#define NUM_PROTECTED_FDS	100
