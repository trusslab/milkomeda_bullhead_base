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

#ifndef _MILKOMEDA_PRINTS_H_
#define _MILKOMEDA_PRINTS_H_
#include <stdio.h>

#define PRINTF0(fmt, args...) 
#define PRINTF_COND0(cond, fmt, args...)

#define PRINTF_ERR(fmt, args...) fprintf(stderr, "%s: Error: " fmt, __func__, ##args)
#endif /* _MILKOMEDA_PRINTS_H_ */
