/*
** Copyright (C) 2007-2009 Sourcefire, Inc.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#ifndef __SF_TYPES_H__
#define __SF_TYPES_H__


#include <sys/types.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef WIN32
#include "stdint.h"
#include "inttypes.h"
#else
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#elif HAVE_STDINT_H
#include <stdint.h>
#else
/* Solaris - if inttypes.h is present, it should bring this in */
#ifndef SYS_INT_TYPES_H
#if defined(_LP64) || defined(_I32LPx)
typedef long int           intptr_t;
typedef unsigned long int  uintptr_t;
#else
typedef int           intptr_t;
typedef unsigned int  uintptr_t;
#endif  /* defined(_LP64) || defined(_I32LPx) */
#endif  /* SYS_INT_TYPES_H */
#endif  /* HAVE_INTTYPES_H elseif HAVE_STDINT_H */
#endif  /* WIN32 */


#ifndef UINT64
#ifdef ULONGIS64BIT
#define UINT64 unsigned long
#define INT64  signed long
#else
#define UINT64 unsigned long long
#define INT64  signed long long
#endif  /* ULONGIS64BIT */
#endif  /* UINT64 */

#ifndef UINT8_MAX
#define UINT8_MAX 0xff
#endif

#ifndef USHRT_MAX
#define USHRT_MAX  0xffff
#endif

#ifndef UINT16_MAX
#define UINT16_MAX 0xffff
#endif

#ifndef UINT32_MAX
#define UINT32_MAX (4294967295U)
#endif

#ifndef UINT64_MAX
#ifdef ULONGIS64BIT
#define UINT64_MAX (18446744073709551615UL)
#else
#define UINT64_MAX (18446744073709551615ULL)
#endif  /* ULONGIS64BIT */
#endif  /* UINT64_MAX */

/* if PRIu64 isn't in <inttypes.h>
 * we define it and similar here
 */
#ifndef PRIu64
#ifdef ULONGIS64BIT
#define _SF_PREFIX "l"
#else
#define _SF_PREFIX "ll"
#endif  /* ULONGIS64BIT */
#define PRIu64 _SF_PREFIX "u"
#define PRIi64 _SF_PREFIX "i"
#endif  /* PRIu64 */

/* use these macros (and those in <inttypes.h>)
 * for 64 bit format portability
 */
#define STDu64 "%" PRIu64
#define CSVu64 STDu64 ","
#define FMTu64(fmt) "%" fmt PRIu64

#define STDi64 "%" PRIi64
#define CSVi64 STDi64 ","
#define FMTi64(fmt) "%" fmt PRIi64

#define MAXPORTS 65536

#endif  /* __SF_TYPES_H__ */

