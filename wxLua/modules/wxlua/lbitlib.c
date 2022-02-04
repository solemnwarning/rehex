/*
 * This is the bit32 library from lua 5.2.0, backported to
 * lua 5.1.4.
 *
 * http://smbolton.com/lua/lbitlib-5.2.0-backport4.c
 * version 5.2.0-backport4
 *
 * This backport was assembled by Sean Bolton (sean at smbolton
 * dot com) almost entirely from the above mentioned Lua distributions,
 * which are:
 *
 * Copyright (C) 1994-2011 Lua.org, PUC-Rio.  All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#define LUA_LIB

#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"  /* for #define LUA_BITLIBNAME in Lua 5.2 and LuaJIT */

/* We install into "bit32" which doesn't conflict with LuaJIT's "bit" */
#if (LUA_VERSION_NUM < 502)

#define LUA_BITLIBNAME	"bit32"

/* ----- adapted from lua-5.2.0 luaconf.h: ----- */

/*
@@ LUA_UNSIGNED is the integral type used by lua_pushunsigned/lua_tounsigned.
** It must have at least 32 bits.
*/
#if !defined(LUAI_INT32)
#if INT_MAX <= 32767
#define LUAI_INT32 long
#else
#define LUAI_INT32 int
#endif
#endif

#define LUA_UNSIGNED    unsigned LUAI_INT32

#if defined(LUA_NUMBER_DOUBLE) && !defined(LUA_ANSI)    /* { */

/* On a Microsoft compiler on a Pentium, use assembler to avoid clashes
   with a DirectX idiosyncrasy */
#if defined(LUA_WIN) && defined(_MSC_VER) && defined(_M_IX86)	/* { */

#define MS_ASMTRICK

#else                           /* }{ */
/* the next definition uses a trick that should work on any machine
   using IEEE754 with a 32-bit integer type */

#define LUA_IEEE754TRICK

/*
@@ LUA_IEEEENDIAN is the endianness of doubles in your machine
** (0 for little endian, 1 for big endian); if not defined, Lua will
** check it dynamically.
*/
/* check for known architectures */
#if defined(__i386__) || defined(__i386) || defined(__X86__) || \
    defined (__x86_64)
#define LUA_IEEEENDIAN  0
#elif defined(__POWERPC__) || defined(__ppc__)
#define LUA_IEEEENDIAN  1
#endif

#endif                          /* } */

#endif                  /* } */

/* ----- from lua-5.2.0 lua.h: ----- */

/* unsigned integer type */
typedef LUA_UNSIGNED lua_Unsigned;

/* ----- adapted from lua-5.2.0 llimits.h: ----- */

/* lua_number2unsigned is a macro to convert a lua_Number to a lua_Unsigned.
** lua_unsigned2number is a macro to convert a lua_Unsigned to a lua_Number.
*/

#if defined(MS_ASMTRICK)        /* { */
/* trick with Microsoft assembler for X86 */

#define lua_number2unsigned(i,n)  \
  {__int64 l; __asm {__asm fld n   __asm fistp l} i = (unsigned int)l;}

#elif defined(LUA_IEEE754TRICK)         /* }{ */
/* the next trick should work on any machine using IEEE754 with
   a 32-bit integer type */

union luai_Cast2 { double l_d; LUAI_INT32 l_p[2]; };

#if !defined(LUA_IEEEENDIAN)    /* { */
#define LUAI_EXTRAIEEE  \
  static const union luai_Cast2 ieeeendian = {-(33.0 + 6755399441055744.0)};
#define LUA_IEEEENDIAN          (ieeeendian.l_p[1] == 33)
#else
#define LUAI_EXTRAIEEE          /* empty */
#endif                          /* } */

#define lua_number2int32(i,n,t) \
  { LUAI_EXTRAIEEE \
    volatile union luai_Cast2 u; u.l_d = (n) + 6755399441055744.0; \
    (i) = (t)u.l_p[LUA_IEEEENDIAN]; }

#define lua_number2unsigned(i,n)        lua_number2int32(i, n, lua_Unsigned)

#endif                          /* } */

#if !defined(lua_number2unsigned)       /* { */
/* the following definition assures proper modulo behavior */
#if defined(LUA_NUMBER_DOUBLE)
#include <math.h>
#define SUPUNSIGNED     ((lua_Number)(~(lua_Unsigned)0) + 1)
#define lua_number2unsigned(i,n)  \
        ((i)=(lua_Unsigned)((n) - floor((n)/SUPUNSIGNED)*SUPUNSIGNED))
#else
#define lua_number2unsigned(i,n)        ((i)=(lua_Unsigned)(n))
#endif
#endif                          /* } */

/* on several machines, coercion from unsigned to double is slow,
   so it may be worth to avoid */
#define lua_unsigned2number(u)  \
    (((u) <= (lua_Unsigned)INT_MAX) ? (lua_Number)(int)(u) : (lua_Number)(u))

/* ----- adapted from lua-5.2.0 lapi.c: ----- */

static void lua_pushunsigned (lua_State *L, lua_Unsigned u) {
  lua_Number n;
  n = lua_unsigned2number(u);
  lua_pushnumber(L, n);
}

/* ----- adapted from lua-5.2.0-work3 lbitlib.c getuintarg(): ----- */

static lua_Unsigned luaL_checkunsigned (lua_State *L, int arg) {
  lua_Unsigned r;
  lua_Number x = lua_tonumber(L, arg);
  if (x == 0) luaL_checktype(L, arg, LUA_TNUMBER);
  lua_number2unsigned(r, x);
  return r;
}

/* ----- Lua 5.2 luaL_newlib() compatibility: ----- */

#define LUAMOD_API  LUALIB_API
/* #define LUA_BITLIBNAME "bit32" */
/* #define luaL_newlib(x, y) luaL_register(x, LUA_BITLIBNAME, y) */

/* ----- avoid a 'symbol redefined' warning below ----- */

#undef LUA_LIB

/* ----- here follows the unmodified lbitlib.c from Lua 5.2.0 ----- */

/*
** $Id: lbitlib.c,v 1.16 2011/06/20 16:35:23 roberto Exp $
** Standard library for bitwise operations
** See Copyright Notice in lua.h
*/

#define lbitlib_c
#define LUA_LIB

#include "lua.h"

#include "lauxlib.h"
#include "lualib.h"


/* number of bits to consider in a number */
#if !defined(LUA_NBITS)
#define LUA_NBITS	32
#endif


#define ALLONES		(~(((~(lua_Unsigned)0) << (LUA_NBITS - 1)) << 1))

/* macro to trim extra bits */
#define trim(x)		((x) & ALLONES)


/* builds a number with 'n' ones (1 <= n <= LUA_NBITS) */
#define mask(n)		(~((ALLONES << 1) << ((n) - 1)))


typedef lua_Unsigned b_uint;



static b_uint andaux (lua_State *L) {
  int i, n = lua_gettop(L);
  b_uint r = ~(b_uint)0;
  for (i = 1; i <= n; i++)
    r &= luaL_checkunsigned(L, i);
  return trim(r);
}


static int b_and (lua_State *L) {
  b_uint r = andaux(L);
  lua_pushunsigned(L, r);
  return 1;
}


static int b_test (lua_State *L) {
  b_uint r = andaux(L);
  lua_pushboolean(L, r != 0);
  return 1;
}


static int b_or (lua_State *L) {
  int i, n = lua_gettop(L);
  b_uint r = 0;
  for (i = 1; i <= n; i++)
    r |= luaL_checkunsigned(L, i);
  lua_pushunsigned(L, trim(r));
  return 1;
}


static int b_xor (lua_State *L) {
  int i, n = lua_gettop(L);
  b_uint r = 0;
  for (i = 1; i <= n; i++)
    r ^= luaL_checkunsigned(L, i);
  lua_pushunsigned(L, trim(r));
  return 1;
}


static int b_not (lua_State *L) {
  b_uint r = ~luaL_checkunsigned(L, 1);
  lua_pushunsigned(L, trim(r));
  return 1;
}


static int b_shift (lua_State *L, b_uint r, int i) {
  if (i < 0) {  /* shift right? */
    i = -i;
    r = trim(r);
    if (i >= LUA_NBITS) r = 0;
    else r >>= i;
  }
  else {  /* shift left */
    if (i >= LUA_NBITS) r = 0;
    else r <<= i;
    r = trim(r);
  }
  lua_pushunsigned(L, r);
  return 1;
}


static int b_lshift (lua_State *L) {
  return b_shift(L, luaL_checkunsigned(L, 1), luaL_checkint(L, 2));
}


static int b_rshift (lua_State *L) {
  return b_shift(L, luaL_checkunsigned(L, 1), -luaL_checkint(L, 2));
}


static int b_arshift (lua_State *L) {
  b_uint r = luaL_checkunsigned(L, 1);
  int i = luaL_checkint(L, 2);
  if (i < 0 || !(r & ((b_uint)1 << (LUA_NBITS - 1))))
    return b_shift(L, r, -i);
  else {  /* arithmetic shift for 'negative' number */
    if (i >= LUA_NBITS) r = ALLONES;
    else
      r = trim((r >> i) | ~(~(b_uint)0 >> i));  /* add signal bit */
    lua_pushunsigned(L, r);
    return 1;
  }
}


static int b_rot (lua_State *L, int i) {
  b_uint r = luaL_checkunsigned(L, 1);
  i &= (LUA_NBITS - 1);  /* i = i % NBITS */
  r = trim(r);
  r = (r << i) | (r >> (LUA_NBITS - i));
  lua_pushunsigned(L, trim(r));
  return 1;
}


static int b_lrot (lua_State *L) {
  return b_rot(L, luaL_checkint(L, 2));
}


static int b_rrot (lua_State *L) {
  return b_rot(L, -luaL_checkint(L, 2));
}


/*
** get field and width arguments for field-manipulation functions,
** checking whether they are valid
*/
static int fieldargs (lua_State *L, int farg, int *width) {
  int f = luaL_checkint(L, farg);
  int w = luaL_optint(L, farg + 1, 1);
  luaL_argcheck(L, 0 <= f, farg, "field cannot be negative");
  luaL_argcheck(L, 0 < w, farg + 1, "width must be positive");
  if (f + w > LUA_NBITS)
    luaL_error(L, "trying to access non-existent bits");
  *width = w;
  return f;
}


static int b_extract (lua_State *L) {
  int w;
  b_uint r = luaL_checkunsigned(L, 1);
  int f = fieldargs(L, 2, &w);
  r = (r >> f) & mask(w);
  lua_pushunsigned(L, r);
  return 1;
}


static int b_replace (lua_State *L) {
  int w;
  b_uint r = luaL_checkunsigned(L, 1);
  b_uint v = luaL_checkunsigned(L, 2);
  int f = fieldargs(L, 3, &w);
  int m = mask(w);
  v &= m;  /* erase bits outside given width */
  r = (r & ~(m << f)) | (v << f);
  lua_pushunsigned(L, r);
  return 1;
}


static const luaL_Reg bitlib[] = {
  {"arshift", b_arshift},
  {"band", b_and},
  {"bnot", b_not},
  {"bor", b_or},
  {"bxor", b_xor},
  {"btest", b_test},
  {"extract", b_extract},
  {"lrotate", b_lrot},
  {"lshift", b_lshift},
  {"replace", b_replace},
  {"rrotate", b_rrot},
  {"rshift", b_rshift},
  {NULL, NULL}
};



LUAMOD_API int luaopen_bit32 (lua_State *L) {
  /* luaL_newlib(L, bitlib); */
  luaL_register(L, LUA_BITLIBNAME, bitlib);
  return 1;
}

#endif // (LUA_VERSION_NUM < 502)
