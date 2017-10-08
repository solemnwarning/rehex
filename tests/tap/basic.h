/*
 * Basic utility routines for the TAP protocol.
 *
 * This file is part of C TAP Harness.  The current version plus supporting
 * documentation is at <http://www.eyrie.org/~eagle/software/c-tap-harness/>.
 *
 * Copyright 2009, 2010, 2011, 2012, 2013, 2014 Russ Allbery <eagle@eyrie.org>
 * Copyright 2001, 2002, 2004, 2005, 2006, 2007, 2008, 2011, 2012, 2014
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#ifndef TAP_BASIC_H
#define TAP_BASIC_H 1

#include <tests/tap/macros.h>
#include <stdarg.h>             /* va_list */
#include <stddef.h>             /* size_t */

/*
 * Used for iterating through arrays.  ARRAY_SIZE returns the number of
 * elements in the array (useful for a < upper bound in a for loop) and
 * ARRAY_END returns a pointer to the element past the end (ISO C99 makes it
 * legal to refer to such a pointer as long as it's never dereferenced).
 */
#define ARRAY_SIZE(array)       (sizeof(array) / sizeof((array)[0]))
#define ARRAY_END(array)        (&(array)[ARRAY_SIZE(array)])

BEGIN_DECLS

/*
 * The test count.  Always contains the number that will be used for the next
 * test status.
 */
extern unsigned long testnum;

/* Print out the number of tests and set standard output to line buffered. */
void plan(unsigned long count);

/*
 * Prepare for lazy planning, in which the plan will be printed automatically
 * at the end of the test program.
 */
void plan_lazy(void);

/* Skip the entire test suite.  Call instead of plan. */
void skip_all(const char *format, ...)
    __attribute__((__noreturn__, __format__(printf, 1, 2)));

/*
 * Basic reporting functions.  The okv() function is the same as ok() but
 * takes the test description as a va_list to make it easier to reuse the
 * reporting infrastructure when writing new tests.  ok() and okv() return the
 * value of the success argument.
 */
int ok(int success, const char *format, ...)
    __attribute__((__format__(printf, 2, 3)));
int okv(int success, const char *format, va_list args);
void skip(const char *reason, ...)
    __attribute__((__format__(printf, 1, 2)));

/*
 * Report the same status on, or skip, the next count tests.  ok_block()
 * returns the value of the success argument.
 */
int ok_block(unsigned long count, int success, const char *format, ...)
    __attribute__((__format__(printf, 3, 4)));
void skip_block(unsigned long count, const char *reason, ...)
    __attribute__((__format__(printf, 2, 3)));

/*
 * Check an expected value against a seen value.  Returns true if the test
 * passes and false if it fails.
 */
int is_int(long wanted, long seen, const char *format, ...)
    __attribute__((__format__(printf, 3, 4)));
int is_string(const char *wanted, const char *seen, const char *format, ...)
    __attribute__((__format__(printf, 3, 4)));
int is_hex(unsigned long wanted, unsigned long seen, const char *format, ...)
    __attribute__((__format__(printf, 3, 4)));
int is_blob(const void *wanted, const void *seen, size_t len, const char *format, ...)
    __attribute__((__format__(printf, 4, 5)));

/* Bail out with an error.  sysbail appends strerror(errno). */
void bail(const char *format, ...)
    __attribute__((__noreturn__, __nonnull__, __format__(printf, 1, 2)));
void sysbail(const char *format, ...)
    __attribute__((__noreturn__, __nonnull__, __format__(printf, 1, 2)));

/* Report a diagnostic to stderr prefixed with #. */
int diag(const char *format, ...)
    __attribute__((__nonnull__, __format__(printf, 1, 2)));
int sysdiag(const char *format, ...)
    __attribute__((__nonnull__, __format__(printf, 1, 2)));

/*
 * Register or unregister a file that contains supplementary diagnostics.
 * Before any other output, all registered files will be read, line by line,
 * and each line will be reported as a diagnostic as if it were passed to
 * diag().  Nul characters are not supported in these files and will result in
 * truncated output.
 */
void diag_file_add(const char *file)
    __attribute__((__nonnull__));
void diag_file_remove(const char *file)
    __attribute__((__nonnull__));

/* Allocate memory, reporting a fatal error with bail on failure. */
void *bcalloc(size_t, size_t)
    __attribute__((__alloc_size__(1, 2), __malloc__, __warn_unused_result__));
void *bmalloc(size_t)
    __attribute__((__alloc_size__(1), __malloc__, __warn_unused_result__));
void *breallocarray(void *, size_t, size_t)
    __attribute__((__alloc_size__(2, 3), __malloc__, __warn_unused_result__));
void *brealloc(void *, size_t)
    __attribute__((__alloc_size__(2), __malloc__, __warn_unused_result__));
char *bstrdup(const char *)
    __attribute__((__malloc__, __nonnull__, __warn_unused_result__));
char *bstrndup(const char *, size_t)
    __attribute__((__malloc__, __nonnull__, __warn_unused_result__));

/*
 * Find a test file under BUILD or SOURCE, returning the full path.  The
 * returned path should be freed with test_file_path_free().
 */
char *test_file_path(const char *file)
    __attribute__((__malloc__, __nonnull__, __warn_unused_result__));
void test_file_path_free(char *path);

/*
 * Create a temporary directory relative to BUILD and return the path.  The
 * returned path should be freed with test_tmpdir_free.
 */
char *test_tmpdir(void)
    __attribute__((__malloc__, __warn_unused_result__));
void test_tmpdir_free(char *path);

/*
 * Register a cleanup function that is called when testing ends.  All such
 * registered functions will be run during atexit handling (and are therefore
 * subject to all the same constraints and caveats as atexit functions).
 *
 * The function must return void and will be passed two argument, an int that
 * will be true if the test completed successfully and false otherwise, and an
 * int that will be true if the cleanup function is run in the primary process
 * (the one that called plan or plan_lazy) and false otherwise.
 */
typedef void (*test_cleanup_func)(int, int);
void test_cleanup_register(test_cleanup_func)
    __attribute__((__nonnull__));

END_DECLS

#endif /* TAP_BASIC_H */
