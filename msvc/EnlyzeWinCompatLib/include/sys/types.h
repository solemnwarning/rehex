#pragma once
#include_next <sys/types.h>

/* libunistring defines a "pid_t" macro which conflicts with the pid_t typedef
 * from winpthreads unless its configure script detects pid_t, so we make it
 * visible from this header.
*/
#include <pthread.h>
