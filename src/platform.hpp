#pragma once

// We specifically target msvc here
#ifdef _MSC_VER

// Use 64 bit file pointers
#define fseeko _fseeki64
#define ftello _ftelli64
#define ftruncate _chsize_s

#define strncasecmp _strnicmp

#define S_ISREG(mode) ((mode & _S_IFMT) == _S_IFREG)
#define S_ISBLK(mode) (false)

// To ensure we are the only one defining it, define: _OFF_T_DEFINED
// See msvc/rehex.props
typedef __int64 _off_t;
typedef _off_t off_t;

#ifdef _WIN64
typedef __int64 ssize_t;
#else
typedef int ssize_t;
#endif

#endif // _MSC_VER

#if __cplusplus >= 201703L
#define REHEX_NODISCARD [[nodiscard]]
#elif defined(_MSC_VER)
#define REHEX_NODISCARD _Check_return_
#elif defined(__GNUC__)
#define REHEX_NODISCARD __attribute__((__warn_unused_result__))
#else
#define REHEX_NODISCARD
#endif

#if defined(__linux__) || defined(__FreeBSD__)
#define REHEX_ENABLE_WAYLAND_HACKS
#endif
