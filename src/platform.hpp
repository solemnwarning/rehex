#pragma once

// We specifically target msvc here
#ifdef _MSC_VER

// Use 64 bit file pointers
#define fseeko _fseeki64
#define ftello _ftelli64
#define ftruncate _chsize_s

#define strncasecmp _strnicmp

// To ensure we are the only one defining it, define: _OFF_T_DEFINED
// See msvc/rehex.props
typedef __int64 _off_t;
typedef _off_t off_t;

#endif // _MSC_VER
