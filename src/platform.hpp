#pragma once

// We specifically target msvc here
#ifdef _MSC_VER

// To ensure we are the only one defining it, define: _OFF_T_DEFINED
// See msvc/rehex.props
typedef __int64 _off_t;
typedef _off_t off_t;

#endif // _MSC_VER
