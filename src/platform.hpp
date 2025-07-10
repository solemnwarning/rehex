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

/* Drawing individual characters to the screen using the text drawing APIs is too slow, so we
 * optimise the common path by drawing whole strings of fixed-width characters, however not all
 * characters in "fixed width" fonts are actually the same size, so any odd-sized characters are
 * instead rendered once to a (cached) bitmap with the text drawing APIs, then the bitmap can be
 * blitted to the screen more quickly.
 *
 * This improves performance on all platforms on my testing, so we always enable it.
*/
#define REHEX_CACHE_CHARACTER_BITMAPS

#if defined(_WIN32) || defined(__APPLE__)
/* Blitting individual character bitmaps is slow on Windows/macOS, however we can get reasonable
 * performance by furthermore blitting character sequences into another cached buffer and then
 * blitting whole sequences to the screen at once. This optimisation doesn't improve anything on
 * Linux in my testing.
*/
#define REHEX_CACHE_STRING_BITMAPS
#endif

#if defined(REHEX_CACHE_CHARACTER_BITMAPS) && defined(__WXGTK__)
/* Cairo is painfully slow at drawing strings, so much so, that drawing more than a few per
 * line of text on-screen is actually slower than caching individual character bitmaps and
 * blitting them to the screen one-at-a-time, so we always use the "slow" path on GTK.
*/
#define REHEX_FORCE_SLOW_TEXT_PATH
#endif

#if __APPLE__
/* Masked or transparent pixels in a wxBitmap don't work on macOS - wxDC.DrawBitmap() will clear
 * any existing pixels in the DC covered by a "transparent" area of the bitmap will be cleared to
 * the background colour.
*/
#define REHEX_BROKEN_BITMAP_TRANSPARENCY
#endif

#ifndef __APPLE__
/* If we can assume characters in a string occupy an integer number of pixels, then we can make
 * some assumptions for improved performance in places... macOS is the only target where I've seen
 * fractional character pitches, so we'll assume everywhere else is sane.
*/
#define REHEX_ASSUME_INTEGER_CHARACTER_WIDTHS
#endif
