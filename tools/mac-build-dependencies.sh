# Reverse Engineer's Hex Editor
# Copyright (C) 2021-2025 Daniel Collins <solemnwarning@solemnwarning.net>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License version 2 as published by
# the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 51
# Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

_rehex_botan_version="2.19.4"
_rehex_botan_url="https://botan.randombit.net/releases/Botan-${_rehex_botan_version}.tar.xz"
_rehex_botan_sha256="5a3a88ef6433e97bcab0efa1ed60c6197e4ada9d9d30bc1c47437bf89b97f276"
_rehex_botan_build_ident="${_rehex_botan_version}-2"

_rehex_capstone_version="5.0"
_rehex_capstone_url="https://github.com/capstone-engine/capstone/archive/refs/tags/${_rehex_capstone_version}.tar.gz"
_rehex_capstone_sha256="df24344407baa7415eeb006f742afc9b92cd33abf2c4c120a6e97cfb376882dc"
_rehex_capstone_build_ident="${_rehex_capstone_version}-1"

_rehex_jansson_version="2.14"
_rehex_jansson_url="https://github.com/akheron/jansson/releases/download/v${_rehex_jansson_version}/jansson-${_rehex_jansson_version}.tar.gz"
_rehex_jansson_sha256="5798d010e41cf8d76b66236cfb2f2543c8d082181d16bc3085ab49538d4b9929"
_rehex_jansson_build_ident="${_rehex_jansson_version}-2"

_rehex_libiconv_version="1.17"
_rehex_libiconv_url="https://ftp.gnu.org/pub/gnu/libiconv/libiconv-${_rehex_libiconv_version}.tar.gz"
_rehex_libiconv_sha256="8f74213b56238c85a50a5329f77e06198771e70dd9a739779f4c02f65d971313"
_rehex_libiconv_build_ident="${_rehex_libiconv_version}-1"

_rehex_libunistring_version="1.3"
_rehex_libunistring_url="https://ftp.gnu.org/gnu/libunistring/libunistring-${_rehex_libunistring_version}.tar.gz"
_rehex_libunistring_sha256="8ea8ccf86c09dd801c8cac19878e804e54f707cf69884371130d20bde68386b7"
_rehex_libunistring_build_ident="${_rehex_libunistring_version}-1"

_rehex_lua_version="5.3.6"
_rehex_lua_url="https://www.lua.org/ftp/lua-${_rehex_lua_version}.tar.gz"
_rehex_lua_sha256="fc5fd69bb8736323f026672b1b7235da613d7177e72558893a0bdcd320466d60"
_rehex_lua_build_ident="${_rehex_lua_version}-3"

_rehex_luarocks_version="3.8.0"
_rehex_luarocks_url="https://luarocks.org/releases/luarocks-${_rehex_luarocks_version}.tar.gz"
_rehex_luarocks_sha256="56ab9b90f5acbc42eb7a94cf482e6c058a63e8a1effdf572b8b2a6323a06d923"

_rehex_wxwidgets_version="3.2.5"
_rehex_wxwidgets_url="https://github.com/wxWidgets/wxWidgets/releases/download/v${_rehex_wxwidgets_version}/wxWidgets-${_rehex_wxwidgets_version}.tar.bz2"
_rehex_wxwidgets_sha256="0ad86a3ad3e2e519b6a705248fc9226e3a09bbf069c6c692a02acf7c2d1c6b51"
_rehex_wxwidgets_build_ident="${_rehex_wxwidgets_version}-2"

_rehex_cpanm_version="1.7044"
_rehex_cpanm_url="https://cpan.metacpan.org/authors/id/M/MI/MIYAGAWA/App-cpanminus-${_rehex_cpanm_version}.tar.gz"
_rehex_cpanm_sha256="9b60767fe40752ef7a9d3f13f19060a63389a5c23acc3e9827e19b75500f81f3"
_rehex_perl_libs_build_ident="2"

_rehex_macos_version_min=10.13
_rehex_arch_flags="-arch arm64 -arch x86_64"

_rehex_ok=1

# https://stackoverflow.com/a/28776166
_rehex_sourced=0
if [ -n "$ZSH_EVAL_CONTEXT" ]; then
	case $ZSH_EVAL_CONTEXT in *:file) _rehex_sourced=1;; esac
elif [ -n "$KSH_VERSION" ]; then
	[ "$(cd $(dirname -- $0) && pwd -P)/$(basename -- $0)" != "$(cd $(dirname -- ${.sh.file}) && pwd -P)/$(basename -- ${.sh.file})" ] && _rehex_sourced=1
elif [ -n "$BASH_VERSION" ]; then
	(return 0 2>/dev/null) && _rehex_sourced=1
else
	# All other shells: examine $0 for known shell binary filenames
	# Detects `sh` and `dash`; add additional shell filenames as needed.
	case ${0##*/} in sh|dash) _rehex_sourced=1;; esac
fi

if [ "$_rehex_sourced" = "0" ]
then
	echo "ERROR: This script must be source'd into your environment" 1>&2
	echo "Example: source $0" 1>&2
	
	_rehex_ok=0
fi

unset _rehex_sourced

if [ -n "$REHEX_DEP_BUILD_DIR" ]
then
	_rehex_dep_build_dir="$REHEX_DEP_BUILD_DIR"
else
	_rehex_dep_build_dir="$(pwd)/mac-dependencies-build"
fi

mkdir -p "${_rehex_dep_build_dir}" || _rehex_ok=0

if [ -n "$REHEX_DEP_TARGET_DIR" ]
then
	_rehex_dep_target_dir="$REHEX_DEP_TARGET_DIR"
else
	_rehex_dep_target_dir="$(pwd)/mac-dependencies"
fi

_rehex_botan_target_dir="${_rehex_dep_target_dir}/botan-${_rehex_botan_build_ident}"
_rehex_capstone_target_dir="${_rehex_dep_target_dir}/capstone-${_rehex_capstone_build_ident}"
_rehex_jansson_target_dir="${_rehex_dep_target_dir}/jansson-${_rehex_jansson_build_ident}"
_rehex_libiconv_target_dir="${_rehex_dep_target_dir}/libiconv-${_rehex_libiconv_build_ident}"
_rehex_libunistring_target_dir="${_rehex_dep_target_dir}/libunistring-${_rehex_libunistring_build_ident}"
_rehex_lua_target_dir="${_rehex_dep_target_dir}/lua-${_rehex_lua_build_ident}"
_rehex_wxwidgets_target_dir="${_rehex_dep_target_dir}/wxwidgets-${_rehex_wxwidgets_build_ident}"
_rehex_perl_libs_target_dir="${_rehex_dep_target_dir}/perl-libs-${_rehex_perl_libs_build_ident}"

if [ "$_rehex_ok" = 1 ] && [ ! -e "$_rehex_botan_target_dir" ]
then
	echo "== Preparing Botan ${_rehex_botan_version}"

	(
		set -e

		cd "${_rehex_dep_build_dir}"

		_rehex_botan_tar="$(basename "${_rehex_botan_url}")"

		if [ ! -e "${_rehex_dep_build_dir}/${_rehex_botan_tar}" ]
		then
			echo "Downloading ${_rehex_botan_url}"
			curl -Lo "${_rehex_botan_tar}" "${_rehex_botan_url}"
		fi

		echo "${_rehex_botan_sha256}  ${_rehex_botan_tar}" | shasum -c
		
		# Build Botan for x86_64
		
		echo "Building Botan for x86_64"

		mkdir -p "botan-${_rehex_botan_build_ident}-x86_64"

		tar -xf "${_rehex_botan_tar}" -C "botan-${_rehex_botan_build_ident}-x86_64"
		pushd "botan-${_rehex_botan_build_ident}-x86_64/Botan-${_rehex_botan_version}"

		python3 configure.py \
			--minimized-build \
			--enable-modules=md5,sha1,sha2_32,sha2_64 \
			--cpu=x86_64 \
			--cc-abi-flags="-arch x86_64 -mmacosx-version-min=${_rehex_macos_version_min}" \
			--prefix="${_rehex_botan_target_dir}" \
			--disable-shared-library \
			--without-documentation

		make -j$(sysctl -n hw.logicalcpu)
		
		if [ "$(uname -m)" != "arm64" ]
		then
			make -j$(sysctl -n hw.logicalcpu) check
		fi
		
		make -j$(sysctl -n hw.logicalcpu) DESTDIR=tmp install
		
		popd
		
		# Build Botan for ARM64 ("Apple Silicon")
		
		echo "Building Botan for ARM64"
		
		mkdir -p "botan-${_rehex_botan_build_ident}-arm64"

		tar -xf "${_rehex_botan_tar}" -C "botan-${_rehex_botan_build_ident}-arm64"
		pushd "botan-${_rehex_botan_build_ident}-arm64/Botan-${_rehex_botan_version}"

		python3 configure.py \
			--minimized-build \
			--enable-modules=md5,sha1,sha2_32,sha2_64 \
			--cpu=arm64 \
			--cc-abi-flags="-arch arm64 -mmacosx-version-min=${_rehex_macos_version_min}" \
			--prefix="${_rehex_botan_target_dir}" \
			--disable-shared-library \
			--without-documentation

		make -j$(sysctl -n hw.logicalcpu)
		
		if [ "$(uname -m)" != "x86_64" ]
		then
			make -j$(sysctl -n hw.logicalcpu) check
		fi
		
		make -j$(sysctl -n hw.logicalcpu) DESTDIR=tmp install
		
		popd
		
		# Build combined library
		# (See https://github.com/randombit/botan/issues/2896#issuecomment-1478157486)
		
		echo "Building combined Botan library"
		
		mkdir -p "botan-${_rehex_botan_build_ident}/"
		
		cp -a "botan-${_rehex_botan_build_ident}-x86_64/Botan-${_rehex_botan_version}/tmp/${_rehex_botan_target_dir}/include" "botan-${_rehex_botan_build_ident}/"
		cp "botan-${_rehex_botan_build_ident}-x86_64/Botan-${_rehex_botan_version}/tmp/${_rehex_botan_target_dir}/include/botan-2/botan/build.h" "botan-${_rehex_botan_build_ident}/include/botan-2/botan/build_x86_64.h"
		cp "botan-${_rehex_botan_build_ident}-arm64/Botan-${_rehex_botan_version}/tmp/${_rehex_botan_target_dir}/include/botan-2/botan/build.h" "botan-${_rehex_botan_build_ident}/include/botan-2/botan/build_arm64.h"
		
		cat > "botan-${_rehex_botan_build_ident}/include/botan-2/botan/build.h" <<'EOF'
#if defined(__x86_64__)
    #include "build_x86_64.h"
#elif defined(__aarch64__)
    #include "build_arm64.h"
#else
    #error Unsupported architecture for botan
#endif
EOF
		
		mkdir -p "botan-${_rehex_botan_build_ident}/lib/"
		lipo -create -output "botan-${_rehex_botan_build_ident}/lib/libbotan-2.a" \
			"botan-${_rehex_botan_build_ident}-x86_64/Botan-${_rehex_botan_version}/tmp/${_rehex_botan_target_dir}/lib/libbotan-2.a" \
			"botan-${_rehex_botan_build_ident}-arm64/Botan-${_rehex_botan_version}/tmp/${_rehex_botan_target_dir}/lib/libbotan-2.a"
		
		mkdir -p "$(dirname "${_rehex_botan_target_dir}")"
		cp -a "botan-${_rehex_botan_build_ident}" "${_rehex_botan_target_dir}"
	)

	[ $? -ne 0 ] && _rehex_ok=0
fi

if [ "$_rehex_ok" = 1 ] && [ ! -e "$_rehex_capstone_target_dir" ]
then
	echo "== Preparing Capstone ${_rehex_capstone_version}"
	
	(
		set -e
		
		cd "${_rehex_dep_build_dir}"
		
		_rehex_capstone_tar="$(basename "${_rehex_capstone_url}")"
		
		if [ ! -e "${_rehex_dep_build_dir}/${_rehex_capstone_tar}" ]
		then
			echo "Downloading ${_rehex_capstone_url}"
			curl -Lo "${_rehex_capstone_tar}" "${_rehex_capstone_url}"
		fi
		
		echo "${_rehex_capstone_sha256}  ${_rehex_capstone_tar}" | shasum -c
		
		mkdir -p "capstone-${_rehex_capstone_build_ident}"
		
		tar -xf "${_rehex_capstone_tar}" -C "capstone-${_rehex_capstone_build_ident}"
		cd "capstone-${_rehex_capstone_build_ident}/capstone-${_rehex_capstone_version}"
		
		PREFIX="${_rehex_capstone_target_dir}" \
			CFLAGS="${_rehex_arch_flags} -mmacosx-version-min=${_rehex_macos_version_min}" \
			CAPSTONE_STATIC=yes \
			CAPSTONE_SHARED=no \
			CAPSTONE_BUILD_CORE_ONLY=yes \
			make install
	)
	
	[ $? -ne 0 ] && _rehex_ok=0
fi

if [ "$_rehex_ok" = 1 ] && [ ! -e "$_rehex_jansson_target_dir" ]
then
	echo "== Preparing Jansson ${_rehex_jansson_version}"
	
	(
		set -e
		
		cd "${_rehex_dep_build_dir}"
		
		_rehex_jansson_tar="$(basename "${_rehex_jansson_url}")"
		
		if [ ! -e "${_rehex_dep_build_dir}/${_rehex_jansson_tar}" ]
		then
			echo "Downloading ${_rehex_jansson_url}"
			curl -Lo "${_rehex_jansson_tar}" "${_rehex_jansson_url}"
		fi
		
		echo "${_rehex_jansson_sha256}  ${_rehex_jansson_tar}" | shasum -c
		
		mkdir -p "jansson-${_rehex_jansson_build_ident}"
		
		tar -xf "${_rehex_jansson_tar}" -C "jansson-${_rehex_jansson_build_ident}"
		cd "jansson-${_rehex_jansson_build_ident}/jansson-${_rehex_jansson_version}"
		
		./configure \
			--prefix="${_rehex_jansson_target_dir}" \
			--enable-shared=no \
			--enable-static=yes \
			CFLAGS="${_rehex_arch_flags} -mmacosx-version-min=${_rehex_macos_version_min}"
		
		make -j$(sysctl -n hw.logicalcpu)
		make -j$(sysctl -n hw.logicalcpu) check
		make -j$(sysctl -n hw.logicalcpu) install
	)
	
	[ $? -ne 0 ] && _rehex_ok=0
fi

if [ "$_rehex_ok" = 1 ] && [ ! -e "$_rehex_libiconv_target_dir" ]
then
	echo "== Preparing libiconv ${_rehex_libiconv_version}"

	(
		set -e

		cd "${_rehex_dep_build_dir}"

		_rehex_libiconv_tar="$(basename "${_rehex_libiconv_url}")"

		if [ ! -e "${_rehex_dep_build_dir}/${_rehex_libiconv_tar}" ]
		then
			echo "Downloading ${_rehex_libiconv_url}"
			curl -Lo "${_rehex_libiconv_tar}" "${_rehex_libiconv_url}"
		fi

		echo "${_rehex_libiconv_sha256}  ${_rehex_libiconv_tar}" | shasum -c

		mkdir -p "libiconv-${_rehex_libiconv_build_ident}"

		tar -xf "${_rehex_libiconv_tar}" -C "libiconv-${_rehex_libiconv_build_ident}"
		cd "libiconv-${_rehex_libiconv_build_ident}/libiconv-${_rehex_libiconv_version}"

		./configure \
			--prefix="${_rehex_libiconv_target_dir}" \
			--enable-shared=no \
			--enable-static=yes \
			CFLAGS="${_rehex_arch_flags} -mmacosx-version-min=${_rehex_macos_version_min}"

		make -j$(sysctl -n hw.logicalcpu)
		make -j$(sysctl -n hw.logicalcpu) check
		make -j$(sysctl -n hw.logicalcpu) install
	)

	[ $? -ne 0 ] && _rehex_ok=0
fi

if [ "$_rehex_ok" = 1 ] && [ ! -e "$_rehex_libunistring_target_dir" ]
then
	echo "== Preparing libunistring ${_rehex_libunistring_version}"
	
	(
		set -e
		
		cd "${_rehex_dep_build_dir}"
		
		_rehex_libunistring_tar="$(basename "${_rehex_libunistring_url}")"
		
		if [ ! -e "${_rehex_dep_build_dir}/${_rehex_libunistring_tar}" ]
		then
			echo "Downloading ${_rehex_libunistring_url}"
			curl -Lo "${_rehex_libunistring_tar}" "${_rehex_libunistring_url}"
		fi
		
		echo "${_rehex_libunistring_sha256}  ${_rehex_libunistring_tar}" | shasum -c
		
		mkdir -p "libunistring-${_rehex_libunistring_build_ident}"
		
		tar -xf "${_rehex_libunistring_tar}" -C "libunistring-${_rehex_libunistring_build_ident}"
		cd "libunistring-${_rehex_libunistring_build_ident}/libunistring-${_rehex_libunistring_version}"
		
		# https://savannah.gnu.org/bugs/?67007
		# https://git.savannah.gnu.org/gitweb/?p=gnulib.git;a=commit;h=b49212bd6ce6182d95af45d490d4de9f84bcc223
		patch <<'EOF'
diff -ru tests/test-c32isalnum.c tests/test-c32isalnum.c
--- tests/test-c32isalnum.c	2024-06-07 19:47:34.000000000 +0100
+++ tests/test-c32isalnum.c	2025-04-19 23:48:15.929364851 +0100
@@ -222,7 +222,7 @@
           /* U+00D7 MULTIPLICATION SIGN */
           is = for_character ("\241\301", 2);
           ASSERT (is == 0);
-        #if !(defined __FreeBSD__ || defined __DragonFly__ || defined __sun)
+        #if !((defined __APPLE__ && defined __MACH__) || defined __FreeBSD__ || defined __DragonFly__ || defined __sun)
           /* U+00D8 LATIN CAPITAL LETTER O WITH STROKE */
           is = for_character ("\201\060\211\061", 4);
           ASSERT (is != 0);
diff -ru tests/test-c32isalpha.c tests/test-c32isalpha.c
--- tests/test-c32isalpha.c	2024-09-12 00:03:55.000000000 +0100
+++ tests/test-c32isalpha.c	2025-04-19 23:48:59.633234499 +0100
@@ -220,7 +220,7 @@
           /* U+00D7 MULTIPLICATION SIGN */
           is = for_character ("\241\301", 2);
           ASSERT (is == 0);
-        #if !(defined __FreeBSD__ || defined __DragonFly__ || defined __sun)
+        #if !((defined __APPLE__ && defined __MACH__) || defined __FreeBSD__ || defined __DragonFly__ || defined __sun)
           /* U+00D8 LATIN CAPITAL LETTER O WITH STROKE */
           is = for_character ("\201\060\211\061", 4);
           ASSERT (is != 0);
diff -ru tests/test-c32isgraph.c tests/test-c32isgraph.c
--- tests/test-c32isgraph.c	2024-09-12 00:03:55.000000000 +0100
+++ tests/test-c32isgraph.c	2025-04-19 23:49:55.305068441 +0100
@@ -124,7 +124,7 @@
           is = for_character ("\240", 1);
           ASSERT (is != 0);
         #endif
-        #if !(defined __FreeBSD__ || defined __DragonFly__)
+        #if !((defined __APPLE__ && defined __MACH__) || defined __FreeBSD__ || defined __DragonFly__)
           /* U+00B8 CEDILLA */
           is = for_character ("\270", 1);
           ASSERT (is != 0);
@@ -209,7 +209,7 @@
           is = for_character ("\201\060\204\062", 4);
           ASSERT (is != 0);
         #endif
-        #if !(defined __FreeBSD__ || defined __DragonFly__ || defined __sun)
+        #if !((defined __APPLE__ && defined __MACH__) || defined __FreeBSD__ || defined __DragonFly__ || defined __sun)
           /* U+00B8 CEDILLA */
           is = for_character ("\201\060\206\060", 4);
           ASSERT (is != 0);
diff -ru tests/test-c32islower.c tests/test-c32islower.c
--- tests/test-c32islower.c	2024-09-12 00:03:55.000000000 +0100
+++ tests/test-c32islower.c	2025-04-19 23:59:49.259296282 +0100
@@ -285,7 +285,7 @@
           /* U+00C9 LATIN CAPITAL LETTER E WITH ACUTE */
           is = for_character ("\201\060\207\067", 4);
           ASSERT (is == 0);
-        #if !(defined __FreeBSD__ || defined __DragonFly__ || defined __sun)
+        #if !((defined __APPLE__ && defined __MACH__) || defined __FreeBSD__ || defined __DragonFly__ || defined __sun)
           /* U+00DF LATIN SMALL LETTER SHARP S */
           is = for_character ("\201\060\211\070", 4);
           ASSERT (is != 0);
@@ -295,7 +295,7 @@
           is = for_character ("\250\246", 2);
           ASSERT (is != 0);
         #endif
-        #if !(defined __FreeBSD__ || defined __DragonFly__ || defined __sun)
+        #if !((defined __APPLE__ && defined __MACH__) || defined __FreeBSD__ || defined __DragonFly__ || defined __sun)
           /* U+00FF LATIN SMALL LETTER Y WITH DIAERESIS */
           is = for_character ("\201\060\213\067", 4);
           ASSERT (is != 0);
@@ -303,7 +303,7 @@
           /* U+0141 LATIN CAPITAL LETTER L WITH STROKE */
           is = for_character ("\201\060\221\071", 4);
           ASSERT (is == 0);
-        #if !(defined __FreeBSD__ || defined __DragonFly__ || defined __sun)
+        #if !((defined __APPLE__ && defined __MACH__) || defined __FreeBSD__ || defined __DragonFly__ || defined __sun)
           /* U+0142 LATIN SMALL LETTER L WITH STROKE */
           is = for_character ("\201\060\222\060", 4);
           ASSERT (is != 0);
@@ -311,7 +311,7 @@
           /* U+0429 CYRILLIC CAPITAL LETTER SHCHA */
           is = for_character ("\247\273", 2);
           ASSERT (is == 0);
-        #if !(defined __FreeBSD__ || defined __DragonFly__)
+        #if !((defined __APPLE__ && defined __MACH__) || defined __FreeBSD__ || defined __DragonFly__)
           /* U+0449 CYRILLIC SMALL LETTER SHCHA */
           is = for_character ("\247\353", 2);
           ASSERT (is != 0);
diff -ru tests/test-c32isprint.c tests/test-c32isprint.c
--- tests/test-c32isprint.c	2024-09-12 00:03:55.000000000 +0100
+++ tests/test-c32isprint.c	2025-04-20 00:01:12.707047261 +0100
@@ -118,12 +118,12 @@
           /* U+007F <control> */
           is = for_character ("\177", 1);
           ASSERT (is == 0);
-        #if !(defined __FreeBSD__ || defined __DragonFly__ || defined __sgi || (defined _WIN32 && !defined __CYGWIN__))
+        #if !((defined __APPLE__ && defined __MACH__) || defined __FreeBSD__ || defined __DragonFly__ || defined __sgi || (defined _WIN32 && !defined __CYGWIN__))
           /* U+00A0 NO-BREAK SPACE */
           is = for_character ("\240", 1);
           ASSERT (is != 0);
         #endif
-        #if !(defined __FreeBSD__ || defined __DragonFly__)
+        #if !((defined __APPLE__ && defined __MACH__) || defined __FreeBSD__ || defined __DragonFly__)
           /* U+00B8 CEDILLA */
           is = for_character ("\270", 1);
           ASSERT (is != 0);
@@ -207,7 +207,7 @@
           /* U+007F <control> */
           is = for_character ("\177", 1);
           ASSERT (is == 0);
-        #if !(defined __FreeBSD__ || defined __DragonFly__ || defined __sun)
+        #if !((defined __APPLE__ && defined __MACH__) || defined __FreeBSD__ || defined __DragonFly__ || defined __sun)
           /* U+00A0 NO-BREAK SPACE */
           is = for_character ("\201\060\204\062", 4);
           ASSERT (is != 0);
@@ -223,7 +223,7 @@
           is = for_character ("\201\066\247\061", 4);
           ASSERT (is == 0);
         #endif
-        #if !(defined __FreeBSD__ || defined __DragonFly__)
+        #if !((defined __APPLE__ && defined __MACH__) || defined __FreeBSD__ || defined __DragonFly__)
           /* U+3000 IDEOGRAPHIC SPACE */
           is = for_character ("\241\241", 2);
           ASSERT (is != 0);
diff -ru tests/test-c32ispunct.c tests/test-c32ispunct.c
--- tests/test-c32ispunct.c	2024-09-12 00:03:55.000000000 +0100
+++ tests/test-c32ispunct.c	2025-04-20 00:04:02.230541354 +0100
@@ -150,12 +150,12 @@
       case '1':
         /* Locale encoding is ISO-8859-1 or ISO-8859-15.  */
         {
-        #if !(defined __FreeBSD__ || defined __DragonFly__)
+        #if !((defined __APPLE__ && defined __MACH__) || defined __FreeBSD__ || defined __DragonFly__)
           /* U+00BF INVERTED QUESTION MARK */
           is = for_character ("\277", 1);
           ASSERT (is != 0);
         #endif
-        #if !(defined __FreeBSD__ || defined __DragonFly__ || defined __sun)
+        #if !((defined __APPLE__ && defined __MACH__) || defined __FreeBSD__ || defined __DragonFly__ || defined __sun)
           /* U+00D7 MULTIPLICATION SIGN */
           is = for_character ("\327", 1);
           ASSERT (is != 0);
@@ -177,7 +177,7 @@
           is = for_character ("\217\242\304", 3);
           ASSERT (is != 0);
         #endif
-        #if !(defined __FreeBSD__ || defined __DragonFly__)
+        #if !((defined __APPLE__ && defined __MACH__) || defined __FreeBSD__ || defined __DragonFly__)
           /* U+00D7 MULTIPLICATION SIGN */
           is = for_character ("\241\337", 2);
           ASSERT (is != 0);
@@ -216,7 +216,7 @@
           /* U+00BF INVERTED QUESTION MARK */
           is = for_character ("\302\277", 2);
           ASSERT (is != 0);
-        #if !(defined __FreeBSD__ || defined __DragonFly__ || defined __sun)
+        #if !((defined __APPLE__ && defined __MACH__) || defined __FreeBSD__ || defined __DragonFly__ || defined __sun)
           /* U+00D7 MULTIPLICATION SIGN */
           is = for_character ("\303\227", 2);
           ASSERT (is != 0);
@@ -233,7 +233,7 @@
           /* U+05F3 HEBREW PUNCTUATION GERESH */
           is = for_character ("\327\263", 2);
           ASSERT (is != 0);
-        #if !(defined __FreeBSD__ || defined __DragonFly__ || defined __sun || (defined _WIN32 && !defined __CYGWIN__))
+        #if !((defined __APPLE__ && defined __MACH__) || defined __FreeBSD__ || defined __DragonFly__ || defined __sun || (defined _WIN32 && !defined __CYGWIN__))
           /* U+2192 RIGHTWARDS ARROW */
           is = for_character ("\342\206\222", 3);
           ASSERT (is != 0);
@@ -250,7 +250,7 @@
           /* U+10330 GOTHIC LETTER AHSA */
           is = for_character ("\360\220\214\260", 4);
           ASSERT (is == 0);
-        #if !(defined __FreeBSD__ || defined __DragonFly__ || defined __sun)
+        #if !((defined __APPLE__ && defined __MACH__) || defined __FreeBSD__ || defined __DragonFly__ || defined __sun)
           /* U+1D100 MUSICAL SYMBOL SINGLE BARLINE */
           is = for_character ("\360\235\204\200", 4);
           ASSERT (is != 0);
@@ -272,12 +272,12 @@
         return 77;
         #endif
         {
-        #if !(defined __FreeBSD__ || defined __DragonFly__ || defined __sun)
+        #if !((defined __APPLE__ && defined __MACH__) || defined __FreeBSD__ || defined __DragonFly__ || defined __sun)
           /* U+00BF INVERTED QUESTION MARK */
           is = for_character ("\201\060\206\067", 4);
           ASSERT (is != 0);
         #endif
-        #if !(defined __FreeBSD__ || defined __DragonFly__ || defined __sun)
+        #if !((defined __APPLE__ && defined __MACH__) || defined __FreeBSD__ || defined __DragonFly__ || defined __sun)
           /* U+00D7 MULTIPLICATION SIGN */
           is = for_character ("\241\301", 2);
           ASSERT (is != 0);
@@ -291,12 +291,12 @@
           /* U+0141 LATIN CAPITAL LETTER L WITH STROKE */
           is = for_character ("\201\060\221\071", 4);
           ASSERT (is == 0);
-        #if !(defined __FreeBSD__ || defined __DragonFly__ || defined __sun)
+        #if !((defined __APPLE__ && defined __MACH__) || defined __FreeBSD__ || defined __DragonFly__ || defined __sun)
           /* U+05F3 HEBREW PUNCTUATION GERESH */
           is = for_character ("\201\060\374\067", 4);
           ASSERT (is != 0);
         #endif
-        #if !(defined __FreeBSD__ || defined __DragonFly__ || defined __sun)
+        #if !((defined __APPLE__ && defined __MACH__) || defined __FreeBSD__ || defined __DragonFly__ || defined __sun)
           /* U+2192 RIGHTWARDS ARROW */
           is = for_character ("\241\372", 2);
           ASSERT (is != 0);
diff -ru tests/test-c32isspace.c tests/test-c32isspace.c
--- tests/test-c32isspace.c	2024-06-07 19:47:34.000000000 +0100
+++ tests/test-c32isspace.c	2025-04-20 00:04:38.958431743 +0100
@@ -175,12 +175,12 @@
           /* U+00B7 MIDDLE DOT */
           is = for_character ("\241\244", 2);
           ASSERT (is == 0);
-        #if !(defined __FreeBSD__ || defined __DragonFly__ || defined __sun)
+        #if !((defined __APPLE__ && defined __MACH__) || defined __FreeBSD__ || defined __DragonFly__ || defined __sun)
           /* U+2002 EN SPACE */
           is = for_character ("\201\066\243\070", 4);
           ASSERT (is != 0);
         #endif
-        #if !(defined __FreeBSD__ || defined __DragonFly__)
+        #if !((defined __APPLE__ && defined __MACH__) || defined __FreeBSD__ || defined __DragonFly__)
           /* U+3000 IDEOGRAPHIC SPACE */
           is = for_character ("\241\241", 2);
           ASSERT (is != 0);
diff -ru tests/test-c32isupper.c tests/test-c32isupper.c
--- tests/test-c32isupper.c	2024-06-07 19:47:34.000000000 +0100
+++ tests/test-c32isupper.c	2025-04-20 00:06:07.022168925 +0100
@@ -272,7 +272,7 @@
           /* U+00B5 MICRO SIGN */
           is = for_character ("\201\060\205\070", 4);
           ASSERT (is == 0);
-        #if !(defined __FreeBSD__ || defined __DragonFly__ || defined __sun)
+        #if !((defined __APPLE__ && defined __MACH__) || defined __FreeBSD__ || defined __DragonFly__ || defined __sun)
           /* U+00C9 LATIN CAPITAL LETTER E WITH ACUTE */
           is = for_character ("\201\060\207\067", 4);
           ASSERT (is != 0);
@@ -286,7 +286,7 @@
           /* U+00FF LATIN SMALL LETTER Y WITH DIAERESIS */
           is = for_character ("\201\060\213\067", 4);
           ASSERT (is == 0);
-        #if !(defined __FreeBSD__ || defined __DragonFly__ || defined __sun)
+        #if !((defined __APPLE__ && defined __MACH__) || defined __FreeBSD__ || defined __DragonFly__ || defined __sun)
           /* U+0141 LATIN CAPITAL LETTER L WITH STROKE */
           is = for_character ("\201\060\221\071", 4);
           ASSERT (is != 0);
@@ -294,7 +294,7 @@
           /* U+0142 LATIN SMALL LETTER L WITH STROKE */
           is = for_character ("\201\060\222\060", 4);
           ASSERT (is == 0);
-        #if !(defined __FreeBSD__ || defined __DragonFly__)
+        #if !((defined __APPLE__ && defined __MACH__) || defined __FreeBSD__ || defined __DragonFly__)
           /* U+0429 CYRILLIC CAPITAL LETTER SHCHA */
           is = for_character ("\247\273", 2);
           ASSERT (is != 0);
diff -ru tests/test-c32tolower.c tests/test-c32tolower.c
--- tests/test-c32tolower.c	2024-09-12 00:03:55.000000000 +0100
+++ tests/test-c32tolower.c	2025-04-20 00:06:55.310024815 +0100
@@ -349,7 +349,7 @@
           mb = for_character ("\201\060\205\070", 4);
           ASSERT (mb.nbytes == 4);
           ASSERT (memcmp (mb.buf, "\201\060\205\070", 4) == 0);
-        #if !(defined __FreeBSD__ || defined __DragonFly__ || defined __sun)
+        #if !((defined __APPLE__ && defined __MACH__) || defined __FreeBSD__ || defined __DragonFly__ || defined __sun)
           /* U+00C9 LATIN CAPITAL LETTER E WITH ACUTE */
           mb = for_character ("\201\060\207\067", 4);
           ASSERT (mb.nbytes == 2);
@@ -367,7 +367,7 @@
           mb = for_character ("\201\060\213\067", 4);
           ASSERT (mb.nbytes == 4);
           ASSERT (memcmp (mb.buf, "\201\060\213\067", 4) == 0);
-        #if !(defined __FreeBSD__ || defined __DragonFly__ || defined __sun)
+        #if !((defined __APPLE__ && defined __MACH__) || defined __FreeBSD__ || defined __DragonFly__ || defined __sun)
           /* U+0141 LATIN CAPITAL LETTER L WITH STROKE */
           mb = for_character ("\201\060\221\071", 4);
           ASSERT (mb.nbytes == 4);
@@ -377,7 +377,7 @@
           mb = for_character ("\201\060\222\060", 4);
           ASSERT (mb.nbytes == 4);
           ASSERT (memcmp (mb.buf, "\201\060\222\060", 4) == 0);
-        #if !(defined __FreeBSD__ || defined __DragonFly__)
+        #if !((defined __APPLE__ && defined __MACH__) || defined __FreeBSD__ || defined __DragonFly__)
           /* U+0429 CYRILLIC CAPITAL LETTER SHCHA */
           mb = for_character ("\247\273", 2);
           ASSERT (mb.nbytes == 2);
EOF
		
		./configure \
			--prefix="${_rehex_libunistring_target_dir}" \
			--with-libiconv-prefix="${_rehex_libiconv_target_dir}" \
			--enable-shared=no \
			--enable-static=yes \
			CFLAGS="${_rehex_arch_flags} -mmacosx-version-min=${_rehex_macos_version_min}"
		
		make -j$(sysctl -n hw.logicalcpu)
		make -j$(sysctl -n hw.logicalcpu) check
		make -j$(sysctl -n hw.logicalcpu) install
	)
	
	[ $? -ne 0 ] && _rehex_ok=0
fi

if [ "$_rehex_ok" = 1 ] && [ ! -e "$_rehex_lua_target_dir" ]
then
	echo "== Preparing Lua ${_rehex_lua_version}"
	
	(
		set -e
		
		cd "${_rehex_dep_build_dir}"
		
		_rehex_lua_tar="$(basename "${_rehex_lua_url}")"
		
		if [ ! -e "${_rehex_dep_build_dir}/${_rehex_lua_tar}" ]
		then
			echo "Downloading ${_rehex_lua_url}"
			curl -Lo "${_rehex_lua_tar}" "${_rehex_lua_url}"
		fi
		
		echo "${_rehex_lua_sha256}  ${_rehex_lua_tar}" | shasum -c
		
		mkdir -p "lua-${_rehex_lua_build_ident}"
		
		tar -xf "${_rehex_lua_tar}" -C "lua-${_rehex_lua_build_ident}"
		cd "lua-${_rehex_lua_build_ident}/lua-${_rehex_lua_version}"
		
		make -j$(sysctl -n hw.logicalcpu) macosx MYCFLAGS="${_rehex_arch_flags} -mmacosx-version-min=${_rehex_macos_version_min}"
		make -j$(sysctl -n hw.logicalcpu) test
		make -j$(sysctl -n hw.logicalcpu) install INSTALL_TOP="${_rehex_lua_target_dir}"
		
		cd "../../"
		
		echo "== Installing LuaRocks ${_rehex_luarocks_version}"
		
		_rehex_luarocks_tar="$(basename "${_rehex_luarocks_url}")"
		
		if [ ! -e "${_rehex_dep_build_dir}/${_rehex_luarocks_tar}" ]
		then
			echo "Downloading ${_rehex_luarocks_url}"
			curl -Lo "${_rehex_luarocks_tar}" "${_rehex_luarocks_url}"
		fi
		
		echo "${_rehex_luarocks_sha256}  ${_rehex_luarocks_tar}" | shasum -c
		
		tar -xf "${_rehex_luarocks_tar}" -C "lua-${_rehex_lua_build_ident}"
		cd "lua-${_rehex_lua_build_ident}/luarocks-${_rehex_luarocks_version}"
		
		./configure --prefix="${_rehex_lua_target_dir}" --with-lua="${_rehex_lua_target_dir}"
		make
		make install
		
		echo "== Installing Busted"
		
		"${_rehex_lua_target_dir}/bin/luarocks" \
			--lua-dir="${_rehex_lua_target_dir}" \
			--tree="${_rehex_lua_target_dir}" \
			--global \
			install busted
	)
	
	[ $? -ne 0 ] && _rehex_ok=0
fi

if [ "$_rehex_ok" = 1 ] && [ ! -e "$_rehex_wxwidgets_target_dir" ]
then
	echo "== Preparing wxWidgets ${_rehex_wxwidgets_version}"
	
	(
		set -e
		
		cd "${_rehex_dep_build_dir}"
		
		_rehex_wxwidgets_tar="$(basename "${_rehex_wxwidgets_url}")"
		
		if [ ! -e "${_rehex_dep_build_dir}/${_rehex_wxwidgets_tar}" ]
		then
			echo "Downloading ${_rehex_wxwidgets_url}"
			curl -Lo "${_rehex_wxwidgets_tar}" "${_rehex_wxwidgets_url}"
		fi
		
		echo "${_rehex_wxwidgets_sha256}  ${_rehex_wxwidgets_tar}" | shasum -c
		
		mkdir -p "wxwidgets-${_rehex_wxwidgets_build_ident}"
		
		tar -xf "${_rehex_wxwidgets_tar}" -C "wxwidgets-${_rehex_wxwidgets_build_ident}"
		cd "wxwidgets-${_rehex_wxwidgets_build_ident}/wxWidgets-${_rehex_wxwidgets_version}"
		
		# Workaround for https://github.com/wxWidgets/wxWidgets/issues/24560
		patch <<'EOF'
--- src/osx/cocoa/toolbar.mm	2024-05-28 00:56:37
+++ src/osx/cocoa/toolbar.mm	2024-05-28 00:57:38
@@ -970,8 +970,8 @@
         if (curToolbarRef == NULL)
         {
             bResult = true;
-            [tlw setToolbar:(NSToolbar*) m_macToolbar];
             [(NSToolbar*) m_macToolbar setVisible:YES];
+            [tlw setToolbar:(NSToolbar*) m_macToolbar];
 
             GetPeer()->Move(0,0,0,0 );
             SetSize( wxSIZE_AUTO_WIDTH, 0 );
EOF
		
		# https://github.com/wxWidgets/wxWidgets/pull/24961
		patch <<'EOF'
--- include/wx/osx/cocoa/private.h
+++ include/wx/osx/cocoa/private.h
@@ -546,6 +546,7 @@ WX_NSCursor  wxMacCocoaCreateCursorFromCGImage( CGImageRef cgImageRef, float hot
 void  wxMacCocoaSetCursor( WX_NSCursor cursor );
 void  wxMacCocoaHideCursor();
 void  wxMacCocoaShowCursor();
+wxPoint  wxMacCocoaGetCursorHotSpot( WX_NSCursor cursor );
 
 typedef struct tagClassicCursor
 {
--- include/wx/osx/cursor.h
+++ include/wx/osx/cursor.h
@@ -33,6 +33,8 @@ public:
     void SetHCURSOR(WXHCURSOR cursor);
     WXHCURSOR GetHCURSOR() const;
 
+    virtual wxPoint GetHotSpot() const override;
+
 protected:
     virtual wxGDIRefData *CreateGDIRefData() const override;
     virtual wxGDIRefData *CloneGDIRefData(const wxGDIRefData *data) const override;
--- src/osx/carbon/cursor.cpp
+++ src/osx/carbon/cursor.cpp
@@ -341,6 +341,16 @@ void wxCursor::MacInstall() const
 #endif
 }
 
+wxPoint wxCursor::GetHotSpot() const
+{
+#if wxOSX_USE_COCOA
+    if ( IsOk() )
+        return wxMacCocoaGetCursorHotSpot( M_CURSORDATA->m_hCursor );
+#endif
+
+    return wxDefaultPosition;
+}
+
 // Global cursor setting
 wxCursor gGlobalCursor;
 void wxSetCursor(const wxCursor& cursor)
diff --git a/src/osx/carbon/utilscocoa.mm b/src/osx/carbon/utilscocoa.mm
index dc24410d7f..ab963937d0 100644
--- src/osx/carbon/utilscocoa.mm
+++ src/osx/carbon/utilscocoa.mm
@@ -671,6 +671,11 @@ void  wxMacCocoaShowCursor()
 {
     [NSCursor unhide];
 }
+
+wxPoint wxMacCocoaGetCursorHotSpot(WX_NSCursor cursor)
+{
+    return wxPoint([cursor hotSpot].x, [cursor hotSpot].y);
+}
 #endif
 
 //---------------------------------------------------------
EOF
		
		# https://github.com/wxWidgets/wxWidgets/pull/24962
		patch <<'EOF'
--- src/osx/cocoa/settings.mm
+++ src/osx/cocoa/settings.mm
@@ -221,6 +221,21 @@ wxFont wxSystemSettingsNative::GetFont(wxSystemFont index)
 // system metrics/features
 // ----------------------------------------------------------------------------
 
+static float GetCursorScale()
+{
+    NSDictionary *dict = [[NSUserDefaults standardUserDefaults] persistentDomainForName:@"com.apple.universalaccess"];
+
+    /* https://developer.apple.com/documentation/devicemanagement/accessibility?language=objc */
+    if([dict objectForKey: @"mouseDriverCursorSize"])
+    {
+        return [dict[@"mouseDriverCursorSize"] floatValue];
+    }
+    else
+    {
+        return 1.0f;
+    }
+}
+
 // Get a system metric, e.g. scrollbar size
 int wxSystemSettingsNative::GetMetric(wxSystemMetric index, const wxWindow* WXUNUSED(win))
 {
@@ -233,8 +248,6 @@ int wxSystemSettingsNative::GetMetric(wxSystemMetric index, const wxWindow* WXUN
 
         // TODO case wxSYS_BORDER_X:
         // TODO case wxSYS_BORDER_Y:
-        // TODO case wxSYS_CURSOR_X:
-        // TODO case wxSYS_CURSOR_Y:
         // TODO case wxSYS_DCLICK_X:
         // TODO case wxSYS_DCLICK_Y:
         // TODO case wxSYS_DRAG_X:
@@ -242,6 +255,11 @@ int wxSystemSettingsNative::GetMetric(wxSystemMetric index, const wxWindow* WXUN
         // TODO case wxSYS_EDGE_X:
         // TODO case wxSYS_EDGE_Y:
 
+        case wxSYS_CURSOR_X:
+            return wxRound((float)([[[NSCursor arrowCursor] image] size].width) * GetCursorScale());
+        case wxSYS_CURSOR_Y:
+            return wxRound((float)([[[NSCursor arrowCursor] image] size].height) * GetCursorScale());
+
         case wxSYS_HSCROLL_ARROW_X:
             return 16;
         case wxSYS_HSCROLL_ARROW_Y:
EOF
		
		./configure \
			--prefix="${_rehex_wxwidgets_target_dir}" \
			--with-libiconv-prefix="${_rehex_libiconv_target_dir}" \
			--disable-shared \
			--enable-unicode \
			--with-libjpeg=no \
			--with-libpng=builtin \
			--with-libtiff=no \
			--with-regex=builtin \
			--with-liblzma=no \
			--enable-universal_binary=x86_64,arm64 \
			-enable-cxx11 \
			-with-macosx-version-min="${_rehex_macos_version_min}" \
			CXXFLAGS="-stdlib=libc++" \
			CPPFLAGS="-stdlib=libc++" \
			LIBS=-lc++
		
		make -j$(sysctl -n hw.logicalcpu)
		make -j$(sysctl -n hw.logicalcpu) install
	)
	
	[ $? -ne 0 ] && _rehex_ok=0
fi

if [ "$_rehex_ok" = 1 ] && [ ! -e "$_rehex_perl_libs_target_dir" ]
then
	echo "== Preparing Template Toolkit (for manual generation)"
	
	(
		set -e
		
		cd "${_rehex_dep_build_dir}"
		
		_rehex_cpanm_tar="$(basename "${_rehex_cpanm_url}")"
		
		if [ ! -e "${_rehex_dep_build_dir}/${_rehex_cpanm_tar}" ]
		then
			echo "Downloading ${_rehex_cpanm_url}"
			curl -Lo "${_rehex_cpanm_tar}" "${_rehex_cpanm_url}"
		fi
		
		echo "${_rehex_cpanm_sha256}  ${_rehex_cpanm_tar}" | shasum -c
		
		mkdir -p "cpanm-${_rehex_cpanm_build_ident}"
		
		tar -xf "${_rehex_cpanm_tar}" -C "cpanm-${_rehex_cpanm_build_ident}"
		
		CPANM="$(echo "cpanm-${_rehex_cpanm_build_ident}/"*"/bin/cpanm")"
		
		if [ ! -e "$CPANM" ]
		then
			echo "ERROR: cpanm not found!" 2>&1
			exit 1
		fi
		
		perl "$CPANM" -l "$_rehex_perl_libs_target_dir" Template
	)
	
	[ $? -ne 0 ] && _rehex_ok=0
fi

if [ "$_rehex_ok" = 1 ]
then
	cat <<EOF

All done!

You can now build rehex using \`make -f Makefile.osx\` in this shell.

The dependencies have been cached and won't be rebuilt if you source this
script again.
EOF
	export BOTAN_PKG="botan-2" # used to determine required -std= for C++
	export BOTAN_LIBS="-L${_rehex_botan_target_dir}/lib/ -lbotan-2"
	export BOTAN_CFLAGS="-I${_rehex_botan_target_dir}/include/botan-2/"

	export CAPSTONE_LIBS="-L${_rehex_capstone_target_dir}/lib/ -lcapstone"
	export CAPSTONE_CFLAGS="-I${_rehex_capstone_target_dir}/include/"
	
	export JANSSON_LIBS="-L${_rehex_jansson_target_dir}/lib/ -ljansson"
	export JANSSON_CFLAGS="-I${_rehex_jansson_target_dir}/include/"
	
	export LUA="${_rehex_lua_target_dir}/bin/lua"
	export LUA_LIBS="-L${_rehex_lua_target_dir}/lib/ -llua"
	export LUA_CFLAGS="-I${_rehex_lua_target_dir}/include/"
	export BUSTED="${_rehex_lua_target_dir}/bin/busted"
	
	export WX_CONFIG="${_rehex_wxwidgets_target_dir}/bin/wx-config"
	
	export CFLAGS="${_rehex_arch_flags} -mmacosx-version-min=${_rehex_macos_version_min}"
	export CXXFLAGS="-I${_rehex_libiconv_target_dir}/include/ -I${_rehex_libunistring_target_dir}/include/ ${_rehex_arch_flags} -mmacosx-version-min=${_rehex_macos_version_min}"
	export LDFLAGS="-L${_rehex_libiconv_target_dir}/lib/ -L${_rehex_libunistring_target_dir}/lib/"
	export LDLIBS="-liconv -lunistring"
	
	export PERL="perl -I\"$(dirname "$(find "${_rehex_perl_libs_target_dir}" -name Template.pm)")\""
fi

unset _rehex_perl_libs_target_dir
unset _rehex_wxwidgets_target_dir
unset _rehex_lua_target_dir
unset _rehex_libunistring_target_dir
unset _rehex_libiconv_target_dir
unset _rehex_jansson_target_dir
unset _rehex_capstone_target_dir
unset _rehex_botan_target_dir

unset _rehex_dep_target_dir
unset _rehex_dep_build_dir
unset _rehex_ok
unset _rehex_arch_flags
unset _rehex_macos_version_min

unset _rehex_perl_libs_build_ident
unset _rehex_cpanm_sha256
unset _rehex_cpanm_url
unset _rehex_cpanm_version

unset _rehex_wxwidgets_build_ident
unset _rehex_wxwidgets_sha256
unset _rehex_wxwidgets_url
unset _rehex_wxwidgets_version

unset _rehex_luarocks_sha256
unset _rehex_luarocks_url
unset _rehex_luarocks_version

unset _rehex_lua_build_ident
unset _rehex_lua_sha256
unset _rehex_lua_url
unset _rehex_lua_version

unset _rehex_libunistring_build_ident
unset _rehex_libunistring_sha256
unset _rehex_libunistring_url
unset _rehex_libunistring_version

unset _rehex_libiconv_build_ident
unset _rehex_libiconv_sha256
unset _rehex_libiconv_url
unset _rehex_libiconv_version

unset _rehex_jansson_build_ident
unset _rehex_jansson_sha256
unset _rehex_jansson_url
unset _rehex_jansson_version

unset _rehex_capstone_build_ident
unset _rehex_capstone_sha256
unset _rehex_capstone_url
unset _rehex_capstone_version

unset _rehex_botan_build_ident
unset _rehex_botan_sha256
unset _rehex_botan_url
unset _rehex_botan_version
