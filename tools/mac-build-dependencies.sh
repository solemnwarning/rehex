# Reverse Engineer's Hex Editor
# Copyright (C) 2021-2026 Daniel Collins <solemnwarning@solemnwarning.net>
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

_rehex_capstone_version="5.0.6"
_rehex_capstone_url="https://github.com/capstone-engine/capstone/releases/download/${_rehex_capstone_version}/capstone-${_rehex_capstone_version}.tar.xz"
_rehex_capstone_sha256="98773eea590f19355fa7e41157109eaad9771d771f426f276b06eaed40d1e47d"
_rehex_capstone_build_ident="${_rehex_capstone_version}-1"

_rehex_jansson_version="2.14"
_rehex_jansson_url="https://github.com/akheron/jansson/releases/download/v${_rehex_jansson_version}/jansson-${_rehex_jansson_version}.tar.gz"
_rehex_jansson_sha256="5798d010e41cf8d76b66236cfb2f2543c8d082181d16bc3085ab49538d4b9929"
_rehex_jansson_build_ident="${_rehex_jansson_version}-2"

_rehex_libiconv_version="1.18"
_rehex_libiconv_url="https://ftp.gnu.org/pub/gnu/libiconv/libiconv-${_rehex_libiconv_version}.tar.gz"
_rehex_libiconv_sha256="3b08f5f4f9b4eb82f151a7040bfd6fe6c6fb922efe4b1659c66ea933276965e8"
_rehex_libiconv_build_ident="${_rehex_libiconv_version}-1"

_rehex_libunistring_version="1.3"
_rehex_libunistring_url="https://ftp.gnu.org/gnu/libunistring/libunistring-${_rehex_libunistring_version}.tar.gz"
_rehex_libunistring_sha256="8ea8ccf86c09dd801c8cac19878e804e54f707cf69884371130d20bde68386b7"
_rehex_libunistring_build_ident="${_rehex_libunistring_version}-1"

_rehex_lua_version="5.3.6"
_rehex_lua_url="https://www.lua.org/ftp/lua-${_rehex_lua_version}.tar.gz"
_rehex_lua_sha256="fc5fd69bb8736323f026672b1b7235da613d7177e72558893a0bdcd320466d60"
_rehex_lua_build_ident="${_rehex_lua_version}-7"

_rehex_luarocks_version="3.8.0"
_rehex_luarocks_url="https://luarocks.org/releases/luarocks-${_rehex_luarocks_version}.tar.gz"
_rehex_luarocks_sha256="56ab9b90f5acbc42eb7a94cf482e6c058a63e8a1effdf572b8b2a6323a06d923"

_rehex_wxwidgets_version="3.2.10"
_rehex_wxwidgets_url="https://github.com/wxWidgets/wxWidgets/releases/download/v${_rehex_wxwidgets_version}/wxWidgets-${_rehex_wxwidgets_version}.tar.bz2"
_rehex_wxwidgets_sha256="d66e929569947a4a5920699539089a9bda83a93e5f4917fb313a61f0c344b896"
_rehex_wxwidgets_build_ident="${_rehex_wxwidgets_version}-1"

_rehex_cpanm_version="1.7044"
_rehex_cpanm_url="https://cpan.metacpan.org/authors/id/M/MI/MIYAGAWA/App-cpanminus-${_rehex_cpanm_version}.tar.gz"
_rehex_cpanm_sha256="9b60767fe40752ef7a9d3f13f19060a63389a5c23acc3e9827e19b75500f81f3"
_rehex_perl_libs_build_ident="2"

_rehex_macos_version_min=10.13

if which python3 > /dev/null 2>&1
then
	_rehex_python=python3
else
	_rehex_python=python
fi

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

if [ -n "$REHEX_BUILD_ARCH" ]
then
	if [ "$REHEX_BUILD_ARCH" != "arm64" ] && [ "$REHEX_BUILD_ARCH" != "x86_64" ]
	then
		echo "ERROR: Unsupported architecture in REHEX_BUILD_ARCH environment variable (expected 'arm64' or 'x86_64')" 1>&2
		_rehex_ok=0
	fi
	
	_rehex_arch_flags="-arch $REHEX_BUILD_ARCH"
	_rehex_arch_suffix="-${REHEX_BUILD_ARCH}"
else
	_rehex_arch_flags="-arch arm64 -arch x86_64"
	_rehex_arch_suffix=
fi

_rehex_botan_target_dir="${_rehex_dep_target_dir}/botan-${_rehex_botan_build_ident}${_rehex_arch_suffix}"
_rehex_capstone_target_dir="${_rehex_dep_target_dir}/capstone-${_rehex_capstone_build_ident}${_rehex_arch_suffix}"
_rehex_jansson_target_dir="${_rehex_dep_target_dir}/jansson-${_rehex_jansson_build_ident}${_rehex_arch_suffix}"
_rehex_libiconv_target_dir="${_rehex_dep_target_dir}/libiconv-${_rehex_libiconv_build_ident}${_rehex_arch_suffix}"
_rehex_libunistring_target_dir="${_rehex_dep_target_dir}/libunistring-${_rehex_libunistring_build_ident}${_rehex_arch_suffix}"
_rehex_lua_target_dir="${_rehex_dep_target_dir}/lua-${_rehex_lua_build_ident}${_rehex_arch_suffix}"
_rehex_wxwidgets_target_dir="${_rehex_dep_target_dir}/wxwidgets-${_rehex_wxwidgets_build_ident}${_rehex_arch_suffix}"
_rehex_perl_libs_target_dir="${_rehex_dep_target_dir}/perl-libs-${_rehex_perl_libs_build_ident}${_rehex_arch_suffix}"

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
		
		if [ -z "${_rehex_arch_suffix}" ] || [ "${_rehex_arch_suffix}" = "-x86_64" ]
		then
			echo "Building Botan for x86_64"
	
			mkdir -p "botan-${_rehex_botan_build_ident}-x86_64"
	
			tar -xf "${_rehex_botan_tar}" -C "botan-${_rehex_botan_build_ident}-x86_64"
			pushd "botan-${_rehex_botan_build_ident}-x86_64/Botan-${_rehex_botan_version}"
	
			"${_rehex_python}" configure.py \
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
			
			if [ -z "${_rehex_arch_suffix}" ]
			then
				make -j$(sysctl -n hw.logicalcpu) DESTDIR=tmp install
			else
				make -j$(sysctl -n hw.logicalcpu) install
			fi
			
			popd
		fi
		
		# Build Botan for ARM64 ("Apple Silicon")
		
		if [ -z "${_rehex_arch_suffix}" ] || [ "${_rehex_arch_suffix}" = "-arm64" ]
		then
			echo "Building Botan for ARM64"
			
			mkdir -p "botan-${_rehex_botan_build_ident}-arm64"
	
			tar -xf "${_rehex_botan_tar}" -C "botan-${_rehex_botan_build_ident}-arm64"
			pushd "botan-${_rehex_botan_build_ident}-arm64/Botan-${_rehex_botan_version}"
	
			"${_rehex_python}" configure.py \
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
			
			if [ -z "${_rehex_arch_suffix}" ]
			then
				make -j$(sysctl -n hw.logicalcpu) DESTDIR=tmp install
			else
				make -j$(sysctl -n hw.logicalcpu) install
			fi
			
			popd
		fi
		
		if [ -z "${_rehex_arch_suffix}" ]
		then
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
		fi
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
		
		mkdir -p "capstone-${_rehex_capstone_build_ident}${_rehex_arch_suffix}"
		
		tar -xf "${_rehex_capstone_tar}" -C "capstone-${_rehex_capstone_build_ident}${_rehex_arch_suffix}"
		cd "capstone-${_rehex_capstone_build_ident}${_rehex_arch_suffix}/capstone-${_rehex_capstone_version}"
		
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
		
		mkdir -p "jansson-${_rehex_jansson_build_ident}${_rehex_arch_suffix}"
		
		tar -xf "${_rehex_jansson_tar}" -C "jansson-${_rehex_jansson_build_ident}${_rehex_arch_suffix}"
		cd "jansson-${_rehex_jansson_build_ident}${_rehex_arch_suffix}/jansson-${_rehex_jansson_version}"
		
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

		mkdir -p "libiconv-${_rehex_libiconv_build_ident}${_rehex_arch_suffix}"

		tar -xf "${_rehex_libiconv_tar}" -C "libiconv-${_rehex_libiconv_build_ident}${_rehex_arch_suffix}"
		cd "libiconv-${_rehex_libiconv_build_ident}${_rehex_arch_suffix}/libiconv-${_rehex_libiconv_version}"

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
		
		mkdir -p "libunistring-${_rehex_libunistring_build_ident}${_rehex_arch_suffix}"
		
		tar -xf "${_rehex_libunistring_tar}" -C "libunistring-${_rehex_libunistring_build_ident}${_rehex_arch_suffix}"
		cd "libunistring-${_rehex_libunistring_build_ident}${_rehex_arch_suffix}/libunistring-${_rehex_libunistring_version}"
		
		# https://savannah.gnu.org/bugs/?67007
		# https://git.savannah.gnu.org/gitweb/?p=gnulib.git;a=commit;h=b49212bd6ce6182d95af45d490d4de9f84bcc223
		patch -p0 <<'EOF'
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
		
		mkdir -p "lua-${_rehex_lua_build_ident}${_rehex_arch_suffix}"
		
		tar -xf "${_rehex_lua_tar}" -C "lua-${_rehex_lua_build_ident}${_rehex_arch_suffix}"
		cd "lua-${_rehex_lua_build_ident}${_rehex_arch_suffix}/lua-${_rehex_lua_version}"
		
		make -j$(sysctl -n hw.logicalcpu) macosx \
			MYCFLAGS="${_rehex_arch_flags} -mmacosx-version-min=${_rehex_macos_version_min}" \
			MYLDFLAGS="${_rehex_arch_flags} -mmacosx-version-min=${_rehex_macos_version_min}"
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
		
		tar -xf "${_rehex_luarocks_tar}" -C "lua-${_rehex_lua_build_ident}${_rehex_arch_suffix}"
		cd "lua-${_rehex_lua_build_ident}${_rehex_arch_suffix}/luarocks-${_rehex_luarocks_version}"
		
		./configure --prefix="${_rehex_lua_target_dir}" --with-lua="${_rehex_lua_target_dir}"
		make
		make install
		
		echo "== Installing Busted"
		
		"${_rehex_lua_target_dir}/bin/luarocks" \
			CFLAGS="${_rehex_arch_flags} -mmacosx-version-min=${_rehex_macos_version_min}" \
			LIBFLAG="${_rehex_arch_flags} -mmacosx-version-min=${_rehex_macos_version_min} -undefined dynamic_lookup -all_load" \
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
		
		mkdir -p "wxwidgets-${_rehex_wxwidgets_build_ident}${_rehex_arch_suffix}"
		
		tar -xf "${_rehex_wxwidgets_tar}" -C "wxwidgets-${_rehex_wxwidgets_build_ident}${_rehex_arch_suffix}"
		cd "wxwidgets-${_rehex_wxwidgets_build_ident}${_rehex_arch_suffix}/wxWidgets-${_rehex_wxwidgets_version}"
		
		# Workaround for https://github.com/wxWidgets/wxWidgets/issues/24560
		patch -p0 <<'EOF'
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

	# https://github.com/wxWidgets/wxWidgets/commit/c8880e21b166efc0971bf2d6d770c2c17840807e
	patch -p0 <<'EOF'
--- include/wx/osx/toolbar.h	2025-05-25 18:15:56
+++ include/wx/osx/toolbar.h	2026-01-02 18:35:00
@@ -124,6 +124,11 @@
 #ifdef __WXOSX_IPHONE__
     WX_UIView m_macToolbar;
 #endif
+
+private:
+#if wxOSX_USE_NATIVE_TOOLBAR
+    wxString FormatToolId(const wxToolBarToolBase *tool) const;
+#endif
 };
 
 #endif // wxUSE_TOOLBAR
--- src/osx/cocoa/toolbar.mm	2025-05-25 18:15:56
+++ src/osx/cocoa/toolbar.mm	2026-01-02 18:38:27
@@ -439,8 +439,11 @@
 - (NSToolbarItem*) toolbar:(NSToolbar*) toolbar itemForItemIdentifier:(NSString*) itemIdentifier willBeInsertedIntoToolbar:(BOOL) flag
 {
     wxUnusedVar(toolbar);
-    wxToolBarTool* tool = (wxToolBarTool*) [itemIdentifier longLongValue];
-    if ( tool )
+
+    // This must be consistent with FormatToolId().
+    wxToolBarTool* tool = nullptr;
+    void* macToolbar;
+    if ( sscanf([itemIdentifier UTF8String], "%p:%p", &macToolbar, &tool) == 2 && tool )
     {
         wxNSToolbarItem* item = (wxNSToolbarItem*) tool->GetToolbarItemRef();
         if ( flag && tool->IsControl() )
@@ -1239,7 +1242,7 @@
                     }
                     else
                     {
-                        cfidentifier = wxCFStringRef(wxString::Format("%ld", (long)tool));
+                        cfidentifier = wxCFStringRef(FormatToolId(tool));
                         nsItemId = cfidentifier.AsNSString();
                     }
                     
@@ -1520,7 +1523,7 @@
 #if wxOSX_USE_NATIVE_TOOLBAR
                 if (m_macToolbar != NULL)
                 {
-                    wxString identifier = wxString::Format(wxT("%ld"), (long) tool);
+                    wxString identifier = FormatToolId(tool);
                     wxCFStringRef cfidentifier( identifier, wxFont::GetDefaultEncoding() );
                     wxNSToolbarItem* item = [[wxNSToolbarItem alloc] initWithItemIdentifier:cfidentifier.AsNSString() ];
                     [item setImplementation:tool];
@@ -1549,7 +1552,7 @@
                 WXWidget view = (WXWidget) tool->GetControl()->GetHandle() ;
                 wxCHECK_MSG( view, false, wxT("control must be non-NULL") );
 
-                wxString identifier = wxString::Format(wxT("%ld"), (long) tool);
+                wxString identifier = FormatToolId(tool);
                 wxCFStringRef cfidentifier( identifier, wxFont::GetDefaultEncoding() );
                 wxNSToolbarItem* item = [[wxNSToolbarItem alloc] initWithItemIdentifier:cfidentifier.AsNSString() ];
                 [item setImplementation:tool];
@@ -1706,9 +1709,14 @@
     wxCHECK_RET( tool, "invalid tool ID" );
     wxCHECK_RET( m_macToolbar, "toolbar must be non-NULL" );
 
-    wxString identifier = wxString::Format(wxT("%ld"), (long)tool);
+    wxString identifier = FormatToolId(tool);
     wxCFStringRef cfidentifier(identifier, wxFont::GetDefaultEncoding());
     [(NSToolbar*)m_macToolbar setSelectedItemIdentifier:cfidentifier.AsNSString()];
+}
+
+wxString wxToolBar::FormatToolId(const wxToolBarToolBase *tool) const
+{
+    return wxString::Format("%p:%p", m_macToolbar, tool);
 }
 #endif // wxOSX_USE_NATIVE_TOOLBAR
EOF

	# Fix for https://github.com/wxWidgets/wxWidgets/issues/26172
	patch -p1 <<'EOF'
commit e4ce307374f9998d92ea03ca12713aba0f30095b
Author: Vadim Zeitlin <vadim@wxwidgets.org>
Date:   Fri Feb 13 23:15:31 2026 +0100

    Ensure windows are destroyed before wxApp::OnExit() is called
    
    In some circumstances we could call wxApp::OnExit() before destroying
    the application windows, which violated the documented (and reasonably
    expected) behaviour.
    
    Fix this by adding a wrapper CallOnExit() function which destroys all
    windows before calling OnExit() and, for good measure, then does it
    again in case the user-overridden version of this function created more
    windows when it was called.
    
    This also has a nice side effect of freeing the user code from the need
    to call the base OnExit(), as it is now trivial and doesn't do anything
    any more.
    
    Finally, remove the WX_SUPPRESS_UNUSED_WARN hack from init.cpp and just
    use scope guard macro instead of an ad hoc helper class.
    
    See #26189.
    
    Closes #26172.

diff --git a/include/wx/app.h b/include/wx/app.h
index 5655105041..eec5ba2149 100644
--- a/include/wx/app.h
+++ b/include/wx/app.h
@@ -471,6 +471,10 @@ public:
     // returns true for GUI wxApp subclasses
     virtual bool IsGUI() const { return false; }
 
+    // Perform the always needed cleanup before and after calling possibly
+    // overridden OnExit().
+    int CallOnExit();
+
 
     // command line arguments (public for backwards compatibility)
     int argc;
@@ -491,6 +495,13 @@ protected:
     // called from ProcessPendingEvents()
     void DeletePendingObjects();
 
+    // Perform all delayed cleanup, including deleting the pending objects and
+    // anything else, e.g. the GUI version uses it to delete any remaining
+    // windows too.
+    //
+    // This function is safe to call multiple times.
+    virtual void DoDelayedCleanup();
+
     // the function which creates the traits object when GetTraits() needs it
     // for the first time
     virtual wxAppTraits *CreateTraits();
@@ -711,6 +722,9 @@ public:
     }
 
 protected:
+    // Override base class method to do the GUI-specific cleanup too.
+    virtual void DoDelayedCleanup() override;
+
     // override base class method to use GUI traits
     virtual wxAppTraits *CreateTraits() wxOVERRIDE;
 
diff --git a/include/wx/msw/mfc.h b/include/wx/msw/mfc.h
index 39c9ed4693..52f4e316ea 100644
--- a/include/wx/msw/mfc.h
+++ b/include/wx/msw/mfc.h
@@ -84,7 +84,7 @@ public:
         BaseApp::m_pMainWnd = NULL;
 
         if ( wxTheApp )
-            wxTheApp->OnExit();
+            wxTheApp->CallOnExit();
 
         wxEntryCleanup();
 
diff --git a/src/common/appbase.cpp b/src/common/appbase.cpp
index 4c30c5fd3d..461554fa0e 100644
--- a/src/common/appbase.cpp
+++ b/src/common/appbase.cpp
@@ -323,16 +323,29 @@ void wxAppConsoleBase::OnLaunched()
 
 int wxAppConsoleBase::OnExit()
 {
-    // Delete all pending objects first, they might use wxConfig to save their
-    // state during their destruction.
-    DeletePendingObjects();
+    return 0;
+}
+
+int wxAppConsoleBase::CallOnExit()
+{
+    // As we're not dispatching any events any more, it should be safe to
+    // delete all pending objects and all still existing TLWs now, as they
+    // won't get any events any more.
+    DoDelayedCleanup();
+
+    const int rc = OnExit();
+
+    // Delete all pending objects again, in case more of them were created
+    // inside OnExit(): they might use wxConfig to save their state during
+    // their destruction.
+    DoDelayedCleanup();
 
 #if wxUSE_CONFIG
     // Ensure we won't create it on demand any more if we hadn't done it yet.
     wxConfigBase::DontCreateOnDemand();
 #endif // wxUSE_CONFIG
 
-    return 0;
+    return rc;
 }
 
 void wxAppConsoleBase::Exit()
@@ -663,6 +676,11 @@ void wxAppConsoleBase::DeletePendingObjects()
     }
 }
 
+void wxAppConsoleBase::DoDelayedCleanup()
+{
+    DeletePendingObjects();
+}
+
 // ----------------------------------------------------------------------------
 // exception handling
 // ----------------------------------------------------------------------------
diff --git a/src/common/appcmn.cpp b/src/common/appcmn.cpp
index 6be5402ce2..f6178f87c1 100644
--- a/src/common/appcmn.cpp
+++ b/src/common/appcmn.cpp
@@ -139,16 +139,19 @@ void wxAppBase::DeleteAllTLWs()
     }
 }
 
-void wxAppBase::CleanUp()
+void wxAppBase::DoDelayedCleanup()
 {
-    // Clean up any still pending objects. Normally there shouldn't any as we
-    // already do this in OnExit(), but this could happen if the user code has
-    // somehow managed to create more of them since then or just forgot to call
-    // the base class OnExit().
-    DeletePendingObjects();
+    wxAppConsole::DoDelayedCleanup();
 
-    // and any remaining TLWs
     DeleteAllTLWs();
+}
+
+void wxAppBase::CleanUp()
+{
+    // Clean up any still pending objects. Normally there shouldn't any as we
+    // already do this in CallOnExit(), but this could happen if the user code
+    // has somehow managed to create more of them since then.
+    DoDelayedCleanup();
 
     // undo everything we did in Initialize() above
     wxBitmap::CleanUpHandlers();
diff --git a/src/common/init.cpp b/src/common/init.cpp
index 701447951f..1dc21585db 100644
--- a/src/common/init.cpp
+++ b/src/common/init.cpp
@@ -27,7 +27,9 @@
 #endif
 
 #include "wx/init.h"
+
 #include "wx/atomic.h"
+#include "wx/scopeguard.h"
 
 #include "wx/scopedptr.h"
 #include "wx/except.h"
@@ -111,15 +113,6 @@ private:
     wxAppConsole *m_app;
 };
 
-// ----------------------------------------------------------------------------
-// private functions
-// ----------------------------------------------------------------------------
-
-// suppress warnings about unused variables
-static inline void Use(void *) { }
-
-#define WX_SUPPRESS_UNUSED_WARN(x) Use(&x)
-
 // ----------------------------------------------------------------------------
 // initialization data
 // ----------------------------------------------------------------------------
@@ -485,13 +478,7 @@ int wxEntryReal(int& argc, wxChar **argv)
         }
 
         // ensure that OnExit() is called if OnInit() had succeeded
-        class CallOnExit
-        {
-        public:
-            ~CallOnExit() { wxTheApp->OnExit(); }
-        } callOnExit;
-
-        WX_SUPPRESS_UNUSED_WARN(callOnExit);
+        wxON_BLOCK_EXIT_OBJ0(*wxTheApp, wxAppConsoleBase::CallOnExit);
 
         // app execution
         return wxTheApp->OnRun();
diff --git a/src/msw/app.cpp b/src/msw/app.cpp
index f79a9c9b15..4c6ee9135c 100644
--- a/src/msw/app.cpp
+++ b/src/msw/app.cpp
@@ -847,14 +847,10 @@ void wxApp::OnEndSession(wxCloseEvent& WXUNUSED(event))
     if ( !wxTopLevelWindows.empty() )
         wxTopLevelWindows[0]->DissociateHandle();
 
-    // Destroy all the remaining TLWs before calling OnExit() to have the same
-    // sequence of events in this case as in case of the normal shutdown,
-    // otherwise we could have many problems due to wxApp being already
-    // destroyed when window cleanup code (in close event handlers or dtor) is
-    // executed.
-    DeleteAllTLWs();
-
-    const int rc = OnExit();
+    // Note that we survive after this call only because we don't delete any
+    // windows at MSW level, see gs_gotEndSession check in wxWindow dtor, even
+    // though CallOnExit() deletes all C++ top level window objects.
+    const int rc = CallOnExit();
 
     wxEntryCleanup();
 
EOF

		# Allow disabling wxWidgets's default behaviour of swallowing any
		# uncaught exceptions and turning them into a "successful" exit.
		#
		# This is a backport of the following commits from wxWidgets 3.3.x:
		#
		# 25f3a3f536af05b035cfa35faf1ebea3621f688a  Add static wxApp::CallOnUnhandledException() wrapper and use it
		# 5f0ca366883dc729482ac5fd8a9e7d53f8d2fb59  Use wxScopeGuard instead of try/catch in docview code
		# ec12651b9b1763d6cd41aaebab9c2b83b2246be1  Add wxSafeCall() function replacing wxTRY/wxCATCH_ALL macros
		# 819824bdb43541a66d087d9a551a047b3494e106  Add catch-unhandled-exception system option
		# c69cf3bc8779e4c1d395ee2cc86991efc85b625b  Cache the value of "catch-unhandled-exceptions" system option
		# e43d57fd405aaf84e86bed521f72e3d10febac75  Fix handling of exceptions thrown from event loop in wxOSX

		patch -p1 <<'EOF'
commit f39c3aee3be3ad7bb6b450872d67dc1644f889cc
Author: Vadim Zeitlin <vadim@wxwidgets.org>
Date:   Thu Mar 20 17:32:19 2025 +0100

    Add static wxApp::CallOnUnhandledException() wrapper and use it
    
    The new function simply checks if wxTheApp exists and calls
    OnUnhandledException() on it if it does. It also handles any exceptions
    thrown by the overridden OnUnhandledException(), which was previously
    done in a single place only but should be really done everywhere (or,
    alternatively, nowhere).
    
    Use it instead of calling OnUnhandledException() directly: an extra
    checks for wxTheApp should do no harm and may prevent a crash in some
    rare scenarios.

diff --git a/include/wx/app.h b/include/wx/app.h
index eec5ba2149..040e23e69d 100644
--- a/include/wx/app.h
+++ b/include/wx/app.h
@@ -302,6 +302,9 @@ public:
     // OnExceptionInMainLoop()
     virtual void OnUnhandledException();
 
+    // Call OnUnhandledException() on the current wxTheApp object if it exists.
+    static void CallOnUnhandledException();
+
     // Function called if an uncaught exception is caught inside the main
     // event loop: it may return true to continue running the event loop or
     // false to stop it. If this function rethrows the exception, as it does by
@@ -331,7 +334,11 @@ public:
     // The default version does nothing when using C++98 and uses
     // std::rethrow_exception() in C++11.
     virtual void RethrowStoredException();
-#endif // wxUSE_EXCEPTIONS
+#else // !wxUSE_EXCEPTIONS
+    // For convenience, still define this to allow the code using it to avoid
+    // checking for wxUSE_EXCEPTIONS.
+    static void CallOnUnhandledException() { }
+#endif // wxUSE_EXCEPTIONS/!wxUSE_EXCEPTIONS
 
 
     // pending events
diff --git a/interface/wx/app.h b/interface/wx/app.h
index 110fc553b4..b8bdc0b675 100644
--- a/interface/wx/app.h
+++ b/interface/wx/app.h
@@ -499,9 +499,29 @@ public:
 
         The default implementation dumps information about the exception using
         wxMessageOutputBest.
+
+        @note This function should _not_ throw any exceptions itself.
     */
     virtual void OnUnhandledException();
 
+    /**
+        Call OnUnhandledException() on the current wxTheApp object if it exists.
+
+        This function is used by wxWidgets itself and is usually not meant to
+        be called by the application code. If you do call it, it must be done
+        from a `catch` clause of a `try` block, i.e. there must be a currently
+        handled exception.
+
+        The function checks if ::wxTheApp is not @NULL and if it is, calls
+        OnUnhandledException() on it.
+
+        Additionally, if this call results in an exception, it is caught and
+        wxAppConsole::OnUnhandledException() is called.
+
+        @since 3.3.0
+     */
+    static void CallOnUnhandledException();
+
     /**
         Method to store exceptions not handled by OnExceptionInMainLoop().
 
diff --git a/src/common/appbase.cpp b/src/common/appbase.cpp
index 461554fa0e..068a0cf3ec 100644
--- a/src/common/appbase.cpp
+++ b/src/common/appbase.cpp
@@ -36,6 +36,7 @@
 #include "wx/cmdline.h"
 #include "wx/confbase.h"
 #include "wx/evtloop.h"
+#include "wx/except.h"
 #include "wx/filename.h"
 #include "wx/msgout.h"
 #include "wx/scopedptr.h"
@@ -742,6 +743,23 @@ void wxAppConsoleBase::OnUnhandledException()
     );
 }
 
+/* static */
+void wxAppConsoleBase::CallOnUnhandledException()
+{
+    if ( wxTheApp )
+    {
+        wxTRY
+        {
+            wxTheApp->OnUnhandledException();
+        }
+        // And OnUnhandledException() absolutely shouldn't throw,
+        // but we still must account for the possibility that it
+        // did. At least show some information about the exception
+        // in this case by calling our, non-overridden version.
+        wxCATCH_ALL( wxTheApp->wxAppConsoleBase::OnUnhandledException(); )
+    }
+}
+
 // ----------------------------------------------------------------------------
 // exceptions support
 // ----------------------------------------------------------------------------
diff --git a/src/common/event.cpp b/src/common/event.cpp
index 327f7e669f..406adf140b 100644
--- a/src/common/event.cpp
+++ b/src/common/event.cpp
@@ -1768,19 +1768,7 @@ void wxEvtHandler::WXConsumeException()
         // consistently everywhere.
         if ( !stored )
         {
-            try
-            {
-                if ( wxTheApp )
-                    wxTheApp->OnUnhandledException();
-            }
-            catch ( ... )
-            {
-                // And OnUnhandledException() absolutely shouldn't throw,
-                // but we still must account for the possibility that it
-                // did. At least show some information about the exception
-                // in this case.
-                wxTheApp->wxAppConsoleBase::OnUnhandledException();
-            }
+            wxApp::CallOnUnhandledException();
 
             wxAbort();
         }
diff --git a/src/common/init.cpp b/src/common/init.cpp
index 1dc21585db..1c06c93aba 100644
--- a/src/common/init.cpp
+++ b/src/common/init.cpp
@@ -483,7 +483,7 @@ int wxEntryReal(int& argc, wxChar **argv)
         // app execution
         return wxTheApp->OnRun();
     }
-    wxCATCH_ALL( wxTheApp->OnUnhandledException(); return -1; )
+    wxCATCH_ALL( wxApp::CallOnUnhandledException(); return -1; )
 }
 
 #if wxUSE_UNICODE
diff --git a/src/msw/thread.cpp b/src/msw/thread.cpp
index e684208820..203c998942 100644
--- a/src/msw/thread.cpp
+++ b/src/msw/thread.cpp
@@ -511,7 +511,7 @@ void wxThreadInternal::DoThreadOnExit(wxThread *thread)
     {
         thread->OnExit();
     }
-    wxCATCH_ALL( wxTheApp->OnUnhandledException(); )
+    wxCATCH_ALL( wxApp::CallOnUnhandledException(); )
 }
 
 /* static */
@@ -536,7 +536,7 @@ THREAD_RETVAL wxThreadInternal::DoThreadStart(wxThread *thread)
 
         rc = wxPtrToUInt(thread->Entry());
     }
-    wxCATCH_ALL( wxTheApp->OnUnhandledException(); )
+    wxCATCH_ALL( wxApp::CallOnUnhandledException(); )
 
     return rc;
 }
diff --git a/src/unix/threadpsx.cpp b/src/unix/threadpsx.cpp
index 7f920f76e2..f5a1c61ad2 100644
--- a/src/unix/threadpsx.cpp
+++ b/src/unix/threadpsx.cpp
@@ -929,7 +929,7 @@ void *wxThreadInternal::PthreadStart(wxThread *thread)
 #endif // HAVE_ABI_FORCEDUNWIND
         catch ( ... )
         {
-            wxTheApp->OnUnhandledException();
+            wxApp::CallOnUnhandledException();
         }
 #endif // !wxNO_EXCEPTIONS
 
@@ -1758,7 +1758,7 @@ void wxThread::Exit(ExitCode status)
     {
         OnExit();
     }
-    wxCATCH_ALL( wxTheApp->OnUnhandledException(); )
+    wxCATCH_ALL( wxApp::CallOnUnhandledException(); )
 
     // delete C++ thread object if this is a detached thread - user is
     // responsible for doing this for joinable ones
commit beb920e5b6d8a98e9526ed1ac40b341f53126829
Author: Vadim Zeitlin <vadim@wxwidgets.org>
Date:   Thu Mar 20 19:24:07 2025 +0100

    Use wxScopeGuard instead of try/catch in docview code
    
    Simplify the code and avoid having to catch the exceptions just to
    rethrow them by using wxScopeGuard.
    
    No real changes.
    
    This commit is best viewed ignoring whitespace-only changes.

diff --git a/src/common/docview.cpp b/src/common/docview.cpp
index 1389910312..20df1a95c8 100644
--- a/src/common/docview.cpp
+++ b/src/common/docview.cpp
@@ -57,7 +57,6 @@
 #include "wx/scopedarray.h"
 #include "wx/scopedptr.h"
 #include "wx/scopeguard.h"
-#include "wx/except.h"
 
 #if wxUSE_STD_IOSTREAM
     #include "wx/beforestd.h"
@@ -855,16 +854,8 @@ wxDocument *wxDocTemplate::CreateDocument(const wxString& path, long flags)
 bool
 wxDocTemplate::InitDocument(wxDocument* doc, const wxString& path, long flags)
 {
-    wxTRY
+    wxScopeGuard guard = wxMakeGuard([&, this]()
     {
-        doc->SetFilename(path);
-        doc->SetDocumentTemplate(this);
-        GetDocumentManager()->AddDocument(doc);
-        doc->SetCommandProcessor(doc->OnCreateCommandProcessor());
-
-        if ( doc->OnCreate(path, flags) )
-            return true;
-
         // The document may be already destroyed, this happens if its view
         // creation fails as then the view being created is destroyed
         // triggering the destruction of the document as this first view is
@@ -873,14 +864,19 @@ wxDocTemplate::InitDocument(wxDocument* doc, const wxString& path, long flags)
         // to clean it up ourselves to avoid having a zombie document.
         if ( GetDocumentManager()->GetDocuments().Member(doc) )
             doc->DeleteAllViews();
+    });
+
+    doc->SetFilename(path);
+    doc->SetDocumentTemplate(this);
+    GetDocumentManager()->AddDocument(doc);
+    doc->SetCommandProcessor(doc->OnCreateCommandProcessor());
 
+    if ( !doc->OnCreate(path, flags) )
         return false;
-    }
-    wxCATCH_ALL(
-        if ( GetDocumentManager()->GetDocuments().Member(doc) )
-            doc->DeleteAllViews();
-        throw;
-    )
+
+    guard.Dismiss();
+
+    return true;
 }
 
 wxView *wxDocTemplate::CreateView(wxDocument *doc, long flags)
@@ -1524,18 +1520,17 @@ wxDocument *wxDocManager::CreateDocument(const wxString& pathOrig, long flags)
 
     docNew->SetDocumentName(temp->GetDocumentName());
 
-    wxTRY
+    wxScopeGuard guard = wxMakeObjGuard(*docNew, &wxDocument::DeleteAllViews);
+
+    // call the appropriate function depending on whether we're creating a
+    // new file or opening an existing one
+    if ( !(flags & wxDOC_NEW ? docNew->OnNewDocument()
+                             : docNew->OnOpenDocument(path)) )
     {
-        // call the appropriate function depending on whether we're creating a
-        // new file or opening an existing one
-        if ( !(flags & wxDOC_NEW ? docNew->OnNewDocument()
-                                 : docNew->OnOpenDocument(path)) )
-        {
-            docNew->DeleteAllViews();
-            return NULL;
-        }
+        return NULL;
     }
-    wxCATCH_ALL( docNew->DeleteAllViews(); throw; )
+
+    guard.Dismiss();
 
     // add the successfully opened file to MRU, but only if we're going to be
     // able to reopen it successfully later which requires the template for
commit e05b59e52b65de053b8849d95de34d27127f030f
Author: Vadim Zeitlin <vadim@wxwidgets.org>
Date:   Thu Mar 20 19:04:56 2025 +0100

    Add wxSafeCall() function replacing wxTRY/wxCATCH_ALL macros
    
    The function is more readable and easier to debug and will also allow
    changing the behaviour of the code catching exceptions at run-time.

diff --git a/include/wx/evtloop.h b/include/wx/evtloop.h
index 257b7574dc..23f3b8bb54 100644
--- a/include/wx/evtloop.h
+++ b/include/wx/evtloop.h
@@ -254,6 +254,9 @@ protected:
     int m_exitcode;
 
 private:
+    // run the event loop until it exits, either normally or via exception
+    void DoRunLoop();
+
     // process all already pending events and dispatch a new one (blocking
     // until it appears in the event queue if necessary)
     //
diff --git a/include/wx/private/safecall.h b/include/wx/private/safecall.h
new file mode 100644
index 0000000000..d7f27177ec
--- /dev/null
+++ b/include/wx/private/safecall.h
@@ -0,0 +1,60 @@
+///////////////////////////////////////////////////////////////////////////////
+// Name:        wx/private/safecall.h
+// Purpose:     Call a function "safely", i.e. potentially catching exceptions.
+// Author:      Vadim Zeitlin
+// Created:     2025-03-20
+// Copyright:   (c) 2025 Vadim Zeitlin <vadim@wxwidgets.org>
+// Licence:     wxWindows licence
+///////////////////////////////////////////////////////////////////////////////
+
+#ifndef _WX_PRIVATE_SAFECALL_H_
+#define _WX_PRIVATE_SAFECALL_H_
+
+#include "wx/app.h"
+
+#if wxUSE_EXCEPTIONS
+
+// General version calls the given function or function-like object and
+// executes the provided handler if an exception is thrown.
+//
+// Both the function and the handler must return the value of the same type R,
+// possibly void.
+template <typename R, typename T1, typename T2>
+inline R wxSafeCall(const T1& func, const T2& handler)
+{
+    try
+    {
+        return func();
+    }
+    catch ( ... )
+    {
+        return handler();
+    }
+}
+
+// Simplified version for the common case when the function doesn't return
+// anything and we just want to call wxApp::OnUnhandledException() if it
+// throws.
+template <typename T>
+inline void wxSafeCall(const T& func)
+{
+    wxSafeCall<void>(func, wxApp::CallOnUnhandledException);
+}
+
+#else // !wxUSE_EXCEPTIONS
+
+template <typename R, typename T1, typename T2>
+inline R wxSafeCall(const T1& func, const T2& WXUNUSED(handler))
+{
+    return func();
+}
+
+template <typename T>
+inline void wxSafeCall(const T& func)
+{
+    func();
+}
+
+#endif // wxUSE_EXCEPTIONS/!wxUSE_EXCEPTIONS
+
+#endif // _WX_PRIVATE_SAFECALL_H_
diff --git a/src/common/appbase.cpp b/src/common/appbase.cpp
index 068a0cf3ec..f12332bea2 100644
--- a/src/common/appbase.cpp
+++ b/src/common/appbase.cpp
@@ -36,7 +36,6 @@
 #include "wx/cmdline.h"
 #include "wx/confbase.h"
 #include "wx/evtloop.h"
-#include "wx/except.h"
 #include "wx/filename.h"
 #include "wx/msgout.h"
 #include "wx/scopedptr.h"
@@ -45,6 +44,8 @@
 #include "wx/thread.h"
 #include "wx/stdpaths.h"
 
+#include "wx/private/safecall.h"
+
 #if wxUSE_EXCEPTIONS
     // Do we have a C++ compiler with enough C++11 support for
     // std::exception_ptr and functions working with it?
@@ -748,15 +749,17 @@ void wxAppConsoleBase::CallOnUnhandledException()
 {
     if ( wxTheApp )
     {
-        wxTRY
+        wxSafeCall<void>([]()
         {
             wxTheApp->OnUnhandledException();
-        }
-        // And OnUnhandledException() absolutely shouldn't throw,
-        // but we still must account for the possibility that it
-        // did. At least show some information about the exception
-        // in this case by calling our, non-overridden version.
-        wxCATCH_ALL( wxTheApp->wxAppConsoleBase::OnUnhandledException(); )
+        }, []()
+        {
+            // And OnUnhandledException() absolutely shouldn't throw,
+            // but we still must account for the possibility that it
+            // did. At least show some information about the exception
+            // in this case by calling our, non-overridden version.
+            wxTheApp->wxAppConsoleBase::OnUnhandledException();
+        });
     }
 }
 
diff --git a/src/common/datavcmn.cpp b/src/common/datavcmn.cpp
index b825a1059c..34fda312d0 100644
--- a/src/common/datavcmn.cpp
+++ b/src/common/datavcmn.cpp
@@ -34,6 +34,8 @@
     #include "wx/access.h"
 #endif // wxUSE_ACCESSIBILITY
 
+#include "wx/private/safecall.h"
+
 // Uncomment this line to, for custom renderers, visually show the extent
 // of both a cell and its item.
 //#define DEBUG_RENDER_EXTENTS
@@ -887,7 +889,7 @@ wxDataViewRendererBase::PrepareForItem(const wxDataViewModel *model,
 {
     // This method is called by the native control, so we shouldn't allow
     // exceptions to escape from it.
-    wxTRY
+    return wxSafeCall<bool>([&, this]()
     {
 
     // Now check if we have a value and remember it if we do.
@@ -915,14 +917,13 @@ wxDataViewRendererBase::PrepareForItem(const wxDataViewModel *model,
     SetEnabled(model->IsEnabled(item, column));
 
     return !value.IsNull();
-    }
-    wxCATCH_ALL
-    (
+    }, []()
+    {
         // There is not much we can do about it here, just log it and don't
         // show anything in this cell.
         wxLogDebug("Retrieving the value from the model threw an exception");
         return false;
-    )
+    });
 }
 
 
diff --git a/src/common/event.cpp b/src/common/event.cpp
index 406adf140b..728f27ade1 100644
--- a/src/common/event.cpp
+++ b/src/common/event.cpp
@@ -44,6 +44,8 @@
 
 #include "wx/thread.h"
 
+#include "wx/private/safecall.h"
+
 #if wxUSE_BASE
     #include "wx/scopedptr.h"
 
@@ -1694,20 +1696,17 @@ bool wxEvtHandler::TryHereOnly(wxEvent& event)
 
 bool wxEvtHandler::SafelyProcessEvent(wxEvent& event)
 {
-#if wxUSE_EXCEPTIONS
-    try
+    return wxSafeCall<bool>([&event, this]
     {
-#endif
         return ProcessEvent(event);
-#if wxUSE_EXCEPTIONS
-    }
-    catch ( ... )
+    }, []()
     {
+#if wxUSE_EXCEPTIONS
         WXConsumeException();
+#endif // wxUSE_EXCEPTIONS
 
         return false;
-    }
-#endif // wxUSE_EXCEPTIONS
+    });
 }
 
 #if wxUSE_EXCEPTIONS
diff --git a/src/common/evtloopcmn.cpp b/src/common/evtloopcmn.cpp
index c197250d67..c081141f27 100644
--- a/src/common/evtloopcmn.cpp
+++ b/src/common/evtloopcmn.cpp
@@ -21,6 +21,7 @@
 #include "wx/scopeguard.h"
 #include "wx/apptrait.h"
 #include "wx/private/eventloopsourcesmanager.h"
+#include "wx/private/safecall.h"
 
 // Counts currently existing event loops.
 //
@@ -243,132 +244,131 @@ bool wxEventLoopManual::ProcessEvents()
     return res;
 }
 
-int wxEventLoopManual::DoRun()
+void wxEventLoopManual::DoRunLoop()
 {
+    // this is the event loop itself
+    for ( ;; )
+    {
+        // give them the possibility to do whatever they want
+        OnNextIteration();
+
+        // generate and process idle events for as long as we don't
+        // have anything else to do, but stop doing this if Exit() is
+        // called by one of the idle handlers
+        //
+        // note that Pending() only checks for pending events from the
+        // underlying toolkit, but not our own pending events added by
+        // QueueEvent(), so we need to call HasPendingEvents() to check
+        // for them too
+        while ( !m_shouldExit
+                    && !Pending()
+                        && !(wxTheApp && wxTheApp->HasPendingEvents())
+                            && ProcessIdle() )
+            ;
+
+        // if Exit() was called, don't dispatch any more events here
+        if ( m_shouldExit )
+            break;
 
-    // we must ensure that OnExit() is called even if an exception is thrown
-    // from inside ProcessEvents() but we must call it from Exit() in normal
-    // situations because it is supposed to be called synchronously,
-    // wxModalEventLoop depends on this (so we can't just use ON_BLOCK_EXIT or
-    // something similar here)
-#if wxUSE_EXCEPTIONS
+        // a message came or no more idle processing to do, dispatch
+        // all the pending events and call Dispatch() to wait for the
+        // next message
+        if ( !ProcessEvents() || m_shouldExit )
+            break;
+    }
+
+    // Process any still pending events.
     for ( ;; )
     {
-        try
+        bool hasMoreEvents = false;
+
+        // We always dispatch events pending at wx level: it may be
+        // important to do it before the loop exits and e.g. the modal
+        // dialog possibly referenced by these events handlers is
+        // destroyed. It also shouldn't result in the problems
+        // described below for the native events and while there is
+        // still a risk of never existing the loop due to an endless
+        // stream of events generated from the user-defined event
+        // handlers, we consider that well-behaved programs shouldn't
+        // do this -- and if they do, it's better to keep running the
+        // loop than crashing after leaving it.
+        if ( wxTheApp && wxTheApp->HasPendingEvents() )
         {
-#endif // wxUSE_EXCEPTIONS
+            wxTheApp->ProcessPendingEvents();
+            hasMoreEvents = true;
+        }
 
-            // this is the event loop itself
-            for ( ;; )
+        // For the underlying toolkit events, we only handle them when
+        // exiting the outermost event loop but not when exiting nested
+        // loops. This is required at least under MSW where, in case of
+        // a nested modal event loop, the modality has already been
+        // undone as Exit() had been already called, so all UI elements
+        // are re-enabled and if we dispatched events from them here,
+        // we could end up reentering the same event handler that had
+        // shown the modal dialog in the first place and showing the
+        // dialog second time before its first instance was destroyed,
+        // resulting in a lot of fun.
+        //
+        // Also, unlike wx events above, it should be fine to dispatch
+        // the native events from the outer event loop, as any events
+        // generated from outside the dialog itself (necessarily, as
+        // the dialog is already hidden and about to be destroyed)
+        // shouldn't reference the dialog. Which is one of the reasons
+        // we still dispatch them in the outermost event loop, to
+        // ensure they're still processed. Another reason is that if we
+        // do have an endless stream of native events, e.g. because we
+        // have a timer with a too short interval, it's arguably better
+        // to keep handling them instead of exiting.
+        if ( gs_eventLoopCount == 1 )
+        {
+            if ( Pending() )
             {
-                // give them the possibility to do whatever they want
-                OnNextIteration();
-
-                // generate and process idle events for as long as we don't
-                // have anything else to do, but stop doing this if Exit() is
-                // called by one of the idle handlers
-                //
-                // note that Pending() only checks for pending events from the
-                // underlying toolkit, but not our own pending events added by
-                // QueueEvent(), so we need to call HasPendingEvents() to check
-                // for them too
-                while ( !m_shouldExit
-                            && !Pending()
-                                && !(wxTheApp && wxTheApp->HasPendingEvents())
-                                    && ProcessIdle() )
-                    ;
-
-                // if Exit() was called, don't dispatch any more events here
-                if ( m_shouldExit )
-                    break;
-
-                // a message came or no more idle processing to do, dispatch
-                // all the pending events and call Dispatch() to wait for the
-                // next message
-                if ( !ProcessEvents() || m_shouldExit )
-                    break;
+                Dispatch();
+                hasMoreEvents = true;
             }
+        }
 
-            // Process any still pending events.
-            for ( ;; )
-            {
-                bool hasMoreEvents = false;
-
-                // We always dispatch events pending at wx level: it may be
-                // important to do it before the loop exits and e.g. the modal
-                // dialog possibly referenced by these events handlers is
-                // destroyed. It also shouldn't result in the problems
-                // described below for the native events and while there is
-                // still a risk of never existing the loop due to an endless
-                // stream of events generated from the user-defined event
-                // handlers, we consider that well-behaved programs shouldn't
-                // do this -- and if they do, it's better to keep running the
-                // loop than crashing after leaving it.
-                if ( wxTheApp && wxTheApp->HasPendingEvents() )
-                {
-                    wxTheApp->ProcessPendingEvents();
-                    hasMoreEvents = true;
-                }
-
-                // For the underlying toolkit events, we only handle them when
-                // exiting the outermost event loop but not when exiting nested
-                // loops. This is required at least under MSW where, in case of
-                // a nested modal event loop, the modality has already been
-                // undone as Exit() had been already called, so all UI elements
-                // are re-enabled and if we dispatched events from them here,
-                // we could end up reentering the same event handler that had
-                // shown the modal dialog in the first place and showing the
-                // dialog second time before its first instance was destroyed,
-                // resulting in a lot of fun.
-                //
-                // Also, unlike wx events above, it should be fine to dispatch
-                // the native events from the outer event loop, as any events
-                // generated from outside the dialog itself (necessarily, as
-                // the dialog is already hidden and about to be destroyed)
-                // shouldn't reference the dialog. Which is one of the reasons
-                // we still dispatch them in the outermost event loop, to
-                // ensure they're still processed. Another reason is that if we
-                // do have an endless stream of native events, e.g. because we
-                // have a timer with a too short interval, it's arguably better
-                // to keep handling them instead of exiting.
-                if ( gs_eventLoopCount == 1 )
-                {
-                    if ( Pending() )
-                    {
-                        Dispatch();
-                        hasMoreEvents = true;
-                    }
-                }
-
-                if ( !hasMoreEvents )
-                    break;
-            }
-#if wxUSE_EXCEPTIONS
-            // exit the outer loop as well
+        if ( !hasMoreEvents )
             break;
-        }
-        catch ( ... )
+    }
+}
+
+int wxEventLoopManual::DoRun()
+{
+#if wxUSE_EXCEPTIONS
+    // we must ensure that OnExit() is called even if an exception is thrown
+    // from inside ProcessEvents() but we must call it from Exit() in normal
+    // situations because it is supposed to be called synchronously,
+    // wxModalEventLoop depends on this, so we can't just use ON_BLOCK_EXIT and
+    // need a named guard to be able to dismiss it if it was called normally
+    wxScopeGuard guardOnExit = wxMakeObjGuard(*this, &wxEventLoopManual::OnExit);
+#endif // wxUSE_EXCEPTIONS
+
+    // This loop is only used when exceptions are used, but it should hopefully
+    // be optimized away completely when they are not, so use it in any case to
+    // make the code simpler.
+    for ( bool stop = false; !stop; )
+    {
+        wxSafeCall<void>([&, this]
         {
-            try
-            {
-                if ( !wxTheApp || !wxTheApp->OnExceptionInMainLoop() )
-                {
-                    OnExit();
-                    break;
-                }
-                //else: continue running the event loop
-            }
-            catch ( ... )
+            DoRunLoop();
+
+#if wxUSE_EXCEPTIONS
+            guardOnExit.Dismiss();
+#endif // wxUSE_EXCEPTIONS
+
+            stop = true;
+        }, [&]()
+        {
+#if wxUSE_EXCEPTIONS
+            if ( !wxTheApp || !wxTheApp->OnExceptionInMainLoop() )
             {
-                // OnException() thrown, possibly rethrowing the same
-                // exception again: very good, but we still need OnExit() to
-                // be called
-                OnExit();
-                throw;
+                stop = true;
             }
-        }
-    }
+            //else: continue running the event loop
 #endif // wxUSE_EXCEPTIONS
+        });
+    }
 
     return m_exitcode;
 }
diff --git a/src/common/init.cpp b/src/common/init.cpp
index 1c06c93aba..dcd3ab2dba 100644
--- a/src/common/init.cpp
+++ b/src/common/init.cpp
@@ -32,7 +32,6 @@
 #include "wx/scopeguard.h"
 
 #include "wx/scopedptr.h"
-#include "wx/except.h"
 
 #if defined(__WINDOWS__)
     #include "wx/msw/private.h"
@@ -53,6 +52,7 @@
 #endif // __WINDOWS__
 
 #include "wx/private/localeset.h"
+#include "wx/private/safecall.h"
 
 // ----------------------------------------------------------------------------
 // private classes
@@ -468,7 +468,7 @@ int wxEntryReal(int& argc, wxChar **argv)
         return -1;
     }
 
-    wxTRY
+    return wxSafeCall<int>([]()
     {
         // app initialization
         if ( !wxTheApp->CallOnInit() )
@@ -482,8 +482,11 @@ int wxEntryReal(int& argc, wxChar **argv)
 
         // app execution
         return wxTheApp->OnRun();
-    }
-    wxCATCH_ALL( wxApp::CallOnUnhandledException(); return -1; )
+    }, []()
+    {
+        wxApp::CallOnUnhandledException();
+        return -1;
+    });
 }
 
 #if wxUSE_UNICODE
diff --git a/src/msw/ole/droptgt.cpp b/src/msw/ole/droptgt.cpp
index 4b77b64d95..d476328414 100644
--- a/src/msw/ole/droptgt.cpp
+++ b/src/msw/ole/droptgt.cpp
@@ -33,7 +33,8 @@
 #include "wx/msw/wrapshl.h"            // for DROPFILES structure
 
 #include "wx/dnd.h"
-#include "wx/except.h"
+
+#include "wx/private/safecall.h"
 
 #include "wx/msw/ole/oleutils.h"
 
@@ -111,7 +112,20 @@ protected:
 
         return E_UNEXPECTED;
     }
-#endif // wxUSE_EXCEPTIONS
+
+    // More convenient version of wxSafeCall() used in this class.
+    template <typename T>
+    HRESULT SafeCall(const T& func)
+    {
+        return wxSafeCall<HRESULT>(func, [&]() { return HandleException(); });
+    }
+#else // !wxUSE_EXCEPTIONS
+    template <typename T>
+    HRESULT SafeCall(const T& func)
+    {
+        return func();
+    }
+#endif // wxUSE_EXCEPTIONS/!wxUSE_EXCEPTIONS
 
     wxDECLARE_NO_COPY_CLASS(wxIDropTarget);
 };
@@ -196,7 +210,7 @@ STDMETHODIMP wxIDropTarget::DragEnter(IDataObject *pIDataSource,
                                       POINTL       pt,
                                       DWORD       *pdwEffect)
 {
-    wxTRY
+    return SafeCall([&, this]()
     {
         wxLogTrace(wxTRACE_OleCalls, wxT("IDropTarget::DragEnter"));
 
@@ -259,8 +273,7 @@ STDMETHODIMP wxIDropTarget::DragEnter(IDataObject *pIDataSource,
         m_pTarget->MSWUpdateDragImageOnDragOver(pt.x, pt.y, res);
 
         return S_OK;
-    }
-    wxCATCH_ALL( return HandleException(); )
+    });
 }
 
 
@@ -278,7 +291,7 @@ STDMETHODIMP wxIDropTarget::DragOver(DWORD   grfKeyState,
                                      POINTL  pt,
                                      LPDWORD pdwEffect)
 {
-    wxTRY
+    return SafeCall([&, this]()
     {
         // there are too many of them... wxLogDebug("IDropTarget::DragOver");
 
@@ -312,8 +325,7 @@ STDMETHODIMP wxIDropTarget::DragOver(DWORD   grfKeyState,
                                                 ConvertDragEffectToResult(*pdwEffect));
 
         return S_OK;
-    }
-    wxCATCH_ALL( return HandleException(); )
+    });
 }
 
 // Name    : wxIDropTarget::DragLeave
@@ -322,7 +334,7 @@ STDMETHODIMP wxIDropTarget::DragOver(DWORD   grfKeyState,
 // Notes   : good place to do any clean-up
 STDMETHODIMP wxIDropTarget::DragLeave()
 {
-    wxTRY
+    return SafeCall([&, this]()
     {
         wxLogTrace(wxTRACE_OleCalls, wxT("IDropTarget::DragLeave"));
 
@@ -336,8 +348,7 @@ STDMETHODIMP wxIDropTarget::DragLeave()
         m_pTarget->MSWUpdateDragImageOnLeave();
 
         return S_OK;
-    }
-    wxCATCH_ALL( return HandleException(); )
+    });
 }
 
 // Name    : wxIDropTarget::Drop
@@ -354,7 +365,7 @@ STDMETHODIMP wxIDropTarget::Drop(IDataObject *pIDataSource,
                                  POINTL       pt,
                                  DWORD       *pdwEffect)
 {
-    wxTRY
+    return SafeCall([&, this]()
     {
         wxLogTrace(wxTRACE_OleCalls, wxT("IDropTarget::Drop"));
 
@@ -432,8 +443,7 @@ STDMETHODIMP wxIDropTarget::Drop(IDataObject *pIDataSource,
         }
 
         return S_OK;
-    }
-    wxCATCH_ALL( return HandleException(); )
+    });
 }
 
 // ============================================================================
diff --git a/src/msw/thread.cpp b/src/msw/thread.cpp
index 203c998942..f9d93d3c79 100644
--- a/src/msw/thread.cpp
+++ b/src/msw/thread.cpp
@@ -38,9 +38,10 @@
 #include "wx/msw/missing.h"
 #include "wx/msw/seh.h"
 
-#include "wx/except.h"
 #include "wx/dynlib.h"
 
+#include "wx/private/safecall.h"
+
 // must have this symbol defined to get _beginthread/_endthread declarations
 #ifndef _MT
     #define _MT
@@ -507,11 +508,7 @@ private:
 /* static */
 void wxThreadInternal::DoThreadOnExit(wxThread *thread)
 {
-    wxTRY
-    {
-        thread->OnExit();
-    }
-    wxCATCH_ALL( wxApp::CallOnUnhandledException(); )
+    wxSafeCall([&thread] { thread->OnExit(); });
 }
 
 /* static */
@@ -521,7 +518,7 @@ THREAD_RETVAL wxThreadInternal::DoThreadStart(wxThread *thread)
 
     THREAD_RETVAL rc = THREAD_ERROR_EXIT;
 
-    wxTRY
+    wxSafeCall([&]()
     {
         // store the thread object in the TLS
         wxASSERT_MSG( gs_tlsThisThread != TLS_OUT_OF_INDEXES,
@@ -531,12 +528,12 @@ THREAD_RETVAL wxThreadInternal::DoThreadStart(wxThread *thread)
         {
             wxLogSysError(_("Cannot start thread: error writing TLS."));
 
-            return THREAD_ERROR_EXIT;
+            rc = THREAD_ERROR_EXIT;
+            return;
         }
 
         rc = wxPtrToUInt(thread->Entry());
-    }
-    wxCATCH_ALL( wxApp::CallOnUnhandledException(); )
+    });
 
     return rc;
 }
diff --git a/src/unix/threadpsx.cpp b/src/unix/threadpsx.cpp
index f5a1c61ad2..78bccf0fac 100644
--- a/src/unix/threadpsx.cpp
+++ b/src/unix/threadpsx.cpp
@@ -26,7 +26,6 @@
 #if wxUSE_THREADS
 
 #include "wx/thread.h"
-#include "wx/except.h"
 #include "wx/scopeguard.h"
 
 #include "wx/private/threadinfo.h"
@@ -42,6 +41,8 @@
     #include "wx/module.h"
 #endif
 
+#include "wx/private/safecall.h"
+
 #include <stdio.h>
 #include <unistd.h>
 #include <pthread.h>
@@ -90,6 +91,8 @@
     #define HAS_ATOMIC_ULONG
 #endif // C++11
 
+#include <exception>
+
 #define THR_ID_CAST(id)  (reinterpret_cast<void*>(id))
 #define THR_ID(thr)      THR_ID_CAST((thr)->GetId())
 
@@ -906,32 +909,42 @@ void *wxThreadInternal::PthreadStart(wxThread *thread)
                    wxT("Thread %p about to enter its Entry()."),
                    THR_ID(pthread));
 
-        wxTRY
-        {
-            pthread->m_exitcode = thread->Entry();
-
-            wxLogTrace(TRACE_THREADS,
-                       wxT("Thread %p Entry() returned %lu."),
-                       THR_ID(pthread), wxPtrToUInt(pthread->m_exitcode));
-        }
-#ifndef wxNO_EXCEPTIONS
-#ifdef HAVE_ABI_FORCEDUNWIND
         // When using common C++ ABI under Linux we must always rethrow this
         // special exception used to unwind the stack when the thread was
         // cancelled, otherwise the thread library would simply terminate the
         // program, see http://udrepper.livejournal.com/21541.html
-        catch ( abi::__forced_unwind& )
-        {
-            wxCriticalSectionLocker lock(thread->m_critsect);
-            pthread->SetState(STATE_EXITED);
-            throw;
-        }
-#endif // HAVE_ABI_FORCEDUNWIND
-        catch ( ... )
+#if defined(HAVE_ABI_FORCEDUNWIND) && wxUSE_EXCEPTIONS
+        #define CATCH_AND_RETHROW_FORCED_UNWIND
+
+        std::exception_ptr threadException;
+#endif
+
+        wxSafeCall([&]()
         {
-            wxApp::CallOnUnhandledException();
-        }
-#endif // !wxNO_EXCEPTIONS
+#ifdef CATCH_AND_RETHROW_FORCED_UNWIND
+            try
+            {
+#endif // CATCH_AND_RETHROW_FORCED_UNWIND
+                pthread->m_exitcode = thread->Entry();
+
+                wxLogTrace(TRACE_THREADS,
+                           wxT("Thread %p Entry() returned %lu."),
+                           THR_ID(pthread), wxPtrToUInt(pthread->m_exitcode));
+#ifdef CATCH_AND_RETHROW_FORCED_UNWIND
+            }
+            catch ( abi::__forced_unwind& )
+            {
+                wxCriticalSectionLocker lock(thread->m_critsect);
+                pthread->SetState(STATE_EXITED);
+                threadException = std::current_exception();
+            }
+#endif // CATCH_AND_RETHROW_FORCED_UNWIND
+        });
+
+#ifdef CATCH_AND_RETHROW_FORCED_UNWIND
+        if ( threadException )
+            std::rethrow_exception(threadException);
+#endif // CATCH_AND_RETHROW_FORCED_UNWIND
 
         {
             wxCriticalSectionLocker lock(thread->m_critsect);
@@ -1754,11 +1767,10 @@ void wxThread::Exit(ExitCode status)
     // might deadlock if, for example, it signals a condition in OnExit() (a
     // common case) while the main thread calls any of functions entering
     // m_critsect on us (almost all of them do)
-    wxTRY
+    wxSafeCall([this]()
     {
         OnExit();
-    }
-    wxCATCH_ALL( wxApp::CallOnUnhandledException(); )
+    });
 
     // delete C++ thread object if this is a detached thread - user is
     // responsible for doing this for joinable ones
commit 970c97afa7bba76d1473ae402585b65a5fb4e6f2
Author: Vadim Zeitlin <vadim@wxwidgets.org>
Date:   Thu Mar 20 19:39:52 2025 +0100

    Add catch-unhandled-exception system option
    
    Allow setting this option to 0 to prevent wxWidgets from catching any
    exceptions, even in a build with wxUSE_EXCEPTIONS=1 (which is the
    default).
    
    Co-authored-by: Lauri Nurmi <lanurmi@iki.fi>

diff --git a/include/wx/private/safecall.h b/include/wx/private/safecall.h
index d7f27177ec..fa3cd936f9 100644
--- a/include/wx/private/safecall.h
+++ b/include/wx/private/safecall.h
@@ -14,6 +14,8 @@
 
 #if wxUSE_EXCEPTIONS
 
+#include "wx/sysopt.h"
+
 // General version calls the given function or function-like object and
 // executes the provided handler if an exception is thrown.
 //
@@ -22,6 +24,13 @@
 template <typename R, typename T1, typename T2>
 inline R wxSafeCall(const T1& func, const T2& handler)
 {
+    // This special option exists in order to avoid having try/catch blocks
+    // around potentially throwing code.
+    if ( wxSystemOptions::IsFalse("catch-unhandled-exceptions") )
+    {
+        return func();
+    }
+
     try
     {
         return func();
diff --git a/interface/wx/sysopt.h b/interface/wx/sysopt.h
index bdb4dceaaa..5a0c54d5b1 100644
--- a/interface/wx/sysopt.h
+++ b/interface/wx/sysopt.h
@@ -37,6 +37,16 @@
         this option allows changing it without modifying the program code and
         also applies to asserts which may happen before the wxApp object
         creation or after its destruction.
+    @flag{catch-unhandled-exceptions}
+        If set to zero, wxWidgets will not catch unhandled exceptions, but
+        rather lets the default behaviour of aborting the program take place.
+        Not catching unhandled exceptions makes debugging easier, as the
+        backtrace is more likely to show what actually happened, and where.
+        The same applies to any crash dumps generated due to unhandled exceptions.
+        By default unhandled exceptions are eventually caught by wxWidgets.
+        This flag should be set very early during program startup, within
+        the constructor of the wxApp derivative. This option has been added in
+        wxWidgets 3.3.0.
     @endFlagTable
 
     @section sysopt_win Windows
commit b1e13d49102856772b45cf2adece9cdc39a4ffac
Author: Vadim Zeitlin <vadim@wxwidgets.org>
Date:   Wed May 14 18:31:03 2025 +0200

    Cache the value of "catch-unhandled-exceptions" system option
    
    Looking up its value for every event being processed, which happened
    since the changes of #25257, was too expensive and resulted in
    noticeable overhead, so don't do it and cache this option value in a
    global variable -- thus reducing the overhead to just a single function
    call returning it.

diff --git a/include/wx/private/safecall.h b/include/wx/private/safecall.h
index fa3cd936f9..d67e4353d1 100644
--- a/include/wx/private/safecall.h
+++ b/include/wx/private/safecall.h
@@ -14,7 +14,11 @@
 
 #if wxUSE_EXCEPTIONS
 
-#include "wx/sysopt.h"
+// Returns true if a special system option disabling catching unhandled
+// exceptions is set.
+//
+// This function is implemented in sysopt.cpp.
+extern bool WXDLLIMPEXP_BASE wxIsCatchUnhandledExceptionsDisabled();
 
 // General version calls the given function or function-like object and
 // executes the provided handler if an exception is thrown.
@@ -24,12 +28,12 @@
 template <typename R, typename T1, typename T2>
 inline R wxSafeCall(const T1& func, const T2& handler)
 {
-    // This special option exists in order to avoid having try/catch blocks
-    // around potentially throwing code.
-    if ( wxSystemOptions::IsFalse("catch-unhandled-exceptions") )
+#if wxUSE_SYSTEM_OPTIONS
+    if ( wxIsCatchUnhandledExceptionsDisabled() )
     {
         return func();
     }
+#endif // wxUSE_SYSTEM_OPTIONS
 
     try
     {
diff --git a/src/common/sysopt.cpp b/src/common/sysopt.cpp
index cee43108af..b51eccc57b 100644
--- a/src/common/sysopt.cpp
+++ b/src/common/sysopt.cpp
@@ -31,6 +31,9 @@
     #include "wx/arrstr.h"
 #endif
 
+// Include header containing wxIsCatchUnhandledExceptionsDisabled() declaration.
+#include "wx/private/safecall.h"
+
 // ----------------------------------------------------------------------------
 // private globals
 // ----------------------------------------------------------------------------
@@ -38,6 +41,17 @@
 static wxArrayString gs_optionNames,
                      gs_optionValues;
 
+namespace
+{
+
+// Name of a system option that we handle specially for performance reasons.
+constexpr char CATCH_UNHANDLED_EXCEPTIONS[] = "catch-unhandled-exceptions";
+
+// Cached return value of wxIsCatchUnhandledExceptionsDisabled().
+int gs_catchUnhandledExceptionsDisabled = -1;
+
+} // anonymous namespace
+
 // ============================================================================
 // wxSystemOptions implementation
 // ============================================================================
@@ -45,6 +59,12 @@ static wxArrayString gs_optionNames,
 // Option functions (arbitrary name/value mapping)
 void wxSystemOptions::SetOption(const wxString& name, const wxString& value)
 {
+    if ( name == CATCH_UNHANDLED_EXCEPTIONS )
+    {
+        // Invalidate the cached value.
+        gs_catchUnhandledExceptionsDisabled = -1;
+    }
+
     int idx = gs_optionNames.Index(name, false);
     if (idx == wxNOT_FOUND)
     {
@@ -105,4 +125,15 @@ bool wxSystemOptions::HasOption(const wxString& name)
     return !GetOption(name).empty();
 }
 
+bool wxIsCatchUnhandledExceptionsDisabled()
+{
+    if ( gs_catchUnhandledExceptionsDisabled == -1 )
+    {
+        gs_catchUnhandledExceptionsDisabled =
+            wxSystemOptions::IsFalse(CATCH_UNHANDLED_EXCEPTIONS);
+    }
+
+    return gs_catchUnhandledExceptionsDisabled;
+}
+
 #endif // wxUSE_SYSTEM_OPTIONS
commit ff2abae981ee6ed2929e401ee6172cbb3c1a4f68
Author: Stefan Csomor <csomor@advancedconcepts.ch>
Date:   Tue Feb 3 21:08:33 2026 +0100

    Fix handling of exceptions thrown from event loop in wxOSX
    
    Previously they were simply ignored, rethrow them later now, as in the
    other ports.
    
    Closes #26157.

diff --git a/src/osx/cocoa/evtloop.mm b/src/osx/cocoa/evtloop.mm
index 1e333a7d9f..252cacb180 100644
--- a/src/osx/cocoa/evtloop.mm
+++ b/src/osx/cocoa/evtloop.mm
@@ -342,6 +342,13 @@ static NSUInteger CalculateNSEventMaskFromEventCategory(wxEventCategory cat)
         }
     }
 
+#if wxUSE_EXCEPTIONS
+    // Rethrow any exceptions which could have been produced by the handlers
+    // ran by the event loop.
+    if ( wxTheApp )
+        wxTheApp->RethrowStoredException();
+#endif // wxUSE_EXCEPTIONS
+
     // Wake up the enclosing loop so that it can check if it also needs
     // to exit.
     WakeUp();
diff --git a/src/osx/core/evtloop_cf.cpp b/src/osx/core/evtloop_cf.cpp
index 9004763836..4dc8dd2dbb 100644
--- a/src/osx/core/evtloop_cf.cpp
+++ b/src/osx/core/evtloop_cf.cpp
@@ -31,10 +31,14 @@
 
 #include "wx/scopedptr.h"
 
+#include "wx/scopeguard.h"
+
 #include "wx/osx/private.h"
 #include "wx/osx/core/cfref.h"
 #include "wx/thread.h"
 
+#include "wx/private/safecall.h"
+
 #if wxUSE_GUI
     #include "wx/nonownedwnd.h"
 #endif
@@ -311,46 +315,40 @@ void wxCFEventLoop::OSXDoStop()
 // terminating when Exit() is called
 int wxCFEventLoop::DoRun()
 {
+#if wxUSE_EXCEPTIONS
     // we must ensure that OnExit() is called even if an exception is thrown
     // from inside ProcessEvents() but we must call it from Exit() in normal
     // situations because it is supposed to be called synchronously,
-    // wxModalEventLoop depends on this (so we can't just use ON_BLOCK_EXIT or
-    // something similar here)
-#if wxUSE_EXCEPTIONS
-    for ( ;; )
-    {
-        try
-        {
+    // wxModalEventLoop depends on this, so we can't just use ON_BLOCK_EXIT and
+    // need a named guard to be able to dismiss it if it was called normally
+    wxScopeGuard guardOnExit = wxMakeObjGuard(*this, &wxCFEventLoop::OnExit);
 #endif // wxUSE_EXCEPTIONS
 
+    // This loop is only used when exceptions are used, but it should hopefully
+    // be optimized away completely when they are not, so use it in any case to
+    // make the code simpler.
+    for ( bool stop = false; !stop; )
+    {
+        wxSafeCall<void>([&, this]
+        {
             OSXDoRun();
 
 #if wxUSE_EXCEPTIONS
-            // exit the outer loop as well
-            break;
-        }
-        catch ( ... )
+            guardOnExit.Dismiss();
+#endif // wxUSE_EXCEPTIONS
+
+            stop = true;
+        }, [&]()
         {
-            try
-            {
-                if ( !wxTheApp || !wxTheApp->OnExceptionInMainLoop() )
-                {
-                    OnExit();
-                    break;
-                }
-                //else: continue running the event loop
-            }
-            catch ( ... )
+#if wxUSE_EXCEPTIONS
+            if ( !wxTheApp || !wxTheApp->OnExceptionInMainLoop() )
             {
-                // OnException() throwed, possibly rethrowing the same
-                // exception again: very good, but we still need OnExit() to
-                // be called
-                OnExit();
-                throw;
+                stop = true;
             }
-        }
-    }
+            //else: continue running the event loop
 #endif // wxUSE_EXCEPTIONS
+        });
+    }
 
     return m_exitcode;
 }
EOF

		_rehex_wxwidgets_arch_flag=
		if [ -z "${_rehex_arch_suffix}" ]
		then
			_rehex_wxwidgets_arch_flag=--enable-universal_binary=x86_64,arm64
		fi
		
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
			$_rehex_wxwidgets_arch_flag \
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
unset _rehex_arch_suffix
unset _rehex_arch_flags
unset _rehex_macos_version_min
unset _rehex_python

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
