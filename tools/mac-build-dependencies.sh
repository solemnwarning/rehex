# Reverse Engineer's Hex Editor
# Copyright (C) 2021-2023 Daniel Collins <solemnwarning@solemnwarning.net>
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

_rehex_botan_version="2.19.3"
_rehex_botan_url="https://botan.randombit.net/releases/Botan-${_rehex_botan_version}.tar.xz"
_rehex_botan_sha256="dae047f399c5a47f087db5d3d9d9e8f11ae4985d14c928d71da1aff801802d55"
_rehex_botan_build_ident="${_rehex_botan_version}-2"

_rehex_capstone_version="5.0"
_rehex_capstone_url="https://github.com/capstone-engine/capstone/archive/refs/tags/${_rehex_capstone_version}.tar.gz"
_rehex_capstone_sha256="df24344407baa7415eeb006f742afc9b92cd33abf2c4c120a6e97cfb376882dc"
_rehex_capstone_build_ident="${_rehex_capstone_version}-1"

_rehex_jansson_version="2.14"
_rehex_jansson_url="https://github.com/akheron/jansson/releases/download/v${_rehex_jansson_version}/jansson-${_rehex_jansson_version}.tar.gz"
_rehex_jansson_sha256="5798d010e41cf8d76b66236cfb2f2543c8d082181d16bc3085ab49538d4b9929"
_rehex_jansson_build_ident="${_rehex_jansson_version}-2"

_rehex_libunistring_version="0.9.10"
_rehex_libunistring_url="https://ftp.gnu.org/gnu/libunistring/libunistring-${_rehex_libunistring_version}.tar.gz"
_rehex_libunistring_sha256="a82e5b333339a88ea4608e4635479a1cfb2e01aafb925e1290b65710d43f610b"
_rehex_libunistring_build_ident="${_rehex_libunistring_version}-2"

_rehex_lua_version="5.3.6"
_rehex_lua_url="https://www.lua.org/ftp/lua-${_rehex_lua_version}.tar.gz"
_rehex_lua_sha256="fc5fd69bb8736323f026672b1b7235da613d7177e72558893a0bdcd320466d60"
_rehex_lua_build_ident="${_rehex_lua_version}-3"

_rehex_luarocks_version="3.8.0"
_rehex_luarocks_url="https://luarocks.org/releases/luarocks-${_rehex_luarocks_version}.tar.gz"
_rehex_luarocks_sha256="56ab9b90f5acbc42eb7a94cf482e6c058a63e8a1effdf572b8b2a6323a06d923"

_rehex_wxwidgets_version="3.2.2.1"
_rehex_wxwidgets_url="https://github.com/wxWidgets/wxWidgets/releases/download/v${_rehex_wxwidgets_version}/wxWidgets-${_rehex_wxwidgets_version}.tar.bz2"
_rehex_wxwidgets_sha256="dffcb6be71296fff4b7f8840eb1b510178f57aa2eb236b20da41182009242c02"
_rehex_wxwidgets_build_ident="${_rehex_wxwidgets_version}-1"

_rehex_cpanm_version="1.7044"
_rehex_cpanm_url="https://cpan.metacpan.org/authors/id/M/MI/MIYAGAWA/App-cpanminus-${_rehex_cpanm_version}.tar.gz"
_rehex_cpanm_sha256="9b60767fe40752ef7a9d3f13f19060a63389a5c23acc3e9827e19b75500f81f3"
_rehex_perl_libs_build_ident="2"

_rehex_macos_version_min=10.13

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

		mkdir -p "botan-${_rehex_botan_build_ident}"

		tar -xf "${_rehex_botan_tar}" -C "botan-${_rehex_botan_build_ident}"
		cd "botan-${_rehex_botan_build_ident}/Botan-${_rehex_botan_version}"

		python3 configure.py \
			--minimized-build \
			--enable-modules=md5,sha1,sha2_32,sha2_64 \
			--cc-abi-flags="-mmacosx-version-min=${_rehex_macos_version_min}" \
			--prefix="${_rehex_botan_target_dir}" \
			--disable-shared-library \
			--without-documentation

		make -j$(sysctl -n hw.logicalcpu)
		make -j$(sysctl -n hw.logicalcpu) check
		make -j$(sysctl -n hw.logicalcpu) install
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
			CFLAGS="-mmacosx-version-min=${_rehex_macos_version_min}" \
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
			CFLAGS="-mmacosx-version-min=${_rehex_macos_version_min}"
		
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
		
		./configure \
			--prefix="${_rehex_libunistring_target_dir}" \
			--enable-shared=no \
			--enable-static=yes \
			CFLAGS="-mmacosx-version-min=${_rehex_macos_version_min}"
		
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
		
		make -j$(sysctl -n hw.logicalcpu) macosx MYCFLAGS="-mmacosx-version-min=${_rehex_macos_version_min}"
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
		
		./configure \
			--prefix="${_rehex_wxwidgets_target_dir}" \
			--disable-shared \
			--enable-unicode \
			--with-libjpeg=no \
			--with-libpng=builtin \
			--with-libtiff=no \
			--with-regex=builtin \
			--with-liblzma=no \
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
	
	export CFLAGS="-mmacosx-version-min=${_rehex_macos_version_min}"
	export CXXFLAGS="-I${_rehex_libunistring_target_dir}/include/ -mmacosx-version-min=${_rehex_macos_version_min}"
	export LDLIBS="-L${_rehex_libunistring_target_dir}/lib/ -lunistring"
	
	export PERL="perl -I\"$(dirname "$(find "${_rehex_perl_libs_target_dir}" -name Template.pm)")\""
fi

unset _rehex_perl_libs_target_dir
unset _rehex_wxwidgets_target_dir
unset _rehex_lua_target_dir
unset _rehex_libunistring_target_dir
unset _rehex_jansson_target_dir
unset _rehex_capstone_target_dir
unset _rehex_botan_target_dir

unset _rehex_dep_target_dir
unset _rehex_dep_build_dir
unset _rehex_ok
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
