#!/bin/bash
# Reverse Engineer's Hex Editor
# Copyright (C) 2022 Daniel Collins <solemnwarning@solemnwarning.net>
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

MAKEFLAGS="LUA=lua5.3 -j$(nproc)"

[ -z "$I386_CHROOT" ]      && I386_CHROOT="bionic-i386-sbuild"
[ -z "$I386_LINUXDEPLOY" ] && I386_LINUXDEPLOY="https://github.com/linuxdeploy/linuxdeploy/releases/download/continuous/linuxdeploy-i386.AppImage"
[ -z "$I386_RUNTIME" ]     && I386_RUNTIME="https://github.com/AppImage/type2-runtime/releases/download/continuous/runtime-i686"

[ -z "$AMD64_CHROOT" ]      && AMD64_CHROOT="bionic-amd64-sbuild"
[ -z "$AMD64_LINUXDEPLOY" ] && AMD64_LINUXDEPLOY="https://github.com/linuxdeploy/linuxdeploy/releases/download/continuous/linuxdeploy-x86_64.AppImage"
[ -z "$AMD64_RUNTIME" ]     && AMD64_RUNTIME="https://github.com/AppImage/type2-runtime/releases/download/continuous/runtime-x86_64"

DEPENDS="
	libbotan-2-dev
	libcapstone-dev
	libgtk2.0-dev
	libjansson-dev
	liblua5.3-dev
	libtemplate-perl
	libunistring-dev
	libwxgtk3.0-dev
	lua-busted
	lua5.1
	lua5.3
	pkg-config
	wx3.0-headers
	zip
	zlib1g-dev
"

selected_arch=

if [ "$#" -ge 1 ]
then
	if [ "$1" = "--i386" ]
	then
		selected_arch=i386
		shift
	elif [ "$1" = "--amd64" ]
	then
		selected_arch=amd64
		shift
	fi
fi

if [ "$#" -ne 1 ]
then
	echo "Usage: $0 [--i386|--amd64] <version>" 1>&2
	exit 64 # EX_USAGE
fi

dist="rehex-$1.tar.gz"
i386_out="rehex-$1-linux-generic-i386.AppImage"
amd64_out="rehex-$1-linux-generic-x86_64.AppImage"

if [ ! -f "$dist" ]
then
	echo "$dist not found" 1>&2
	exit 66 # EX_NOINPUT
fi

if [ "$selected_arch" != "amd64" ] && [ -e "$i386_out" ]
then
	echo "$i386_out already exists!" 1>&2
	exit 73 # EX_CANTCREAT
fi

if [ "$selected_arch" != "i386" ] && [ -e "$amd64_out" ]
then
	echo "$amd64_out already exists!" 1>&2
	exit 73 # EX_CANTCREAT
fi

function build-appimage()
{
	tmpdir=$(mktemp -d "$(pwd)/build-appimage-release.XXXXXXXX")
	
	# TODO: Set up X server and run tests
	
	# Create schroot session
	SESSION="$(schroot -c "$2" -b)"
	if [ "$?" -ne 0 ]
	then
		return $?
	fi
	
	echo "Started schroot session $SESSION"
	
	tar --strip-components=1 -xf "$dist" -C "$tmpdir" \
		&& schroot -c "$SESSION" -r -u root -- apt-get update \
		&& schroot -c "$SESSION" -r -u root -- apt-get -y install $DEPENDS \
		&& wget -O "$tmpdir/linuxdeploy.AppImage" "$4" \
		&& wget -O "$tmpdir/linuxdeploy-plugin-gtk.sh" "https://raw.githubusercontent.com/linuxdeploy/linuxdeploy-plugin-gtk/master/linuxdeploy-plugin-gtk.sh" \
		&& chmod +x "$tmpdir/linuxdeploy.AppImage" "$tmpdir/linuxdeploy-plugin-gtk.sh" \
		&& wget -O "$tmpdir/AppImage-runtime" "$5" \
		&& schroot -c "$SESSION" -d "$tmpdir" -r -- make -f Makefile.AppImage $MAKEFLAGS LINUXDEPLOY="LDAI_RUNTIME_FILE=AppImage-runtime DEPLOY_GTK_VERSION=2 ./linuxdeploy.AppImage --appimage-extract-and-run" \
		&& cp "$tmpdir/rehex.AppImage" "$3"
	
	status=$?
	
	# End schroot session
	schroot -c "$SESSION" -e
	
	rm -rf "$tmpdir"
	
	return $status
}

if [ "$selected_arch" != "amd64" ]
then
	build-appimage "$1" "$I386_CHROOT" "$i386_out" "$I386_LINUXDEPLOY" "$I386_RUNTIME" || exit $?
fi

if [ "$selected_arch" != "i386" ]
then
	build-appimage "$1" "$AMD64_CHROOT" "$amd64_out" "$AMD64_LINUXDEPLOY" "$AMD64_RUNTIME" || exit $?
fi
