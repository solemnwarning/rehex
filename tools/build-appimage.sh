#!/bin/bash
# Reverse Engineer's Hex Editor
# Copyright (C) 2022-2025 Daniel Collins <solemnwarning@solemnwarning.net>
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

[ -z "$I386_CHROOT" ]      && I386_CHROOT="bullseye-i386-sbuild"
[ -z "$I386_LINUXDEPLOY" ] && I386_LINUXDEPLOY="https://github.com/linuxdeploy/linuxdeploy/releases/download/continuous/linuxdeploy-i386.AppImage"
[ -z "$I386_RUNTIME" ]     && I386_RUNTIME="https://github.com/AppImage/type2-runtime/releases/download/continuous/runtime-i686"

[ -z "$AMD64_CHROOT" ]      && AMD64_CHROOT="bullseye-amd64-sbuild"
[ -z "$AMD64_LINUXDEPLOY" ] && AMD64_LINUXDEPLOY="https://github.com/linuxdeploy/linuxdeploy/releases/download/continuous/linuxdeploy-x86_64.AppImage"
[ -z "$AMD64_RUNTIME" ]     && AMD64_RUNTIME="https://github.com/AppImage/type2-runtime/releases/download/continuous/runtime-x86_64"

DEPENDS="
	libbotan-2-dev
	libcapstone-dev/bullseye-backports
	libgtk-3-dev
	libjansson-dev
	liblua5.3-dev
	libtemplate-perl
	libunistring-dev
	libwxgtk3.2-dev
	lua-busted
	lua5.3
	pkg-config
	xauth
	xvfb
	wx3.2-headers
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
	
	# Create schroot session
	SESSION="$(schroot -c "$2" -b)"
	if [ "$?" -ne 0 ]
	then
		return $?
	fi
	
	echo "Started schroot session $SESSION"
	
	gpg --dearmor <<EOF | schroot -c "$SESSION" -r -u root -- tee /etc/apt/trusted.gpg.d/solemnwarning-archive-keyring.gpg > /dev/null
-----BEGIN PGP PUBLIC KEY BLOCK-----

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
=f5F/
-----END PGP PUBLIC KEY BLOCK-----
EOF
	
	schroot -c "$SESSION" -r -u root -- tee -a /etc/apt/sources.list > /dev/null <<EOF
deb http://repos.solemnwarning.net/debian/ bullseye-backports main
deb-src http://repos.solemnwarning.net/debian/ bullseye-backports main
EOF
	
	LINUXDEPLOY_CMD="LDAI_RUNTIME_FILE=AppImage-runtime DEPLOY_GTK_VERSION=3 ./linuxdeploy.AppImage --appimage-extract-and-run"
	
	tar --strip-components=1 -xf "$dist" -C "$tmpdir" \
		&& schroot -c "$SESSION" -r -u root -- apt-get update \
		&& schroot -c "$SESSION" -r -u root -- apt-get -y install $DEPENDS \
		&& wget -O "$tmpdir/linuxdeploy.AppImage" "$4" \
		&& wget -O "$tmpdir/linuxdeploy-plugin-gtk.sh" "https://raw.githubusercontent.com/linuxdeploy/linuxdeploy-plugin-gtk/master/linuxdeploy-plugin-gtk.sh" \
		&& chmod +x "$tmpdir/linuxdeploy.AppImage" "$tmpdir/linuxdeploy-plugin-gtk.sh" \
		&& wget -O "$tmpdir/AppImage-runtime" "$5" \
		&& schroot -c "$SESSION" -d "$tmpdir" -r -- make -f Makefile.AppImage $MAKEFLAGS LINUXDEPLOY="$LINUXDEPLOY_CMD" \
		&& schroot -c "$SESSION" -d "$tmpdir" -r -- xvfb-run -a -e /dev/stdout make -f Makefile.AppImage $MAKEFLAGS LINUXDEPLOY="$LINUXDEPLOY_CMD" check \
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
