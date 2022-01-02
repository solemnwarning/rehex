%define base_version 0.4.0
%define tilde_dist %(echo %{?dist} | tr '.' '~')

Name:     rehex
Version:  %{base_version}+%{git_commit_sha}
Release:  0%{tilde_dist}
Summary:  Reverse Engineers' Hex Editor

License:  GPLv2
URL:      https://www.github.com/solemnwarning/rehex/
Source0:  rehex-%{git_commit_sha}.tar.gz

BuildRequires: capstone-devel
BuildRequires: gcc-c++
BuildRequires: jansson-devel
BuildRequires: libunistring-devel
BuildRequires: lua
BuildRequires: lua-devel
BuildRequires: make
BuildRequires: wxGTK3-devel
BuildRequires: xorg-x11-server-Xvfb

Requires: jansson
Requires: wxGTK3

%define base_make_flags DEBUG_CFLAGS="-DNDEBUG -ggdb" LUA_PKG=lua bindir=%{_bindir} datarootdir=%{_datadir} libdir=%{_libdir}

%if 0%{?el7}
%define extra_make_flags WX_CONFIG=wx-config-3.0 PLUGINS=exe
BuildRequires: pkgconfig
%else
BuildRequires: luarocks
BuildRequires: pkgconf
%endif

%description

%prep
%setup -q -n rehex-%{git_commit_sha}

%build

%if 0%{?el7}
# No need to install busted on EL7
%else
luarocks --tree="$(pwd)/lua-libs" install busted
export BUSTED="$(pwd)/lua-libs/bin/busted"

cat > "$(pwd)/lua-libs.env" <<EOF
%if 0%{?el8}
export LUA_PATH="$(pwd)/lua-libs/share/lua/5.3/?.lua;$(pwd)/lua-libs/share/lua/5.3/?/init.lua;;"
export LUA_CPATH="$(pwd)/lua-libs/lib64/lua/5.3/?.so"
%else
export LUA_PATH="$(pwd)/lua-libs/share/lua/5.4/?.lua;$(pwd)/lua-libs/share/lua/5.4/?/init.lua;;"
export LUA_CPATH="$(pwd)/lua-libs/lib64/lua/5.4/?.so"
%endif
EOF

. "$(pwd)/lua-libs.env"
%endif

make %{?_smp_mflags} %{base_make_flags} %{?extra_make_flags}

%check
%if 0%{?el7}
# No need to install busted on EL7
%else
. "$(pwd)/lua-libs.env"
%endif

xvfb-run -a -e /dev/stdout make %{?_smp_mflags} %{base_make_flags} %{?extra_make_flags} check

%install
%if 0%{?el7}
# No need to install busted on EL7
%else
. "$(pwd)/lua-libs.env"
%endif

rm -rf %{buildroot}
make %{base_make_flags} %{?extra_make_flags} DESTDIR=%{buildroot} install

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%{_bindir}/rehex
%{_datadir}/applications/rehex.desktop
%{_datadir}/icons/hicolor/16x16/apps/rehex.png
%{_datadir}/icons/hicolor/32x32/apps/rehex.png
%{_datadir}/icons/hicolor/48x48/apps/rehex.png
%{_datadir}/icons/hicolor/64x64/apps/rehex.png
%{_datadir}/icons/hicolor/128x128/apps/rehex.png
%{_datadir}/icons/hicolor/256x256/apps/rehex.png
%{_datadir}/icons/hicolor/512x512/apps/rehex.png
%{_libdir}/rehex/
