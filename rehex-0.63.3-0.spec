%define base_version 0.63.3
%define tilde_dist %(echo %{?dist} | tr '.' '~')

Name:     rehex
Version:  %{base_version}
Release:  0%{tilde_dist}
Summary:  Reverse Engineers' Hex Editor

License:  GPLv2
URL:      https://www.github.com/solemnwarning/rehex/
Source0:  rehex-%{base_version}.tar.gz

BuildRequires: capstone-devel
BuildRequires: gcc-c++
BuildRequires: jansson-devel
BuildRequires: libunistring-devel
BuildRequires: lua
BuildRequires: lua-devel
BuildRequires: make
BuildRequires: perl-Template-Toolkit
BuildRequires: xorg-x11-server-Xvfb

Requires: jansson

%if 0%{?fedora} >= 39
BuildRequires: wxGTK-devel
Requires: wxGTK
%else
BuildRequires: wxGTK3-devel
Requires: wxGTK3
%endif

%define base_make_flags DEBUG_CFLAGS="-DNDEBUG -ggdb" LUA_PKG=lua bindir=%{_bindir} datarootdir=%{_datadir} libdir=%{_libdir}

%if 0%{?el7}
# Build with -fpermissive to work around GCC bug #56480 on RHEL 7.
%define extra_make_flags WX_CONFIG=wx-config-3.0 PLUGINS=exe CXX="g++ -fpermissive" BOTAN_PKG=botan-1.10
BuildRequires: botan-devel
BuildRequires: pkgconfig
%else
BuildRequires: botan2-devel
BuildRequires: luarocks
BuildRequires: pkgconf
%endif

%description

%prep
%setup -q -n rehex-%{base_version}

%build

%if 0%{?el7}
# No need to install busted on EL7
%else
luarocks --tree="$(pwd)/lua-libs" install busted

%if 0%{?el8}
%define lua_env_vars BUSTED="$(pwd)/lua-libs/bin/busted" LUA_PATH="$(pwd)/lua-libs/share/lua/5.3/?.lua;$(pwd)/lua-libs/share/lua/5.3/?/init.lua;;" LUA_CPATH="$(pwd)/lua-libs/lib64/lua/5.3/?.so"
%else
%define lua_env_vars BUSTED="$(pwd)/lua-libs/bin/busted" LUA_PATH="$(pwd)/lua-libs/share/lua/5.4/?.lua;$(pwd)/lua-libs/share/lua/5.4/?/init.lua;;" LUA_CPATH="$(pwd)/lua-libs/lib64/lua/5.4/?.so"
%endif
%endif

%{?lua_env_vars} make %{?_smp_mflags} %{base_make_flags} %{?extra_make_flags}

%check
%{?lua_env_vars} xvfb-run -a -e xvfb-run.err make %{?_smp_mflags} %{base_make_flags} %{?extra_make_flags} check
cat xvfb-run.err

%install
rm -rf %{buildroot}
%{?lua_env_vars} make %{base_make_flags} %{?extra_make_flags} DESTDIR=%{buildroot} install

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
%{_datadir}/rehex/
%{_libdir}/rehex/
