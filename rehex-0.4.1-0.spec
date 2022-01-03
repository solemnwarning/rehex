%define base_version 0.4.1
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
BuildRequires: wxGTK3-devel
BuildRequires: xorg-x11-server-Xvfb

Requires: jansson
Requires: wxGTK3

%define base_make_flags DEBUG_CFLAGS="-DNDEBUG -ggdb" LUA_PKG=lua bindir=%{_bindir} datarootdir=%{_datadir} libdir=%{_libdir}

%if 0%{?el7}
%define extra_make_flags WX_CONFIG=wx-config-3.0
BuildRequires: pkgconfig
%else
BuildRequires: pkgconf
%endif

%description

%prep
%setup -q -n rehex-%{base_version}

%build
make %{?_smp_mflags} %{base_make_flags} %{?extra_make_flags}

%check
xvfb-run -a -e xvfb-run.err make %{?_smp_mflags} %{base_make_flags} %{?extra_make_flags} check
cat xvfb-run.err

%install
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
