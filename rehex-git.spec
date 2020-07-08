%define base_version 0.2.0
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
BuildRequires: make
BuildRequires: wxGTK3-devel
BuildRequires: xorg-x11-server-Xvfb

Requires: jansson
Requires: wxGTK3

# TODO: Remove LLVM dependencies when switch to Capstone is complete

%if 0%{?el7}
%define extra_make_flags WX_CONFIG=wx-config-3.0 LLVM_CONFIG=llvm-config-7.0-64
BuildRequires: llvm7.0-devel
%else
BuildRequires: llvm-devel
%endif

%description

%prep
%setup -q -n rehex-%{git_commit_sha}

%build
make %{?_smp_mflags} %{?extra_make_flags}

%check
xvfb-run -a -e /dev/stdout make %{?_smp_mflags} %{?extra_make_flags} check

%install
rm -rf %{buildroot}
make %{?extra_make_flags} bindir=%{_bindir} datarootdir=%{_datadir} DESTDIR=%{buildroot} install

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
