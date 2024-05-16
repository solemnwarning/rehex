# Compiling REHex

 - [Introduction](#introduction)
 - [Dependencies](#dependencies)
 - [Makefile environment variables](#makefile-environment-variables)
 - [Platform specific details](#platform-specific-details)
   - [Windows](#windows)
   - [macOS](#macos)

## Introduction

REHex is compiled using a (GNU) Makefile, most of the common targets (e.g. `all`, `install` and `check`) are present and the application can be configured by passing environment variables to make.

## Dependencies

The following libraries are required for building/running REHex:

 - Botan
 - Capstone
 - Jansson
 - libunistring
 - Lua (5.3+)
 - Template Toolkit (unless help is disabled)
 - wxWidgets

## Makefile environment variables

| Variable      | Default      | Description                                                   |
|---------------|--------------|---------------------------------------------------------------|
| `BUILD_HELP`  | `1`          | Enables (`1`) or disables (`0`) building the built-in manual. |
| `BUILD_TYPE`  | `release`    | Selects building a `release` or `debug` build.                |
| `WX_CONFIG`   | `wx-config`  | Name of `wx-config` command provided by wxWidgets.            |
| `BOTAN_PKG`<br>`CAPSTONE_PKG`<br>`JANSSON_PKG`<br>`LUA_PKG` | | Names of libraries registered with `pkg-config`. Ignored if `XXX_CFLAGS` and `XXX_LIBS` is set. |
| `BOTAN_CFLAGS`<br>`CAPSTONE_CFLAGS`<br>`JANSSON_CFLAGS`<br>`LUA_CFLAGS` | Obtained from `pkg-config` | Compile flags for library dependencies. |
| `BOTAN_LIBS`<br>`CAPSTONE_LIBS`<br>`JANSSON_LIBS`<br>`LUA_LIBS` | Obtained from `pkg-config` | Link flags for library dependencies. |
| `GTK_CFLAGS`<br>`GTK_LIBS` | Obtained from `pkg-config` | Compiler flags for GTK. Not used on Windows and macOS. |
| `CFLAGS`       |                       | Additional flags to use when compiling C source code.      |
| `CXXFLAGS`     |                       | Additional flags to use when compiling C++ source code.    |
| `LDFLAGS`      |                       | Additional linker flags.                                   |
| `LDLIBS`       |                       | Additional library flags to use when linking application.  |
| `prefix`       | `/usr/local`          | Installation path prefix.                                  |
| `exec_prefix`  | `$(prefix)`           | Installation path prefix.                                  |
| `bindir`       | `$(exec_prefix)/bin`  | Executable installation path.                              |
| `datarootdir`  | `$(prefix)/share`     | "Data files" installation path.                            |
| `datadir`      | `$(datarootdir)`      | "Data files" installation path.                            |
| `libdir`       | `$(exec_prefix)/lib`  | Library (plugins) installation path.                       |

## Platform-specific details

### Windows

The recommended way to compile REHex on Windows is using [MinGW MSYS2](https://www.msys2.org/) and the `Makefile.win` makefile.

    # Installing dependencies (MinGW64)
    $ pacman -S base-devel git mingw-w64-x86_64-{toolchain,wxWidgets3.2,jansson,capstone,jbigkit,lua,libbotan,libunistring}

    # Installing dependencies (MinGW32)
    $ pacman -S base-devel git mingw-w64-i686-{toolchain,wxWidgets3.2,jansson,capstone,jbigkit,lua,libbotan,libunistring}

    # Building the application.
    $ cd /path/to/rehex/source/
    $ make -f Makefile.win

There is also a Visual Studio solution (`msvc/rehex.sln`) which will download and build dependencies using vcpkg and then build the editor. This is less-tested, but provided for those who prefer development within the Visual Studio environment. Note that some things (e.g. running plugin tests and generating the help file) aren't integrated with the solution.

There is a `Makefile.msvc` makefile which uses the above Visual Studio solution to build the application while allowing you to run the tests and build a distribution package as per normal. It needs to be run from an MSYS2 (or similar) shell for the POSIX tools and the path to `MSBuild.exe` may be specified via the `MSBUILD` variable. This is used for the official 32-bit packages.

### macOS

You will need the XCode build tools and the libraries listed above to build REHex on macOS.

You can provide the libraries yourself, or source the included script in your shell to download and build private copies of them specifically for building rehex against:

    $ . tools/mac-build-dependencies.sh

Once the script finishes, you will be able to build rehex in the shell that ran it. The builds will be cached so the next time you open a shell and need to run it, it should complete immediately. Lots of environment variables are set in the shell so you probably shouldn't use it to build other software afterwards.

The following environment variables can be set before sourcing `mac-build-dependencies.sh`:

| Variable                | Default                          | Description                           |
|-------------------------|----------------------------------|---------------------------------------|
| `REHEX_DEP_BUILD_DIR`   | `<cwd>/mac-dependencies-build/`  | Directory to build libraries under.   |
| `REHEX_DEP_TARGET_DIR`  | `<cwd>/mac-dependencies/`        | Directory to install libraries under. |

To build the application:

    $ make -f Makefile.osx

To build a dmg containing the application:

    $ make -f Makefile.osx REHex.dmg
