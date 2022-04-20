# Building for Windows

REHex is built on Windows using MinGW and libraries from the MSYS2 project.

## Toolchain setup

1) Download and install MSYS2 from http://www.msys2.org/

2) Open either the MinGW32 or MinGW64 (depending which architecture you want to build for) MSYS2 shell from the start menu.

3) Install required packages:

    # For 64-bit
    $ pacman -S base-devel git mingw-w64-x86_64-{toolchain,wxWidgets,jansson,capstone,jbigkit,lua,libunistring}

    # For 32-bit
    $ pacman -S base-devel git mingw-w64-i686-{toolchain,wxWidgets,jansson,capstone,jbigkit,lua,libunistring}

4) Build it

    $ cd /path/to/rehex/source/
    $ make -f Makefile.win
