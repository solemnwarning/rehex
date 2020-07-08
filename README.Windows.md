# Building for Windows

This is a rough guide of how I have set up my 64-bit Windows build environment. Things may need changing e.g. to install a 32-bit one, or when version numbers change.

## Toolchain setup

### mingw-w64

Download the installer from http://mingw-w64.org/ and use the following settings:

Architecture: x86_64
Threads: posix
Install path: C:\x86_64-w64-mingw32\

You can use a different install path, but it will impact the following steps, and it MUST NOT contain any spaces.

### MSYS2

Download and install MSYS2 from http://www.msys2.org/

Open the MSYS2 command line and install additional packages.

    $ pacman -S make

### wxWidgets

Open the MSYS2 command line and add the appropriate mingw-w64 toolchain to your PATH.

    $ export PATH="$PATH:/c/x86_64-w64-mingw32/mingw64/bin"

Unpack the wxWidgets source and set up a build directory.

    $ cd wxWidgets-3.0.4
    $ mkdir build-release-static-x86_64
    $ cd build-release-static-x86_64

Build and install wxWidgets.

    $ ../configure --host=x86_64-w64-mingw32 \
                   --build=x86_64-w64-mingw32 \
                   --prefix=/c/x86_64-w64-mingw32/wxWidgets-3.0.4-release-static/ \
                   --disable-shared \
                   --with-zlib=builtin \
                   --with-expat=builtin \
                   --without-libjpeg \
                   --without-libtiff \
                   --without-regex
    $ make
    $ make install

### Jansson

Open the MSYS2 command line and add the appropriate mingw-w64 toolchain to your PATH.

    $ export PATH="$PATH:/c/x86_64-w64-mingw32/mingw64/bin"

Build and install Jansson.

    $ cd jansson-2.10
    $ ./configure --host=x86_64-w64-mingw32 \
                  --build=x86_64-w64-mingw32 \
                  --prefix=/c/x86_64-w64-mingw32/mingw64/x86_64-w64-mingw32/ \
                  --enable-shared=no \
                  --enable-static=yes
    $ make
    $ make install

### Capstone

Open the MSYS2 command line.

    $ cd capstone-4.0.2
    $ PREFIX=/c/x86_64-w64-mingw32/mingw64/x86_64-w64-mingw32/ \
      CAPSTONE_STATIC=yes \
      CAPSTONE_SHARED=no \
      CAPSTONE_BUILD_CORE_ONLY=yes \
      CC=x86_64-w64-mingw32-gcc \
      CXX=x86_64-w64-mingw32-g++ \
      make install

## Build rehex

Once the above steps are done, you should be able to build from the MSYS2 command line so long as you have the appropriate environment variables set.

    $ export PATH="$PATH:/c/x86_64-w64-mingw32/mingw64/bin"
    $ export CC=x86_64-w64-mingw32-gcc
    $ export CXX=x86_64-w64-mingw32-g++
    $ export WX_CONFIG=/c/x86_64-w64-mingw32/wxWidgets-3.0.4-release-static/bin/wx-config
    
    $ make -f Makefile.win
    $ make -f Makefile.win check

# Buildkite Agent deployment

Create a "buildkite" user

Install the Buildkite Agent somewhere (e.g. `C:\Program Files\Buildkite`)

Create a "builds" folder under the installation directory, give the buildkite user permission to write under it.

Create buildkite-agent-i686.cfg, e.g:

    # The token from your Buildkite "Agents" page
    token="XXX"
    
    # The name of the agent
    name="%hostname-%n"
    
    # The priority of the agent (higher priorities are assigned work first)
    # priority=1
    
    # Meta-data for the agent (default is "queue=default")
    meta-data="queue=windows-i686"
    
    # Path to the bootstrap script. You should avoid changing this file as it will
    # be overridden when you update your agent. If you need to make changes to this
    # file: use the hooks provided, or copy the file and reference it here.
    bootstrap-script="bootstrap.bat"
    
    # Path to where the builds will run from
    build-path="builds"
    
    # Directory where the hook scripts are found
    hooks-path="hooks"
    
    # Flags to pass to the `git clean` command
    git-clean-flags="-fdqx"

Create run-agent-i686.bat:

    C:
    cd "\Program Files\Buildkite"
    
    set PATH=%PATH%;C:\i686-w64-mingw32\mingw64\bin;C:\msys64\usr\bin
    set CC=x86_64-w64-mingw32-gcc
    set CXX=x86_64-w64-mingw32-g++
    
    buildkite-agent.exe start --config buildkite-agent-i686.cfg

Setup service(s) to run the Agent using NSSM (https://nssm.cc/)

## Appendix: HTTP proxy

If your build agent needs to access the internet via a HTTP proxy, put lines like the following in your agent startup batch script:

    set http_proxy=http://10.52.13.1:8080/
    set https_proxy=http://10.52.13.1:8080/
    
    set HTTP_PROXY=http://10.52.13.1:8080/
    set HTTPS_PROXY=http://10.52.13.1:8080/

You may also need to change the buildkite user's Windows proxy settings, you can do this from your own account by running Internet Explorer as the buildkite user and changing the Internet Options within.
