# Building for Windows

## Cross compiling

Easier to set up than a native Windows toolchain, only downside is you can't (easily) run the tests. The following steps are based on a Debian host.

NOTE: Replace x86_64 with i686 if you want to produce 32-bit binaries.

1) Install the MinGW cross-compiling toolchain.

  $ sudo apt-get install mingw-w64

2) Build wxWidgets and install under your toolchain directory

  $ cd wxWidgets-XXX
  $ ./configure --host=x86_64-w64-mingw32 --prefix=/usr/x86_64-w64-mingw32/
  $ make
  $ sudo make install

3) Build and install Jansson in the same way

4) Now build rehex.exe with the following command:

  $ CC=x86_64-w64-mingw32-gcc CXX=x86_64-w64-mingw32-g++ \
    WX_CONFIG=/usr/x86_64-w64-mingw32/bin/wx-config EXE=.exe make

You will need to copy the following DLLs (version numbers or paths may differ) from your build host alongside rehex.exe:

 * /usr/x86_64-w64-mingw32/bin/libjansson-4.dll
 * /usr/x86_64-w64-mingw32/lib/wxbase30u_gcc_custom.dll
 * /usr/x86_64-w64-mingw32/lib/wxmsw30u_core_gcc_custom.dll
 * /usr/lib/gcc/x86_64-w64-mingw32/6.3-win32/libgcc_s_seh-1.dll
 * /usr/lib/gcc/x86_64-w64-mingw32/6.3-win32/libstdc++-6.dll

## Compiling on Windows

Somewhat of a faff to set up a toolchain, but read on...

1) MSYS2

Download and install MSYS2 from http://www.msys2.org/

2) win-builds

Download and run the win-builds installer from http://win-builds.org/

Choose architecture and install to C:\i686-w64-mingw32 or C:\x86_64-w64-mingw32 depending whether you want to make 32-bit or 64-bit binaries. You may install both.

You may change the install paths, but it MUST NOT contain spaces, else the wxWidgets build process will fail.

3) wxwidgets

Run the MSYS command line.

NOTE: In all commands below, substitute `$ARCH` for i686 or x86_64, depending which you chose above.

Add the win-builds toolchain to your PATH:

  export PATH="$PATH:/c/$ARCH-w64-mingw32/bin"

Configure and install wxWidgets in the traditional way:

  ./configure --host=$ARCH-w64-mingw32 --build=$ARCH-w64-mingw32 --prefix=/c/$ARCH-w64-mingw32
  make
  make install

If you find GCC silently exits with status 1 while building wxWidgets, try running configure with `--disable-precomp-headers`.

Copy the wxWidgets DLLs to your toolchain bin directory so they can be found when you try running executables linked against them:

  cp /c/$ARCH-w64-mingw32/lib/wx*.dll /c/$ARCH-w64-mingw32/bin/

4) jansson

Same as above, but you don't need to copy the DLLs to bin/ (make install will do it)

5) Build rehex

Once the above steps are done, you should be able to build inside msys so long as you have the appropriate toolchain in your PATH.

  make
  make check

# Buildkite

Create a "buildkite" user

1) Install the Buildkite Agent somewhere (e.g. `C:\Program Files\Buildkite`)

2) Create a "builds" folder under the installation directory, give the buildkite user permission to write under it.

3) Create buildkite-agent-i686.cfg, e.g:

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

4) Create run-agent-i686.bat:

  C:
  cd "\Program Files\Buildkite"
  
  set PATH=%PATH%;C:\i686-w64-mingw32\bin;C:\msys64\usr\bin
  
  buildkite-agent.exe start --config buildkite-agent-i686.cfg

5) Setup service(s) to run the Agent using NSSM (https://nssm.cc/)

## Appendix: HTTP proxy

If your build agent needs to access the internet via a HTTP proxy, put lines like the following in your agent startup batch script:

  set http_proxy=http://10.52.13.1:8080/
  set https_proxy=http://10.52.13.1:8080/
  
  set HTTP_PROXY=http://10.52.13.1:8080/
  set HTTPS_PROXY=http://10.52.13.1:8080/

You may also need to change the user's Windows proxy settings, you can do this from your own account by running Internet Explorer as the buildkite user and changing the Internet Options within.
