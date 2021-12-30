# Building for OS X

You will need the XCode build tools and the following additional libraries to build rehex on Mac:

- Capstone
- Jansson
- libunistring
- Lua (5.3+)
- wxWidgets

You can install them yourself, or source the included script in your shell to download and build private copies of them specifically for building rehex against:

    $ . tools/mac-build-dependencies.sh

Once the script finishes, you will be able to build rehex in the shell that ran it. The builds will be cached so the next time you open a shell and need to run it, it should complete immediately. Lots of environment variables are set in the shell so you probably shouldn't use it to build other software afterwards.

The following environment variables can be set before sourcing `mac-build-dependencies.sh`:

    REHEX_DEP_BUILD_DIR - Directory to build libraries under (defaults to <cwd>/mac-dependencies-build/)
    REHEX_DEP_TARGET_DIR - Directory to install libraries under (defauls to <cwd>/mac-dependencies/)

To build the application:

    $ make -f Makefile.osx

To build a dmg containing the application:

    $ make -f Makefile.osx REHex.dmg
