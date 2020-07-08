# Building for OS X

## Building libraries

### wxWidgets

    $ tar xf wxWidgets-3.0.4.tar.bz2
    $ cd wxWidgets-3.0.4/
    
    $ mkdir build-debug
    $ cd build-debug/
    
    $ ../configure --disable-shared --enable-debug --enable-unicode \
                   -enable-cxx11 --prefix="/opt/wxWidgets-3.0.4-debug/" \
                   -with-macosx-version-min=10.10 \
                   CXXFLAGS="-stdlib=libc++" CPPFLAGS="-stdlib=libc++" \
                   LIBS=-lc++
    $ make
    $ sudo make install

### Jansson

    $ tar xf jansson-2.11.tar
    $ cd jansson-2.11/
    
    $ ./configure --prefix=/usr/local/ --enable-shared=no --enable-static=yes \
                  CFLAGS="-mmacosx-version-min=10.10"
    $ make
    $ sudo make install

### Capstone

    $ tar xf capstone-4.0.2.tar.xz
    $ cd capstone-4.0.2/
    
    $ mkdir build-release
    $ cd build-release/
    
    $ PREFIX=/usr/local/ \
      CAPSTONE_STATIC=yes \
      CAPSTONE_SHARED=no \
      CAPSTONE_BUILD_CORE_ONLY=yes
      sudo make install

## Building the editor

    $ WX_CONFIG=/opt/wxWidgets-3.0.4-debug/bin/wx-config \
        make -f Makefile.osx

To build a dmg, run:

    make -f Makefile.osx REHex.dmg
