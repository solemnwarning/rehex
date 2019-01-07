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

### LLVM

    $ tar xf llvm-7.0.0.src.tar.xz
    $ cd llvm-7.0.0.src/
    
    $ mkdir build-release
    $ cd build-release/
    
    $ cmake .. -DCMAKE_BUILD_TYPE=Release \
               -DCMAKE_INSTALL_PREFIX=/opt/llvm-7.0.0-release-static/ \
               -DLLVM_BUILD_LLVM_DYLIB=OFF \
               -DCMAKE_CXX_FLAGS="-std=c++11 -stdlib=libc++" \
               -DCMAKE_OSX_DEPLOYMENT_TARGET=10.10
    $ cmake --build .
    $ sudo cmake --build . --target install

## Building the editor

    $ WX_CONFIG=/opt/wxWidgets-3.0.4-debug/bin/wx-config \
        LLVM_CONFIG=/opt/llvm-7.0.0-release-static/bin/llvm-config \
        make -f Makefile.osx

To build a dmg, run:

    make -f Makefile.osx REHex.dmg
