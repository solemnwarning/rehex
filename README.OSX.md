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

## Building the editor

    WX_CONFIG=/opt/wxWidgets-3.0.4-debug/bin/wx-config make
