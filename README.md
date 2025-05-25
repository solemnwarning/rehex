# ![rehex logo](res/icon64.png) Reverse Engineers' Hex Editor

A cross-platform (Windows, Linux, Mac, BSD) hex editor for reverse engineering, and everything else.

An online copy of the manual can be accessed here: [solemnwarning.net/rehex/manual/](https://solemnwarning.net/rehex/manual/).

## Features

* Large (1TB+) file support
* Decoding of integer/floating point value types
* Inline disassembly of machine code
* Highlighting and annotation of ranges of bytes
* Side by side comparision of whole files or selections
* Lua scripting support ([API reference](http://www.solemnwarning.net/rehex/luadoc/))
* Virtual address mapping support
* Support for common text encodings (ASCII, Unicode, ISO-8859-X, etc)
* Import and export of Intel HEX files.
* Bitmap data visualisation.
* Binary Templates for automatically annotating data (similar to 010 Editor).
* Bit editing/manipulation.
* Checksumming of files/selections.

![inline comments + data types demo](doc/comments-types.gif)

![file diff demo](doc/file-diff.gif)

## Installation

The [Releases](https://github.com/solemnwarning/rehex/releases) page has standalone packages for Windows and Mac, as well as installable packages for popular Linux distributions, or you can install them from a distribution package repository as described below.

The same packages are also produced for Git commits (look for the tick), if you want to try the development/unreleased versions.

### Debian

First, you will need to add my APT signing key to your system:

    sudo wget -O /etc/apt/trusted.gpg.d/solemnwarning-archive-keyring.gpg \
        https://repos.solemnwarning.net/debian/solemnwarning-archive-keyring.gpg

Add the following lines to your `/etc/apt/sources.list` file:

    deb http://repos.solemnwarning.net/debian/ CODENAME main
    deb-src http://repos.solemnwarning.net/debian/ CODENAME main

**NOTE:** Replace `CODENAME` with the version you're running (e.g. `bookworm` or `bullseye`).

Finally, you can install the package:

    $ sudo apt-get update
    $ sudo apt-get install rehex

### Ubuntu

First, you will need to add my APT signing key to your system:

    sudo wget -O /etc/apt/trusted.gpg.d/solemnwarning-archive-keyring.gpg \
        https://repos.solemnwarning.net/ubuntu/solemnwarning-archive-keyring.gpg

Add the following lines to your `/etc/apt/sources.list` file:

    deb  [arch=amd64] http://repos.solemnwarning.net/ubuntu/ CODENAME main
    deb-src  [arch=amd64] http://repos.solemnwarning.net/ubuntu/ CODENAME main

**NOTE:** Replace `CODENAME` with the version you're running (e.g. `focal` for 20.04 or `lunar` for 23.04).

Finally, you can install the package:

    $ sudo apt-get update
    $ sudo apt-get install rehex

**NOTE:** Ubuntu users must have the "universe" package repository enabled to install some of the dependencies.

### Fedora

    $ sudo dnf copr enable solemnwarning/rehex
    $ sudo dnf install rehex

### CentOS

    $ sudo dnf install epel-release
    $ sudo dnf copr enable solemnwarning/rehex
    $ sudo dnf install rehex

### openSUSE
    $ sudo zypper ar obs://editors editors
    $ sudo zypper ref
    $ sudo zypper in rehex

### FreeBSD
    $ pkg install rehex

### Gentoo (pentoo-overlay)
    $ USE="git" emerge eselect-repository -av
    $ eselect repository enable pentoo
    $ emaint -a sync
    $ emerge app-editors/rehex -va
    
## Building

Compiling REHex from source is described in [COMPILING.md](COMPILING.md).

## Feedback

If you find any bugs or have suggestions for improvements or new features, please open an issue on Github.
