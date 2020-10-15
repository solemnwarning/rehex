# ![rehex logo](res/icon64.png) Reverse Engineers' Hex Editor

A cross-platform (Windows, Linux, Mac) hex editor for reverse engineering, and everything else.

## Features

* Large (1TB+) file support
* Decoding of integer/floating point value types
* Disassembly of machine code
* Highlighting and annotation of ranges of bytes
* Side by side comparision of selections

![inline comments + data types demo](doc/comments-types.gif)

![file diff demo](doc/file-diff.gif)

## Installation

The [Releases](https://github.com/solemnwarning/rehex/releases) page has standalone packages for Windows and Mac, as well as installable packages for popular Linux distributions.

The same packages are also produced for Git commits (look for the tick), if you want to try the latest/unreleased version.

If you want to compile it yourself on Linux, just check out the source and run `make`. You will need Jansson, wxWidgets and capstone installed, along with their development packages (Install `build-essential`, `git`, `libwxgtk3.0-dev`, `libjansson-dev` and `libcapstone-dev` on Ubuntu).

For Windows or Mac build instructions, see the relevant README: [README.Windows.md](README.Windows.md) [README.OSX.md](README.OSX.md)

## Feedback

If you find any bugs or have suggestions for improvements or new features, please open an issue on Github.
