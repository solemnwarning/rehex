bindings/readme.txt - describes generating the binding files for wxLua

The bindings for wxLua provide information for lua to interface with
the wxWindows C++ API. The binding files are a skeleton that the program
genwxbind.lua parses and turns into C functions that are imported into lua. For
more information about writing your own bindings see docs/binding.html.

The output of the bindings are placed into modules/wxbind and modules/wxbindstc.

If you have edited the *.i interface files you need to regenerate the bindings.
The lua program must have been previously compiled for this to work.
   MSW: run genwxbind.bat
   Unix: run make in the bindings/ dir

DO NOT EDIT the cpp files in modules/wxbind and modules/wxbindstc since any
changes will be overwritten by the binding generator. You should make changes
to the interface files and regenerate the bindings.
