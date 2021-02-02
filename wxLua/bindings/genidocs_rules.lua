-- ----------------------------------------------------------------------------
-- Rules to build the wxWidgets reference for wxLua
--  load using : $lua -e"rulesFilename=\"rules.lua\"" genidocs.lua
-- ----------------------------------------------------------------------------

-- ----------------------------------------------------------------------------
-- Set the root directory of the wxLua distribution, used only in this file
wxlua_dir = "../"

-- ============================================================================
-- Set the output filename for the generated html
output_filename = wxlua_dir.."/docs/wxluaref.html"

-- ============================================================================
-- A list of interface files to use to make the bindings. These files will be
--   converted into a html file and placed in the output_filepath directory.
--   The files are loaded from the file_path.
interface_fileTable =
{
    {
        ["namespace"] = "wx",
        ["file_path"] = "wxwidgets/",
        ["prepend_name"] = "wxbase/",
        ["datatypes_filename"] = "wxbase_datatypes.lua",
        ["files"] = {
            "wxbase_base.i",
            "wxbase_config.i",
            "wxbase_data.i",
            "wxbase_datetime.i",
            "wxbase_file.i",
        }
    },
    {
        ["namespace"] = "wx",
        ["file_path"] = "wxwidgets/",
        ["prepend_name"] = "wxcore/",
        ["datatypes_filename"] = "wxcore_datatypes.lua",
        ["files"] = {
            "wxcore_appframe.i",
            "wxcore_clipdrag.i",
            "wxcore_controls.i",
            "wxcore_core.i",
            "wxcore_defsutils.i",
            "wxcore_dialogs.i",
            "wxcore_event.i",
            "wxcore_gdi.i",
            "wxcore_geometry.i",
            "wxcore_help.i",
            "wxcore_image.i",
            "wxcore_mdi.i",
            "wxcore_menutool.i",
            "wxcore_picker.i",
            "wxcore_print.i",
            "wxcore_sizer.i",
            "wxcore_windows.i",
        }
    },
    {
        ["namespace"] = "wx",
        ["file_path"] = "wxwidgets/",
        ["prepend_name"] = "wxadv/",
        ["datatypes_filename"] = "wxadv_datatypes.lua",
        ["files"] = {
            "wxadv_adv.i",
            "wxadv_grid.i"
        }
    },
    {
        ["namespace"] = "wx",
        ["file_path"] = "wxwidgets/",
        ["prepend_name"] = "wxnet/",
        ["datatypes_filename"] = "wxnet_datatypes.lua",
        ["files"] = {
            "wxnet_net.i"
        }
    },
    {
        ["namespace"] = "wx",
        ["file_path"] = "wxwidgets/",
        ["prepend_name"] = "wxmedia/",
        ["datatypes_filename"] = "wxmedia_datatypes.lua",
        ["files"] = {
            "wxmedia_media.i"
        }
    },
    {
        ["namespace"] = "wx",
        ["file_path"] = "wxwidgets/",
        ["prepend_name"] = "wxgl/",
        ["datatypes_filename"] = "wxgl_datatypes.lua",
        ["files"] = {
            "wxgl_gl.i"
        }
    },
    {
        ["namespace"] = "wx",
        ["file_path"] = "wxwidgets/",
        ["prepend_name"] = "wxxml/",
        ["datatypes_filename"] = "wxxml_datatypes.lua",
        ["files"] = {
            "wxxml_xml.i"
        }
    },
    {
        ["namespace"] = "wx",
        ["file_path"] = "wxwidgets/",
        ["prepend_name"] = "wxxrc/",
        ["datatypes_filename"] = "wxxrc_datatypes.lua",
        ["files"] = {
            "wxxrc_xrc.i"
        }
    },

    {
        ["namespace"] = "wxaui",
        ["file_path"] = "wxwidgets/",
        ["prepend_name"] = "wxaui/",
        ["datatypes_filename"] = "wxaui_datatypes.lua",
        ["files"] = {
            "wxaui_aui.i"
        }
    },
    {
        ["namespace"] = "wxhtml",
        ["file_path"] = "wxwidgets/",
        ["prepend_name"] = "wxhtml/",
        ["datatypes_filename"] = "wxhtml_datatypes.lua",
        ["files"] = {
            "wxhtml_html.i"
        }
    },
    {
        ["namespace"] = "wxstc",
        ["file_path"] = "wxwidgets/",
        ["prepend_name"] = "wxstc/",
        ["datatypes_filename"] = "wxstc_datatypes.lua",
        ["files"] = {
            "wxstc_stc.i"
        }
    },
    { 
        ["namespace"] = "wxwebview",
        ["file_path"] = "wxwidgets/",
        ["prepend_name"] = "wxwebview/",
        ["datatypes_filename"] = "wxwebview_datatypes.lua",
        ["files"] = {
            "wxwebview_webview.i"
        }
    },

    {
        ["namespace"] = "wxlua",
        ["file_path"] = "wxlua/",
        ["prepend_name"] = "wxlua/",
        ["datatypes_filename"] = "wxlua_datatypes.lua",
        ["files"] = {
            "wxlua.i"
        }
    },
    {
        ["namespace"] = "wxlua",
        ["file_path"] = "wxlua_debugger/",
        ["prepend_name"] = "wxluadebugger/",
        ["datatypes_filename"] = "wxluadebugger_datatypes.lua",
        ["files"] = {
            "wxluadebugger.i"
        }
    }
}

-- ============================================================================
-- A list of files that contain class names only that should be a complete
-- list of all classes that could be wrapped.
-- This will be mixed in with the classes in the interface files to explicitly
-- show what is and isn't wrapped.
completeClassRefFileTable = { "wxwidgets/wxclassref.txt" }

-- If you specify the complete list above, name the col that will be checked
-- if the class wrapped by lua in in the complete list
completeClassRefColLabel = "In wxWidgets Manual"

-- A message to append to the class name in the index for classes.
msgForClassInIndex = {
    ["wxAccessible"]        = "MS Windows only and disabled by default in wxWidgets",
    ["wxAppTraits"]         = "Most functions are available elsewhere",
    ["wxArray"]             = "Not a real class, see implementations (wxArrayInt)",
    ["wxArrayInt"]          = "Interchangeable with a numeric indexed Lua table",
    ["wxArrayDouble"]       = "Interchangeable with a numeric indexed Lua table",
    ["wxArrayString"]       = "Interchangeable with a numeric indexed Lua table",
    ["wxBitmapHandler"]     = "Base class for bitmap loaders, not needed",
    ["wxCondition"]         = "For threading in C",
    ["wxCmdLineParser"]     = "Easier to implement in Lua",
    ["wxCSConv"]            = "Lua uses ANSI 8-bit strings",

    ["wxDb"]                = "Deprecated and will not be in wxWidgets 3.0",
    ["wxDbColDataPtr"]      = "Deprecated and will not be in wxWidgets 3.0",
    ["wxDbColDef"]          = "Deprecated and will not be in wxWidgets 3.0",
    ["wxDbColFor"]          = "Deprecated and will not be in wxWidgets 3.0",
    ["wxDbColInf"]          = "Deprecated and will not be in wxWidgets 3.0",
    ["wxDbConnectInf"]      = "Deprecated and will not be in wxWidgets 3.0",
    ["wxDbGridColInfo"]     = "Deprecated and will not be in wxWidgets 3.0",
    ["wxDbGridTableBase"]   = "Deprecated and will not be in wxWidgets 3.0",
    ["wxDbIdxDef"]          = "Deprecated and will not be in wxWidgets 3.0",
    ["wxDbInf"]             = "Deprecated and will not be in wxWidgets 3.0",
    ["wxDbTable"]           = "Deprecated and will not be in wxWidgets 3.0",
    ["wxDbTableInf"]        = "Deprecated and will not be in wxWidgets 3.0",

    ["wxDirTraverser"]      = "Use wxDir::GetFirst() and GetNext()",
    ["wxDllLoader"]         = "Deprecated since version 2.4, see wxDynamicLibrary",
    ["wxEncodingConverter"] = "Lua uses ANSI 8-bit strings",
    ["wxHashMap"]           = "Lua tables are hash tables",
    ["wxHashSet"]           = "Lua tables are hash tables",
    ["wxHashTable"]         = "Lua tables are hash tables",
    ["wxMBConv"]            = "Lua uses ANSI 8-bit strings",
    ["wxMBConvFile"]        = "Lua uses ANSI 8-bit strings",
    ["wxMBConvUTF16"]       = "Lua uses ANSI 8-bit strings",
    ["wxMBConvUTF32"]       = "Lua uses ANSI 8-bit strings",
    ["wxMBConvUTF7"]        = "Lua uses ANSI 8-bit strings",
    ["wxMBConvUTF8"]        = "Lua uses ANSI 8-bit strings",
    ["wxModule"]            = "Useable in C++ only",
    ["wxMutex"]             = "For threading in C",
    ["wxMutexLocker"]       = "For threading in C",
    ["wxRealPoint"]         = "Not used anywhere in wxWidgets",
    ["wxRecursionGuard"]    = "Easier to implement in Lua",
    ["wxRecursionGuardFlag"]= "Easier to implement in Lua",
    ["wxScopedArray"]       = "Useable in C++ only (unnecessary in Lua)",
    ["wxScopedPtr"]         = "Useable in C++ only (unnecessary in Lua)",
    ["wxScopedTiedPtr"]     = "Useable in C++ only (unnecessary in Lua)",
    ["wxSemaphore"]         = "For threading in C",
    ["wxSortedArrayString"] = "Interchangeable with a numeric indexed Lua table",
    ["wxString"]            = "Interchangeable with a Lua string",
    ["wxStringBuffer"]      = "Useable in C++ only (unnecessary in Lua)",
    ["wxStringBufferLength"]= "Useable in C++ only (unnecessary in Lua)",
    ["wxVariant"]           = "Unnecessary in Lua",
    ["wxVariantData"]       = "Unnecessary in Lua",
}

-- ============================================================================
-- The HTML header for the generated file.
htmlHeader = [[
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html>
<head>
    <meta content="text/html; charset=ISO-8859-1" http-equiv="content-type">
    <title>wxLua Reference Manual</title>
    <meta content="John Labenski" name="author">
    <META content="wxLua Reference Manual" name="description">
    <LINK rel="stylesheet" type="text/css" href="wxlua.css">
</head>
<body>

<h1>wxLua 2.8.12.2 Reference Manual for wxWidgets 2.8.12</h1>
]]

