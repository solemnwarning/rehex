-- ---------------------------------------------------------------------------
-- Name:        genwxbind.lua
-- Purpose:     This script generates wrapper files from the table interface_fileTable (see below)
-- Author:      Ray Gilbert, J Winwood, John Labenski
-- Created:     19/05/2004
-- Copyright:   Ray Gilbert
-- Licence:     wxWidgets licence
-- ---------------------------------------------------------------------------
-- This generator creates
-- * separate cpp files for each interface file
-- * each wrapper file uses c-preprocessor defines, and leaves it
--   up to the compiler to add correct wrapper functions. This also has
--   the advantage of being able to distribute pre-generated wrapper interface files
-- ---------------------------------------------------------------------------

-- ---------------------------------------------------------------------------
-- Globals
-- ---------------------------------------------------------------------------

WXLUA_BINDING_VERSION = 41 -- Used to verify that the bindings are updated
                           -- This must match modules/wxlua/wxldefs.h
                           -- otherwise a compile time error will be generated.

-- Test the interface files by casting the object to the baseclasses, use only temporarily for debugging
testInheritanceByCasting = false

bindingKeywordTable     = {} -- Binding keywords used by the generator %XXX
skipBindingKeywordTable = {} -- Binding keywords to skip and not handle (for testing?)
bindingOperatorTable    = {} -- Binding %operator keywords

preprocConditionTable = {} -- Preprocessor conditions for #ifing the output code
                           --   table["binding code condition"] = "C preproc code suitable for #if statement"
preprocOperatorTable  = {} -- Preprocessor operators, e.g. table["&"] == "&&"

typedefTable        = {} -- all typedefs read from the interface files
dataTypeTable       = {} -- all datatypes; int, double, class names, see AllocDataType
dataTypeAttribTable = {} -- attributes for data types; unsigned, const
dataTypeUIntTable   = {} -- datatypes that are unsigned numbers
dataTypeFloatTable  = {} -- datatypes that are float (and similar) numbers
dataTypeBoolTable   = {} -- datatypes that are boolean
functionAttribTable = {} -- attributes for functions; static, virtual

enumBindingTable           = {} -- table[i] = { Map, Condition, ... }
defineBindingTable         = {} -- table[i] = { Map, Condition, ... }
stringBindingTable         = {} -- table[i] = { Map, Condition, ... }
objectBindingTable         = {} -- table[i] = { Map, Condition, ... }
pointerBindingTable        = {} -- table[i] = { Map, Condition, ... }
eventBindingTable          = {} -- table[i] = { Map, Condition, ... }
functionBindingTable       = {} -- table[i] = { Map, Condition, Method, ... }
classBindingTable          = {}
enumClassBindingTable      = {} -- table[classname][i] = { Map, Condition, ... }
classTypeBindingTable      = {}
classIncludeBindingTable   = {}

overrideTable     = {} -- binding code from override file as a table indexed by C function name
overrideTableUsed = {} -- table set to true if override was used, indexed by C function name

-- ----------------------------------------------------------------------------
-- Helpers for SplitString to make it faster
-- ----------------------------------------------------------------------------

-- Table of delimiters in the binding text that separate different elements.
-- Used in SplitString when reading the binding files.
bindingDelimiters   = { "[]", "==", ">=", "<=", "&&", "||", "//", "/*", "*/", "*", "&", "|", "(", ")", "[", "]", "::", ":", ",", "=", "+", "-", "/", "\\", "~", "<", ">", "{", "}", "!", ";", "\t", "\r", "\n", " " }
bindingDelimsToKeep = { "[]", "==", ">=", "<=", "&&", "||", "//", "/*", "*/", "*", "&", "|", "(", ")", "[", "]", "::", ":", ",", "=", "+", "-", "/", "\\", "~", "<", ">", "{", "}", "!", ";" }

bindingDelimiters_hash = {}
for i = 1, #bindingDelimiters do
    bindingDelimiters_hash[bindingDelimiters[i]] = true
end

-- make these string.XXX functions local so there's no table lookup
local string_sub  = string.sub
local string_len  = string.len
local string_byte = string.byte

local char_BACKSLASH   = string.byte("\\")
local char_DOUBLEQUOTE = string.byte("\"")
local char_DASH        = string.byte("-")

digitTable = { [string_byte("0")]=true, [string_byte("1")]=true,
               [string_byte("2")]=true, [string_byte("3")]=true,
               [string_byte("4")]=true, [string_byte("5")]=true,
               [string_byte("6")]=true, [string_byte("7")]=true,
               [string_byte("8")]=true, [string_byte("9")]=true }

-- ---------------------------------------------------------------------------
-- CheckRules - check the settings in the rules file for common errors
-- ---------------------------------------------------------------------------
function CheckRules()
    assert(type(interface_filepath)         == "string", "Rules file ERROR: 'interface_filepath' is not a string")
    assert(type(output_cpp_filepath)        == "string", "Rules file ERROR: 'output_cpp_filepath' is not a string")
    assert(type(output_cpp_header_filepath) == "string", "Rules file ERROR: 'output_cpp_header_filepath' is not a string")
    assert(type(output_cpp_impexpsymbol)    == "string", "Rules file ERROR: 'output_cpp_impexpsymbol' is not a string")
    assert(type(output_cpp_impexpdatasymbol) == "string", "Rules file ERROR: 'output_cpp_impexpdatasymbol' is not a string")

    assert(type(hook_lua_namespace) == "string", "Rules file ERROR: 'hook_lua_namespace' is not a string")
    assert(type(hook_cpp_namespace) == "string", "Rules file ERROR: 'hook_cpp_namespace' is not a string")

    assert(wxLuaBinding_PreRegister == nil, "Rules file ERROR: 'wxLuaBinding_PreRegister' is deprecated")
    assert(wxLuaBinding_PostRegister == nil, "Rules file ERROR: 'wxLuaBinding_PreRegister' is deprecated")
end

-- ---------------------------------------------------------------------------
-- Replacement for pairs(table) that sorts them alphabetically, returns iterator
--  Code from "Programming in Lua" by Roberto Ierusalimschy
--  the input is a Lua table and optional comp function (see table.sort)
-- ---------------------------------------------------------------------------
function pairs_sort(atable, comp_func)
    local a = {}
    for n in pairs(atable) do table.insert(a, n) end
    table.sort(a, comp_func)
    local i = 0                -- iterator variable
    local iter = function ()   -- iterator function
        i = i + 1
        if a[i] == nil then return nil
        else return a[i], atable[a[i]] end
    end
    return iter
end

-- ---------------------------------------------------------------------------
-- Sort the table keys and return it as an numerically indexed table array
-- ---------------------------------------------------------------------------
function TableSort(atable, comp_func)
    local a = {}
    for k, v in pairs(atable) do table.insert(a, k) end
    table.sort(a, comp_func)
    local b = {}
    for n = 1, #a do table.insert(b, atable[a[n]]) end
    return b
end

-- ---------------------------------------------------------------------------
-- Completely dump the contents of a table
--   atable is the input table to dump the contents of
--   prefix is a string prefix for debugging purposes
--   tablelevel is tracker for recursive calls to TableDump (do not use initially)
-- ---------------------------------------------------------------------------
function TableDump(atable, prefix, tablelevel)
    if prefix == nil then prefix = "" end
    if tablelevel == nil then tablelevel = "" end

    prefix = prefix.."  "
    print(prefix..tablelevel.." Dumping Table "..tostring(atable).."#"..tostring(#atable))
    local n = 0

    for k, v in pairs_sort(atable) do
        n = n + 1
        print(prefix..n, tablelevel.."["..k.."]", v)
        if type(v) == "table" then
            TableDump(v, prefix.."  ", tablelevel.."["..k.."]")
        end
    end
end

-- ---------------------------------------------------------------------------
-- Make a deep copy of a table, including all sub tables
-- ---------------------------------------------------------------------------
function TableCopy(atable)
    local newtable = {}
    for k, v in pairs(atable) do
        if type(v) == "table" then
            newtable[k] = TableCopy(v)
        else
            newtable[k] = v
        end
    end
    return newtable
end

-- ---------------------------------------------------------------------------
-- Add a value to the table at any number of keys into it
--   TableAdd(value, atable, "b", 2, 5) = atable["b"][2][5] = value
-- ---------------------------------------------------------------------------
function TableAdd(value, atable, ...)
    local t = atable
    for n = 1, #arg-1 do
        if not t[arg[n]] then t[arg[n]] = {} end
        t = t[arg[n]]
    end
    t[arg[#arg]] = value
end

-- ---------------------------------------------------------------------------
-- A simple function to implement "cond ? A : B", eg "result = iff(cond, A, B)"
-- ---------------------------------------------------------------------------
function iff(cond, A, B) if cond then return A else return B end end

-- ---------------------------------------------------------------------------
-- Append text to a table if "comment_cpp_binding_code", else do nothing
-- ---------------------------------------------------------------------------
function CommentBindingTable(atable, str)
    if comment_cpp_binding_code then
        table.insert(atable, str)
    end
end

-- ---------------------------------------------------------------------------
-- Allocate a data type description table (int, double, class...) to dataTypeTable
-- ---------------------------------------------------------------------------

function AllocDataType(name, value_type, is_number, abstract)
    dataTypeTable[name] =
    {
        Name        = name,       -- typename, eg. void, bool, wxInt32
        ValueType   = value_type, -- "number", "enum", "class", "special" (special handling)
                                  -- determines how to handle the data type
        BaseClasses = nil,        -- the BaseClass of this, if this is a class
        IsNumber    = is_number,  -- can this data type be stored as a double (Lua's number type)
        Abstract    = abstract,
        Condition   = nil,        -- conditions for this data type, eg. wxLUA_USE_xxx
    }
end

-- ---------------------------------------------------------------------------
-- Initialize the data types with standard ones and wxWidget's types
-- ---------------------------------------------------------------------------
function InitDataTypes()
    -- Standard C data types
    AllocDataType("bool",               "number", true)
    AllocDataType("BOOL",               "number", true)
    AllocDataType("double",             "number", true)
    AllocDataType("int",                "number", true)
    AllocDataType("char",               "number", true)
    AllocDataType("float",              "number", true)
    AllocDataType("long",               "number", true)
    AllocDataType("short",              "number", true)
    AllocDataType("size_t",             "number", true)
    AllocDataType("time_t",             "number", true)
    AllocDataType("unsigned char",      "number", true)
    AllocDataType("unsigned short",     "number", true)
    AllocDataType("unsigned int",       "number", true)
    AllocDataType("unsigned long",      "number", true)
    AllocDataType("uchar",              "number", true)
    AllocDataType("ushort",             "number", true)
    AllocDataType("uint",               "number", true)
    AllocDataType("ulong",              "number", true)
    AllocDataType("void",               "number", true)
    AllocDataType("wchar_t",            "number", true)

    -- wxWidgets defined data types
    --AllocDataType("wxString",           "special", true) -- treat as wxString
    AllocDataType("wxByte",             "number", true)
    AllocDataType("wxChar",             "number", true)
    AllocDataType("wxUniChar",          "number", true)
    AllocDataType("wxWord",             "number", true)
    AllocDataType("wxInt8",             "number", true)
    AllocDataType("wxUint8",            "number", true)
    AllocDataType("wxInt16",            "number", true)
    AllocDataType("wxUint16",           "number", true)
    AllocDataType("wxInt32",            "number", true)
    AllocDataType("wxUint32",           "number", true)
    AllocDataType("wxInt64",            "number", true)
    AllocDataType("wxUint64",           "number", true)
    AllocDataType("wxIntPtr",           "number", true)
    AllocDataType("wxUIntPtr",          "number", true)
    AllocDataType("wxFloat32",          "number", true)
    AllocDataType("wxFloat64",          "number", true)
    AllocDataType("wxDouble",           "number", true)
    AllocDataType("wxCoord",            "number", true)
    AllocDataType("wxTextCoord",        "number", true)
    AllocDataType("wxMemorySize",       "number", true)
    AllocDataType("WXTYPE",             "number", true)
    AllocDataType("wxWindowID",         "number", true)
    AllocDataType("wxEventType",        "number", true)
    AllocDataType("wxFileOffset",       "number", true)
    --AllocDataType("wxStructStat",       "number", true)

    -- Lua data types
    AllocDataType("lua_State",          "number", false)

    -- win32 data types
    --AllocDataType("HANDLE",             "number", false)
    --AllocDataType("DWORD64",            "number", true)
    --AllocDataType("DWORD",              "number", true)
    --AllocDataType("PVOID",              "number", true)
    --AllocDataType("LPCVOID",            "number", true)
    --AllocDataType("LPVOID",             "number", true)
    --AllocDataType("LPDWORD",            "number", true)

    -- "fake" data types that we handle in some more complicated way
    AllocDataType("LuaFunction",           "special", true)
    AllocDataType("LuaTable",              "special", true)
    AllocDataType("wxString",              "special", true)
    AllocDataType("wxCharBuffer",          "special", true)
    --AllocDataType("wxArrayString",         "special", true) -- special, but we only convert input, not output
    --AllocDataType("wxSortedArrayString",   "special", true) -- special, but we only convert input, not output
    --AllocDataType("wxArrayInt",            "special", true) -- special, but we only convert input, not output
    AllocDataType("IntArray_FromLuaTable", "special", true)
    AllocDataType("wxPointArray_FromLuaTable", "special", true);
    AllocDataType("wxPoint2DDoubleArray_FromLuaTable", "special", true);
    AllocDataType("voidptr_long",          "special", true)
    AllocDataType("any",                   "special", true)

    -- attributes that can precede a data type (must set equal to true)
    dataTypeAttribTable["unsigned"] = true
    dataTypeAttribTable["const"]    = true

    dataTypeAttribTable["%gc"]     = true -- this object will be gc by Lua
    dataTypeAttribTable["%ungc"]   = true -- this object won't be gc by Lua

    dataTypeAttribTable["%IncRef"] = true -- special to wxGridCellWorker/wxRefCounter classes and IncRef() will be called on it

    -- datatypes that are float numbers to be treated differently
    dataTypeFloatTable["float"]     = true
    dataTypeFloatTable["double"]    = true
    dataTypeFloatTable["wxFloat32"] = true
    dataTypeFloatTable["wxFloat64"] = true
    dataTypeFloatTable["wxDouble"]  = true

    -- datatypes that are unsigned integers to be treated differently
    dataTypeUIntTable["size_t"]         = true
    dataTypeUIntTable["time_t"]         = true
    dataTypeUIntTable["unsigned char"]  = true
    dataTypeUIntTable["unsigned short"] = true
    dataTypeUIntTable["unsigned int"]   = true
    dataTypeUIntTable["unsigned long"]  = true
    dataTypeUIntTable["uchar"]          = true
    dataTypeUIntTable["ushort"]         = true
    dataTypeUIntTable["uint"]           = true
    dataTypeUIntTable["ulong"]          = true
    dataTypeUIntTable["void"]           = true

    dataTypeUIntTable["wxUint8"]        = true
    dataTypeUIntTable["wxUint16"]       = true
    dataTypeUIntTable["wxUint32"]       = true
    dataTypeUIntTable["wxUint64"]       = true
    dataTypeUIntTable["wxMemorySize"]   = true
    dataTypeUIntTable["wxFileOffset"]   = true

    -- datatypes that are boolean integers to be treated differently
    dataTypeBoolTable["bool"] = true
    dataTypeBoolTable["BOOL"] = true

    -- attributes that can precede a function (must set equal to true)
    functionAttribTable["static"]  = true
    functionAttribTable["virtual"] = true
    functionAttribTable["inline"]  = true
    functionAttribTable["friend"]  = true

    -- attributes that classes use
    classAccessTable              = {}
    classAccessTable["public"]    = true
    classAccessTable["protected"] = true
    classAccessTable["private"]   = true
end

-- ---------------------------------------------------------------------------
-- Decode Declaration of a data type, see DecodeDataType
--  For "const wxDateTime &" returns {"const"}, "wxDateTime", {"&"}
-- ---------------------------------------------------------------------------
function DecodeDecl(decl)
    local attribs = {}
    local data_type = nil
    local ptrs = {}
    local cast = 0

    local typeData = SplitString(decl, { "[]", " ", "&", "*", "(", ")" }, { "[]", "&", "*", "(", ")" })

    for i = 1, #typeData do
        if cast < 0 then
            print("ERROR: Mismatched () in casting data type: '"..decl.."'")
        end

        local type_n = typeData[i]

        if type_n == "(" then
            cast = cast + 1
        elseif type_n == ")" then
            cast = cast - 1
        elseif cast == 0 then
            if dataTypeAttribTable[type_n] then
                table.insert(attribs, type_n)
            elseif (type_n == "[]") or (type_n == "*") or (type_n == "&") then
                table.insert(ptrs, type_n)
            elseif dataTypeTable[type_n] then
                data_type = type_n
            elseif typedefTable[type_n] then
                data_type = type_n
            end
        end
    end

    if not data_type then
        print("ERROR: Cannot find data type: '"..decl.."'")
    end

    return attribs, data_type, ptrs
end

-- ---------------------------------------------------------------------------
-- Decode DataType, also handles typedefs, see TranslateDataType
--  For "const wxDateTime &" returns {"const"}, "wxDateTime", {"&"}
-- ---------------------------------------------------------------------------
function DecodeDataType(decl)
    local attribs, data_type, ptrs = DecodeDecl(decl)

    -- merge typeDef declaration
    if typedefTable[data_type] then
        -- build new datatype using typeDef
        local datatype = nil
        if #attribs > 0 then
            datatype = table.concat(attribs, " ")
        end

        datatype = SpaceSeparateStrings(datatype, typedefTable[data_type])
        datatype = datatype..table.concat(ptrs)

        attribs, data_type, ptrs = DecodeDataType(datatype)
    end

    return attribs, data_type, ptrs
end

-- ---------------------------------------------------------------------------
-- Translate the data type from a typedef
-- ---------------------------------------------------------------------------
function TranslateDataType(param)
    -- build datatype
    local datatype = param.DataTypeWithAttrib.." "..table.concat(param.DataTypePointer)

    local attribs, data_type, ptrs = DecodeDataType(datatype)

    -- build new datatype
    local tlstype = nil
    if #attribs > 0 then
        tlstype = table.concat(attribs, " ")
    end

    tlstype = SpaceSeparateStrings(tlstype, data_type)

    param.TypedDataType           = data_type
    param.TypedDataTypeWithAttrib = tlstype
    param.TypedDataTypePointer    = ptrs
end

-- ---------------------------------------------------------------------------
-- Is the input to this a data type? Generate a error if typedef not complete
-- ---------------------------------------------------------------------------
function IsDataType(datatype)
    if dataTypeTable[datatype] then
        return true
    elseif typedefTable[datatype] then
        if not dataTypeTable[typedefTable[datatype]] then
            print("ERROR: Supposed datatype: '"..tostring(datatype).."' has typedef = '"..typedefTable[datatype].."' which is not a data type either")
        end

        return true
    end

    return false
end

-- ---------------------------------------------------------------------------
-- Get the dataTypeTable[typedefinition] from a string after removing delimiters
-- ---------------------------------------------------------------------------
function GetDataTypeOnly(typedefinition)
    local typeData = SplitString(typedefinition, { " ", "&", "*" })

    for i = 1, #typeData do
        if dataTypeTable[typeData[i]] then
            return typeData[i]
        end
    end

    return nil
end

-- ---------------------------------------------------------------------------
-- Get the base dataTypeTable[typedefinition] by translating typedefs
-- ---------------------------------------------------------------------------
function GetDataTypedefBase(datatype)
    if dataTypeTable[datatype] then
        return dataTypeTable[datatype]
    end

    -- try for underlying TypeDef DataType
    if  typedefTable[datatype] then
        local base_type = GetDataTypeOnly(typedefTable[datatype])
        if base_type and dataTypeTable[base_type] then
            return dataTypeTable[base_type]
        end
    end

    print("ERROR: Missing data type '"..tostring(datatype).."' in GetDataTypedefBase.")

    return nil
end

-- ---------------------------------------------------------------------------
-- Returns true if the classname is derived from base_classname
-- ---------------------------------------------------------------------------

function IsDerivedClass(classname, base_classname)

    if dataTypeTable[classname] == nil then
        print("ERROR: dataTypeTable for classname is nil in IsDerivedClass()", classname, base_classname)
        return false
    end

    if classname == base_classname then
        return true
    end

    if dataTypeTable[classname].BaseClasses then
        for _, c in ipairs(dataTypeTable[classname].BaseClasses) do
            local c_name = dataTypeTable[c].Name
            if IsDerivedClass(c_name, base_classname) then
                return true
            end
        end
    end

    return false
end

-- ---------------------------------------------------------------------------
-- Get any conditions for this data type
-- ---------------------------------------------------------------------------
function GetDataTypeCondition(datatype)
    local dtype = GetDataTypedefBase(datatype)
    if dtype then
        return dtype.Condition
    else
        print("ERROR: Missing data type '"..datatype.."' in GetDataTypeCondition.")
    end

    return nil
end

-- ---------------------------------------------------------------------------
-- Is this data type intrinisic, eg is it basically a number
-- ---------------------------------------------------------------------------
function IsDataTypeNumeric(datatype)

    assert(datatype ~= nil, "Invalid datatype")

    local dtype = GetDataTypedefBase(string.gsub(datatype, "const ", ""))
    if dtype then
        return dtype.IsNumber
    else
        print("ERROR: Missing data type '"..tostring(datatype).."' in IsDataTypeNumeric.")
    end

    return false
end

-- ---------------------------------------------------------------------------
-- Is this data type an unsigned integer
-- ---------------------------------------------------------------------------
function IsDataTypeUInt(datatype)
    local dtype = GetDataTypedefBase(string.gsub(datatype, "const ", ""))
    if dtype then
        return dataTypeUIntTable[dtype.Name] or false
    else
        print("ERROR: Missing data type '"..tostring(datatype).."' in IsDataTypeUInt.")
    end

    return false
end

-- ---------------------------------------------------------------------------
-- Is this data type an unsigned integer
-- ---------------------------------------------------------------------------
function IsDataTypeFloat(datatype)
    local dtype = GetDataTypedefBase(string.gsub(datatype, "const ", ""))
    if dtype then
        return dataTypeFloatTable[dtype.Name] or false
    else
        print("ERROR: Missing data type '"..tostring(datatype).."' in IsDataTypeFloat.")
    end

    return false
end

-- ---------------------------------------------------------------------------
-- Is this data type an enum
-- ---------------------------------------------------------------------------
function IsDataTypeEnum(datatype)
    local dtype = GetDataTypedefBase(string.gsub(datatype, "const ", ""))
    if dtype then
        return (dtype.ValueType == "enum")
    else
        print("ERROR: Missing data type '"..tostring(datatype).."' in IsDataTypeEnum.")
    end

    return false
end

-- ---------------------------------------------------------------------------
-- Is this data type a boolean
-- ---------------------------------------------------------------------------
function IsDataTypeBool(datatype)
    local dtype = GetDataTypedefBase(string.gsub(datatype, "const ", ""))
    if dtype then
        return dataTypeBoolTable[dtype.Name] or false
    else
        print("ERROR: Missing data type '"..tostring(datatype).."' in IsDataTypeBool.")
    end

    return false
end

-- ---------------------------------------------------------------------------
-- Is the input in the 'bindingDelimiters' table?
-- ---------------------------------------------------------------------------
function IsDelimiter(delim)
    return bindingDelimiters_hash[delim] or false
end

-- ---------------------------------------------------------------------------
-- FileExists - return true if file exists and is readable
-- ---------------------------------------------------------------------------
function FileExists(path)
    local file_handle = io.open(path, "rb")
    if not file_handle then
        return false
    end

    io.close(file_handle)
    return true
end

-- ---------------------------------------------------------------------------
-- Do the contents of the file match the strings in the fileData table?
--   the table may contain any number of \n per index
--   returns true for a match or false if not
-- ---------------------------------------------------------------------------
function FileDataIsStringData(filename, strData)
    local file_handle = io.open(filename, "r")
    if not file_handle then return false end -- ok if it doesn't exist

    local f = file_handle:read("*a")
    local is_same = (f == strData)
    io.close(file_handle)
    return is_same
end

-- ---------------------------------------------------------------------------
-- Write the contents of the table fileData (indexes 1.. are line numbers)
--  to the filename, but only write to the file if FileDataIsStringData returns
--  false. If overwrite_always is true then always overwrite the file.
--  returns true if the file was overwritten
-- ---------------------------------------------------------------------------
function WriteTableToFile(filename, fileData, overwrite_always)
    assert(filename and fileData, "Invalid filename or fileData in WriteTableToFile")

    local strData = table.concat(fileData)

    if (not overwrite_always) and FileDataIsStringData(filename, strData) then
        print("No changes to file : '"..filename.."'")
        return false
    end

    print("Updating file      : '"..filename.."'")

    local outfile = io.open(filename, "w+")
    if not outfile then
        print("Unable to open file for writing '"..filename.."'.")
        return
    end

    outfile:write(strData)

    outfile:flush()
    outfile:close()
    return true
end

-- ---------------------------------------------------------------------------
-- Find and return an already set condition or for a special set of conditions
--   create a new one and add it to the condition table, else return nil
-- ---------------------------------------------------------------------------
function FindOrCreateCondition(condition)
    local result = nil

    if preprocConditionTable[condition] then
        result = preprocConditionTable[condition]

    elseif string.find(condition, "%wxchkver_", 1, 1) then
        -- check for conditions like %wxchkver_1_2_3 = wxCHECK_VERSION(1,2,3)
        local ver = { 0, 0, 0 }
        local n = 1
        for v in string.gmatch(condition, "%d+") do
            ver[n] = tonumber(v);
            n = n + 1
        end
        assert(#ver == 3, "%wxchkver_x_y_z conditions has too many version numbers. '"..condition.."'")
        result = string.format("wxCHECK_VERSION(%d,%d,%d)", ver[1], ver[2], ver[3])
        preprocConditionTable[condition] = result -- cache result
    elseif string.find(condition, "wxchkver_", 1, 1) then
        print("WARNING: found wxchkver_XXX, did you forget the leading '%'? '"..condition.."'")

    elseif string.find(condition, "%wxcompat_", 1, 1) then
        -- check for conditions like %wxcompat_1_2 = WXWIN_COMPATIBILITY_1_2
        -- just copy everything after wxcompat_
        local p1, p2 = string.find(condition, "%wxcompat_", 1, 1)
        result = "WXWIN_COMPATIBILITY"..string.sub(condition, p2)
        result = "(defined("..result..") && "..result..")"
        preprocConditionTable[condition] = result -- cache result
    elseif string.find(condition, "wxcompat_", 1, 1) then
        print("WARNING: found wxcompat_XXX, did you forget the leading '%'? '"..condition.."'")

    --elseif string.find(condition, "wxLUA_USE_", 1, 1) then
    --    print("WARNING: unknown wxLUA_USE_XXX condition? '"..condition.."'")
    --elseif string.find(condition, "wxUSE_", 1, 1) then
    --    print("WARNING: unknown wxUSE_XXX condition? '"..condition.."'")

    elseif string.find(condition, "%wxchkver2", 1, 1) then
        assert(false, "ERROR: %wxchkverXYZ has been replaced by %wxchkver_X_Y_Z, please update your bindings.")
    elseif string.find(condition, "%wxcompat2", 1, 1) then
        assert(false, "ERROR: %wxcompatXY has been replaced by %wxcompat_X_Y, please update your bindings.")
    end

    return result
end

-- ---------------------------------------------------------------------------
-- Is this condition really a condition? "1" is a placeholder for none
-- ---------------------------------------------------------------------------
function HasCondition(condition)
    return (condition ~= nil) and (condition ~= "1") and (condition ~= "")
end

-- ---------------------------------------------------------------------------
-- Fix the condition to be uniform, "1" means none
-- ---------------------------------------------------------------------------
function FixCondition(condition)
    if not HasCondition(condition) then
        return "1"
    end

    return condition
end

-- ---------------------------------------------------------------------------
-- Build condition string using condition stack (number indexed Lua table)
-- ---------------------------------------------------------------------------
function BuildCondition(conditionStack)
    local conditions = {}
    for i = 1, #conditionStack do
        if HasCondition(conditionStack[i]) then table.insert(conditions, conditionStack[i]) end
    end
    table.sort(conditions)
    return #conditions > 1 and "("..table.concat(conditions, ") && (")..")"
        or #conditions == 1 and conditions[1]
        or nil
end

-- ---------------------------------------------------------------------------
-- Add conditions with &&, either input condition may be nil
-- ---------------------------------------------------------------------------
function AddCondition(condition1, condition2)
    local condition = nil

    if HasCondition(condition1) and HasCondition(condition2) then
        condition = condition1 <= condition2
          and "("..condition1..") && ("..condition2..")"
          or "("..condition2..") && ("..condition1..")"
    elseif HasCondition(condition1) then
        condition = condition1
    elseif HasCondition(condition2) then
        condition = condition2
    end

    return condition
end

-- ---------------------------------------------------------------------------
-- Add a value to or with a string of values
-- ---------------------------------------------------------------------------
function AddOredValue(value, new_value)
    local v = value

    if not string.find(value, new_value, 1, 1) then
        if string.len(v) > 1 then
            v = value.."|"..new_value
        else
            v = new_value
        end
    end

    return v
end

-- ---------------------------------------------------------------------------
-- Init all the bindingKeywordTable used for parsing
-- ---------------------------------------------------------------------------
function InitKeywords()

    preprocConditionTable["WXWIN_COMPATIBILITY_2"]   = "(defined(WXWIN_COMPATIBILITY_2) && WXWIN_COMPATIBILITY_2)"
    preprocConditionTable["WXWIN_COMPATIBILITY_2_2"] = "(defined(WXWIN_COMPATIBILITY_2_2) && WXWIN_COMPATIBILITY_2_2)"
    preprocConditionTable["WXWIN_COMPATIBILITY_2_4"] = "(defined(WXWIN_COMPATIBILITY_2_4) && WXWIN_COMPATIBILITY_2_4)"
    preprocConditionTable["WXWIN_COMPATIBILITY_2_6"] = "(defined(WXWIN_COMPATIBILITY_2_6) && WXWIN_COMPATIBILITY_2_6)"
    preprocConditionTable["WXWIN_COMPATIBILITY_2_8"] = "(defined(WXWIN_COMPATIBILITY_2_8) && WXWIN_COMPATIBILITY_2_8)"

    -- wxWidgets platform checks
    preprocConditionTable["%win"]        = "defined(__WXMSW__)"
    preprocConditionTable["%msw"]        = "defined(__WXMSW__)"
    preprocConditionTable["%gtk"]        = "defined(__WXGTK__)"
    preprocConditionTable["%mac"]        = "defined(__WXMAC__)"
    preprocConditionTable["%mgl"]        = "defined(__WXMGL__)"
    preprocConditionTable["%motif"]      = "defined(__WXMOTIF__)"
    preprocConditionTable["%univ"]       = "defined(__WXUNIVERSAL__)"
    preprocConditionTable["%x11"]        = "defined(__WXX11__)"
    preprocConditionTable["%cocoa"]      = "defined(__WXCOCOA__)"
    preprocConditionTable["%os2"]        = "defined(__WXPM__)"
    preprocConditionTable["%palm"]       = "defined(__WXPALMOS__)"
    preprocConditionTable["%wince"]      = "defined(__WXWINCE__)"

    preprocConditionTable["%__WINDOWS__"]       = "defined(__WINDOWS__)"
    preprocConditionTable["%__WIN16__"]         = "defined(__WIN16__)"
    preprocConditionTable["%__WIN32__"]         = "defined(__WIN32__)"
    preprocConditionTable["%__WIN95__"]         = "defined(__WIN95__)"
    preprocConditionTable["%__WXBASE__"]        = "defined(__WXBASE__)"
    preprocConditionTable["%__WXCOCOA__"]       = "defined(__WXCOCOA__)"
    preprocConditionTable["%__WXWINCE__"]       = "defined(__WXWINCE__)"
    preprocConditionTable["%__WXGTK__"]         = "defined(__WXGTK__)"
    preprocConditionTable["%__WXGTK12__"]       = "defined(__WXGTK12__)"
    preprocConditionTable["%__WXGTK20__"]       = "defined(__WXGTK20__)"
    preprocConditionTable["%__WXMOTIF__"]       = "defined(__WXMOTIF__)"
    preprocConditionTable["%__WXMOTIF20__"]     = "defined(__WXMOTIF20__)"
    preprocConditionTable["%__WXMAC__"]         = "defined(__WXMAC__)"
    preprocConditionTable["%__WXMAC_CLASSIC__"] = "defined(__WXMAC_CLASSIC__)"
    preprocConditionTable["%__WXMAC_CARBON__"]  = "defined(__WXMAC_CARBON__)"
    preprocConditionTable["%__WXMAC_OSX__"]     = "defined(__WXMAC_OSX__)"
    preprocConditionTable["%__WXMGL__"]         = "defined(__WXMGL__)"
    preprocConditionTable["%__WXMSW__"]         = "defined(__WXMSW__)"
    preprocConditionTable["%__WXOS2__"]         = "defined(__WXOS2__)"
    preprocConditionTable["%__WXOSX__"]         = "defined(__WXOSX__)"
    preprocConditionTable["%__WXPALMOS__"]      = "defined(__WXPALMOS__)"
    preprocConditionTable["%__WXPM__"]          = "defined(__WXPM__)"
    preprocConditionTable["%__WXSTUBS__"]       = "defined(__WXSTUBS__)"
    preprocConditionTable["%__WXXT__"]          = "defined(__WXXT__)"
    preprocConditionTable["%__WXX11__"]         = "defined(__WXX11__)"
    preprocConditionTable["%__WXWINE__"]        = "defined(__WXWINE__)"
    preprocConditionTable["%__WXUNIVERSAL__"]   = "defined(__WXUNIVERSAL__)"
    preprocConditionTable["%__X__"]             = "defined(__X__)"
    preprocConditionTable["%__WXWINCE__"]       = "defined(__WXWINCE__)"

    preprocConditionTable["wxHAS_POWER_EVENTS"]     = "defined(wxHAS_POWER_EVENTS)"
    preprocConditionTable["%wxHAS_NATIVE_RENDERER"] = "defined(wxHAS_NATIVE_RENDERER)"

    -- wxUSE_ conditions
    preprocConditionTable["wxUSE_ABOUTDLG"]                = "wxUSE_ABOUTDLG"
    preprocConditionTable["wxUSE_ACCEL"]                   = "wxUSE_ACCEL"
    preprocConditionTable["wxUSE_ACCESSIBILITY"]           = "wxUSE_ACCESSIBILITY"
    preprocConditionTable["wxUSE_AFM_FOR_POSTSCRIPT"]      = "wxUSE_AFM_FOR_POSTSCRIPT"
    preprocConditionTable["wxUSE_ANIMATIONCTRL"]           = "wxUSE_ANIMATIONCTRL"
    preprocConditionTable["wxUSE_APPLE_IEEE"]              = "wxUSE_APPLE_IEEE"
    preprocConditionTable["wxUSE_AUI"]                     = "wxUSE_AUI"
    preprocConditionTable["wxUSE_BITMAPCOMBOBOX"]          = "wxUSE_BITMAPCOMBOBOX"
    preprocConditionTable["wxUSE_BMPBUTTON"]               = "wxUSE_BMPBUTTON"
    preprocConditionTable["wxUSE_BOOKCTRL"]                = "wxUSE_BOOKCTRL"
    preprocConditionTable["wxUSE_BUILTIN_IODBC"]           = "wxUSE_BUILTIN_IODBC"
    preprocConditionTable["wxUSE_BUSYINFO"]                = "wxUSE_BUSYINFO"
    preprocConditionTable["wxUSE_BUTTON"]                  = "wxUSE_BUTTON"
    preprocConditionTable["wxUSE_CALENDARCTRL"]            = "wxUSE_CALENDARCTRL"
    preprocConditionTable["wxUSE_CARET"]                   = "wxUSE_CARET"
    preprocConditionTable["wxUSE_CHECKBOX"]                = "wxUSE_CHECKBOX"
    preprocConditionTable["wxUSE_CHECKLISTBOX"]            = "wxUSE_CHECKLISTBOX"
    preprocConditionTable["wxUSE_CHOICE"]                  = "wxUSE_CHOICE"
    preprocConditionTable["wxUSE_CHOICEBOOK"]              = "wxUSE_CHOICEBOOK"
    preprocConditionTable["wxUSE_CHOICEDLG"]               = "wxUSE_CHOICEDLG"
    preprocConditionTable["wxUSE_CLIPBOARD"]               = "wxUSE_CLIPBOARD"
    preprocConditionTable["wxUSE_CMDLINE_PARSER"]          = "wxUSE_CMDLINE_PARSER"
    preprocConditionTable["wxUSE_COLLPANE"]                = "wxUSE_COLLPANE"
    preprocConditionTable["wxUSE_COLOURDLG"]               = "wxUSE_COLOURDLG"
    preprocConditionTable["wxUSE_COLOURPICKERCTRL"]        = "wxUSE_COLOURPICKERCTRL"
    preprocConditionTable["wxUSE_COMBOBOX"]                = "wxUSE_COMBOBOX"
    preprocConditionTable["wxUSE_CONFIG"]                  = "wxUSE_CONFIG"
    preprocConditionTable["wxUSE_CONSTRAINTS"]             = "wxUSE_CONSTRAINTS"
    preprocConditionTable["wxUSE_CONTROLS"]                = "wxUSE_CONTROLS"
    preprocConditionTable["wxUSE_DATAOBJ"]                 = "wxUSE_DATAOBJ"
    preprocConditionTable["wxUSE_DATAVIEWCTRL"]            = "wxUSE_DATAVIEWCTRL"
    preprocConditionTable["wxUSE_DATEPICKCTRL"]            = "wxUSE_DATEPICKCTRL"
    preprocConditionTable["wxUSE_TIMEPICKCTRL"]            = "wxUSE_TIMEPICKCTRL"
    preprocConditionTable["wxUSE_DATETIME"]                = "wxUSE_DATETIME"
    preprocConditionTable["wxUSE_DEBUG_CONTEXT"]           = "wxUSE_DEBUG_CONTEXT"
    preprocConditionTable["wxUSE_DEBUG_NEW_ALWAYS"]        = "wxUSE_DEBUG_NEW_ALWAYS"
    preprocConditionTable["wxUSE_DIALUP_MANAGER"]          = "wxUSE_DIALUP_MANAGER"
    preprocConditionTable["wxUSE_DIRDLG"]                  = "wxUSE_DIRDLG"
    preprocConditionTable["wxUSE_DIRPICKERCTRL"]           = "wxUSE_DIRPICKERCTRL"
    preprocConditionTable["wxUSE_DISPLAY"]                 = "wxUSE_DISPLAY"
    preprocConditionTable["wxUSE_DOC_VIEW_ARCHITECTURE"]   = "wxUSE_DOC_VIEW_ARCHITECTURE"
    preprocConditionTable["wxUSE_DRAGIMAGE"]               = "wxUSE_DRAGIMAGE"
    preprocConditionTable["wxUSE_DRAG_AND_DROP"]           = "wxUSE_DRAG_AND_DROP"
    preprocConditionTable["wxUSE_DYNAMIC_CLASSES"]         = "wxUSE_DYNAMIC_CLASSES"
    preprocConditionTable["wxUSE_DYNAMIC_LOADER"]          = "wxUSE_DYNAMIC_LOADER"
    preprocConditionTable["wxUSE_DYNLIB_CLASS"]            = "wxUSE_DYNLIB_CLASS"
    preprocConditionTable["wxUSE_ENH_METAFILE"]            = "wxUSE_ENH_METAFILE"
    preprocConditionTable["wxUSE_EXCEPTIONS"]              = "wxUSE_EXCEPTIONS"
    preprocConditionTable["wxUSE_EXPERIMENTAL_PRINTF"]     = "wxUSE_EXPERIMENTAL_PRINTF"
    preprocConditionTable["wxUSE_FFILE"]                   = "wxUSE_FFILE"
    preprocConditionTable["wxUSE_FILE"]                    = "wxUSE_FILE"
    preprocConditionTable["wxUSE_FILEDLG"]                 = "wxUSE_FILEDLG"
    preprocConditionTable["wxUSE_FILEPICKERCTRL"]          = "wxUSE_FILEPICKERCTRL"
    preprocConditionTable["wxUSE_FILESYSTEM"]              = "wxUSE_FILESYSTEM"
    preprocConditionTable["wxUSE_FINDREPLDLG"]             = "wxUSE_FINDREPLDLG"
    preprocConditionTable["wxUSE_FONTDLG"]                 = "wxUSE_FONTDLG"
    preprocConditionTable["wxUSE_FONTMAP"]                 = "wxUSE_FONTMAP"
    preprocConditionTable["wxUSE_FONTPICKERCTRL"]          = "wxUSE_FONTPICKERCTRL"
    preprocConditionTable["wxUSE_FREETYPE"]                = "wxUSE_FREETYPE"
    preprocConditionTable["wxUSE_FSVOLUME"]                = "wxUSE_FSVOLUME"
    preprocConditionTable["wxUSE_FS_INET"]                 = "wxUSE_FS_INET"
    preprocConditionTable["wxUSE_FS_ZIP"]                  = "wxUSE_FS_ZIP"
    preprocConditionTable["wxUSE_GAUGE"]                   = "wxUSE_GAUGE"
    preprocConditionTable["wxUSE_GEOMETRY"]                = "wxUSE_GEOMETRY"
    preprocConditionTable["wxUSE_GIF"]                     = "wxUSE_GIF"
    preprocConditionTable["wxUSE_GLCANVAS"]                = "wxUSE_GLCANVAS"
    preprocConditionTable["wxUSE_GLOBAL_MEMORY_OPERATORS"] = "wxUSE_GLOBAL_MEMORY_OPERATORS"
    preprocConditionTable["wxUSE_GRID"]                    = "wxUSE_GRID"
    preprocConditionTable["wxUSE_GUI"]                     = "wxUSE_GUI"
    preprocConditionTable["wxUSE_HELP"]                    = "wxUSE_HELP"
    preprocConditionTable["wxUSE_HOTKEY"]                  = "wxUSE_HOTKEY"
    preprocConditionTable["wxUSE_HTML"]                    = "wxUSE_HTML"
    preprocConditionTable["wxUSE_HYPERLINKCTRL"]           = "wxUSE_HYPERLINKCTRL"
    preprocConditionTable["wxUSE_ICO_CUR"]                 = "wxUSE_ICO_CUR"
    preprocConditionTable["wxUSE_IFF"]                     = "wxUSE_IFF"
    preprocConditionTable["wxUSE_IMAGE"]                   = "wxUSE_IMAGE"
    preprocConditionTable["wxUSE_IMAGLIST"]                = "wxUSE_IMAGLIST"
    preprocConditionTable["wxUSE_INTL"]                    = "wxUSE_INTL"
    preprocConditionTable["wxUSE_IOSTREAMH"]               = "wxUSE_IOSTREAMH"
    preprocConditionTable["wxUSE_IPC"]                     = "wxUSE_IPC"
    preprocConditionTable["wxUSE_JOYSTICK"]                = "wxUSE_JOYSTICK"
    preprocConditionTable["wxUSE_LIBJPEG"]                 = "wxUSE_LIBJPEG"
    preprocConditionTable["wxUSE_LIBMSPACK"]               = "wxUSE_LIBMSPACK"
    preprocConditionTable["wxUSE_LIBPNG"]                  = "wxUSE_LIBPNG"
    preprocConditionTable["wxUSE_LIBSDL"]                  = "wxUSE_LIBSDL"
    preprocConditionTable["wxUSE_LIBTIFF"]                 = "wxUSE_LIBTIFF"
    preprocConditionTable["wxUSE_LISTBOOK"]                = "wxUSE_LISTBOOK"
    preprocConditionTable["wxUSE_LISTBOX"]                 = "wxUSE_LISTBOX"
    preprocConditionTable["wxUSE_LISTCTRL"]                = "wxUSE_LISTCTRL"
    preprocConditionTable["wxUSE_LOG"]                     = "wxUSE_LOG"
    preprocConditionTable["wxUSE_LOGGUI"]                  = "wxUSE_LOGGUI"
    preprocConditionTable["wxUSE_LOGWINDOW"]               = "wxUSE_LOGWINDOW"
    preprocConditionTable["wxUSE_LOG_DIALOG"]              = "wxUSE_LOG_DIALOG"
    preprocConditionTable["wxUSE_LONGLONG"]                = "wxUSE_LONGLONG"
    preprocConditionTable["wxUSE_MDI"]                     = "wxUSE_MDI"
    preprocConditionTable["wxUSE_MDI_ARCHITECTURE"]        = "wxUSE_MDI_ARCHITECTURE"
    preprocConditionTable["wxUSE_MEDIACTRL"]               = "wxUSE_MEDIACTRL"
    preprocConditionTable["wxUSE_MEMORY_TRACING"]          = "wxUSE_MEMORY_TRACING"
    preprocConditionTable["wxUSE_MENUS"]                   = "wxUSE_MENUS"
    preprocConditionTable["wxUSE_METAFILE"]                = "wxUSE_METAFILE"
    preprocConditionTable["wxUSE_MIMETYPE"]                = "wxUSE_MIMETYPE"
    preprocConditionTable["wxUSE_MINIFRAME"]               = "wxUSE_MINIFRAME"
    preprocConditionTable["wxUSE_MOUSEWHEEL"]              = "wxUSE_MOUSEWHEEL"
    preprocConditionTable["wxUSE_MSGDLG"]                  = "wxUSE_MSGDLG"
    preprocConditionTable["wxUSE_MS_HTML_HELP"]            = "wxUSE_MS_HTML_HELP"
    preprocConditionTable["wxUSE_NANOX"]                   = "wxUSE_NANOX"
    preprocConditionTable["wxUSE_NATIVE_STATUSBAR"]        = "wxUSE_NATIVE_STATUSBAR"
    preprocConditionTable["wxUSE_NEW_GRID"]                = "wxUSE_NEW_GRID"
    preprocConditionTable["wxUSE_NOGUI"]                   = "wxUSE_NOGUI"
    preprocConditionTable["wxUSE_NORMALIZED_PS_FONTS"]     = "wxUSE_NORMALIZED_PS_FONTS"
    preprocConditionTable["wxUSE_NOTEBOOK"]                = "wxUSE_NOTEBOOK"
    preprocConditionTable["wxUSE_NUMBERDLG"]               = "wxUSE_NUMBERDLG"
    preprocConditionTable["wxUSE_ODBC"]                    = "wxUSE_ODBC"
    preprocConditionTable["wxUSE_OLE"]                     = "wxUSE_OLE"
    preprocConditionTable["wxUSE_ON_FATAL_EXCEPTION"]      = "wxUSE_ON_FATAL_EXCEPTION"
    preprocConditionTable["wxUSE_OPENGL"]                  = "wxUSE_OPENGL"
    preprocConditionTable["wxUSE_OWNER_DRAWN"]             = "wxUSE_OWNER_DRAWN"
    preprocConditionTable["wxUSE_PALETTE"]                 = "wxUSE_PALETTE"
    preprocConditionTable["wxUSE_PCX"]                     = "wxUSE_PCX"
    preprocConditionTable["wxUSE_PLUGINS"]                 = "wxUSE_PLUGINS"
    preprocConditionTable["wxUSE_PNM"]                     = "wxUSE_PNM"
    preprocConditionTable["wxUSE_POPUPWIN"]                = "wxUSE_POPUPWIN"
    preprocConditionTable["wxUSE_POSTSCRIPT"]              = "wxUSE_POSTSCRIPT"
    preprocConditionTable["wxUSE_PRINTING_ARCHITECTURE"]   = "wxUSE_PRINTING_ARCHITECTURE"
    preprocConditionTable["wxUSE_PRIVATE_FONTS"]           = "wxUSE_PRIVATE_FONTS"
    preprocConditionTable["wxUSE_PROGRESSDLG"]             = "wxUSE_PROGRESSDLG"
    preprocConditionTable["wxUSE_PROLOGIO"]                = "wxUSE_PROLOGIO"
    preprocConditionTable["wxUSE_PROPSHEET"]               = "wxUSE_PROPSHEET"
    preprocConditionTable["wxUSE_PROTOCOL"]                = "wxUSE_PROTOCOL"
    preprocConditionTable["wxUSE_PROTOCOL_FILE"]           = "wxUSE_PROTOCOL_FILE"
    preprocConditionTable["wxUSE_PROTOCOL_FTP"]            = "wxUSE_PROTOCOL_FTP"
    preprocConditionTable["wxUSE_PROTOCOL_HTTP"]           = "wxUSE_PROTOCOL_HTTP"
    preprocConditionTable["wxUSE_RADIOBOX"]                = "wxUSE_RADIOBOX"
    preprocConditionTable["wxUSE_RADIOBTN"]                = "wxUSE_RADIOBTN"
    preprocConditionTable["wxUSE_REGEX"]                   = "wxUSE_REGEX"
    preprocConditionTable["wxUSE_RESOURCES"]               = "wxUSE_RESOURCES"
    preprocConditionTable["wxUSE_RICHEDIT"]                = "wxUSE_RICHEDIT"
    preprocConditionTable["wxUSE_RICHTEXT"]                = "wxUSE_RICHTEXT"
    preprocConditionTable["wxUSE_SASH"]                    = "wxUSE_SASH"
    preprocConditionTable["wxUSE_SCROLLBAR"]               = "wxUSE_SCROLLBAR"
    preprocConditionTable["wxUSE_SLIDER"]                  = "wxUSE_SLIDER"
    preprocConditionTable["wxUSE_SNGLINST_CHECKER"]        = "wxUSE_SNGLINST_CHECKER"
    preprocConditionTable["wxUSE_SOCKETS"]                 = "wxUSE_SOCKETS"
    preprocConditionTable["wxUSE_SOUND"]                   = "wxUSE_SOUND"
    preprocConditionTable["wxUSE_SPINBTN"]                 = "wxUSE_SPINBTN"
    preprocConditionTable["wxUSE_SPINCTRL"]                = "wxUSE_SPINCTRL"
    preprocConditionTable["wxUSE_SPLASH"]                  = "wxUSE_SPLASH"
    preprocConditionTable["wxUSE_SPLINES"]                 = "wxUSE_SPLINES"
    preprocConditionTable["wxUSE_SPLITTER"]                = "wxUSE_SPLITTER"
    preprocConditionTable["wxUSE_STARTUP_TIPS"]            = "wxUSE_STARTUP_TIPS"
    preprocConditionTable["wxUSE_STATBMP"]                 = "wxUSE_STATBMP"
    preprocConditionTable["wxUSE_STATBOX"]                 = "wxUSE_STATBOX"
    preprocConditionTable["wxUSE_STATLINE"]                = "wxUSE_STATLINE"
    preprocConditionTable["wxUSE_STATTEXT"]                = "wxUSE_STATTEXT"
    preprocConditionTable["wxUSE_STATUSBAR"]               = "wxUSE_STATUSBAR"
    preprocConditionTable["wxUSE_STD_IOSTREAM"]            = "wxUSE_STD_IOSTREAM"
    preprocConditionTable["wxUSE_STL"]                     = "wxUSE_STL"
    preprocConditionTable["wxUSE_STOPWATCH"]               = "wxUSE_STOPWATCH"
    preprocConditionTable["wxUSE_STREAMS"]                 = "wxUSE_STREAMS"
    preprocConditionTable["wxUSE_SYSTEM_OPTIONS"]          = "wxUSE_SYSTEM_OPTIONS"
    preprocConditionTable["wxUSE_TABDIALOG"]               = "wxUSE_TABDIALOG"
    preprocConditionTable["wxUSE_TAB_DIALOG"]              = "wxUSE_TAB_DIALOG"
    preprocConditionTable["wxUSE_TEXTBUFFER"]              = "wxUSE_TEXTBUFFER"
    preprocConditionTable["wxUSE_TEXTCTRL"]                = "wxUSE_TEXTCTRL"
    preprocConditionTable["wxUSE_TEXTDLG"]                 = "wxUSE_TEXTDLG"
    preprocConditionTable["wxUSE_TEXTFILE"]                = "wxUSE_TEXTFILE"
    preprocConditionTable["wxUSE_TGA"]                     = "wxUSE_TGA"
    preprocConditionTable["wxUSE_THREADS"]                 = "wxUSE_THREADS"
    preprocConditionTable["wxUSE_TIMEDATE"]                = "wxUSE_TIMEDATE"
    preprocConditionTable["wxUSE_TIMER"]                   = "wxUSE_TIMER"
    preprocConditionTable["wxUSE_TIPWINDOW"]               = "wxUSE_TIPWINDOW"
    preprocConditionTable["wxUSE_TOGGLEBTN"]               = "wxUSE_TOGGLEBTN"
    preprocConditionTable["wxUSE_TOOLBAR"]                 = "wxUSE_TOOLBAR"
    preprocConditionTable["wxUSE_TOOLBAR_NATIVE"]          = "wxUSE_TOOLBAR_NATIVE"
    preprocConditionTable["wxUSE_TOOLBOOK"]                = "wxUSE_TOOLBOOK"
    preprocConditionTable["wxUSE_TOOLTIPS"]                = "wxUSE_TOOLTIPS"
    preprocConditionTable["wxUSE_TREEBOOK"]                = "wxUSE_TREEBOOK"
    preprocConditionTable["wxUSE_TREECTRL"]                = "wxUSE_TREECTRL"
    preprocConditionTable["wxUSE_TREELISTCTRL"]            = "wxUSE_TREELISTCTRL"
    preprocConditionTable["wxUSE_TREELAYOUT"]              = "wxUSE_TREELAYOUT"
    preprocConditionTable["wxUSE_UNICODE"]                 = "wxUSE_UNICODE"
    preprocConditionTable["wxUSE_UNICODE_MSLU"]            = "wxUSE_UNICODE_MSLU"
    preprocConditionTable["wxUSE_UNIX"]                    = "wxUSE_UNIX"
    preprocConditionTable["wxUSE_URL"]                     = "wxUSE_URL"
    preprocConditionTable["wxUSE_UXTHEME"]                 = "wxUSE_UXTHEME"
    preprocConditionTable["wxUSE_UXTHEME_AUTO"]            = "wxUSE_UXTHEME_AUTO"
    preprocConditionTable["wxUSE_VALIDATORS"]              = "wxUSE_VALIDATORS"
    preprocConditionTable["wxUSE_WAVE"]                    = "wxUSE_WAVE"
    preprocConditionTable["wxUSE_WCHAR_T"]                 = "wxUSE_WCHAR_T"
    preprocConditionTable["wxUSE_WCSRTOMBS"]               = "wxUSE_WCSRTOMBS"
    preprocConditionTable["wxUSE_WIZARDDLG"]               = "wxUSE_WIZARDDLG"
    preprocConditionTable["wxUSE_WXHTML_HELP"]             = "wxUSE_WXHTML_HELP"
    preprocConditionTable["wxUSE_WX_RESOURCES"]            = "wxUSE_WX_RESOURCES"
    preprocConditionTable["wxUSE_XML"]                     = "wxUSE_XML"
    preprocConditionTable["wxUSE_XPM"]                     = "wxUSE_XPM"
    preprocConditionTable["wxUSE_XPM_IN_MSW"]              = "wxUSE_XPM_IN_MSW"
    preprocConditionTable["wxUSE_XRC"]                     = "wxUSE_XRC"
    preprocConditionTable["wxUSE_X_RESOURCES"]             = "wxUSE_X_RESOURCES"
    preprocConditionTable["wxUSE_ZIPSTREAM"]               = "wxUSE_ZIPSTREAM"
    preprocConditionTable["wxUSE_ZLIB"]                    = "wxUSE_ZLIB"

    -- wxLUA_USE_xxx conditions
    preprocConditionTable["wxLUA_USE_FL"]                      = "wxLUA_USE_FL"
    preprocConditionTable["wxLUA_USE_Geometry"]                = "wxLUA_USE_Geometry"
    preprocConditionTable["wxLUA_USE_MDI"]                     = "wxLUA_USE_MDI"
    preprocConditionTable["wxLUA_USE_wxAboutDialog"]           = "wxLUA_USE_wxAboutDialog"
    preprocConditionTable["wxLUA_USE_wxAcceleratorTable"]      = "wxLUA_USE_wxAcceleratorTable"
    preprocConditionTable["wxLUA_USE_wxAnimation"]             = "wxLUA_USE_wxAnimation"
    preprocConditionTable["wxLUA_USE_wxApp"]                   = "wxLUA_USE_wxApp"
    preprocConditionTable["wxLUA_USE_wxArrayInt"]              = "wxLUA_USE_wxArrayInt"
    preprocConditionTable["wxLUA_USE_wxArrayDouble"]           = "wxLUA_USE_wxArrayDouble"
    preprocConditionTable["wxLUA_USE_wxArrayString"]           = "wxLUA_USE_wxArrayString"
    preprocConditionTable["wxLUA_USE_wxArtProvider"]           = "wxLUA_USE_wxArtProvider"
    preprocConditionTable["wxLUA_USE_wxAUI"]                   = "wxLUA_USE_wxAUI"
    preprocConditionTable["wxLUA_USE_wxBitmap"]                = "wxLUA_USE_wxBitmap"
    preprocConditionTable["wxLUA_USE_wxBitmapComboBox"]        = "wxLUA_USE_wxBitmapComboBox"
    preprocConditionTable["wxLUA_USE_wxBitmapButton"]          = "wxLUA_USE_wxBitmapButton"
    preprocConditionTable["wxLUA_USE_wxBrushList"]             = "wxLUA_USE_wxBrushList"
    preprocConditionTable["wxLUA_USE_wxBusyCursor"]            = "wxLUA_USE_wxBusyCursor"
    preprocConditionTable["wxLUA_USE_wxBusyInfo"]              = "wxLUA_USE_wxBusyInfo"
    preprocConditionTable["wxLUA_USE_wxButton"]                = "wxLUA_USE_wxButton"
    preprocConditionTable["wxLUA_USE_wxCalendarCtrl"]          = "wxLUA_USE_wxCalendarCtrl"
    preprocConditionTable["wxLUA_USE_wxCaret"]                 = "wxLUA_USE_wxCaret"
    preprocConditionTable["wxLUA_USE_wxCheckBox"]              = "wxLUA_USE_wxCheckBox"
    preprocConditionTable["wxLUA_USE_wxCheckListBox"]          = "wxLUA_USE_wxCheckListBox"
    preprocConditionTable["wxLUA_USE_wxChoice"]                = "wxLUA_USE_wxChoice"
    preprocConditionTable["wxLUA_USE_wxClassInfo"]             = "wxLUA_USE_wxClassInfo"
    preprocConditionTable["wxLUA_USE_wxClipboard"]             = "wxLUA_USE_wxClipboard"
    preprocConditionTable["wxLUA_USE_wxCollapsiblePane"]       = "wxLUA_USE_wxCollapsiblePane"
    preprocConditionTable["wxLUA_USE_wxColourDialog"]          = "wxLUA_USE_wxColourDialog"
    preprocConditionTable["wxLUA_USE_wxColourPenBrush"]        = "wxLUA_USE_wxColourPenBrush"
    preprocConditionTable["wxLUA_USE_wxColourPickerCtrl"]      = "wxLUA_USE_wxColourPickerCtrl"
    preprocConditionTable["wxLUA_USE_wxComboBox"]              = "wxLUA_USE_wxComboBox"
    preprocConditionTable["wxLUA_USE_wxCommandProcessor"]      = "wxLUA_USE_wxCommandProcessor"
    preprocConditionTable["wxLUA_USE_wxConfig"]                = "wxLUA_USE_wxConfig"
    preprocConditionTable["wxLUA_USE_wxCursor"]                = "wxLUA_USE_wxCursor"
    preprocConditionTable["wxLUA_USE_wxCriticalSection"]       = "wxLUA_USE_wxCriticalSection"
    preprocConditionTable["wxLUA_USE_wxCriticalSectionLocker"] = "wxLUA_USE_wxCriticalSectionLocker"
    preprocConditionTable["wxLUA_USE_wxDataObject"]            = "wxLUA_USE_wxDataObject"
    preprocConditionTable["wxLUA_USE_wxDataViewCtrl"]          = "wxLUA_USE_wxDataViewCtrl"
    preprocConditionTable["wxLUA_USE_wxDatePickerCtrl"]        = "wxLUA_USE_wxDatePickerCtrl"
    preprocConditionTable["wxLUA_USE_wxTimePickerCtrl"]        = "wxLUA_USE_wxTimePickerCtrl"
    preprocConditionTable["wxLUA_USE_wxDateSpan"]              = "wxLUA_USE_wxDateSpan"
    preprocConditionTable["wxLUA_USE_wxDateTime"]              = "wxLUA_USE_wxDateTime"
    preprocConditionTable["wxLUA_USE_wxDateTimeHolidayAuthority"] = "wxLUA_USE_wxDateTimeHolidayAuthority"
    preprocConditionTable["wxLUA_USE_wxDC"]                    = "wxLUA_USE_wxDC"
    preprocConditionTable["wxLUA_USE_wxDialog"]                = "wxLUA_USE_wxDialog"
    preprocConditionTable["wxLUA_USE_wxDir"]                   = "wxLUA_USE_wxDir"
    preprocConditionTable["wxLUA_USE_wxDirDialog"]             = "wxLUA_USE_wxDirDialog"
    preprocConditionTable["wxLUA_USE_wxDirPickerCtrl"]         = "wxLUA_USE_wxDirPickerCtrl"
    preprocConditionTable["wxLUA_USE_wxDisplay"]               = "wxLUA_USE_wxDisplay"
    preprocConditionTable["wxLUA_USE_wxDragDrop"]              = "wxLUA_USE_wxDragDrop"
    preprocConditionTable["wxLUA_USE_wxDynamicLibrary"]        = "wxLUA_USE_wxDynamicLibrary"
    preprocConditionTable["wxLUA_USE_wxFile"]                  = "wxLUA_USE_wxFile"
    preprocConditionTable["wxLUA_USE_wxFileDialog"]            = "wxLUA_USE_wxFileDialog"
    preprocConditionTable["wxLUA_USE_wxFileHistory"]           = "wxLUA_USE_wxFileHistory"
    preprocConditionTable["wxLUA_USE_wxFileName"]              = "wxLUA_USE_wxFileName"
    preprocConditionTable["wxLUA_USE_wxFilePickerCtrl"]        = "wxLUA_USE_wxFilePickerCtrl"
    preprocConditionTable["wxLUA_USE_wxFindReplaceDialog"]     = "wxLUA_USE_wxFindReplaceDialog"
    preprocConditionTable["wxLUA_USE_wxFont"]                  = "wxLUA_USE_wxFont"
    preprocConditionTable["wxLUA_USE_wxFontDialog"]            = "wxLUA_USE_wxFontDialog"
    preprocConditionTable["wxLUA_USE_wxFontEnumerator"]        = "wxLUA_USE_wxFontEnumerator"
    preprocConditionTable["wxLUA_USE_wxFontList"]              = "wxLUA_USE_wxFontList"
    preprocConditionTable["wxLUA_USE_wxFontMapper"]            = "wxLUA_USE_wxFontMapper"
    preprocConditionTable["wxLUA_USE_wxFontPickerCtrl"]        = "wxLUA_USE_wxFontPickerCtrl"
    preprocConditionTable["wxLUA_USE_wxFrame"]                 = "wxLUA_USE_wxFrame"
    preprocConditionTable["wxLUA_USE_wxGauge"]                 = "wxLUA_USE_wxGauge"
    preprocConditionTable["wxLUA_USE_wxGenericDirCtrl"]        = "wxLUA_USE_wxGenericDirCtrl"
    preprocConditionTable["wxLUA_USE_wxGenericValidator"]      = "wxLUA_USE_wxGenericValidator"
    preprocConditionTable["wxLUA_USE_wxGLCanvas"]              = "wxLUA_USE_wxGLCanvas"
    preprocConditionTable["wxLUA_USE_wxGrid"]                  = "wxLUA_USE_wxGrid"
    preprocConditionTable["wxLUA_USE_wxHashTable"]             = "wxLUA_USE_wxHashTable"
    preprocConditionTable["wxLUA_USE_wxHelpController"]        = "wxLUA_USE_wxHelpController"
    preprocConditionTable["wxLUA_USE_wxHTML"]                  = "wxLUA_USE_wxHTML"
    preprocConditionTable["wxLUA_USE_wxHtmlHelpController"]    = "wxLUA_USE_wxHtmlHelpController"
    preprocConditionTable["wxLUA_USE_wxHyperlinkCtrl"]         = "wxLUA_USE_wxHyperlinkCtrl"
    preprocConditionTable["wxLUA_USE_wxIcon"]                  = "wxLUA_USE_wxIcon"
    preprocConditionTable["wxLUA_USE_wxID_XXX"]                = "wxLUA_USE_wxID_XXX"
    preprocConditionTable["wxLUA_USE_wxImage"]                 = "wxLUA_USE_wxImage"
    preprocConditionTable["wxLUA_USE_wxImageList"]             = "wxLUA_USE_wxImageList"
    preprocConditionTable["wxLUA_USE_wxJoystick"]              = "wxLUA_USE_wxJoystick"
    preprocConditionTable["wxLUA_USE_wxLayoutConstraints"]     = "wxLUA_USE_wxLayoutConstraints"
    preprocConditionTable["wxLUA_USE_wxList"]                  = "wxLUA_USE_wxList"
    preprocConditionTable["wxLUA_USE_wxListBox"]               = "wxLUA_USE_wxListBox"
    preprocConditionTable["wxLUA_USE_wxListCtrl"]              = "wxLUA_USE_wxListCtrl"
    preprocConditionTable["wxLUA_USE_wxLog"]                   = "wxLUA_USE_wxLog"
    preprocConditionTable["wxLUA_USE_wxLogWindow"]             = "wxLUA_USE_wxLogWindow"
    preprocConditionTable["wxLUA_USE_wxLuaHtmlWindow"]         = "wxLUA_USE_wxLuaHtmlWindow"
    preprocConditionTable["wxLUA_USE_wxLuaPrintout"]           = "wxLUA_USE_wxLuaPrintout"
    preprocConditionTable["wxLUA_USE_wxMask"]                  = "wxLUA_USE_wxMask"
    preprocConditionTable["wxLUA_USE_wxMediaCtrl"]             = "wxLUA_USE_wxMediaCtrl"
    preprocConditionTable["wxLUA_USE_wxMenu"]                  = "wxLUA_USE_wxMenu"
    preprocConditionTable["wxLUA_USE_wxMessageDialog"]         = "wxLUA_USE_wxMessageDialog"
    preprocConditionTable["wxLUA_USE_wxMetafile"]              = "wxLUA_USE_wxMetafile"
    preprocConditionTable["wxLUA_USE_wxMiniFrame"]             = "wxLUA_USE_wxMiniFrame"
    preprocConditionTable["wxLUA_USE_wxMultiChoiceDialog"]     = "wxLUA_USE_wxMultiChoiceDialog"
    preprocConditionTable["wxLUA_USE_wxNotebook"]              = "wxLUA_USE_wxNotebook"
    preprocConditionTable["wxLUA_USE_wxObject"]                = "wxLUA_USE_wxObject"
    preprocConditionTable["wxLUA_USE_wxPalette"]               = "wxLUA_USE_wxPalette"
    preprocConditionTable["wxLUA_USE_wxPenList"]               = "wxLUA_USE_wxPenList"
    preprocConditionTable["wxLUA_USE_wxPicker"]                = "wxLUA_USE_wxPicker"
    preprocConditionTable["wxLUA_USE_wxPointSizeRect"]         = "wxLUA_USE_wxPointSizeRect"
    preprocConditionTable["wxLUA_USE_wxPopupWindow"]           = "wxLUA_USE_wxPopupWindow"
    preprocConditionTable["wxLUA_USE_wxPopupTransientWindow"]  = "wxLUA_USE_wxPopupTransientWindow"
    preprocConditionTable["wxLUA_USE_wxPrint"]                 = "wxLUA_USE_wxPrint"
    preprocConditionTable["wxLUA_USE_wxProcess"]               = "wxLUA_USE_wxProcess"
    preprocConditionTable["wxLUA_USE_wxProgressDialog"]        = "wxLUA_USE_wxProgressDialog"
    preprocConditionTable["wxLUA_USE_wxRadioBox"]              = "wxLUA_USE_wxRadioBox"
    preprocConditionTable["wxLUA_USE_wxRadioButton"]           = "wxLUA_USE_wxRadioButton"
    preprocConditionTable["wxLUA_USE_wxRegEx"]                 = "wxLUA_USE_wxRegEx"
    preprocConditionTable["wxLUA_USE_wxRegion"]                = "wxLUA_USE_wxRegion"
    preprocConditionTable["wxLUA_USE_wxRenderer"]              = "wxLUA_USE_wxRenderer"
    preprocConditionTable["wxLUA_USE_wxRichText"]              = "wxLUA_USE_wxRichText"
    preprocConditionTable["wxLUA_USE_wxSashWindow"]            = "wxLUA_USE_wxSashWindow"
    preprocConditionTable["wxLUA_USE_wxScrollBar"]             = "wxLUA_USE_wxScrollBar"
    preprocConditionTable["wxLUA_USE_wxScrolledWindow"]        = "wxLUA_USE_wxScrolledWindow"
    preprocConditionTable["wxLUA_USE_wxSingleChoiceDialog"]    = "wxLUA_USE_wxSingleChoiceDialog"
    preprocConditionTable["wxLUA_USE_wxSizer"]                 = "wxLUA_USE_wxSizer"
    preprocConditionTable["wxLUA_USE_wxSlider"]                = "wxLUA_USE_wxSlider"
    preprocConditionTable["wxLUA_USE_wxSocket"]                = "wxLUA_USE_wxSocket"
    preprocConditionTable["wxLUA_USE_wxSpinButton"]            = "wxLUA_USE_wxSpinButton"
    preprocConditionTable["wxLUA_USE_wxSpinCtrl"]              = "wxLUA_USE_wxSpinCtrl"
    preprocConditionTable["wxLUA_USE_wxSpinCtrlDouble"]        = "wxLUA_USE_wxSpinCtrlDouble"
    preprocConditionTable["wxLUA_USE_wxSplashScreen"]          = "wxLUA_USE_wxSplashScreen"
    preprocConditionTable["wxLUA_USE_wxSplitterWindow"]        = "wxLUA_USE_wxSplitterWindow"
    preprocConditionTable["wxLUA_USE_wxStandardPaths"]         = "wxLUA_USE_wxStandardPaths"
    preprocConditionTable["wxLUA_USE_wxStaticBitmap"]          = "wxLUA_USE_wxStaticBitmap"
    preprocConditionTable["wxLUA_USE_wxStaticBox"]             = "wxLUA_USE_wxStaticBox"
    preprocConditionTable["wxLUA_USE_wxStaticLine"]            = "wxLUA_USE_wxStaticLine"
    preprocConditionTable["wxLUA_USE_wxStaticText"]            = "wxLUA_USE_wxStaticText"
    preprocConditionTable["wxLUA_USE_wxStatusBar"]             = "wxLUA_USE_wxStatusBar"
    preprocConditionTable["wxLUA_USE_wxStopWatch"]             = "wxLUA_USE_wxStopWatch"
    preprocConditionTable["wxLUA_USE_wxStringList"]            = "wxLUA_USE_wxStringList"
    preprocConditionTable["wxLUA_USE_wxSystemOptions"]         = "wxLUA_USE_wxSystemOptions"
    preprocConditionTable["wxLUA_USE_wxSystemSettings"]        = "wxLUA_USE_wxSystemSettings"
    preprocConditionTable["wxLUA_USE_wxTabCtrl"]               = "wxLUA_USE_wxTabCtrl"
    preprocConditionTable["wxLUA_USE_wxTaskBarIcon"]           = "wxLUA_USE_wxTaskBarIcon"
    preprocConditionTable["wxLUA_USE_wxTextCtrl"]              = "wxLUA_USE_wxTextCtrl"
    preprocConditionTable["wxLUA_USE_wxTextEntryDialog"]       = "wxLUA_USE_wxTextEntryDialog"
    preprocConditionTable["wxLUA_USE_wxTextValidator"]         = "wxLUA_USE_wxTextValidator"
    preprocConditionTable["wxLUA_USE_wxTimer"]                 = "wxLUA_USE_wxTimer"
    preprocConditionTable["wxLUA_USE_wxTimeSpan"]              = "wxLUA_USE_wxTimeSpan"
    preprocConditionTable["wxLUA_USE_wxToggleButton"]          = "wxLUA_USE_wxToggleButton"
    preprocConditionTable["wxLUA_USE_wxToolbar"]               = "wxLUA_USE_wxToolbar"
    preprocConditionTable["wxLUA_USE_wxToolbook"]              = "wxLUA_USE_wxToolbook"
    preprocConditionTable["wxLUA_USE_wxTooltip"]               = "wxLUA_USE_wxTooltip"
    preprocConditionTable["wxLUA_USE_wxTranslations"]          = "wxLUA_USE_wxTranslations"
    preprocConditionTable["wxLUA_USE_wxTreebook"]              = "wxLUA_USE_wxTreebook"
    preprocConditionTable["wxLUA_USE_wxTreeCtrl"]              = "wxLUA_USE_wxTreeCtrl"
    preprocConditionTable["wxLUA_USE_wxTreeListCtrl"]          = "wxLUA_USE_wxTreeListCtrl"
    preprocConditionTable["wxLUA_USE_wxValidator"]             = "wxLUA_USE_wxValidator"
    preprocConditionTable["wxLUA_USE_wxWave"]                  = "wxLUA_USE_wxWave"
    preprocConditionTable["wxLUA_USE_wxWindowList"]            = "wxLUA_USE_wxWindowList"
    preprocConditionTable["wxLUA_USE_wxWizard"]                = "wxLUA_USE_wxWizard"
    preprocConditionTable["wxLUA_USE_wxXML"]                   = "wxLUA_USE_wxXML"
    preprocConditionTable["wxLUA_USE_wxXRC"]                   = "wxLUA_USE_wxXRC"

    -- condition operators for preprocessor #if statements
    preprocOperatorTable["|"]  = "||"
    preprocOperatorTable["||"] = "||"
    preprocOperatorTable["&"]  = "&&"
    preprocOperatorTable["&&"] = "&&"
    preprocOperatorTable[">"]  = ">"
    preprocOperatorTable[">="] = ">="
    preprocOperatorTable["<"]  = "<"
    preprocOperatorTable["<="] = "<="
    preprocOperatorTable["!"]  = "!"
    preprocOperatorTable["("]  = "("
    preprocOperatorTable[")"]  = ")"

    -- operators for %operator

    bindingOperatorTable["=="]  = "op_eq"
    bindingOperatorTable["!="]  = "op_ne"
    bindingOperatorTable["<"]   = "op_lt"
    bindingOperatorTable[">"]   = "op_gt"
    bindingOperatorTable["<="]  = "op_le"
    bindingOperatorTable[">="]  = "op_ge"
    bindingOperatorTable["||"]  = "op_lor"  -- logical or
    bindingOperatorTable["&&"]  = "op_land" -- logical and
    bindingOperatorTable["!"]   = "op_not"

    bindingOperatorTable["|"]   = "op_or"
    bindingOperatorTable["&"]   = "op_and"
    bindingOperatorTable["^"]   = "op_xor"
    bindingOperatorTable["<<"]  = "op_lshift"
    bindingOperatorTable[">>"]  = "op_rshift"

    bindingOperatorTable["|="]  = "op_ior"
    bindingOperatorTable["&="]  = "op_iand"
    bindingOperatorTable["^="]  = "op_ixor"
    bindingOperatorTable["<<="] = "op_ilshift"
    bindingOperatorTable[">>="] = "op_irshift"

    bindingOperatorTable["="]  = "op_set"
    bindingOperatorTable["()"] = "op_func"
    bindingOperatorTable["[]"] = "op_index"

    bindingOperatorTable["++"] = "op_inc"  -- or op_preinc
    bindingOperatorTable["--"] = "op_dec"  -- or op_predec
    bindingOperatorTable["~"]  = "op_comp" -- bitwise one's compliment
    --bindingOperatorTable["-"] = "op_neg" -- also op_sub if not unary -

    bindingOperatorTable["+"]  = "op_add"
    bindingOperatorTable["-"]  = "op_sub"  -- also op_neg if unary -
    bindingOperatorTable["*"]  = "op_mul"  -- also op_deref if no args
    bindingOperatorTable["/"]  = "op_div"
    bindingOperatorTable["%"]  = "op_mod"

    bindingOperatorTable["+="] = "op_iadd"
    bindingOperatorTable["-="] = "op_isub"
    bindingOperatorTable["*="] = "op_imul"
    bindingOperatorTable["/="] = "op_idiv"
    bindingOperatorTable["%="] = "op_imod"

    -- bindingKeywordTable
    bindingKeywordTable["%rename"]      = true
        -- keywords that come after class tag
        bindingKeywordTable["%delete"]      = true
        -- keywords that can only be used within class tag
        bindingKeywordTable["%member"]      = true
        bindingKeywordTable["%member_func"] = true
        bindingKeywordTable["%operator"]    = true
    bindingKeywordTable["%abstract"]    = true
    bindingKeywordTable["struct"]      = true
    bindingKeywordTable["enum"]        = true
    bindingKeywordTable["%function"]    = true
    bindingKeywordTable["%override"]    = true
    bindingKeywordTable["%override_name"] = true
    bindingKeywordTable["%not_overload"] = true
    bindingKeywordTable["%includefile"] = true

    bindingKeywordTable["%wxEventType"]    = true

    -- Switching over to these
    bindingKeywordTable["#define"]          = true
    bindingKeywordTable["#define_string"]   = true
    bindingKeywordTable["#define_wxstring"] = true
    bindingKeywordTable["#define_object"]   = true
    bindingKeywordTable["#define_pointer"]  = true
    bindingKeywordTable["#if"]              = true
    --bindingKeywordTable["#ifdef"]           = true
    bindingKeywordTable["#endif"]           = true
    bindingKeywordTable["#include"]         = true

    bindingKeywordTable["class"]            = true
        bindingKeywordTable["public"]       = true
        bindingKeywordTable["protected"]    = true
        bindingKeywordTable["private"]      = true
        bindingKeywordTable["operator"]     = true
        bindingKeywordTable["friend"]       = true
    bindingKeywordTable["enum"]             = true
    bindingKeywordTable["struct"]           = true
    bindingKeywordTable["typedef"]          = true


    bindingKeywordTable["%gc_this"]     = true
    bindingKeywordTable["%ungc_this"]   = true


    bindingKeywordTable["//"]           = true
    bindingKeywordTable["/*"]           = true
    bindingKeywordTable["*/"]           = true
    bindingKeywordTable["{"]            = true
    bindingKeywordTable["}"]            = true
    bindingKeywordTable[";"]            = true
end

-- ---------------------------------------------------------------------------
-- SpaceSeparateStrings - add a space between strings, either can be nil
-- returns either the sum of them or whichever is not nil
-- ---------------------------------------------------------------------------
function SpaceSeparateStrings(str1, str2)
    if str1 and str2 then
        return str1.." "..str2
    end

    return str1 or str2
end

-- ---------------------------------------------------------------------------
-- SplitString - String tokenizing function
--
-- str            - input string to split
-- delimTable     - list of strings that delimit string tokens
-- keepTable      - list of delimiters that will be kept in return list
-- stringliterals - bool - true to not tokenise string literals
-- lineTable      - table w/ .FileName name and .LineNumber for error messages
-- ---------------------------------------------------------------------------
function SplitString(str, delimTable, keepTable, stringliterals, lineTable)
    assert(str, "Error: input string is nil in SplitString "..LineTableErrString(lineTable))

    local len = string_len(str)
    local tokens = {}

    if len == 0 then return tokens end

    local wordStart = nil
    local wordEnd   = nil
    local inStringLiteral = false
    local escapedQuote = false

    -- Trim out unused delimiters using faster C find function
    local delimTable_start = {} -- starting char of the delimiters
    local delimTable_char  = {} -- single char delims in this string
    local delimTable_str   = {} -- multichar delimiters in this string
    local delimTable_len   = {} -- lengths of the delimTable_str strings
    for n = 1, #delimTable do
        local delim = delimTable[n]
        if string.find(str, delim, 1, 1) then
            local delim_len = string_len(delim)
            local char = string_byte(delim)
            delimTable_start[char] = true
            if delim_len == 1 then
                delimTable_char[char] = delim
            else
                table.insert(delimTable_str, delim)
                table.insert(delimTable_len, delim_len)
            end
        end
    end

    -- create a hash table of the keepTable strings
    local keepTable_hash = {}
    if keepTable then
        for n = 1, #keepTable do
            keepTable_hash[keepTable[n]] = true
        end
    end

    local i = 1
    while i <= len do
        local delim = nil
        local keepDelim = false
        local char = string_byte(str, i)

        if stringliterals then
            if inStringLiteral then
                if (char == char_BACKSLASH) and (string_byte(str, i+2) == char_DOUBLEQUOTE) then
                    i = i + 1 -- skip \"
                    char = char_DOUBLEQUOTE
                elseif (char == char_DOUBLEQUOTE) then
                    inStringLiteral = false
                end
            elseif char == char_DOUBLEQUOTE then
                inStringLiteral = true
            end
        end

        if (not inStringLiteral) and delimTable_start[char] then
            -- check multichar delimiters
            for n = 1, #delimTable_str do
                --if string.find(str, delimTable_str[n], i, 1) == i then
                if string_sub(str, i, i+delimTable_len[n]-1) == delimTable_str[n] then
                    delim = delimTable_str[n]
                    break
                end
            end
            -- check single char delimiters
            if not delim and delimTable_char[char] then
                delim = delimTable_char[char]
            end
            -- check if unairy '-' on a number, if it is keep the - with the number
            if (char == char_DASH) and digitTable[string_byte(str, i+1)] then
                delim = nil
            end
            -- keep delimiter in list
            if delim and keepTable and keepTable_hash[delim] then
                keepDelim = true
            end
        end

        if not delim then
            if not wordStart then
                wordStart = i
            end

            wordEnd = i
            i = i + 1
        else
            if wordStart then
                table.insert(tokens, string_sub(str, wordStart, wordEnd))
            end
            if keepDelim then
                table.insert(tokens, delim)
            end

            wordStart = nil
            i = i + string_len(delim)
        end
    end

    if wordStart then
        table.insert(tokens, string_sub(str, wordStart))
    end

    if inStringLiteral then
        print("ERROR: Couldn't find closing quote for string literal. "..LineTableErrString(lineTable))
        print(str)
    end

    return tokens;
end

-- ---------------------------------------------------------------------------
-- Load Override Functions from the override file
-- ---------------------------------------------------------------------------
function ReadOverrideFile(override_file)
    local inOverride   = false
    local inComment    = false
    local filename     = interface_filepath.."/"..override_file
    local linenumber   = 0
    local OverrideFunc = nil
    local delimiters   = {" ", "\t"}

    if not FileExists(filename) then
        print("ERROR: Missing override file:'"..filename.."'")
        return
    end

    for line in io.lines(filename) do
        line = line:gsub("%s+$","") -- drop all trailing whitespaces not handled by io.lines
        local lineData = SplitString(line, delimiters)
        local isOverride = false
        local isEnd = false

        linenumber = linenumber + 1

        -- %override or %end
        for i = 1, #lineData do
            local tag = lineData[i]

            if (not inOverride) and (tag == "/*") then
                inComment = true
            elseif (not inOverride) and (tag == "*/") then
                inComment = false
            elseif tag == "//" then
                break
            elseif tag == "%override" then
                isOverride = true
            elseif tag == "%end" then
                isEnd = true
            elseif isOverride and (not inComment) then
                OverrideFunc = tag
                break
            end
        end

        if isOverride and (not inComment) then
            if inOverride then
                print("ERROR: Expected %end. File: "..filename.." (Line: "..linenumber..")")
            elseif not OverrideFunc then
                print("ERROR: Expected Override Function Name. File: "..filename.." (Line: "..linenumber..")")
            end
        elseif isEnd and (not inOverride) and (not inComment) then
            print("ERROR: Expected %override. File: "..filename.." (Line: "..linenumber..")")
        end

        if isOverride and (not inComment) then
            if not overrideTable[OverrideFunc] then overrideTable[OverrideFunc] = {} end
            if not overrideTableUsed[OverrideFunc] then overrideTableUsed[OverrideFunc] = false end
            inOverride = true

            table.insert(overrideTable[OverrideFunc], "// "..line.."\n")
        elseif isEnd and (not inComment) then
            table.insert(overrideTable[OverrideFunc], "\n")

            inOverride = false
            OverrideFunc = nil
        elseif inOverride and (not inComment) then
            table.insert(overrideTable[OverrideFunc], line.."\n")
        end
    end
end

-- ---------------------------------------------------------------------------
-- Get the cpp filename to write the binding to by prepending the path
-- ---------------------------------------------------------------------------
function GetCPPFileName(filename)
    local splitpath = SplitString(filename, { "/", "\\" })
    local name = SplitString(splitpath[#splitpath], { "." })
    return output_cpp_filepath.."/"..name[1]..".cpp"
end

-- ---------------------------------------------------------------------------
-- Get the cpp header filename to write the bindings to
-- ---------------------------------------------------------------------------
function GetCPPHeaderFileName(filename)
    local splitpath = SplitString(filename, { "/", "\\" })
    local name = SplitString(splitpath[#splitpath], { "." })

    if not output_cpp_header_filepath then
        output_cpp_header_filepath = output_cpp_filepath
    end

    return output_cpp_header_filepath.."/"..name[1]..".h"
end

-- ---------------------------------------------------------------------------
-- Load an interface file creating a table {FileName, LineNumber, Tags, Line}
-- ---------------------------------------------------------------------------
function ReadInterfaceFile(filename)
    local fileData   = {}
    local linenumber = 0

    for line in io.lines(filename) do
        line = line:gsub("%s+$","") -- drop all trailing whitespaces not handled by io.lines
        linenumber = linenumber + 1

        local lineTable =
        {
            FileName   = filename,
            LineNumber = linenumber,
            LineText   = line,
            Tags       = SplitString(line, bindingDelimiters, bindingDelimsToKeep, true, lineTable)
        }

        table.insert(fileData, lineTable)
    end

    return fileData
end

-- ---------------------------------------------------------------------------
-- Return a nicely formatted string where an error occurred using the lineTable
--   from ReadInterfaceFile
-- ---------------------------------------------------------------------------
function LineTableErrString(lineTable)
    if type(lineTable) == "table" then
        return "File: '"..lineTable.FileName.."':(line "..lineTable.LineNumber..")\n    '"..lineTable.LineText.."'"
    else
        return ""
    end
end

-- ---------------------------------------------------------------------------
-- Entry point to read the .i interface files and parse them into data
-- ---------------------------------------------------------------------------
function GenerateInterfaceData()
    local interfaceFileDataList = {}
    local interfaceList = {}

    local time1 = os.time()

    -- read all interface files and build DataType Table
    for i = 1, #interface_fileTable do
        local filename = interface_filepath.."/"..interface_fileTable[i]

        if FileExists(filename) then
            -- read the interface .i file into a table
            local interfaceFileData = ReadInterfaceFile(filename)
            -- find and add data types to the dataTypeTable table
            BuildDataTypeTable(interfaceFileData)

            table.insert(interfaceFileDataList, { FileName=filename, Data=interfaceFileData })
        else
            print("ERROR: Interface file does not exist : '"..filename.."'")
        end
    end

    local time2 = os.time()
    print("Timing: BuildDataTypeTable "..os.difftime(time2, time1).." seconds.")
    time1 = time2

    for i = 1, #interfaceFileDataList do
        -- Parse interface file data into a structured object list
        local objectList = ParseData(interfaceFileDataList[i].Data)

        if objectList then
            local interface =
            {
                CPPFileName         = GetCPPFileName(interfaceFileDataList[i].FileName),
                includeBindingTable = {},
                includeFiles        = {},
                objectData          = objectList,
                lineData            = interfaceFileDataList[i].Data
            }

            table.insert(interfaceList, interface)
        end
    end

    local time2 = os.time()
    print("Timing: ParseData "..os.difftime(time2, time1).." seconds.")

    return interfaceList
end

-- ---------------------------------------------------------------------------
-- After generating the wrapper files, write them to disk
-- ---------------------------------------------------------------------------
function WriteWrapperFiles(interfaceList)
    local time1 = os.time()

    local monolithicFileData = {}
    local updated_files = 0

    -- generatelanguage binding, binding is stored in objectList
    for i = 1, #interfaceList do
        local interface = interfaceList[i]

        -- theoretically you could write other language binding generators
        -- using parsed interface data
        GenerateLuaLanguageBinding(interface)

        -- create c/c++ file
        local fileData = {}
        local add_includes = true
        if output_single_cpp_binding_file then
            fileData = monolithicFileData
            add_includes = (i == 1)
        end

        fileData = GenerateBindingFileTable(interface, fileData, add_includes)

        if output_single_cpp_binding_file then
            monolithicFileData[#monolithicFileData+1] = "\n\n"
        else
            local written = WriteTableToFile(interface.CPPFileName, fileData, false)
            if written then
                updated_files = updated_files + 1
            end
        end
    end

    local fileData = GenerateHookHeaderFileTable()
    local written = WriteTableToFile(GetCPPHeaderFileName(hook_cpp_header_filename), fileData, false)
    if written then
        updated_files = updated_files + 1
    end

    local fileData = {} -- reset to empty table
    if output_single_cpp_binding_file then
        fileData = monolithicFileData
    end

    fileData = GenerateHookCppFileHeader(fileData, GetCPPFileName(hook_cpp_binding_filename), not output_single_cpp_binding_file)
    table.insert(fileData, (hook_cpp_binding_source_includes or "").."\n")
    fileData = GenerateHookEventFileTable(fileData)
    fileData = GenerateHookDefineFileTable(fileData)
    fileData = GenerateHookObjectFileTable(fileData)
    fileData = GenerateHookCFunctionFileTable(fileData)
    fileData = GenerateHookClassFileTable(fileData)
    written = WriteTableToFile(GetCPPFileName(hook_cpp_binding_filename), fileData, false)
    if written then
        updated_files = updated_files + 1
    end

    local time2 = os.time()
    --print("Timing: GenerateLuaLanguageBinding and write files "..os.difftime(time2, time1).." seconds.")
    return updated_files
end

function AllocParseObject(obj_type)
    local parseObject =
    {
        Name             = "<"..obj_type..">",
        ObjType          = obj_type,
        Access           = "public", -- public, protected, private
        TagDeclaration   = nil,
        BindTable        = {},
        BaseClasses      = {},
        Members          = {},
        ["%delete"]      = false,
        Condition        = nil,
    }

    return parseObject
end

function AllocMember(lineState, extraCondition)
    local member =
    {
        DefType                 = lineState.DefType,
        DataType                = lineState.DataType,
        DataTypeWithAttrib      = lineState.DataTypeWithAttrib,
        DataTypePointer         = lineState.DataTypePointer,
        TypedDataType           = lineState.DataType,
        TypedDataTypeWithAttrib = lineState.DataTypeWithAttrib,
        TypedDataTypePointer    = lineState.DataTypePointer,
        Name                    = lineState.Name,
        ["%rename"]             = lineState["%rename"],
        Value                   = lineState.Value,
        ["%function"]           = lineState["%function"],
        IsConstructor           = lineState.IsConstructor,
        ["%operator"]           = lineState["%operator"],
        IsFunction              = lineState.IsFunction,
        IsConstFunction         = lineState.IsConstFunction,
        IsStaticFunction        = lineState.IsStaticFunction,
        IsVirtualFunction       = lineState.IsVirtualFunction,
        IsPureVirtualFunction   = lineState.IsPureVirtualFunction,
        NotOverload             = lineState.NotOverload,
        override_name           = lineState.override_name,
        Condition               = lineState.Condition,
        ExtraCondition          = extraCondition,
        Params                  = lineState.Params,
        FileName                = lineState.FileName,
        LineNumber              = lineState.LineNumber,
        LineText                = lineState.LineText,
        ["%gc_this"]            = lineState["%gc_this"],
        ["%ungc_this"]          = lineState["%ungc_this"],
    }

    return member
end

function AllocParam()
    local member =
    {
        DataType                = nil,
        DataTypeWithAttrib      = nil,
        DataTypePointer         = {},
        TypedDataType           = nil,
        TypedDataTypeWithAttrib = nil,
        TypedDataTypePointer    = {},
        Name                    = nil,
        DefaultValue            = nil,
        ParamObjectDeclared     = nil,
        Binding                 = nil
    }

    return member
end

function InsertParamState(Params, ParamState)
    -- don't insert func(void) parameters
    if ParamState.DataType and ((ParamState.DataTypeWithAttrib ~= "void") or (#ParamState.DataTypePointer > 0)) then
        table.insert(Params, ParamState)
    end
end

-- ---------------------------------------------------------------------------
-- Build DataType Table by adding classes (and their bases), structs, and enums
-- ---------------------------------------------------------------------------
function BuildDataTypeTable(interfaceData)
    local in_block_comment = 0
    local namespaceStack = {} -- todo, use this
    local enumType = ""

    for l = 1, #interfaceData do
        local lineTable = interfaceData[l]
        local lineTags  = lineTable.Tags

        local classname = nil -- current classname if any
        local action    = nil -- what to look for next

        local typedefTable = {}

        local t = 0

        while t < #lineTags do
            t = t + 1
            local tag = lineTags[t]
            -- handle classA::classB ...
            while (in_block_comment == 0) and (lineTags[t+1] == "::") do
                tag = tag..lineTags[t+1]..lineTags[t+2]
                t = t + 2
            end

            if bindingKeywordTable[tag] then

                -- block comment (/* start) to (*/ end)
                if     tag == "/*" then in_block_comment = in_block_comment + 1
                elseif tag == "*/" then in_block_comment = in_block_comment - 1
                end

                -- ignore until end of block comment
                if in_block_comment == 0 then
                    -- rest of line comment
                    if tag == "//" then
                        t = #lineTags + 1
                        break

                    elseif (tag == "class"  ) then action = "find_classname"
                    elseif (tag == "struct" ) then action = "find_structname"
                    elseif (tag == "enum"   ) then action = "find_enumname"
                    elseif (tag == "typedef") then action = "find_typedef"
                    elseif (tag == "}"      ) then
                      enumType = string.sub(enumType, 1, math.max(0, #enumType - #(namespaceStack[#namespaceStack] or {})))
                      namespaceStack[#namespaceStack] = nil
                    end
                end
            elseif (in_block_comment == 0) and action and
                   (not preprocOperatorTable[tag]) and (not FindOrCreateCondition(tag)) and
                   (not skipBindingKeywordTable[tag]) then

                if action == "find_classname" then
                    if not dataTypeTable[tag] then
                        AllocDataType(tag, "class", false)
                    end

                    classname = tag
                    enumType = tag.."::"
                    namespaceStack[#namespaceStack+1] = tag.."::"
                    action = "find_classcolon"
                elseif action == "find_classcolon" then
                    if tag ~= ":" then
                        print("WARNING: Expected colon (':') after class name : '"..classname.."' in "..LineTableErrString(lineTable))
                    end
                    action = "find_classbase"
                elseif action == "find_classcomma" then
                    if tag ~= "," then
                        print("WARNING: Expected comma (',') after baseclass name in : '"..classname.."' in "..LineTableErrString(lineTable))
                    end
                    action = "find_classbase"
                elseif action == "find_classbase" then
                    -- Note that [public,protected,private] is skipped by bindingKeywordTable

                    if not dataTypeTable[tag] then
                        AllocDataType(tag, "class", false)
                    end

                    -- set class's BaseClass
                    if not dataTypeTable[classname].BaseClasses then
                        dataTypeTable[classname].BaseClasses = {}
                    end

                    table.insert(dataTypeTable[classname].BaseClasses, tag)

                    action = "find_classcomma"
                elseif action == "find_structname" then
                    if not dataTypeTable[tag] then
                        AllocDataType(tag, "struct", false)
                    end

                    namespaceStack[#namespaceStack+1] = tag.."::"

                    action = nil
                elseif action == "find_enumname" then
                    if not dataTypeTable[tag] then
                        AllocDataType(enumType..tag, "enum", true)
                    end

                    namespaceStack[#namespaceStack+1] = tag

                    action = nil
                elseif action == "find_typedef" then
                    table.insert(typedefTable, tag)

                end
            end
        end

        if #typedefTable > 0 then
            local typedef_name = typedefTable[#typedefTable]
            local typedef_type = table.concat(typedefTable, " ", 1, #typedefTable-1)
            local dt = false
            for i = 1,#typedefTable-1 do
                -- increment forward until we know the type, skipping const and other attribs
                dt = dataTypeTable[table.concat(typedefTable, " ", i, #typedefTable-1)]
                if dt then
                    AllocDataType(typedef_name, dt.ValueType, dt.IsNumber)
                    break
                end
            end
        end

    end
end

-- ---------------------------------------------------------------------------
-- Parse the interface file tags
-- This uses a stack of AllocParseObjects with the top most one the globals
--   classes and enums are temporarily pushed onto it and removed at the end.
-- ---------------------------------------------------------------------------

function ParseData(interfaceData)

    local objectList = {}
    local parseState =
    {
        ObjectStack    = {},
        ConditionStack = {}, -- stack of conditions
        IsBlockComment = 0,  -- /* then +1 else */ then -1, 0 == not in comment
    }

    local globals = AllocParseObject("objtype_globals") -- Global Objects
    globals.Name = "globals"

    table.insert(parseState.ObjectStack, 1, globals)

    local function EndObjectStack(objectList, parseState, lineState)
        table.insert(objectList, parseState.ObjectStack[1])
        table.remove(parseState.ObjectStack, 1)

        --TableDump(parseState.ObjectStack, "EndObjectStack-parseState.ObjectStack ")
        --TableDump(lineState,              "EndObjectStack-lineState ")
        --TableDump(objectList,             "EndObjectStack-objectList ")
    end

    local function AllocLineState(lineTable)
        local lineState =
        {
            Skip                  = false, -- skip rest of line
            InlineConditionIf     = false, -- single line condition
            Action                = nil,
            ActionAttributes      = {},
            ActionMandatory       = false,
            PopParseObject        = nil,
            ParamState            = AllocParam(),
            BaseClasses           = {},
            RValue                = nil,

            DefType               = nil, -- below are copied by AllocMember
            DataType              = nil,
            DataTypeWithAttrib    = nil,
            DataTypePointer       = {},
            Name                  = nil,
            ["%rename"]           = nil,
            Value                 = nil,
            ["%gc_this"]          = nil,
            ["%ungc_this"]        = nil,
            ["%function"]         = nil,
            IsConstructor         = nil,
            ["%operator"]         = nil,
            IsFunction            = nil,
            IsConstFunction       = nil,
            IsStaticFunction      = nil,
            IsVirtualFunction     = nil,
            IsPureVirtualFunction = nil,
            override_name         = nil,
            NotOverload           = nil,
            Condition             = nil,
            Params                = {},
            FileName              = lineTable.FileName,
            LineNumber            = lineTable.LineNumber,
            LineText              = lineTable.LineText,
        }
        return lineState
    end

    local namespaceTable = {}
    local enumType = "" -- FIXME temp fix to remember named enums
    local brace_count = 0
    local statement_end = false -- usually ; terminated end of statement

    local l = 0
    local t = 0
    local tag       -- = lineTags[t]
    local lineTable -- = interfaceData[l]
    local lineTags  -- = interfaceData[l].Tags
    local lineState -- AllocLineState(lineTable)

    -- This relies on upvalues and sets them
    local function GetNextToken()
        if (lineTags == nil) or (lineTags[t+1] == nil) then
            t = 0
            l = l + 1
            if interfaceData[l] == nil then
                tag = nil
                return
            end

            lineTable = interfaceData[l]
            lineTags  = interfaceData[l].Tags

            if (lineState ~= nil) then
                lineState.FileName   = lineTable.FileName
                lineState.LineNumber = lineTable.LineNumber
                lineState.LineText   = lineState.LineText..lineTable.LineText
            end
        end

        if (lineState == nil) then
            lineState = AllocLineState(lineTable)
        end

        t = t + 1
        tag = lineTags[t]

        if tag == "//" then
            -- skip to next line
            tag = nil
            t = #lineTags + 1
            GetNextToken()
        end
    end

    while interfaceData[l+1] do -- not for loop so we can adjust l

        GetNextToken()

        local run_once = 1
        while (run_once == 1) and tag do --lineTags[t+1] do
            run_once = run_once + 1

            -- handle classA::classB ...
            while (parseState.IsBlockComment == 0) and (lineTags[t+1] == "::") do
                tag = tag..lineTags[t+1]..lineTags[t+2]
                t = t + 2
            end

            if lineState.Skip then
                break
            end

            local finding_baseclass_name = (lineState.Action == "action_baseclass") and (classAccessTable[lineTags[t]] ~= nil)

            -- ---------------------------------------------------------------
            -- Is this tag a binding keyword, e.g. %XXX
            -- ---------------------------------------------------------------
            if bindingKeywordTable[tag] and (not finding_baseclass_name) then
                -- block comment (start)
                if tag == "/*" then
                    parseState.IsBlockComment = parseState.IsBlockComment + 1

                -- block comment (end)
                elseif tag == "*/" then
                    parseState.IsBlockComment = parseState.IsBlockComment - 1

                    if (parseState.IsBlockComment < 0) then
                        print("ERROR: Mismatched comments /* ... */  "..LineTableErrString(lineTable))
                        assert(false, "Exiting")
                    end

                -- ignore until end of block comment
                elseif parseState.IsBlockComment == 0 then

                    local class_operator = (tag == "operator") and (lineState.Action == "action_method")

                    -- warn if we're expecting something and it's not there
                    if (not lineState.ActionAttributes[tag]) and lineState.ActionMandatory and (not class_operator) then
                        print("ERROR: Expected Line Action '"..lineState.Action.."', got '"..tag.."'. "..LineTableErrString(lineTable))
                    end

                    -- end inline conditionals since we should have handled it already
                    if lineState.InlineConditionIf then
                        lineState.InlineConditionIf = false
                    end

                    -- rest of line comment
                    if tag == "//" then
                        t = #lineTags + 1
                        break

                    elseif tag == "{" then
                        brace_count = brace_count + 1
                        statement_end = true
                    elseif tag == "}" then
                        brace_count = brace_count - 1
                        if (brace_count < 0) then
                            print("ERROR: Mismatched braces {}. "..LineTableErrString(lineTable))
                            assert(false, "Exiting")
                        end

                        -- Check if we are ending a class, enum, struct
                        if true or (brace_count == 0) then
                            if (parseState.ObjectStack[1].ObjType == "objtype_class") then
                                t = t + 1
                                if (lineTags[t] ~= ";") then
                                    print("ERROR: End of class declaration missing ';'. "..LineTableErrString(lineTable))
                                    assert(false, "Exiting")
                                end

                                -- Strip off "classname::classname2::"
                                enumType = string.sub(enumType, 1, math.max(0, #enumType - #parseState.ObjectStack[1].Name - 2))

                                statement_end = true
                                EndObjectStack(objectList, parseState, lineState)

                                if #parseState.ObjectStack == 0 then
                                    print("ERROR: parseState.ObjectStack is unexpectedly empty at end of class declaration. "..LineTableErrString(lineTable))
                                    assert(false, "Exiting")
                                end

                                lineState.Action = "action_keyword"
                                lineState.ActionMandatory = true
                            elseif (parseState.ObjectStack[1].ObjType == "objtype_enum") then
                                t = t + 1
                                if (lineTags[t] ~= ";") then
                                    print("ERROR: End of enum declaration missing ';'. "..LineTableErrString(lineTable))
                                    assert(false, "Exiting")
                                end

                                -- Strip off "classname::classname2::"
                                enumType = string.sub(enumType, 1, math.max(0, #enumType - #parseState.ObjectStack[1].Name - 2))

                                statement_end = true
                                EndObjectStack(objectList, parseState, lineState)

                                if #parseState.ObjectStack == 0 then
                                    print("ERROR: parseState.ObjectStack is unexpectedly empty at end of enum declaration. "..LineTableErrString(lineTable))
                                end
                            elseif (parseState.ObjectStack[1].ObjType == "objtype_struct") then
                                t = t + 1
                                if (lineTags[t] ~= ";") then
                                    print("ERROR: End of struct declaration missing ';'. "..LineTableErrString(lineTable))
                                    assert(false, "Exiting")
                                end

                                -- Strip off "classname::classname2::"
                                enumType = string.sub(enumType, 1, math.max(0, #enumType - #parseState.ObjectStack[1].Name - 2))

                                statement_end = true
                                EndObjectStack(objectList, parseState, lineState)

                                if #parseState.ObjectStack == 0 then
                                    print("ERROR: parseState.ObjectStack is unexpectedly empty at end of struct declaration. "..LineTableErrString(lineTable))
                                end
                            end
                        end

                    elseif tag == ";" then
                        statement_end = true

                    -- #if wxLUA_USE_xxx ... #endif
                    elseif tag == "#if" then
                        lineState.DefType = "deftype_#if"

                    elseif tag == "#endif" then
                        table.remove(parseState.ConditionStack, #parseState.ConditionStack) -- pop last #if
                        break -- we can stop processing line

                    elseif tag == "%rename" then
                        lineState.Action = "action_rename"
                        lineState.ActionMandatory = true

                    elseif tag == "%function" then
                        lineState["%function"] = true

                    elseif tag == "%gc_this" then
                        lineState["%gc_this"] = true

                        if parseState.ObjectStack[1].ObjType ~= "objtype_class" then
                            print("ERROR: %gc_this is not used for a class member function. "..LineTableErrString(lineTable))
                        end

                    elseif tag == "%ungc_this" then
                        lineState["%ungc_this"] = true

                        if parseState.ObjectStack[1].ObjType ~= "objtype_class" then
                            print("ERROR: %ungc_this is not used for a class member function. "..LineTableErrString(lineTable))
                        end

                    -- -------------------------------------------------------
                    elseif tag == "class" then
                        local parseObject = AllocParseObject("objtype_class")
                        table.insert(parseState.ObjectStack, 1, parseObject)
                        lineState.ParseObjectDeclaration = true

                        lineState.DefType = "deftype_class"
                        lineState.Action = "action_classname"
                        lineState.ActionMandatory = true
                        lineState.ActionAttributes["%delete"] = true
                        lineState.ActionAttributes["%abstract"] = true

                    elseif tag == "%delete" then -- tag for class
                        parseState.ObjectStack[1]["%delete"] = true

                        if (parseState.ObjectStack[1].ObjType ~= "objtype_class") and
                           (parseState.ObjectStack[1].ObjType ~= "objtype_struct") then
                            print("ERROR: %delete is not used for a class. "..LineTableErrString(lineTable))
                        end

                    elseif tag == "%abstract" then -- tag for class
                        parseState.ObjectStack[1]["%abstract"] = true

                        if parseState.ObjectStack[1].ObjType ~= "objtype_class" then
                            print("ERROR: %abstract is not used for a class. "..LineTableErrString(lineTable))
                        end

                    -- -------------------------------------------------------
                    elseif tag == "public" then
                        if (lineTags[t+1] == ":") then
                            if (parseState.ObjectStack[1].ObjType ~= "objtype_class") and
                               (parseState.ObjectStack[1].ObjType ~= "objtype_struct") then
                                print("ERROR: 'public:' is not used in a class or struct. "..LineTableErrString(lineTable))
                            end

                            t = t + 1
                            tag = lineTags[t]

                            parseState.ObjectStack[1].Access = "public"
                        end

                    elseif tag == "protected" then -- skip protected functions
                        lineState.Skip = true

                        if (lineTags[t+1] == ":") then
                            if (parseState.ObjectStack[1].ObjType ~= "objtype_class") and
                               (parseState.ObjectStack[1].ObjType ~= "objtype_struct") then
                                print("ERROR: 'public:' is not used in a class or struct. "..LineTableErrString(lineTable))
                            end

                            t = t + 1
                            tag = lineTags[t]

                            parseState.ObjectStack[1].Access = "protected"
                        end

                    elseif tag == "private" then -- skip private functions
                        lineState.Skip = true

                        if (lineTags[t+1] == ":") then
                            if (parseState.ObjectStack[1].ObjType ~= "objtype_class") and
                               (parseState.ObjectStack[1].ObjType ~= "objtype_struct") then
                                print("ERROR: 'public:' is not used in a class or struct. "..LineTableErrString(lineTable))
                            end

                            t = t + 1
                            tag = lineTags[t]

                            parseState.ObjectStack[1].Access = "private"
                        end

                    elseif tag == "friend" then -- skip friend declarations

                        -- Eat the rest of the statement, "friend class ClassName;"
                        while (lineTags[t+1] ~= "~") and (lineTags[t+1] ~= nil) do
                            t = t + 1
                            tag = lineTags[t]
                        end

                    elseif tag == "%member" then
                        lineState.DefType = "deftype_%member"
                        lineState.Action = "action_member"
                        lineState.ActionMandatory = true

                        if (parseState.ObjectStack[1].ObjType ~= "objtype_class") and (parseState.ObjectStack[1].ObjType ~= "objtype_struct") then
                            print("ERROR: %member is not used in a class or struct. "..LineTableErrString(lineTable))
                        end

                    elseif tag == "%member_func" then
                        lineState.DefType = "deftype_%member_func"
                        lineState.Action = "action_member"
                        lineState.ActionMandatory = true

                        if (parseState.ObjectStack[1].ObjType ~= "objtype_class") and (parseState.ObjectStack[1].ObjType ~= "objtype_struct") then
                            print("ERROR: %member_func is not used for a class or struct. "..LineTableErrString(lineTable))
                        end

                    elseif (tag == "operator") or (tag == "%operator") then
                        lineState["%operator"] = true

                        if parseState.ObjectStack[1].ObjType ~= "objtype_class" then
                            print("ERROR: %operator is not used for a class. "..LineTableErrString(lineTable))
                        end

                        -- eat the rest of the "operator+=(...)" symbols which may be split before (
                        if (string.sub(tag, -1) == "r") and (lineTags[t+1] == "(") and (lineTags[t+2] == ")") then -- op_func
                            tag = tag..lineTags[t+1]..lineTags[t+2]
                            t = t + 2
                        else
                            while lineTags[t+1] and (lineTags[t+1] ~= "(") do
                                tag = tag..lineTags[t+1]
                                t = t + 1
                            end
                        end

                        local a, b = string.find(tag, "operator", 1, 1)
                        local op = string.sub(tag, b+1)
                        lineState["%operator"] = op

                        lineState.Action = "action_methodbracket" -- next char should be (
                        lineState.Name = bindingOperatorTable[op]

                    -- -------------------------------------------------------
                    elseif tag == "struct" then
                        local parseObject = AllocParseObject("objtype_struct")
                        table.insert(parseState.ObjectStack, 1, parseObject)
                        lineState.ParseObjectDeclaration = true

                        lineState.DefType = "deftype_struct"
                        lineState.Action = "action_structname"
                        lineState.ActionMandatory = true
                        lineState.ActionAttributes["%delete"] = true
                        lineState.ActionAttributes["%abstract"] = true

                    -- -------------------------------------------------------
                    elseif tag == "enum" then
                        local parseObject = AllocParseObject("objtype_enum")
                        table.insert(parseState.ObjectStack, 1, parseObject)
                        lineState.ParseObjectDeclaration = true

                        lineState.DefType = "deftype_enum"
                        lineState.Action = "action_enumname"
                        lineState.ActionMandatory = false -- not all enums have a name

                    -- -------------------------------------------------------
                    elseif (tag == "#include") or (tag == "%include") then
                        local parseObject = AllocParseObject("objtype_#include")
                        table.insert(parseState.ObjectStack, 1, parseObject)
                        lineState.ParseObjectDeclaration = true

                        lineState.PopParseObject = true -- pop parseObject off stack at end of line

                        lineState.DefType = "deftype_#include"
                        lineState.Action = "action_include"
                        lineState.ActionMandatory = true

                    elseif tag == "%includefile" then
                        local parseObject = AllocParseObject("objtype_%includefile")
                        table.insert(parseState.ObjectStack, 1, parseObject)
                        lineState.ParseObjectDeclaration = true

                        lineState.PopParseObject = true -- pop parseObject off stack at end of line

                        lineState.DefType = "deftype_%includefile"
                        lineState.Action = "action_includefile"
                        lineState.ActionMandatory = true

                    -- -------------------------------------------------------
                    elseif tag == "typedef" then
                        lineState.DefType = "deftype_typedef"
                        lineState.Action = "action_typedef"
                        lineState.ActionMandatory = true

                    elseif tag == "%override_name" then
                        lineState.Action = "action_override_name"
                        lineState.ActionMandatory = true

                    elseif tag == "%not_overload" then
                        lineState.NotOverload = true

                    -- -------------------------------------------------------
                    elseif tag == "#define" then
                        lineState.DefType = "deftype_#define"
                        lineState.Action = "action_define"
                        lineState.ActionMandatory = true

                    elseif tag == "#define_string" then
                        lineState.DefType = "deftype_#define_string"
                        lineState.Action = "action_define"
                        lineState.ActionMandatory = true

                    elseif tag == "#define_wxstring" then
                        lineState.DefType = "deftype_#define_wxstring"
                        lineState.Action = "action_define"
                        lineState.ActionMandatory = true

                    elseif tag == "%wxEventType" then
                        lineState.DefType = "deftype_%wxEventType"
                        lineState.Action = "action_define"
                        lineState.ActionMandatory = true

                    elseif tag == "#define_object" then
                        lineState.DefType = "deftype_#define_object"
                        lineState.Action = "action_define_object"
                        lineState.ActionMandatory = true

                    elseif tag == "#define_pointer" then
                        lineState.DefType = "deftype_#define_pointer"
                        lineState.Action = "action_define_pointer"
                        lineState.ActionMandatory = true

                    else
                        print("WARNING: Unhandled keyword '"..tag.."' in "..LineTableErrString(lineTable))
                    end
                end
            -- ---------------------------------------------------------------
            -- else !keyword[tag]
            -- ---------------------------------------------------------------
            elseif parseState.IsBlockComment == 0 then

                -- handle condition operators, note can have leading ! for not
                if (tag == "!") or (((lineState.DefType == "deftype_#if") or lineState.InlineConditionIf) and preprocOperatorTable[tag]) then
                    if lineState.Condition or (preprocOperatorTable[tag] == "!") or (preprocOperatorTable[tag] == "(") then
                        if not lineState.Condition then
                            lineState.Condition = preprocOperatorTable[tag]
                        else
                            local c = string.sub(lineState.Condition, -1, -1) -- get last char
                            if ((c ~= "(") and (preprocOperatorTable[tag] ~= ")")) or
                               ((c ~= ")") and (preprocOperatorTable[tag] == ")")) then
                                lineState.Condition = lineState.Condition.." "
                            end

                            -- add c operator
                            lineState.Condition = lineState.Condition..preprocOperatorTable[tag]
                        end
                    else
                        print("ERROR: Unexpected Conditional Operator "..tag..". "..LineTableErrString(lineTable))
                    end

                    if (lineTags[t+1] == nil) or (lineTags[t+1] == "//") then
                        statement_end = true
                    elseif (lineTags[t+1] == "\\") and (lineTags[t+2] == nil) then
                        statement_end = false
                    end

                elseif FindOrCreateCondition(tag) then
                    if (lineState.DefType ~= "deftype_#if") and not lineState.InlineConditionIf then
                        lineState.InlineConditionIf = true
                    end

                    if not lineState.Condition then
                        lineState.Condition = ""
                    else
                        local c = string.sub(lineState.Condition, -1, -1) -- get last char
                        if (c ~= "(") and (c ~= "!") then -- eg. not start of condition
                            if not preprocOperatorTable[c] then
                                print("ERROR: Expected Conditional Operator 1 "..tag..". "..LineTableErrString(lineTable))
                            end

                            lineState.Condition = lineState.Condition.." "
                        end
                    end

                    lineState.Condition = lineState.Condition..FindOrCreateCondition(tag)

                    if (lineTags[t+1] == nil) or (lineTags[t+1] == "//") then
                        statement_end = true
                    elseif (lineTags[t+1] == "\\") and (lineTags[t+2] == nil) then
                        statement_end = false
                    end

                elseif not skipBindingKeywordTable[tag] then
                    -- -------------------------------------------------------
                    --  Process Interface Data
                    -- -------------------------------------------------------
                    if (lineState.Action == "action_keyword") and lineState.ActionMandatory then
                        print("ERROR: Invalid Token '"..tag.."'. "..LineTableErrString(lineTable))
                    end

                    -- -------------------------------------------------------
                    -- add block condition
                    -- -------------------------------------------------------
                    if lineState.DefType == "deftype_#if" then
                        if not lineState.Condition then
                            lineState.Condition = ""
                        else
                            local c0 = string.sub(lineState.Condition,  1,  1) -- get first char
                            local c  = string.sub(lineState.Condition, -1, -1) -- get last char
                            if (c0 ~= "(") and (c ~= "(") and (c ~= "!") then -- eg. not start of condition
                                if not preprocOperatorTable[c] then
                                    print("ERROR: Expected Conditional Operator, got '"..tag.."'. "..LineTableErrString(lineTable))
                                end

                                lineState.Condition = lineState.Condition.." "
                            end
                        end

                        lineState.Condition = lineState.Condition..tag

                        if lineTags[t+1] == nil then
                            statement_end = true
                        end

                    -- -------------------------------------------------------
                    -- apply tag to lineState.Action
                    -- -------------------------------------------------------
                    else
                        -- end inline conditionals
                        if lineState.InlineConditionIf then
                            lineState.InlineConditionIf = false
                        end

                        if not lineState.Action then
                            -- no actions specified

                            -- -----------------------------------------------
                            -- enum parseObject
                            if parseState.ObjectStack[1].ObjType == "objtype_enum" then
                                if IsDataType(tag) or dataTypeAttribTable[tag] or (tag == "*") or (tag == "&") or (tag == "[]") then
                                    print("ERROR: Invalid Enum Token '"..tag.."'. "..LineTableErrString(lineTable))
                                elseif tag ~= "," then -- ignore trailing commas
                                    lineState.DefType = "deftype_enum"
                                    lineState.Name = tag
                                    lineState.DataType = enumType

                                    statement_end = true

                                    local member = AllocMember(lineState, BuildCondition(parseState.ConditionStack))
                                    table.insert(parseState.ObjectStack[1].Members, member)

                                    GetNextToken()
                                    while (tag ~= ";") and (tag ~= ",") and (tag ~= "}") and (tag ~= nil) do
                                        GetNextToken()
                                    end
                                    t = t - 1
                                end

                            -- -----------------------------------------------
                            -- class or function parseObject
                            elseif (parseState.ObjectStack[1].ObjType == "objtype_class") or
                                   (parseState.ObjectStack[1].ObjType == "objtype_struct") or
                                   (parseState.ObjectStack[1].ObjType == "objtype_globals") then

                                if (parseState.ObjectStack[1].Access == "protected") or
                                   (parseState.ObjectStack[1].Access == "private") then
                                   -- do nothing
                                elseif IsDataType(tag) then
                                    lineState.DataType = SpaceSeparateStrings(lineState.DataType, tag)
                                    lineState.DataTypeWithAttrib = SpaceSeparateStrings(lineState.DataTypeWithAttrib, tag)

                                    lineState.DefType = "deftype_method"
                                    lineState.Action = "action_method"
                                    lineState.ActionMandatory = true

                                elseif dataTypeAttribTable[tag] then
                                    lineState.DataTypeWithAttrib = SpaceSeparateStrings(lineState.DataTypeWithAttrib, tag)

                                    lineState.DefType = "deftype_method"
                                    lineState.Action = "action_method"
                                    lineState.ActionMandatory = true

                                elseif tag == "virtual" then
                                    lineState.IsVirtualFunction = true
                                    lineState.DefType = "deftype_method"
                                    lineState.Action = "action_method"
                                    lineState.ActionMandatory = true

                                elseif tag == "static" then
                                    lineState.IsStaticFunction = true
                                    lineState.DefType = "deftype_method"
                                    lineState.Action = "action_method"
                                    lineState.ActionMandatory = true

                                elseif tag == "inline" then
                                    lineState.DefType = "deftype_method"
                                    lineState.Action = "action_method"
                                    lineState.ActionMandatory = true

                                elseif lineState.IsConstructor then
                                    lineState.Name = tag
                                    lineState.DataType = parseState.ObjectStack[1].Name
                                    lineState.DataTypeWithAttrib = lineState.DataType
                                    lineState.DefType = "deftype_method"
                                    lineState.Action = "action_method"

                                else
                                    print("ERROR: Expected DataType, got '"..tag.."'. "..LineTableErrString(lineTable))
                                end
                            else
                                print("ERROR: Unexpected parseObject :"..parseState.ObjectStack[1].ObjType.." "..parseState.ObjectStack[1].Name..". "..LineTableErrString(lineTable))
                            end
                        elseif lineState.Action == "action_classname" then
                            parseState.ObjectStack[1].Name = tag
                            lineState.Action = "action_baseclasscolon"
                            lineState.ActionMandatory = false

                            enumType = enumType..tag.."::"

                        elseif lineState.Action == "action_baseclasscolon" then
                            if tag ~= ":" then
                                print("ERROR: baseclass expected ':'. "..LineTableErrString(lineTable))
                            end

                            lineState.Action = "action_baseclass"
                            lineState.ActionMandatory = true
                        elseif lineState.Action == "action_baseclasscomma" then
                            if tag ~= "," then
                                print("ERROR: baseclass expected ','. "..LineTableErrString(lineTable))
                            end

                            lineState.Action = "action_baseclass"
                            lineState.ActionMandatory = true
                        elseif lineState.Action == "action_baseclass" then
                            if (classAccessTable[tag] == nil) then
                                print("ERROR: baseclass declaration missing access [public/protected/private]. "..LineTableErrString(lineTable))
                                assert(false, "Exiting")
                            end

                            local class_access = tag
                            t = t + 1
                            tag = lineTags[t]

                            if class_access == "public" then
                                table.insert(parseState.ObjectStack[1].BaseClasses, tag)
                            end

                            lineState.Action = "action_baseclasscomma"
                            lineState.ActionMandatory = false
                        elseif lineState.Action == "action_structname" then
                            parseState.ObjectStack[1].Name = tag

                            lineState.Action = nil
                            lineState.ActionMandatory = false

                            enumType = enumType..tag.."::"

                        elseif lineState.Action == "action_enumname" then
                            enumType = enumType..tag
                            parseState.ObjectStack[1].Name = enumType

                            statement_end = true
                            lineState.DataType = enumType
                            lineState.Action = nil
                            lineState.ActionMandatory = false
                        elseif lineState.Action == "action_include" then
                            parseState.ObjectStack[1].Name = tag

                            statement_end = true
                            lineState.Action = nil
                            lineState.ActionMandatory = false
                        elseif lineState.Action == "action_includefile" then
                            parseState.ObjectStack[1].Name = tag

                            statement_end = true
                            lineState.Action = nil
                            lineState.ActionMandatory = false
                        elseif lineState.Action == "action_override_name" then
                            lineState.override_name = tag

                            --statement_end = true
                            lineState.Action = nil
                            lineState.ActionMandatory = false
                        elseif lineState.Action == "action_typedef" then
                            lineState.Name = tag
                            lineState.RValue = {}
                            table.insert(lineState.RValue, tag)

                            lineState.Action = "action_typedefvalue"
                            lineState.ActionMandatory = true
                        elseif lineState.Action == "action_typedefvalue" then
                            --lineState.RValue = SpaceSeparateStrings(lineState.RValue, tag)
                            table.insert(lineState.RValue, tag)

                            lineState.Action = "action_typedefvalue" -- allow more than one word
                            lineState.ActionMandatory = false

                        elseif lineState.Action == "action_rename" then
                            lineState["%rename"] = tag
                            lineState.Action = nil
                            lineState.ActionMandatory = false

                        elseif lineState.Action == "action_define" then
                            lineState.Name = tag
                            -- if they specify a value after the tag use it, unless a keyword
                            while (lineTags[t+1] ~= nil) and (bindingKeywordTable[lineTags[t+1]] == nil) do
                                lineState.Value = (lineState.Value or "")..lineTags[t+1]
                                t = t + 1
                            end

                            statement_end = true
                            lineState.Action = nil
                            lineState.ActionMandatory = false
                        elseif (lineState.Action == "action_define_object") or (lineState.Action == "action_define_pointer") then
                            lineState.Name = tag
                            lineState.DataType = parseState.ObjectStack[1].Name

                            -- If we're at the globals level they should have declared this as
                            -- #define_object wxPoint wxDefaultPosition
                            if (lineState.DataType == "globals") then
                                lineState.DataType = tag
                                lineState.Name = lineTags[t+1]
                                t = t + 1
                            end

                            statement_end = true
                            lineState.Action = nil
                            lineState.ActionMandatory = false
                        elseif lineState.Action == "action_member" then
                            if IsDataType(tag) then
                                lineState.DataType = SpaceSeparateStrings(lineState.DataType, tag)
                                lineState.DataTypeWithAttrib = SpaceSeparateStrings(lineState.DataTypeWithAttrib, tag)

                                lineState.Action = "action_member"
                                lineState.ActionMandatory = true

                            elseif dataTypeAttribTable[tag] then
                                lineState.DataTypeWithAttrib = SpaceSeparateStrings(lineState.DataTypeWithAttrib, tag)

                                lineState.Action = "action_member"
                                lineState.ActionMandatory = true

                            elseif (tag == "*") or (tag == "&") or (tag == "[]") then
                                table.insert(lineState.DataTypePointer, tag)

                                lineState.Action = "action_member"
                                lineState.ActionMandatory = true

                            elseif tag == "static" then
                                lineState.IsStaticFunction = true

                            elseif IsDelimiter(tag) or functionAttribTable[tag] then
                                print("ERROR: Expected Member Name, got Tag='"..tag.."'. "..LineTableErrString(lineTable))
                            else
                                lineState.Name = tag

                                if not lineState.DataType then
                                    print("ERROR: %member requires DataType to be assigned. Tag='"..tag.."'. "..LineTableErrString(lineTable))
                                end

                                lineState.Action = nil
                                lineState.ActionMandatory = false
                            end

                        elseif lineState.Action == "action_method" then
                            if IsDataType(tag) then
                                lineState.DataType = SpaceSeparateStrings(lineState.DataType, tag)
                                lineState.DataTypeWithAttrib = SpaceSeparateStrings(lineState.DataTypeWithAttrib, tag)

                                lineState.Action = "action_method"
                                lineState.ActionMandatory = true

                            elseif dataTypeAttribTable[tag] then
                                lineState.DataTypeWithAttrib = SpaceSeparateStrings(lineState.DataTypeWithAttrib, tag)

                                lineState.Action = "action_method"
                                lineState.ActionMandatory = true

                            elseif (tag == "*") or (tag == "&") or (tag == "[]") then
                                table.insert(lineState.DataTypePointer, tag)

                                lineState.Action = "action_method"
                                lineState.ActionMandatory = true

                            elseif tag == "virtual" then
                                lineState.IsVirtualFunction = true

                            elseif tag == "static" then
                                lineState.IsStaticFunction = true

                            elseif tag == "(" then
                                if lineState.DataType == parseState.ObjectStack[1].Name then
                                    lineState.IsConstructor = true
                                end

                                if lineState.IsConstructor then
                                    if not lineState.Name then
                                        lineState.Name = lineState.DataType
                                    end
                                    lineState.DataType = parseState.ObjectStack[1].Name
                                    lineState.DataTypeWithAttrib = lineState.DataType

                                    if IsDataType(lineState.Name) and (lineState.Name ~= parseState.ObjectStack[1].Name) then
                                        if not IsDataTypeEnum(lineState.Name) then
                                            print("ERROR: Constructor Name ("..lineState.Name..") conflicts with datatype definition. "..LineTableErrString(lineTable))
                                        else
                                            print("WARNING: Constructor Name ("..lineState.Name..") also used by enum definition. "..LineTableErrString(lineTable))
                                        end
                                    end
                                else
                                    print("ERROR: Expected Method Name, got Tag='"..tag.."'. "..LineTableErrString(lineTable))
                                end

                                lineState.Action = "action_methodparam"
                                lineState.ActionMandatory = true

                            elseif IsDelimiter(tag) and (tag ~= "~") then
                                print("ERROR: Expected Method Name, got delimiter Tag='"..tag.."'. "..LineTableErrString(lineTable))
                            elseif tag == "~" then
                                -- do nothing for destructor, skip it.
                                while (lineTags[t] ~= ";") and (lineTags[t] ~= nil) do
                                    t = t + 1
                                end

                                lineState.DefType = nil
                                lineState.Action = nil
                                lineState.ActionMandatory = false
                            else
                                lineState.Name = tag

                                if lineState.IsConstructor then
                                    lineState.DataType = parseState.ObjectStack[1].Name
                                    lineState.DataTypeWithAttrib = lineState.DataType
                                end

                                if not lineState.DataType then
                                    print("ERROR: Method requires DataType to be assigned. Tag='"..tag.."'. "..LineTableErrString(lineTable))
                                end

                                if (lineTags[t+1] == ";") or (lineTags[t+1] == "=") then

                                    t = t + 1
                                    tag = lineTags[t]

                                    if tag == "=" then
                                        while (lineTags[t+1] ~= ";") and (lineTags[t+1] ~= nil) do
                                            t = t + 1
                                        end
                                        tag = lineTags[t]
                                    end

                                    lineState.DefType = "deftype_%member"
                                    lineState.Action = nil
                                    lineState.ActionMandatory = false

                                    statement_end = true

                                    if  (parseState.ObjectStack[1].Name == "globals") then
                                        lineState.DefType = "deftype_#define"
                                    elseif (parseState.ObjectStack[1].ObjType ~= "objtype_class") and (parseState.ObjectStack[1].ObjType ~= "objtype_struct") then
                                        print("ERROR: %member is not used for a class or struct. "..LineTableErrString(lineTable))
                                    end

                                else

                                    lineState.Action = "action_methodbracket"
                                    lineState.ActionMandatory = true

                                end
                            end

                        elseif lineState.Action == "action_methodbracket" then

                                if tag ~= "(" then
                                    local msg = "(Name="..tostring(lineState.Name).."; DataType="..tostring(lineState.DataType)..")"
                                    print("ERROR: Expected Method Tag '(', got Tag='"..tag.."'. "..msg.." "..LineTableErrString(lineTable))
                                end

                                if parseState.ObjectStack[1].Name == "globals" then
                                    lineState["%function"] = true
                                end

                                lineState.IsFunction = true
                                lineState.Action = "action_methodparam"
                                lineState.ActionMandatory = true

                        elseif lineState.Action == "action_methodparam" then
                            lineState.IsFunction = true

                            if IsDataType(tag) then
                                lineState.ParamState.DataType = SpaceSeparateStrings(lineState.ParamState.DataType, tag)
                                lineState.ParamState.DataTypeWithAttrib = SpaceSeparateStrings(lineState.ParamState.DataTypeWithAttrib, tag)

                                lineState.Action = "action_methodparam"
                                lineState.ActionMandatory = true

                            elseif dataTypeAttribTable[tag] then
                                lineState.ParamState.DataTypeWithAttrib = SpaceSeparateStrings(lineState.ParamState.DataTypeWithAttrib, tag)

                                lineState.Action = "action_methodparam"
                                lineState.ActionMandatory = true

                            elseif (tag == "*") or (tag == "&") or (tag == "[]") then
                                table.insert(lineState.ParamState.DataTypePointer, tag)

                                lineState.Action = "action_methodparam"
                                lineState.ActionMandatory = true

                            elseif tag == "," then
                                if not lineState.ParamState.DataType then
                                    print("ERROR: Method Parameter requires DataType to be assigned. "..LineTableErrString(lineTable))
                                end

                                table.insert(lineState.Params, lineState.ParamState)
                                lineState.ParamState = AllocParam()

                                lineState.Action = "action_methodparam"
                                lineState.ActionMandatory = true

                            elseif tag == ")" then
                                if lineState.ParamState.DataType then
                                    InsertParamState(lineState.Params, lineState.ParamState)
                                    lineState.ParamState = AllocParam()
                                end

                                lineState.Action = "action_method_body"
                                lineState.ActionMandatory = false

                            elseif tag == "=" then

                                lineState.Action = "action_methodparam_defaultvalue"
                                lineState.ActionMandatory = true

                            elseif IsDelimiter(tag) or functionAttribTable[tag] then
                                print("ERROR: Expected Method Param Name, got Tag='"..tag.."'. "..LineTableErrString(lineTable))
                            else
                                lineState.ParamState.Name = tag

                                lineState.Action = "action_methodparam_paramdelimiter"
                                lineState.ActionMandatory = true
                            end

                        elseif lineState.Action == "action_methodparam_defaultvalue" then
                            if tag == "," then
                                if not lineState.ParamState.DefaultValue then
                                    print("ERROR: Method Parameter requires DefaultValue to be assigned. "..LineTableErrString(lineTable))
                                end

                                if not lineState.ParamState.DataType then
                                    print("ERROR: Method Parameter requires DataType to be assigned. "..LineTableErrString(lineTable))
                                end

                                InsertParamState(lineState.Params, lineState.ParamState)
                                lineState.ParamState = AllocParam()

                                lineState.Action = "action_methodparam"
                                lineState.ActionMandatory = true

                            elseif tag == ")" then
                                if not lineState.ParamState.DefaultValue then
                                    print("ERROR: Method Parameter requires DefaultValue to be assigned. "..LineTableErrString(lineTable))
                                end

                                InsertParamState(lineState.Params, lineState.ParamState)
                                lineState.ParamState = AllocParam()

                                lineState.Action = "action_method_body"
                                lineState.ActionMandatory = false
                            elseif --IsDataType(tag) or
                                   dataTypeAttribTable[tag] or functionAttribTable[tag] or
                                   (tag == "*") or (tag == "&") or (tag == "[]") or
                                   IsDelimiter(tag) and (tag ~= "|") and (tag ~= "&") then
                                print("ERROR: Expected Parameter Default Value, got Tag='"..tag.."'. "..LineTableErrString(lineTable))
                            else
                                lineState.ParamState.DefaultValue = SpaceSeparateStrings(lineState.ParamState.DefaultValue, tag)

                                lineState.Action = "action_methodparam_defaultvalue"
                                lineState.ActionMandatory = true
                            end

                        elseif lineState.Action == "action_methodparam_paramdelimiter" then
                            if tag == "," then
                                if not lineState.ParamState.DataType then
                                    print("ERROR: Method Parameter requires DataType to be assigned. "..LineTableErrString(lineTable))
                                end

                                InsertParamState(lineState.Params, lineState.ParamState)
                                lineState.ParamState = AllocParam()

                                lineState.Action = "action_methodparam"
                                lineState.ActionMandatory = true
                            elseif tag == ")" then
                                InsertParamState(lineState.Params, lineState.ParamState)
                                lineState.ParamState = AllocParam()

                                lineState.Action = "action_method_body"
                                lineState.ActionMandatory = false

                            elseif tag == "=" then
                                lineState.Action = "action_methodparam_defaultvalue"
                                lineState.ActionMandatory = true

                            elseif tag == "[]" then
                                table.insert(lineState.ParamState.DataTypePointer, tag)

                                lineState.Action = "action_methodparam_paramdelimiter"
                                lineState.ActionMandatory = true

                            else
                                local msg = "(Name="..tostring(lineState.ParamState.Name)..
                                            "; DataType="..tostring(lineState.ParamState.DataType)..")"
                                print("ERROR: Expected Parameter '=', ')', or ',' got Tag='"..tag.."'. "..msg.." "..LineTableErrString(lineTable))
                            end

                        elseif lineState.Action == "action_method_body" then
                            if tag == "const" then
                                lineState.IsConstFunction = true

                                lineState.Action = "action_method_body"
                                lineState.ActionMandatory = false

                            elseif tag == "=" then
                                lineState.IsPureVirtualFunction = true
                                parseState.ObjectStack[1]["%abstract"] = true

                                statement_end = true;
                                t = t + 1
                                while (lineTags[t+1] ~= ";") and (lineTags[t+1] ~= nil) do
                                    t = t + 1
                                end

                                -- junk rest of line
                                lineState.Action = nil
                                lineState.ActionMandatory = false

                                lineState.Skip = true

                            elseif (tag == "{") or (tag == ";") then
                                -- junk rest of line
                                lineState.Action = nil
                                lineState.ActionMandatory = false

                                lineState.Skip = true

                                if true or (tag == ";") then
                                    statement_end = true
                                end
                            else
                                print("ERROR: Expected Parameter 'const', '=', ';', or '{' got Tag='"..tag.."'. "..LineTableErrString(lineTable))
                            end
                        end
                    end
                end
            end -- elseif parseState.IsBlockComment == 0 then

        if (lineTags[t] ~= ",") and (lineTags[t+1] == nil) then
            statement_end = true
        end

        if statement_end then
            statement_end = false

            --TableDump(lineState, "statement_end ")

        -- set line definition data
        if lineState.DefType == "deftype_typedef" then
            -- line is in the form: typedef [unsigned int] wxUInt32
            local typedef_name = lineState.RValue[#lineState.RValue]
            local typedef_type = table.concat(lineState.RValue, " ", 1, #lineState.RValue-1)

            typedefTable[typedef_name] = typedef_type

        elseif lineState.DefType == "deftype_#if" then
            -- line is a block condition, push onto condition stack
            table.insert(parseState.ConditionStack, lineState.Condition)

        elseif (lineState.DefType == "deftype_%member") or (lineState.DefType == "deftype_%member_func") then
            table.insert(parseState.ObjectStack[1].Members, AllocMember(lineState, BuildCondition(parseState.ConditionStack)))

        elseif lineState.DefType == "deftype_#define" then
            table.insert(parseState.ObjectStack[1].Members, AllocMember(lineState, BuildCondition(parseState.ConditionStack)))

        elseif lineState.DefType == "deftype_#define_string" then
            table.insert(parseState.ObjectStack[1].Members, AllocMember(lineState, BuildCondition(parseState.ConditionStack)))

        elseif lineState.DefType == "deftype_#define_wxstring" then
            table.insert(parseState.ObjectStack[1].Members, AllocMember(lineState, BuildCondition(parseState.ConditionStack)))

        elseif lineState.DefType == "deftype_%wxEventType" then
            table.insert(parseState.ObjectStack[1].Members, AllocMember(lineState, BuildCondition(parseState.ConditionStack)))

        elseif lineState.DefType == "deftype_#define_object" then
            table.insert(parseState.ObjectStack[1].Members, AllocMember(lineState, BuildCondition(parseState.ConditionStack)))

        elseif lineState.DefType == "deftype_#define_pointer" then
            table.insert(parseState.ObjectStack[1].Members, AllocMember(lineState, BuildCondition(parseState.ConditionStack)))

        elseif lineState.DefType == "deftype_method" then
            table.insert(parseState.ObjectStack[1].Members, AllocMember(lineState, BuildCondition(parseState.ConditionStack)))
        end

        -- line is an object declaration
        if lineState.ParseObjectDeclaration then
            -- push inline condition onto condition stack
            if not lineState.IsBlockCondition and lineState.Condition then
                table.insert(parseState.ConditionStack, 1, lineState.Condition)
            end

            -- Set Parse Object Condition
            parseState.ObjectStack[1].Condition = BuildCondition(parseState.ConditionStack)

            -- Set Condition for DataType
            if dataTypeTable[parseState.ObjectStack[1].Name] and parseState.ObjectStack[1].Condition then
                dataTypeTable[parseState.ObjectStack[1].Name].Condition = parseState.ObjectStack[1].Condition
            end

            -- pop inline condition onto condition stack
            if not lineState.IsBlockCondition and lineState.Condition then
                table.remove(parseState.ConditionStack, 1)
            end
        end

        -- pop parseObject off objectStack
        if lineState.PopParseObject then
            EndObjectStack(objectList, parseState, lineState)

            --TableDump(parseState.ObjectStack, "PPO-parseState.ObjectStack")
            --TableDump(lineState,              "PPO-lineState")
            --TableDump(objectList,             "PPO-objectList")

            if #parseState.ObjectStack == 0 then
                print("ERROR: parseState.ObjectStack is unexpectedly empty. "..LineTableErrString(lineTable))
            end
        end

        lineState = nil --AllocLineState(lineTable) -- reset to new

        end -- if statement_end then

        end -- while lineTags[t+1] do

    end -- while interfaceData[l+1] do


    -- pop globals parseObject that was put in first
    EndObjectStack(objectList, parseState, lineState)

    if #parseState.ObjectStack ~= 0 then
        print("ERROR: parseState.ObjectStack should be empty, has "..#parseState.ObjectStack.." items left.")
        TableDump(parseState.ObjectStack, "parseState.ObjectStack")
        TableDump(lineState, "lineState")
        TableDump(objectList, "objectList")
        assert(false)
    end

    return objectList
end

-- ---------------------------------------------------------------------------
-- Make a variable from a data type that may contain namespace::var and
--   convert it to namespace_var
-- ---------------------------------------------------------------------------
function MakeVar(type)
    local split = SplitString(type, { "::" })

    local var = split[1]
    for i = 2, #split do
        var = var.."_"..split[i]
    end

    return var
end

-- ---------------------------------------------------------------------------
-- Make a variable from a data type
-- ---------------------------------------------------------------------------
function MakeClassVar(datatype)
    local vartype = datatype

    -- use underlying TypeDef DataType?
    if  typedefTable[datatype] then
        local type = GetDataTypeOnly(typedefTable[datatype])
        if type and dataTypeTable[type] then
            vartype = type
        end
    end

    return MakeVar(vartype)
end

-- ---------------------------------------------------------------------------
-- If output_cpp_impexpdatasymbol is set, return output_cpp_impexpdatasymbol(data_type)
-- ---------------------------------------------------------------------------
function MakeImpExpData(data_type)
    if output_cpp_impexpdatasymbol and (string.len(output_cpp_impexpdatasymbol) > 0) then
        return output_cpp_impexpdatasymbol.."("..data_type..")"
    end
    return data_type
end

-- ---------------------------------------------------------------------------
-- Remove the code line wxLuaState wxlState(L); if it won't be used.
-- ---------------------------------------------------------------------------

function RemovewxLuaStateIfNotUsed(codeList)
    -- remove the wxLuaState if we don't use it
    local needs_wxluastate = -1
    for i = 1, #codeList do
        if string.find(codeList[i], "wxLuaState wxl", 1, 1) then
            needs_wxluastate = i
        elseif string.find(codeList[i], "wxlState", 1, 1) then
            needs_wxluastate = -1
            break
        end
    end
    if (needs_wxluastate > 0) then
        table.remove(codeList, needs_wxluastate)
    end
end

-- ---------------------------------------------------------------------------
-- Create Language Binding - This generates c-binding to Lua interpreter
-- ---------------------------------------------------------------------------
function GenerateLuaLanguageBinding(interface)
    local overloadCount = {} -- overloadCount[methodName] = count #

    for o = 1, #interface.objectData do
        local parseObject = interface.objectData[o]

        -- -------------------------------------------------------------------
        -- de-duplicates include references, must generate them first, no .Members
        if parseObject.ObjType == "objtype_#include" then

            local includecondition = FixCondition(parseObject.Condition)
            local includeBinding =
            {
                Include   = "#include ".. parseObject.Name.."\n",
                Condition = includecondition
            }

            if not interface.includeBindingTable[includecondition] then
                interface.includeBindingTable[includecondition] = {}
            end

            interface.includeBindingTable[includecondition][parseObject.Name] = includeBinding
        elseif parseObject.ObjType == "objtype_%includefile" then
            table.insert(interface.includeFiles, parseObject.Name)
        end

        -- parseObject member binding
        for m = 1, #parseObject.Members do
            local member = parseObject.Members[m]

            local fullcondition = FixCondition(AddCondition(member.Condition, member.ExtraCondition))

            -- ---------------------------------------------------------------
            -- member binding
            -- ---------------------------------------------------------------
            if (member.DefType == "deftype_%member") or (member.DefType == "deftype_%member_func") then
                local memberType    = member.DataType
                local memberGetFunc = "Get_"..member.Name
                local memberSetFunc = "Set_"..member.Name
                if member["%rename"] then
                    memberGetFunc = "Get"..member["%rename"]
                    memberSetFunc = "Set"..member["%rename"]
                end

                local funcType = "WXLUAMETHOD_METHOD"
                local propType = ""
                if member.IsStaticFunction then
                    funcType = "WXLUAMETHOD_METHOD|WXLUAMETHOD_STATIC"
                    propType = "|WXLUAMETHOD_STATIC"
                end

                local memberPtr = member.DataTypePointer[1]
                local indirectionCount = #member.DataTypePointer
                local numeric = IsDataTypeNumeric(member.DataType)

                -- conditions for member are dependent on return type, argument types, and inline conditions
                local dependConditions = {}

                if HasCondition(fullcondition) then
                    dependConditions[fullcondition] = fullcondition
                end

                local returnCondition = GetDataTypeCondition(member.DataType)
                if returnCondition then
                    dependConditions[returnCondition] = returnCondition
                end

                -- build member condition
                local membercondition = nil
                for idx, condition in pairs_sort(dependConditions) do
                    membercondition = AddCondition(membercondition, condition)
                end
                membercondition = FixCondition(membercondition)

                -- GET MEMBER CODE
                local codeList = {}
                local overload_argList = ""
                local funcName = "wxLua_"..MakeVar(parseObject.Name).."_"..memberGetFunc
                CommentBindingTable(codeList, "// "..interface.lineData[member.LineNumber].LineText.."\n")
                table.insert(codeList, "static int LUACALL "..funcName.."(lua_State *L)\n{\n")

                local self_name = "self->"
                if member.IsStaticFunction then
                    self_name = parseObject.Name.."::"
                else
                    CommentBindingTable(codeList, "    // get this\n")
                    table.insert(codeList, "    "..parseObject.Name.." *self = ("..parseObject.Name.." *)wxluaT_getuserdatatype(L, 1, wxluatype_"..MakeClassVar(parseObject.Name)..");\n")
                    overload_argList = "&wxluatype_"..MakeClassVar(parseObject.Name)..", "..overload_argList
                end

                if memberType == "wxString" then
                    CommentBindingTable(codeList, "    // push the result string\n")
                    table.insert(codeList, "    wxlua_pushwxString(L, "..self_name..member.Name..");\n")
                elseif not numeric and (not memberPtr or (memberPtr == "&")) then
                    CommentBindingTable(codeList, "    // push the result datatype\n")

--                    if string.find(member.Name, "::") then
--                        table.insert(codeList, "    wxluaT_pushuserdatatype(L, "..member.Name..", wxluatype_"..MakeClassVar(memberType)..");\n")
--                    else
                        table.insert(codeList, "    wxluaT_pushuserdatatype(L, &"..self_name..member.Name..", wxluatype_"..MakeClassVar(memberType)..");\n")
--                    end
                elseif not numeric then
                    CommentBindingTable(codeList, "    // push the result datatype\n")
                    table.insert(codeList, "    wxluaT_pushuserdatatype(L, "..self_name..member.Name..", wxluatype_"..MakeClassVar(memberType)..");\n")

                elseif IsDataTypeBool(memberType) then
                    CommentBindingTable(codeList, "    // push the result flag\n")
                    table.insert(codeList, "    lua_pushboolean(L, "..self_name..member.Name..");\n")

                elseif IsDataTypeFloat(memberType) then
                    CommentBindingTable(codeList, "    // push the result floating point number\n")
                    table.insert(codeList, "    lua_pushnumber(L, "..self_name..member.Name..");\n")
                else
                    local val = self_name..member.Name
                    CommentBindingTable(codeList, "    // push the result integer? number\n")
                    table.insert(codeList, ([[
#if LUA_VERSION_NUM >= 503
if ((double)(lua_Integer)(%s) == (double)(%s)) {
    // Exactly representable as lua_Integer
    lua_pushinteger(L, %s);
} else
#endif
{
    lua_pushnumber(L, %s);
}
]]):format(val, val, val, val))
                end

                CommentBindingTable(codeList, "    // return the number of values\n")
                table.insert(codeList, "    return 1;\n")
                table.insert(codeList, "}\n")

                local overload_argListName = "s_wxluatypeArray_"..funcName
                if overload_argList == "" then
                    overload_argListName = "g_wxluaargtypeArray_None"
                else
                    overload_argList = "{ "..overload_argList.."NULL }"
                end

                RemovewxLuaStateIfNotUsed(codeList)

                local funcMapName = "s_wxluafunc_"..funcName

                -- bind method
                local methodBinding =
                {
                    LuaName       = memberGetFunc,
                    CFunctionName = funcName,
                    Method        = codeList,
                    ArgArray      = overload_argList,
                    ArgArrayName  = overload_argListName,
                    FuncType      = funcType,
                    FuncMap       = "{ "..funcName..", "..funcType..", 1, 1, "..overload_argListName.." }",
                    FuncMapName   = funcMapName,
                    Map           = "    { \""..memberGetFunc.."\", "..funcType..", "..funcMapName..", 1, NULL },\n",
                    Condition     = membercondition
                }

                -- bind property
                local propertyBinding =
                {
                    LuaName   = member.Name,
                    FuncType  = "WXLUAMETHOD_GETPROP"..propType,
                    Map       = "    { \""..member.Name.."\", WXLUAMETHOD_GETPROP"..propType..", "..funcMapName..", 1, NULL },\n",
                    Condition = membercondition
                }

                -- Override Generated Method Code
                if overrideTable[methodBinding.CFunctionName] then
                    methodBinding.Method = overrideTable[methodBinding.CFunctionName]
                    overrideTableUsed[methodBinding.CFunctionName] = true
                end

                -- rem out the Get function if not %member_func, but we need the code for the property
                if member.DefType == "deftype_%member" then
                    methodBinding.Map = "    // %member"..methodBinding.Map
                end

                table.insert(interface.objectData[o].BindTable, methodBinding)
                table.insert(interface.objectData[o].BindTable, propertyBinding)

                -- SET MEMBER CODE, not for const members
                if not string.find(member.DataTypeWithAttrib, "const ", 1, 1) then

                codeList = {}
                overload_argList = ""
                local funcName = "wxLua_"..MakeVar(parseObject.Name).."_"..memberSetFunc
                CommentBindingTable(codeList, "// "..interface.lineData[member.LineNumber].LineText.."\n")
                table.insert(codeList, "static int LUACALL "..funcName.."(lua_State *L)\n{\n")

                local stack_idx = iff(member.IsStaticFunction, "1", "2")

                if memberType == "wxString" then
                    overload_argList = overload_argList.."&wxluatype_TSTRING, "
                    CommentBindingTable(codeList, "    // get the string value\n")
                    table.insert(codeList, "    wxString val = wxlua_getwxStringtype(L, "..stack_idx..");\n")
                elseif not numeric and (not memberPtr or (memberPtr == "&"))  then
                    overload_argList = overload_argList.."&wxluatype_"..MakeClassVar(memberType)..", "
                    CommentBindingTable(codeList, "    // get the data type value\n")
                    table.insert(codeList, "    "..memberType.."* val = ("..memberType.."*)wxluaT_getuserdatatype(L, "..stack_idx..", wxluatype_"..MakeClassVar(memberType)..");\n")
                elseif not numeric then
                    overload_argList = overload_argList.."&wxluatype_"..MakeClassVar(memberType)..", "
                    CommentBindingTable(codeList, "    // get the data type value\n")
                    table.insert(codeList, "    "..memberType.."* val = ("..memberType.."*)wxluaT_getuserdatatype(L, "..stack_idx..", wxluatype_"..MakeClassVar(memberType)..");\n")
                elseif IsDataTypeBool(memberType) then
                    overload_argList = overload_argList.."&wxluatype_TBOOLEAN, "
                    CommentBindingTable(codeList, "    // get the boolean value\n")
                    table.insert(codeList, "    bool val = wxlua_getbooleantype(L, "..stack_idx..");\n")
                elseif IsDataTypeEnum(memberType) then
                    overload_argList = overload_argList.."&wxluatype_TINTEGER, "
                    CommentBindingTable(codeList, "    // get the enum value\n")
                    table.insert(codeList, "    "..memberType.." val = ("..memberType..")wxlua_getenumtype(L, "..stack_idx..");\n")
                elseif IsDataTypeUInt(memberType) then
                    overload_argList = overload_argList.."&wxluatype_TINTEGER, "
                    CommentBindingTable(codeList, "    // get the unsigned integer value\n")
                    table.insert(codeList, "    "..memberType.." val = ("..memberType..")wxlua_getuintegertype(L, "..stack_idx..");\n")
                else
                    overload_argList = overload_argList.."&wxluatype_TNUMBER, "
                    CommentBindingTable(codeList, "    // get the number value\n")
                    table.insert(codeList, "    "..memberType.." val = ("..memberType..")wxlua_getnumbertype(L, "..stack_idx..");\n")
                end

                if member.IsStaticFunction then
                    if not numeric and (not memberPtr or (memberPtr == "&"))  then
                        table.insert(codeList, "    "..parseObject.Name.."::"..member.Name.." = *val;\n")
                    else
                        table.insert(codeList, "    "..parseObject.Name.."::"..member.Name.." = val;\n")
                    end
                else
                    CommentBindingTable(codeList, "    // get this\n")
                    table.insert(codeList, "    "..parseObject.Name.." *self = ("..parseObject.Name.." *)wxluaT_getuserdatatype(L, 1, wxluatype_"..MakeClassVar(parseObject.Name)..");\n")
                    overload_argList = "&wxluatype_"..MakeClassVar(parseObject.Name)..", "..overload_argList

                    if not numeric and (not memberPtr or (memberPtr == "&"))  then
                        table.insert(codeList, "    self->"..member.Name.." = *val;\n")
                    else
                        table.insert(codeList, "    self->"..member.Name.." = val;\n")
                    end
                end

                CommentBindingTable(codeList, "    // return the number of values\n")
                table.insert(codeList, "    return 0;\n")
                table.insert(codeList, "}\n")

                local overload_argListName = "s_wxluatypeArray_".. funcName
                if overload_argList == "" then
                    overload_argListName = "g_wxluaargtypeArray_None"
                else
                    overload_argList = "{ "..overload_argList.."NULL }"
                end

                RemovewxLuaStateIfNotUsed(codeList)

                local funcMapName = "s_wxluafunc_"..funcName

                -- bind method
                local methodBinding =
                {
                    LuaName       = memberSetFunc,
                    CFunctionName = funcName,
                    Method        = codeList,
                    ArgArray      = overload_argList,
                    ArgArrayName  = overload_argListName,
                    FuncType      = funcType,
                    FuncMap       = "{ "..funcName..", "..funcType..", 2, 2, "..overload_argListName.." }", -- FIXME make sure this is right
                    FuncMapName   = funcMapName,
                    Map           = "    { \""..memberSetFunc.."\", "..funcType..", "..funcMapName..", 1, NULL },\n",
                    Condition     = membercondition
                }

                -- bind property
                local propertyBinding =
                {
                    LuaName   = member.Name,
                    FuncType  = "WXLUAMETHOD_SETPROP"..propType,
                    Map       = "    { \""..member.Name.."\", WXLUAMETHOD_SETPROP"..propType..", "..funcMapName..", 1, NULL },\n",
                    Condition = membercondition
                }

                -- Override Generated Method Code
                if overrideTable[methodBinding.CFunctionName] then
                    methodBinding.Method = overrideTable[methodBinding.CFunctionName]
                    overrideTableUsed[methodBinding.CFunctionName] = true
                end

                -- rem out the Set function if not %member_func, but we need the code for the property
                if member.DefType == "deftype_%member" then
                    methodBinding.Map = "    // %member"..methodBinding.Map
                end

                table.insert(interface.objectData[o].BindTable, methodBinding)
                table.insert(interface.objectData[o].BindTable, propertyBinding)

                end
            -- ---------------------------------------------------------------
            -- enum binding
            -- ---------------------------------------------------------------
            elseif member.DefType == "deftype_enum" then
                -- if we have wxDateTime::TZ, only take the wxDateTime part
                local dataType = member.DataType or ""
                local namespace = ""
                local luaname = member["%rename"] or member.Name -- for %rename
                local classname = ""
                local enumname = luaname

                local pos = string.find(dataType, "::", 1, 1)
                if pos then
                    -- search for last ::, eg. ns1::ns2::enumName -> ns1::ns2 is namespace
                    classname = string.sub(dataType, 0, pos - 1)
                    while pos do
                        local p = string.find(dataType, "::", pos+2, 1)
                        if p then pos = p else break end
                    end

                    namespace = string.sub(dataType, 0, pos - 1)
                    if not member["%rename"] then
                        luaname = MakeVar(namespace).."_"..luaname -- wxFile::read -> wxFile_read
                    end

                    namespace = namespace.."::"
                end

                if (string.len(classname) > 0) then
                    if not enumClassBindingTable[classname] then
                        enumClassBindingTable[classname] = {}
                    end

                    local enumBinding =
                    {
                        LuaName   = enumname,
                        Map       = "        { \""..enumname.."\", "..namespace..member.Name.." },\n",
                        Condition = fullcondition
                    }

                    table.insert(enumClassBindingTable[classname], enumBinding)
                else
                    local enumBinding =
                    {
                        LuaName   = luaname,
                        Map       = "        { \""..luaname.."\", "..namespace..member.Name.." },\n",
                        Condition = fullcondition
                    }

                    table.insert(enumBindingTable, enumBinding)
                end

            -- ---------------------------------------------------------------
            -- #define binding
            -- ---------------------------------------------------------------
            elseif member.DefType == "deftype_#define" then
                local luaname = member["%rename"] or member.Name -- for %rename
                local value = member.Value or member.Name

                local defineBinding =
                {
                    LuaName   = luaname,
                    Map       = "        { \""..luaname.."\", "..value.." },\n",
                    Condition = fullcondition
                }

                table.insert(defineBindingTable, defineBinding)

            -- ---------------------------------------------------------------
            -- #define_string binding
            -- ---------------------------------------------------------------
            elseif member.DefType == "deftype_#define_string" then
                local luaname = member["%rename"] or member.Name -- for %rename
                local value = member.Value or member.Name

                local stringBinding =
                {
                    LuaName   = luaname,
                    Map       = "        { \""..luaname.."\", "..value..", NULL },\n",
                    Condition = fullcondition
                }

                table.insert(stringBindingTable, stringBinding)

            -- ---------------------------------------------------------------
            -- #define_wxstring binding
            -- ---------------------------------------------------------------
            elseif member.DefType == "deftype_#define_wxstring" then
                local luaname = member["%rename"] or member.Name -- for %rename
                local value = member.Value or member.Name

                local stringBinding =
                {
                    LuaName   = luaname,
                    Map       = "        { \""..luaname.."\", NULL, "..value.." },\n",
                    Condition = fullcondition
                }

                table.insert(stringBindingTable, stringBinding)

            -- ---------------------------------------------------------------
            -- #define_object binding
            -- ---------------------------------------------------------------
            elseif member.DefType == "deftype_#define_object" then
                local luaname = member["%rename"] or member.Name -- for %rename

                local objectBinding =
                {
                    LuaName   = luaname,
                    Map       = "        { \""..luaname.."\", &wxluatype_"..MakeClassVar(member.DataType)..", &"..member.Name..", NULL },\n",
                    Condition = fullcondition
                }

                table.insert(objectBindingTable, objectBinding)

            -- ---------------------------------------------------------------
            -- #define_pointer binding
            -- ---------------------------------------------------------------
            elseif member.DefType == "deftype_#define_pointer" then
                local luaname = member["%rename"] or member.Name -- for %rename

                local pointerBinding =
                {
                    LuaName   = luaname,
                    Map       = "        { \""..luaname.."\", &wxluatype_"..MakeClassVar(parseObject.Name)..", NULL, (const void **) &"..member.Name.." },\n",
                    Condition = fullcondition
                }

                table.insert(pointerBindingTable, pointerBinding)

            -- ---------------------------------------------------------------
            -- %wxEventType binding
            -- ---------------------------------------------------------------
            elseif member.DefType == "deftype_%wxEventType" then
                local luaname = member["%rename"] or member.Name -- for %rename

                local eventBinding =
                {
                    LuaName   = luaname,
                    Map       = "        { \""..luaname.."\", WXLUA_GET_wxEventType_ptr("..member.Name.."), &wxluatype_"..MakeClassVar(parseObject.Name).." },\n",
                    Condition = fullcondition
                }

                table.insert(eventBindingTable, eventBinding)

            -- ---------------------------------------------------------------
            -- method binding
            -- ---------------------------------------------------------------
            elseif member.DefType == "deftype_method" then
                local argList = ""
                local overload_argList = ""
                local gcList = {}

                local arg = 0

                if (member["%operator"] == "++") and (#member.Params > 0) then
                    member.Name = "op_preinc"
                    member.Params = {}
                elseif (member["%operator"] == "--") and (#member.Params > 0) then
                    member.Name = "op_predec"
                    member.Params = {}
                elseif (member["%operator"] == "*") and (#member.Params == 0) then
                    member.Name = "op_deref"
                    member.Params = {}
                end

                while member.Params[arg+1] do
                    arg = arg + 1
                    local param = member.Params[arg]

                    -- See if we're supposed to track or untrack the parameter
                    local a = string.find(param.DataTypeWithAttrib, "%gc", 1, 1)
                    if a then
                        param.DataTypeWithAttrib = string.sub(param.DataTypeWithAttrib, 1, a-1)..string.sub(param.DataTypeWithAttrib, a+4)
                        param.GC = true
                    end
                    local a = string.find(param.DataTypeWithAttrib, "%ungc", 1, 1)
                    if a then
                        param.DataTypeWithAttrib = string.sub(param.DataTypeWithAttrib, 1, a-1)..string.sub(param.DataTypeWithAttrib, a+6)
                        param.UnGC = true
                    end
                    local a = string.find(param.DataTypeWithAttrib, "%IncRef", 1, 1)
                    if a then
                        param.DataTypeWithAttrib = string.sub(param.DataTypeWithAttrib, 1, a-1)..string.sub(param.DataTypeWithAttrib, a+8)
                        param.IncRef = true
                    end

                    local declare = nil
                    local argType = param.DataType
                    local argTypeWithAttrib = param.DataTypeWithAttrib
                    local argPtr = param.DataTypePointer[1]
                    local argName = param.Name
                    local argNum = nil
                    local opt = param.DefaultValue
                    local numeric = IsDataTypeNumeric(param.DataType)

                    if member.IsConstructor or member["%function"] or member.IsStaticFunction then
                        argNum = arg -- don't have self
                    else
                        argNum = arg + 1
                    end

                    if not argName then
                        argName = "arg"..arg

                        param.Name = argName
                    end

                    if arg > 1 then
                        argList = argList..", "
                    end

                    local indirectionCount = #param.DataTypePointer

                    local isTranslated = nil
                    local origArgType =  argType
                    local origArgTypeWithAttrib = argTypeWithAttrib
                    local origArgPtr = argPtr
                    local origIndirectionCount = indirectionCount
                    local argCast = nil
                    local argListOverride = nil

                    -- Does DataType need to be translated from typeDef
                    TranslateDataType(param)
                    if #param.TypedDataTypePointer ~= indirectionCount then
                        indirectionCount = #param.TypedDataTypePointer

                        -- translated datatype
                        argType = param.TypedDataType
                        argTypeWithAttrib = param.TypedDataTypeWithAttrib
                        argPtr = param.TypedDataTypePointer[1]

                        isTranslated = true
                    end

                    -- the function takes (void*), but we just pass a long
                    if argType == "voidptr_long" then
                        argType = "wxUIntPtr"
                        argTypeWithAttrib = "wxUIntPtr"
                        argCast = "void*"
                    end

                    -- our special notation to get wxString/IntArray from a Lua table of strings
                    -- BUT! it has to be const wxArrayString& arr or wxArrayString arr
                    --      and NOT wxArrayString& arr or wxArrayString* arr
                    if ((argType == "wxArrayString") and
                        ((indirectionCount == 0) or
                         ((indirectionCount == 1) and (argPtr == "&") and string.find(argTypeWithAttrib, "const", 1, 1)))) then
                        overload_argList = overload_argList.."&wxluatype_wxArrayString, "
                        argItem = "wxlua_getwxArrayString(L, "..argNum..")"
                        declare = "wxLuaSmartwxArrayString"
                    elseif ((argType == "wxSortedArrayString") and
                        ((indirectionCount == 0) or
                         ((indirectionCount == 1) and (argPtr == "&") and string.find(argTypeWithAttrib, "const", 1, 1)))) then
                        overload_argList = overload_argList.."&wxluatype_wxSortedArrayString, "
                        argItem = "wxlua_getwxSortedArrayString(L, "..argNum..")"
                        declare = "wxLuaSmartwxSortedArrayString"
                    elseif ((argType == "wxArrayInt") and
                            ((indirectionCount == 0) or
                             ((indirectionCount == 1) and (argPtr == "&") and string.find(argTypeWithAttrib, "const", 1, 1)))) then
                        overload_argList = overload_argList.."&wxluatype_wxArrayInt, "
                        argItem = "wxlua_getwxArrayInt(L, "..argNum..")"
                        declare = "wxLuaSmartwxArrayInt"
                    elseif ((argType == "wxArrayDouble") and
                            ((indirectionCount == 0) or
                             ((indirectionCount == 1) and (argPtr == "&") and string.find(argTypeWithAttrib, "const", 1, 1)))) then
                        overload_argList = overload_argList.."&wxluatype_wxArrayDouble, "
                        argItem = "wxlua_getwxArrayDouble(L, "..argNum..")"
                        declare = "wxLuaSmartwxArrayDouble"
                    elseif argType == "IntArray_FromLuaTable" then
                        overload_argList = overload_argList.."&wxluatype_TTABLE, "
                        argItem = "NULL; ptr = "..argName.." = wxlua_getintarray(L, "..argNum..", count_)"
                        declare = "int count_ = 0; wxLuaSmartIntArray ptr; int*"
                        argList = argList.."count_, "

                    elseif (argType == "wxPointArray_FromLuaTable") then
                        overload_argList = overload_argList.."&wxluatype_TTABLE, "
                        argItem = "wxlua_getwxPointArray(L, "..argNum..")"
                        declare = "wxLuaSharedPtr<std::vector<wxPoint> >"
                        argListOverride = "(int)("..argName.." ? "..argName.."->size() : 0), ("..argName.." && (!"..argName.."->empty())) ? &"..argName .. "->at(0) : NULL"

                    elseif (argType == "wxPoint2DDoubleArray_FromLuaTable") then
                        overload_argList = overload_argList.."&wxluatype_TTABLE, "
                        argItem = "wxlua_getwxPoint2DDoubleArray(L, "..argNum..")"
                        declare = "wxLuaSharedPtr<std::vector<wxPoint2DDouble> >"
                        argListOverride = "(size_t)("..argName.." ? "..argName.."->size() : 0), ("..argName.." && (!"..argName.."->empty())) ? &"..argName .. "->at(0) : NULL"

                    elseif argType == "LuaTable" then
                        -- THIS MUST BE AN OVERRIDE AND HANDLED THERE, we just set overload_argList
                        -- the code genererated here is nonsense
                        overload_argList = overload_argList.."&wxluatype_TTABLE, "
                        argItem = "YOU MUST OVERRIDE THIS FUNCTION "
                        declare = "YOU MUST OVERRIDE THIS FUNCTION "
                    elseif argType == "LuaFunction" then
                        -- THIS MUST BE AN OVERRIDE AND HANDLED THERE, we just set overload_argList
                        -- the code genererated here is nonsense
                        overload_argList = overload_argList.."&wxluatype_TFUNCTION, "
                        argItem = "YOU MUST OVERRIDE THIS FUNCTION "
                        declare = "YOU MUST OVERRIDE THIS FUNCTION "
                    elseif argType == "any" then
                        -- THIS MUST BE AN OVERRIDE AND HANDLED THERE, we just set overload_argList
                        -- the code genererated here is nonsense
                        overload_argList = overload_argList.."&wxluatype_TANY, "
                        argItem = "YOU MUST OVERRIDE THIS FUNCTION "
                        declare = "YOU MUST OVERRIDE THIS FUNCTION "
                    elseif (indirectionCount == 1) and (argPtr == "[]") then
                        argTypeWithAttrib = argTypeWithAttrib.." *"

                        if argType == "wxString" then
                            -- overload_argList = overload_argList.."&s_wxluaarg_StringArray, " FIXME!
                            -- Un 'const' strings
                            if string.sub(argTypeWithAttrib, 1, 6) == "const " then
                                argTypeWithAttrib = string.sub(argTypeWithAttrib, 7)
                            end

                            overload_argList = overload_argList.."&wxluatype_TTABLE, "
                            argItem = "wxlua_getwxStringarray("..argNum..", count)"
                            declare = "int count = 0; wxLuaSmartStringArray "
                        elseif argType == "int" then
                            -- Un 'const' ints
                            if string.sub(argTypeWithAttrib, 1, 6) == "const " then
                                argTypeWithAttrib = string.sub(argTypeWithAttrib, 7)
                            end

                            overload_argList = overload_argList.."&wxluatype_TTABLE, "
                            argItem = "wxlua_getintarray(L, "..argNum..", count)"
                            declare = "int count = 0; wxLuaSmartIntArray "
                        elseif not numeric then
                            argItem = "("..argTypeWithAttrib..")wxluaT_getuserdatatype(L, "..argNum..", wxluatype_"..MakeClassVar(argType)..")"
                        elseif argTypeWithAttrib == "const char *" then
                            argItem = "("..argTypeWithAttrib..")lua_tostring(L, "..argNum..")"
                        else
                            argItem = "("..argTypeWithAttrib..")wxlua_touserdata(L, "..argNum..")"
                        end
                    elseif (indirectionCount == 1) and (argPtr == "*") then
                        if (argType == "wxChar") or
                          ((argType == "wxString") and (string.sub(argTypeWithAttrib, 1, 6) == "const ")) then

                            overload_argList = overload_argList.."&wxluatype_TSTRING, "
                            argItem = "wxlua_getwxStringtype(L, "..argNum..")"

                            -- Default String Value
                            if opt then
                                if (opt == "\"\"") or (opt == "wxEmptyString") or (opt == "NULL") then
                                    opt = "wxString(wxEmptyString)"
                                elseif string.sub(opt, 1, 1) == "\"" then
                                    opt = "wxT("..opt..")"
                                else
                                    opt = "wxString("..opt..")"
                                end
                            end

                            if (argType == "wxChar") then
                                argTypeWithAttrib = "wxString "
                                argListOverride = argName..".IsEmpty() ? NULL : "..argName..".c_str()"
                            end

                        elseif argType == "char" then
                            overload_argList = overload_argList.."&wxluatype_TSTRING, "
                            argItem = "wxlua_getstringtype(L, "..argNum..")"
                            argTypeWithAttrib = "const char *"
                            if (origArgTypeWithAttrib == "unsigned char" or origArgTypeWithAttrib == "const unsigned char") then
                                argTypeWithAttrib = origArgTypeWithAttrib .. " *"
                                argItem = "("..argTypeWithAttrib..")"..argItem
                            elseif (origArgTypeWithAttrib ~= "const char") then
                                argCast = "("..origArgTypeWithAttrib.."*)"
                            end
                        else
                            if isTranslated and (origIndirectionCount == 0) then
                                argTypeWithAttrib = origArgTypeWithAttrib
                                argCast = origArgTypeWithAttrib
                            else
                                argTypeWithAttrib = argTypeWithAttrib.." *"
                            end

                            if not numeric then
                                overload_argList = overload_argList.."&wxluatype_"..MakeClassVar(argType)..", "
                                argItem = "("..argTypeWithAttrib..")wxluaT_getuserdatatype(L, "..argNum..", wxluatype_"..MakeClassVar(argType)..")"
                            else
                                overload_argList = overload_argList.."&wxluatype_TLIGHTUSERDATA, "
                                argItem = "("..argTypeWithAttrib..")wxlua_touserdata(L, "..argNum..")"
                            end

                            if param.GC then
                                table.insert(gcList, "    if (!wxluaO_isgcobject(L, "..argName..")) wxluaO_addgcobject(L, "..argName..", wxluatype_"..MakeVar(argType)..");\n")
                            elseif param.UnGC then
                                table.insert(gcList, "    if (wxluaO_isgcobject(L, "..argName..")) wxluaO_undeletegcobject(L, "..argName..");\n")
                            end

                            if param.IncRef then
                                table.insert(gcList, "    // This param will have DecRef() called on it so we IncRef() it to not have to worry about the Lua gc\n")
                                table.insert(gcList, "    "..argName.."->IncRef();\n")
                            end
                        end
                    elseif (indirectionCount == 2) and (argPtr == "*") then
                        if not numeric then
                            overload_argList = overload_argList.."&wxluatype_"..MakeClassVar(argType)..", "
                            argTypeWithAttrib = argTypeWithAttrib.." **"
                            argItem = "("..argTypeWithAttrib..")wxluaT_getuserdatatype(L, "..argNum..", wxluatype_"..MakeClassVar(argType)..")"
                        else
                            overload_argList = overload_argList.."&wxluatype_TLIGHTUSERDATA, "
                            argTypeWithAttrib = argTypeWithAttrib.." *"
                            argItem = "("..argTypeWithAttrib..")wxlua_touserdata(L, "..argNum..")"
                        end
                    elseif (indirectionCount == 1) and (argPtr == "&") then
                        if argType == "wxString" then
                            overload_argList = overload_argList.."&wxluatype_TSTRING, "
                            argItem = "wxlua_getwxStringtype(L, "..argNum..")"

                            -- Default String Value
                            if opt then
                                if (opt == "\"\"") or (opt == "wxEmptyString") or (opt == "NULL") then
                                    opt = "wxString(wxEmptyString)"
                                elseif string.sub(opt, 1, 1) == "\"" then
                                    opt = "wxString(wxT("..opt.."))"
                                else
                                    opt = "wxString("..opt..")"
                                end
                            end
                        else
                            argTypeWithAttrib = argTypeWithAttrib.." *"
                            if not numeric then
                                overload_argList = overload_argList.."&wxluatype_"..MakeClassVar(argType)..", "
                                argItem = "("..argTypeWithAttrib..")wxluaT_getuserdatatype(L, "..argNum..", wxluatype_"..MakeClassVar(argType)..")"
                            else
                                overload_argList = overload_argList.."&wxluatype_TLIGHTUSERDATA, "
                                argItem = "("..argTypeWithAttrib..")wxlua_touserdata(L, "..argNum..")"
                            end

                            -- Default Value
                            if opt then opt = "&"..opt end

                            argList = argList.."*"
                        end
                    elseif indirectionCount == 0 then
                        if argType == "wxString" then
                            overload_argList = overload_argList.."&wxluatype_TSTRING, "
                            argItem = "wxlua_getwxStringtype(L, "..argNum..")"

                            -- Default String Value
                            if opt then
                                if (opt == "\"\"") or (opt == "wxEmptyString") or (opt == "NULL") then
                                    opt = "wxString(wxEmptyString)"
                                elseif string.sub(opt, 1, 1) == "\"" then
                                    opt = "wxString(wxT("..opt.."))"
                                else
                                    opt = "wxString("..opt..")"
                                end
                            end
                        elseif IsDataTypeBool(argTypeWithAttrib) then
                            overload_argList = overload_argList.."&wxluatype_TBOOLEAN, "
                            argItem = "wxlua_getbooleantype(L, "..argNum..")"
                        elseif IsDataTypeEnum(argTypeWithAttrib) then
                            overload_argList = overload_argList.."&wxluatype_TINTEGER, "
                            argItem = "("..argTypeWithAttrib..")wxlua_getenumtype(L, "..argNum..")"
                        elseif IsDataTypeUInt(argTypeWithAttrib) then
                            overload_argList = overload_argList.."&wxluatype_TINTEGER, "
                            argItem = "("..argTypeWithAttrib..")wxlua_getuintegertype(L, "..argNum..")"
                        elseif not numeric then
                            overload_argList = overload_argList.."&wxluatype_"..MakeClassVar(argType)..", "
                            argItem = "*("..argTypeWithAttrib.."*)wxluaT_getuserdatatype(L, "..argNum..", wxluatype_"..MakeClassVar(argType)..")"
                        else
                            overload_argList = overload_argList.."&wxluatype_TNUMBER, "
                            argItem = "("..argTypeWithAttrib..")wxlua_getnumbertype(L, "..argNum..")"
                        end
                    else
                        local point = ""
                        for z = 1, #param.TypedDataTypePointer do
                            point = point..param.TypedDataTypePointer[z]
                        end
                        print("ERROR: Unsupported pointer indirection '"..point.."' "..LineTableErrString(member))
                    end

                    if argCast then
                        if (string.sub(argCast, 1, 1) == "(") then
                            argList = argList..argCast
                        else
                            argList = argList.."("..argCast..")"
                        end
                    end

                    argList = argList..(argListOverride or argName)

                    -- except for string arrays, the declare is the argType
                    if not declare then
                        declare = argTypeWithAttrib
                    end

                    if not param.Name then
                        print("ERROR: No Param Name: "..member.LineText.." "..LineTableErrString(member))
                    end

                    -- interface.objectData[o].Members[m].Params[p]
                    codeList = {}

                    if opt then
                        CommentBindingTable(codeList, "    // "..param.DataTypeWithAttrib.." "..param.Name.." = "..param.DefaultValue.."\n")
                        table.insert(codeList, "    "..declare.." "..argName.." = (argCount >= "..argNum.." ? "..argItem.." : "..opt..");\n")
                    else
                        CommentBindingTable(codeList, "    // "..param.DataTypeWithAttrib.." "..param.Name.."\n")
                        table.insert(codeList, "    "..declare.." "..argName.." = "..argItem..";\n")
                    end

                    local paramBinding =
                    {
                        ParamName = argName,
                        ParamType = argType,
                        ParamCast = argCast,
                        ParamCode = codeList,
                    }

                    -- set param binding
                    interface.objectData[o].Members[m].Params[arg].Binding = paramBinding
                end

                -- //////////////////////////////////////////////////////////////////////////////////
                -- method binding
                codeList = {}

                if member.DataType == nil then
                    print("Missing datatype, see table dump:")
                    TableDump(member)
                end

                local numeric = IsDataTypeNumeric(member.DataType)

                -- function name
                local funcType = nil
                local funcName = nil
                local funcNameBase = nil
                local funcLuaCall = nil
                if member.IsConstructor or (member.Name == parseObject.Name) then
                    member.IsConstructor = true
                    funcName = "wxLua_"..MakeVar(member["%rename"] or member.Name).."_constructor"
                    funcNameBase = funcName

                    funcType = "WXLUAMETHOD_CONSTRUCTOR"
                    funcLuaCall = MakeVar(member["%rename"] or member.Name)
                elseif member.Name == "~"..parseObject.Name then
                    print("WARNING: Unhandled ~ destructor ", member.Name, parseObject.Name);
                elseif member.IsStaticFunction then
                    funcName = "wxLua_"..MakeVar(parseObject.Name).."_"..MakeVar(member["%rename"] or member.Name)
                    funcType = "WXLUAMETHOD_METHOD|WXLUAMETHOD_STATIC"
                    funcLuaCall = MakeVar(member["%rename"] or member.Name)
                elseif (parseObject.Name == "globals") or member["%function"] then
                    funcName = "wxLua_function_"..MakeVar(member["%rename"] or member.Name)
                    funcType = "WXLUAMETHOD_CFUNCTION"
                    funcLuaCall = MakeVar(member["%rename"] or member.Name)
                else
                    if not parseObject.Name then
                        print("ERROR: parseObject.Name = nil "..LineTableErrString(member))
                    end

                    -- special case for unary -, convert from op_sub to op_neg if necessary
                    if member["%operator"] and (#member.Params == 0) and (member.Name == "op_sub") then
                        member.Name = "op_neg"
                        if member["%rename"] == "op_sub" then -- maybe they renamed it?
                            member["%rename"] = "op_neg"
                        end
                    end

                    funcName = "wxLua_"..MakeVar(parseObject.Name).."_"..MakeVar(member["%rename"] or member.Name)

                    funcType = "WXLUAMETHOD_METHOD"
                    funcLuaCall = MakeVar(member["%rename"] or member.Name)
                end

                if not funcNameBase then funcNameBase = funcName end

                -- if they declared this, the conditions must be exclusive
                -- since the functions will have the same names
                if (member.NotOverload ~= true) then
                    if overloadCount[funcName] then
                        overloadCount[funcName] = overloadCount[funcName] + 1
                        funcName = funcName..tostring(overloadCount[funcName]-1)
                    else
                        overloadCount[funcName] = 1
                    end
                end

                -- function
                if interface.lineData[member.LineNumber] == nil then
                    print("ERROR bad interface data", member.LineNumber, interface.lineData[member.LineNumber])
                    TableDump(interface.lineData)
                end
                CommentBindingTable(codeList, "// "..interface.lineData[member.LineNumber].LineText.."\n")
                table.insert(codeList, "static int LUACALL "..funcName.."(lua_State *L)\n{\n")

                -- See if we're supposed to track or untrack the return value
                local a = string.find(member.DataTypeWithAttrib, "%gc", 1, 1)
                if a then
                    member.DataTypeWithAttrib = string.sub(member.DataTypeWithAttrib, 1, a-1)..string.sub(member.DataTypeWithAttrib, a+4)
                    member.GC = true
                end
                local a = string.find(member.DataTypeWithAttrib, "%ungc", 1, 1)
                if a then
                    member.DataTypeWithAttrib = string.sub(member.DataTypeWithAttrib, 1, a-1)..string.sub(member.DataTypeWithAttrib, a+6)
                    member.UnGC = true
                end

                -- determine function return type
                local memberType = member.DataType
                local memberTypeWithAttrib = member.DataTypeWithAttrib
                local memberPtr = member.DataTypePointer[1]

                local indirectionCount = #member.DataTypePointer

                local isTranslated = nil
                local origMemberType =  memberType
                local origMemberTypeWithAttrib = memberTypeWithAttrib
                local origMemberPtr = memberPtr
                local origIndirectionCount = indirectionCount
                local memberCast = nil

                -- Does DataType need to be translated from typeDef
                TranslateDataType(member)
                if #member.TypedDataTypePointer ~= indirectionCount then
                    indirectionCount = #member.TypedDataTypePointer

                    -- translated datatype
                    memberType = member.TypedDataType
                    memberTypeWithAttrib = member.TypedDataTypeWithAttrib
                    memberPtr = member.TypedDataTypePointer[1]

                    isTranslated = true
                end

                local returnPtr = "*";

                if (memberType ~= "void") or (indirectionCount > 0) then
                    if numeric and ((indirectionCount == 0) or (memberPtr == "&"))  then
                        returnPtr = ""
                    end

                    if isTranslated and (indirectionCount == 1) and (origIndirectionCount == 0) then
                        memberTypeWithAttrib = origMemberTypeWithAttrib.." "
                        memberCast = origMemberTypeWithAttrib
                    else
                        memberTypeWithAttrib = memberTypeWithAttrib..returnPtr
                    end

                    -- Un 'const' strings and non-pointer datatypes
                    if (string.sub(memberTypeWithAttrib, 1, 6) == "const ") and ((memberType == "wxString") or (returnPtr == "") or member.IsConstructor) then
                        memberTypeWithAttrib = string.sub(memberTypeWithAttrib, 7)
                    end

                    if string.find(memberTypeWithAttrib, "voidptr_long", 1, 1) then
                        memberTypeWithAttrib = "wxUIntPtr"
                    end
                end

                -- conditions for method are dependent on return type, argument types, and inline conditions
                local dependConditions = {}

                if HasCondition(fullcondition) then
                    dependConditions[fullcondition] = fullcondition
                end

                local returnCondition = GetDataTypeCondition(memberType)
                if returnCondition then
                    dependConditions[returnCondition] = returnCondition
                end

                -- get args
                local requiredParamCount = 0
                local paramCount = #member.Params
                if  paramCount > 0 then
                    for arg=1, paramCount do
                        if not member.Params[arg].DefaultValue then
                            requiredParamCount = requiredParamCount + 1
                        elseif member.Params[arg+1] and (not member.Params[arg+1].DefaultValue) then
                            print("ERROR: Missing default arg #"..tostring(arg+1).." in function. "..LineTableErrString(member))
                        end
                    end

                    if requiredParamCount ~= paramCount then
                        CommentBindingTable(codeList, "    // get number of arguments\n")
                        table.insert(codeList, "    int argCount = lua_gettop(L);\n")
                    end

                    for arg = 1, paramCount do
                        -- add function code to get args (in reverse order)
                        local paramLineCount = #(member.Params[paramCount + 1 - arg].Binding.ParamCode)
                        for paramLine=1, paramLineCount do
                            table.insert(codeList, member.Params[paramCount + 1 - arg].Binding.ParamCode[paramLine])
                        end

                        -- param conditions
                        local paramCondition = GetDataTypeCondition(member.Params[arg].DataType)
                        if paramCondition then
                            dependConditions[paramCondition] = paramCondition
                        end
                    end
                end

                for i = 1, #gcList do
                    table.insert(codeList, gcList[i])
                end

                -- constructor?
                if member.IsConstructor then
                    CommentBindingTable(codeList, "    // call constructor\n")
                    table.insert(codeList, "    "..memberTypeWithAttrib.." returns = new "..parseObject.Name.."("..argList..");\n")

                    -- Test the interface files by casting the object to the baseclasses
                    if testInheritanceByCasting then
                    local BaseClasses = dataTypeTable[parseObject.Name].BaseClasses
                    for i = 1, #(BaseClasses or {}) do
                        table.insert(codeList, "    "..BaseClasses[i].."* returns_"..BaseClasses[i].." = dynamic_cast<"..BaseClasses[i].."*>(returns);\n")
                    end
                    end

                    if parseObject["%gc_this"] or (parseObject["%delete"] and (not parseObject["%ungc_this"])) then
                        CommentBindingTable(codeList, "    // add to tracked memory list\n")

                        -- Un 'const' AddTrackedObject
                        local returnCast = memberTypeWithAttrib
                        if string.sub(returnCast, 1, 6) == "const " then
                            returnCast = string.sub(returnCast, 7)
                        end

                        table.insert(codeList, "    wxluaO_addgcobject(L, returns, wxluatype_"..MakeVar(parseObject.Name)..");\n")
                    elseif IsDerivedClass(parseObject.Name, "wxWindow") then
                        CommentBindingTable(codeList, "    // add to tracked window list, it will check validity\n")
                        table.insert(codeList, "    wxluaW_addtrackedwindow(L, returns);\n")
                    end

                    CommentBindingTable(codeList, "    // push the constructed class pointer\n")
                    table.insert(codeList, "    wxluaT_pushuserdatatype(L, returns, wxluatype_"..MakeClassVar(parseObject.Name)..");\n")

                    table.insert(codeList, "\n    return 1;\n")
                    table.insert(codeList, "}\n")
                else
                    -- how we call c-function
                    if parseObject.Name == "globals" then
                        functor = member.Name   -- global
                    elseif member.IsStaticFunction then
                        functor = parseObject.Name.."::"..member.Name -- static member function
                    else
                        CommentBindingTable(codeList, "    // get this\n")

                        table.insert(codeList, "    "..parseObject.Name.." * self = ("..parseObject.Name.." *)wxluaT_getuserdatatype(L, 1, wxluatype_"..MakeClassVar(parseObject.Name)..");\n")
                        overload_argList = "&wxluatype_"..MakeClassVar(parseObject.Name)..", "..overload_argList

                        if parseObject["%ungc_this"] then
                            table.insert(codeList, "    wxluaO_undeletegcobject(L, self);\n")
                        elseif parseObject["%gc_this"] then
                            table.insert(codeList, "    wxluaO_addgcobject(L, self, wxluatype_"..MakeClassVar(parseObject.Name)..");\n")
                        end

                        -- Test the interface files by casting the object to the baseclasses
                        if testInheritanceByCasting then
                        local BaseClasses = dataTypeTable[parseObject.Name].BaseClasses
                        for i = 1, #(BaseClasses or {}) do
                            table.insert(codeList, "    "..BaseClasses[i].."* self_"..BaseClasses[i].." = dynamic_cast<"..BaseClasses[i].."*>(self);\n")
                        end
                        end

                        requiredParamCount = requiredParamCount + 1
                        paramCount = paramCount + 1

                        if member["%operator"] then
                            if (member.Name == "op_preinc") or (member.Name == "op_predec") then
                                functor = member["%operator"].."(*self)"
                            elseif (member.Name == "op_inc") or (member.Name == "op_dec") then
                                functor = "(*self)"..member["%operator"]
                            elseif member["%operator"] == "[]" then     -- op_index
                                functor = "(*self)["
                            elseif member["%operator"] == "()" then -- op_func
                                functor = "(*self)"
                            elseif paramCount > 1 then
                                functor = "(*self)"..member["%operator"]
                            else
                                functor = member["%operator"].."(*self)"
                            end
                        -- static member function?
                        elseif string.find(member.Name, "::") then
                            functor = member.Name
                        else
                            functor = "self->"..member.Name
                        end
                    end

                    -- need cast?
                    if memberCast then
                        functor  = "("..memberCast..")"..functor
                    end

                    local is_func = iff(not member["%operator"] and member.IsFunction, true, false)

                    -- Add Function Argument List
                    if (argList ~= "") or is_func then
                        functor = functor.."("..argList..")"
                    end

                    if member["%operator"] == "[]" then -- op_index
                        functor = functor.."]"
                    end

                    CommentBindingTable(codeList, "    // call "..member.Name.."\n")

                    if not memberType or (memberTypeWithAttrib == "void") then
                        -- call (void) function
                        table.insert(codeList, "    "..functor..";\n")
                        table.insert(codeList, "\n    return 0;\n")
                        table.insert(codeList, "}\n")
                    else
                        -- call function, get return value
                        if member["%operator"] and string.find(origMemberPtr or "", "&", 1, 1) and string.find(member["%operator"], "=", 1, 1) then
                            table.insert(codeList, "    "..functor..";\n")
                            table.insert(codeList, "    "..memberTypeWithAttrib.." returns = self;\n")
                        elseif member["%operator"] and string.find(origMemberPtr or "", "&", 1, 1) and (string.find(member["%operator"], "=", 1, 1) == nil) then
                            if string.find(memberTypeWithAttrib or "", "*", 1, 1) then
                                table.insert(codeList, "    "..memberTypeWithAttrib.." returns = ("..memberTypeWithAttrib..")&("..functor..");\n")
                            else
                                table.insert(codeList, "    "..memberTypeWithAttrib.." returns = "..functor..";\n")
                            end
                        elseif (not numeric) and (not memberPtr) then
                            CommentBindingTable(codeList, "    // allocate a new object using the copy constructor\n")
                            table.insert(codeList, "    "..memberTypeWithAttrib.." returns = new "..memberType.."("..functor..");\n")
                            CommentBindingTable(codeList, "    // add the new object to the tracked memory list\n")

                            -- Un 'const' AddTrackedObject
                            local returnCast = memberTypeWithAttrib
                            if string.sub(returnCast, 1, 6) == "const " then
                                returnCast = string.sub(returnCast, 7)
                            end

                            local member_DataType = GetDataTypedefBase(memberType)

                            table.insert(codeList, "    wxluaO_addgcobject(L, returns, wxluatype_"..MakeVar(member_DataType.Name)..");\n")

                        elseif (not member["%operator"]) and (memberPtr == "&") and string.find(memberTypeWithAttrib, "*") and (memberType ~= "wxString") then
                            table.insert(codeList, "    "..memberTypeWithAttrib.." returns = ("..memberTypeWithAttrib..")&"..functor..";\n")
                        elseif (memberPtr == "*") or (memberType == "voidptr_long") then
                            table.insert(codeList, "    "..memberTypeWithAttrib.." returns = ("..memberTypeWithAttrib..")"..functor..";\n")

                            if member.GC then
                                table.insert(codeList, "    if (!wxluaO_isgcobject(L, returns)) wxluaO_addgcobject(L, returns, wxluatype_"..MakeVar(memberType)..");\n")
                            elseif member.UnGC then
                                table.insert(codeList, "    if (wxluaO_isgcobject(L, returns)) wxluaO_undeletegcobject(L, returns);\n")
                            end

                        else
                            table.insert(codeList, "    "..memberTypeWithAttrib.." returns = ("..functor..");\n")
                        end

                        -- bind return value
                        if memberType == "wxString" then
                            CommentBindingTable(codeList, "    // push the result string\n")
                            table.insert(codeList, "    wxlua_pushwxString(L, "..returnPtr.."returns);\n")
                        elseif (memberType == "char") and (returnPtr == "*") then
                            CommentBindingTable(codeList, "    // push the result string\n")
                            table.insert(codeList, "    lua_pushstring(L, (const char *)returns);\n")
                        elseif memberType == "wxCharBuffer" then
                            CommentBindingTable(codeList, "    // push the result string\n")
                            table.insert(codeList, "    lua_pushstring(L, returns.data());\n")
                        elseif not numeric then
                            CommentBindingTable(codeList, "    // push the result datatype\n")
                            table.insert(codeList, "    wxluaT_pushuserdatatype(L, returns, wxluatype_"..MakeClassVar(memberType)..");\n")
                        elseif IsDataTypeBool(member.DataType) then
                            CommentBindingTable(codeList, "    // push the result flag\n")
                            table.insert(codeList, "    lua_pushboolean(L, returns);\n")
                        elseif returnPtr == "*" then
                            CommentBindingTable(codeList, "    // push the result pointer\n")
                            table.insert(codeList, "    lua_pushlightuserdata(L, (void *)returns);\n")
                        elseif IsDataTypeFloat(member.DataType) then
                            CommentBindingTable(codeList, "    // push the result floating point number\n")
                            table.insert(codeList, "    lua_pushnumber(L, returns);\n")
                        else -- Number
                            CommentBindingTable(codeList, "    // push the result number\n")
                            table.insert(codeList, [[
#if LUA_VERSION_NUM >= 503
if ((double)(lua_Integer)returns == (double)returns) {
    // Exactly representable as lua_Integer
    lua_pushinteger(L, returns);
} else
#endif
{
    lua_pushnumber(L, returns);
}
]])
                        end

                        table.insert(codeList, "\n    return 1;\n")
                        table.insert(codeList, "}\n")
                    end
                end

                local overload_argListName = "s_wxluatypeArray_".. funcName
                if overload_argList == "" then
                    overload_argListName = "g_wxluaargtypeArray_None"
                else
                    overload_argList = "{ "..overload_argList.."NULL }"
                end

                -- add function map only once for the base function name overload
                local funcMapName = "s_wxluafunc_"..funcName
                local funcMap   = "{ "..funcName..", "..funcType..", "..tostring(requiredParamCount)..", "..tostring(paramCount)..", "..overload_argListName.." }"
                local methodMap = "    { \""..funcLuaCall.."\", "..funcType..", "..funcMapName..", 1, NULL },\n"

                -- build method condition
                local methodcondition = nil
                for idx, condition in pairs_sort(dependConditions) do
                    methodcondition = AddCondition(methodcondition, condition)
                end

                RemovewxLuaStateIfNotUsed(codeList)

                methodcondition = FixCondition(methodcondition)

                -- bind method
                methodBinding =
                {
                    ClassName          = parseObject.Name,
                    FuncType           = funcType,
                    LuaName            = funcLuaCall,
                    CFunctionName      = funcName,
                    CFunctionNameBase  = funcNameBase,
                    Method             = codeList,
                    ArgArray           = overload_argList,
                    ArgArrayName       = overload_argListName,
                    ParamCount         = paramCount,
                    RequiredParamCount = requiredParamCount,
                    FuncMap            = funcMap,
                    FuncMapName        = funcMapName,
                    Map                = methodMap,
                    NotOverload        = member.NotOverload,
                    Condition          = methodcondition,
                    PreDefineCode      = nil, -- set later if necessary
                }

                -- Override Generated Method Code
                if (member.override_name and overrideTable[member.override_name]) then
                    methodBinding.Method = overrideTable[member.override_name]
                    methodBinding.PreDefineCode = "#define "..funcName.." "..member.override_name.."\n"
                    overrideTableUsed[member.override_name] = true
                elseif ((member.override_name == nil) and overrideTable[methodBinding.CFunctionName]) then
                    methodBinding.Method = overrideTable[methodBinding.CFunctionName]
                    overrideTableUsed[methodBinding.CFunctionName] = true
                end

                if member["%function"] then
                    table.insert(functionBindingTable, methodBinding)
                elseif not (member.IsConstructor and parseObject["%abstract"]) then
                    table.insert(interface.objectData[o].BindTable, methodBinding)
                end
            end
        end

        if (parseObject.ObjType == "objtype_class") or (parseObject.ObjType == "objtype_struct") then
            -- Class Includes
            for condition, includeBindingList in pairs_sort(interface.includeBindingTable) do
                if not classIncludeBindingTable[condition] then classIncludeBindingTable[condition] = {} end

                for idx, includeBinding in pairs_sort(includeBindingList) do
                    classIncludeBindingTable[condition][idx] = includeBinding
                end
            end

            -- Figure out if we really need to have member enums for the class
                local enumArrayName = "NULL"
                local enumArrayCountName = 0
                local ExternEnumDeclaration = ""
                local ExternEnumCountDeclaration = ""

            if enumClassBindingTable[MakeVar(parseObject.Name)] ~= nil then
                enumArrayName = MakeVar(parseObject.Name).."_enums"
                enumArrayCountName = MakeVar(parseObject.Name).."_enumCount"
                --ExternEnumDeclaration = "extern "..output_cpp_impexpsymbol.." wxLuaBindNumber "..enumArrayName.."[];\n"
                --ExternEnumCountDeclaration = "extern "..MakeImpExpData("int").." "..enumArrayCountName..";\n"
                ExternEnumDeclaration = "extern wxLuaBindNumber "..enumArrayName.."[];\n"
                ExternEnumCountDeclaration = "extern int "..enumArrayCountName..";\n"
            end

            -- Class Tag Declaration
            local decl = "";
            if comment_cpp_binding_code then
                decl = decl.."// Lua MetaTable Tag for Class '"..parseObject.Name.."'\n"
            end
            decl = decl.."int wxluatype_"..MakeClassVar(parseObject.Name).." = WXLUA_TUNKNOWN;\n"

            interface.objectData[o].TagDeclaration = decl

            -- Class Binding
            local baseclassNames = "NULL"
            local baseclassBinds = "NULL"
            local baseclassVtableOffsets      = nil
            local baseclassTypes              = nil
            local baseclassVtableOffsets_name = "NULL"
            local baseclassTypes_name         = "NULL"

            if dataTypeTable[parseObject.Name].BaseClasses then
                baseclassNames = "wxluabaseclassnames_"..MakeVar(parseObject.Name)
                baseclassBinds = "wxluabaseclassbinds_"..MakeVar(parseObject.Name)


                local base_diff_table = {}
                local base_type_table = {}
                local has_multiple_base_classes = false

                local function iter_baseclasses(name, level)
                    if dataTypeTable[name].BaseClasses then
                        for i = 1, #dataTypeTable[name].BaseClasses do
                            if #dataTypeTable[name].BaseClasses > 1 then
                                has_multiple_base_classes = true
                            end
                            -- only increment level since the rest of this branch is from a second or higher base class
                            if i > 1 then
                                level = 2
                            end

                            -- only store the ptr_diffs to higher base classes, the 1st level is always 0
                            if level > 1 then
                                local ptr_diff = "wxIntPtr(((wxIntPtr)("..dataTypeTable[name].BaseClasses[i].."*)("..parseObject.Name.."*)&wxluatype_TNONE) - ((wxIntPtr)("..parseObject.Name.."*)&wxluatype_TNONE))"
                                base_diff_table[#base_diff_table+1] = ptr_diff
                                base_type_table[#base_type_table+1] = "&wxluatype_"..dataTypeTable[name].BaseClasses[i]
                            end

                            iter_baseclasses(dataTypeTable[name].BaseClasses[i], level)
                        end
                    end
                end

                iter_baseclasses(parseObject.Name, 1)
                if has_multiple_base_classes then
                    baseclassVtableOffsets      = "{ "..table.concat(base_diff_table, ", ").." };"
                    baseclassTypes              = "{ "..table.concat(base_type_table, ", ")..", NULL };"
                    baseclassVtableOffsets_name = "wxluabaseclass_vtable_offsets_"..MakeClassVar(parseObject.Name)
                    baseclassTypes_name         = "wxluabaseclass_wxluatypes_"..MakeClassVar(parseObject.Name)
                end

            end

            local wxlua_delete_function_name = "wxLua_"..MakeVar(parseObject.Name).."_delete_function"

            -- Extern Class Tag Declaration
            local tagcondition = FixCondition(parseObject.Condition)
            local classTypeBinding =
            {
                LuaName                      = MakeVar(parseObject.Name),
                ExternDeclaration            = "extern "..MakeImpExpData("int").." wxluatype_"..MakeClassVar(parseObject.Name)..";\n",
                --ExternMethodDeclaration      = "extern "..output_cpp_impexpsymbol.." wxLuaBindMethod "..MakeVar(parseObject.Name).."_methods[];\n",
                --ExternMethodCountDeclaration = "extern "..MakeImpExpData("int").." "..MakeVar(parseObject.Name).."_methodCount;\n",
                ExternMethodDeclaration      = "extern wxLuaBindMethod "..MakeVar(parseObject.Name).."_methods[];\n",
                ExternMethodCountDeclaration = "extern int "..MakeVar(parseObject.Name).."_methodCount;\n",
                ExternEnumDeclaration        = ExternEnumDeclaration,
                ExternEnumCountDeclaration   = ExternEnumCountDeclaration,
                BaseClassTypes               = baseclassTypes,
                BaseClassVtableOffsets       = baseclassVtableOffsets,
                ExternDeleteFunction         = "extern void "..wxlua_delete_function_name.."(void** p);\n",
                Condition                    = tagcondition
            }

            if not classTypeBindingTable[tagcondition] then classTypeBindingTable[tagcondition] = {} end
            classTypeBindingTable[tagcondition][parseObject.Name] = classTypeBinding

            local classinfo = "NULL"
            local is_wxObject = IsDerivedClass(parseObject.Name, "wxObject")

            if is_wxObject then
                classinfo = "CLASSINFO("..parseObject.Name..")"
            end

            -- Class Functions
            if parseObject["%delete"] then
                -- delete routine
                codeList = {}
                local funcName  = "wxLua_"..MakeVar(parseObject.Name).."_delete"
                local funcName_ = funcName

                if not overrideTable[funcName] then
                    funcName_ = "wxlua_userdata_delete"
                end

                local funcMapName = "s_wxluafunc_"..funcName

                local overload_argListName = "s_wxluatypeArray_".. funcName
                local overload_argList = "{ &wxluatype_"..MakeClassVar(parseObject.Name)..", NULL }"

                local condition = FixCondition(parseObject.Condition)

                RemovewxLuaStateIfNotUsed(codeList)

                local funcType = "WXLUAMETHOD_METHOD"

                local delMethodBinding =
                {
                    LuaName         = "delete",
                    CFunctionName   = funcName_,
                    Method          = codeList,
                    FuncType        = funcType,
                    FuncMap         = "{ "..funcName_..", WXLUAMETHOD_METHOD|WXLUAMETHOD_DELETE, 1, 1, "..overload_argListName.." }",
                    FuncMapName     = funcMapName,
                    ArgArray        = overload_argList,
                    ArgArrayName    = overload_argListName,
                    ParamCount      = 1,
                    RequiredParamCount = 1,
                    Map             = "    { \"delete\", WXLUAMETHOD_METHOD|WXLUAMETHOD_DELETE, "..funcMapName..", 1, NULL },\n",
                    Condition       = condition
                }

                -- Override Generated Method Code
                if overrideTable[funcName] then
                    delMethodBinding.Method = overrideTable[funcName]
                    overrideTableUsed[funcName] = true
                end

                table.insert(interface.objectData[o].BindTable, delMethodBinding)
            end


            local classcondition = FixCondition(parseObject.Condition)
            local classBinding =
            {
                LuaName = MakeVar(parseObject.Name),
                Map = "    { wxluaclassname_"..MakeVar(parseObject.Name)..", "
                                ..MakeVar(parseObject.Name).."_methods, "
                                ..MakeVar(parseObject.Name).."_methodCount, "
                                ..classinfo..", "
                                .."&wxluatype_"..MakeClassVar(parseObject.Name)..", "
                                ..baseclassNames..", "
                                ..baseclassBinds..", "
                                ..baseclassTypes_name..", "
                                ..baseclassVtableOffsets_name..", "
                                ..enumArrayName..", "
                                ..enumArrayCountName..", "
                                .."&"..wxlua_delete_function_name..", "
                                .."}, \n",
                BaseClasses            = dataTypeTable[parseObject.Name].BaseClasses,
                Condition              = classcondition
            }

            table.insert(classBindingTable, classBinding)
        end
    end
end

-- ---------------------------------------------------------------------------
-- Convert MapTable[i] to OutTable[MapTable[i].LuaName]
-- ---------------------------------------------------------------------------
function GenerateLuaNameFromIndexedTable(MapTable, OutTable)
    for n = 1, #MapTable do
        local luaname = MapTable[n].LuaName
        if not OutTable[luaname] then OutTable[luaname] = {} end
        if HasCondition(MapTable[n].Condition) then
            table.insert(OutTable[luaname], 1, MapTable[n])
        else
            table.insert(OutTable[luaname], MapTable[n])
        end
    end
end

-- ---------------------------------------------------------------------------
-- Write (typically a Map) to a file
-- fileData is a table to append strings to
-- sortedBindings[i][j] = { Map = , Condition = } the binding table
-- indent is the number of space to indent, may be nil default is ""
-- writeFunc is called with the sortedBindings[i][j] to write whatever, may be nil
-- no_elseif means no #elif and each Condition item if be #ifed
-- ignore_condition is an extra condition to ignore
-- ---------------------------------------------------------------------------
function GenerateMap(fileData, sortedBindings, indent, writeFunc, no_elseif, ignore_condition)
    indent = indent or ""
    no_elseif = no_elseif or false
    local last_condition = "1"

    for n = 1, #sortedBindings do
        local wrote_elseif = false

        local duplicatesTable = {}

        for i = 1, #sortedBindings[n] do
            local condition = sortedBindings[n][i].Condition

--[[
            -- FIXME implement duplicate entries check
            if duplicatesTable[condition] then
                print("WARNING: Duplicate entries with the same #if condition! Check bindings")
                TableDump(duplicatesTable[condition], "Entry #1: ")
                TableDump(sortedBindings[n][i], "Entry #2: ")
            else
                duplicatesTable[condition] = sortedBindings[n][i]
            end
]]

            local next_condition = "1"
            if i < #sortedBindings[n] then
                next_condition = sortedBindings[n][i+1].Condition
            elseif n < #sortedBindings then
                next_condition = sortedBindings[n+1][1].Condition
            end

            -- try to combine the #if statements if possible
            if HasCondition(condition) and (condition ~= ignore_condition) and (condition ~= last_condition) and ((i == 1) or no_elseif) then
                table.insert(fileData, "#if "..condition.."\n")
            end

            if writeFunc then
                writeFunc(sortedBindings[n][i], fileData)
            else
                table.insert(fileData, indent..sortedBindings[n][i].Map)
            end

            last_condition = condition

            if wrote_elseif or (HasCondition(condition) and (condition ~= ignore_condition) and (condition ~= next_condition)) then
                if (i == #sortedBindings[n]) or no_elseif then
                    table.insert(fileData, "#endif // "..condition.."\n")
                    last_condition = "1"
                else
                    table.insert(fileData, "#elif "..next_condition.."\n")
                    wrote_elseif = true
                end
            end

            if not wrote_elseif and (condition ~= next_condition) then
                table.insert(fileData, "\n")
            end
        end
    end
end

-- ---------------------------------------------------------------------------
-- Write Hook Header File
-- ---------------------------------------------------------------------------
function GenerateHookHeaderFileTable()
    local fileData = {}

    table.insert(fileData, "// ---------------------------------------------------------------------------\n")
    table.insert(fileData, "// "..hook_cpp_namespace..".h - headers and wxLua types for wxLua binding\n")
    table.insert(fileData, "//\n")
    table.insert(fileData, "// This file was generated by genwxbind.lua \n")
    table.insert(fileData, "// Any changes made to this file will be lost when the file is regenerated\n")
    table.insert(fileData, "// ---------------------------------------------------------------------------\n")
    table.insert(fileData, "\n")
    table.insert(fileData, "#ifndef __HOOK_WXLUA_"..hook_cpp_namespace.."_H__\n")
    table.insert(fileData, "#define __HOOK_WXLUA_"..hook_cpp_namespace.."_H__\n\n")

    table.insert(fileData, (hook_cpp_binding_header_includes or "").."\n")

    table.insert(fileData, "#include \"wxlua/wxlstate.h\"\n")
    table.insert(fileData, "#include \"wxlua/wxlbind.h\"\n\n")

    table.insert(fileData, "// ---------------------------------------------------------------------------\n")
    table.insert(fileData, "// Check if the version of binding generator used to create this is older than\n")
    table.insert(fileData, "//   the current version of the bindings.\n")
    table.insert(fileData, "//   See 'bindings/genwxbind.lua' and 'modules/wxlua/wxldefs.h'\n")
    table.insert(fileData, "#if WXLUA_BINDING_VERSION > "..WXLUA_BINDING_VERSION.."\n")
    table.insert(fileData, "#   error \"The WXLUA_BINDING_VERSION in the bindings is too old, regenerate bindings.\"\n")
    table.insert(fileData, "#endif //WXLUA_BINDING_VERSION > "..WXLUA_BINDING_VERSION.."\n")
    table.insert(fileData, "// ---------------------------------------------------------------------------\n\n")

    if hook_bind_condition then
        table.insert(fileData, "#if "..hook_bind_condition.."\n\n")
    end

    table.insert(fileData, "// binding class\n")
    table.insert(fileData, "class "..output_cpp_impexpsymbol.." "..hook_cpp_binding_classname.." : public wxLuaBinding\n")
    table.insert(fileData, "{\n")
    table.insert(fileData, "public:\n")
    table.insert(fileData, "    "..hook_cpp_binding_classname.."();\n")
    table.insert(fileData, "\n")
    table.insert(fileData, wxLuaBinding_class_declaration or "")
    table.insert(fileData, "\nprivate:\n")
    table.insert(fileData, "    DECLARE_DYNAMIC_CLASS("..hook_cpp_binding_classname..")\n")
    table.insert(fileData, "};\n")
    table.insert(fileData, "\n\n")

    table.insert(fileData, "// initialize "..hook_cpp_binding_classname.." for all wxLuaStates\n")
    table.insert(fileData, "extern "..output_cpp_impexpsymbol.." wxLuaBinding* "..hook_cpp_binding_classname.."_init();\n\n")

    if hook_bind_condition then
        table.insert(fileData, "#else\n\n")
        table.insert(fileData, "#define bind_"..hook_cpp_namespace.."(L)\n\n")
        table.insert(fileData, "#endif // "..hook_bind_condition.."\n\n")
    end

    -- ------------------------------------------------------------------------
    -- Object Include List - sorted by condition for the C++ compiler
    -- ------------------------------------------------------------------------

    table.insert(fileData, "// ---------------------------------------------------------------------------\n")
    table.insert(fileData, "// Includes\n")
    table.insert(fileData, "// ---------------------------------------------------------------------------\n\n")

    for condition, classIncludeBindingList in pairs_sort(classIncludeBindingTable) do
        local indent = ""

        if HasCondition(condition) then
            indent = "    "
            table.insert(fileData, "#if "..condition.."\n")
        end

        for idx, classIncludeBinding in pairs_sort(classIncludeBindingList) do
            table.insert(fileData, indent..classIncludeBinding.Include)
        end

        if HasCondition(condition) then
            table.insert(fileData, "#endif // "..condition.."\n\n")
        else
            table.insert(fileData, "\n")
        end
    end

    -- ------------------------------------------------------------------------
    -- Class Tag Declaration - sorted by condition for the C++ compiler
    -- ------------------------------------------------------------------------

    table.insert(fileData, "// ---------------------------------------------------------------------------\n")
    table.insert(fileData, "// Lua Tag Method Values and Tables for each Class\n")
    table.insert(fileData, "// ---------------------------------------------------------------------------\n\n")

    for condition, classTypeBindingList in pairs_sort(classTypeBindingTable) do
        local indent = ""

        if HasCondition(condition) then
            indent = "    "
            table.insert(fileData, "#if "..condition.."\n")
        end

        for idx, classTypeBinding in pairs_sort(classTypeBindingList) do
            table.insert(fileData, indent..classTypeBinding.ExternDeclaration)
            --table.insert(fileData, indent..classTypeBinding.ExternMethodDeclaration)
            --table.insert(fileData, indent..classTypeBinding.ExternMethodCountDeclaration)
            --if string.len(classTypeBinding.ExternEnumCountDeclaration) > 0 then
            --    table.insert(fileData, indent..classTypeBinding.ExternEnumDeclaration)
            --    table.insert(fileData, indent..classTypeBinding.ExternEnumCountDeclaration)
            --end
        end

        if HasCondition(condition) then
            table.insert(fileData, "#endif // "..condition.."\n\n")
        else
            table.insert(fileData, "\n")
        end
    end

    table.insert(fileData, "\n")

    table.insert(fileData, "\n")
    table.insert(fileData, "#endif // __HOOK_WXLUA_"..hook_cpp_namespace.."_H__\n\n")

    return fileData
end

-- ---------------------------------------------------------------------------
-- Write the header (top part) of the Cpp files
-- ---------------------------------------------------------------------------

function GenerateHookCppFileHeader(fileData, fileName, add_includes)
    table.insert(fileData, "// ---------------------------------------------------------------------------\n")
    table.insert(fileData, "// "..fileName.." was generated by genwxbind.lua \n")
    table.insert(fileData, "//\n")
    table.insert(fileData, "// Any changes made to this file will be lost when the file is regenerated.\n")
    table.insert(fileData, "// ---------------------------------------------------------------------------\n\n")

    if add_includes then
        table.insert(fileData, hook_cpp_binding_includes or "")
        table.insert(fileData, "\n")
        table.insert(fileData, "#include \"wx/wxprec.h\"\n")
        table.insert(fileData, "\n")
        table.insert(fileData, "#ifdef __BORLANDC__\n")
        table.insert(fileData, "    #pragma hdrstop\n")
        table.insert(fileData, "#endif\n")
        table.insert(fileData, "\n")
        table.insert(fileData, "#ifndef WX_PRECOMP\n")
        table.insert(fileData, "     #include \"wx/wx.h\"\n")
        table.insert(fileData, "#endif\n")
        table.insert(fileData, "\n")
        table.insert(fileData, "#include \"wxlua/wxlstate.h\"\n")
        table.insert(fileData, "#include \""..hook_cpp_header_filename.."\"\n")
        table.insert(fileData, hook_cpp_binding_post_includes or "")
        table.insert(fileData, "\n")

        -- It would be awkward to #ifdef the static string names of the classes
        table.insert(fileData, "#ifdef __GNUC__\n")
        table.insert(fileData, "    #pragma GCC diagnostic ignored \"-Wunused-variable\"\n")
        table.insert(fileData, "#endif // __GNUC__\n")

        -- Allow to use lua_pushinteger in override files and convert it as needed
        table.insert(fileData, "\n")
        table.insert(fileData, "#if LUA_VERSION_NUM < 503\n")
        table.insert(fileData, "#define lua_pushinteger lua_pushnumber\n")
        table.insert(fileData, "#endif\n")
    end

    return fileData
end

-- ---------------------------------------------------------------------------
-- Write GetClassList Hook File
-- ---------------------------------------------------------------------------
function GenerateHookClassFileTable(fileData)
    fileData = fileData or {}

    table.insert(fileData, "\n\n")

    -- ------------------------------------------------------------------------
    -- GetClassList
    -- ------------------------------------------------------------------------

    table.insert(fileData, "// ---------------------------------------------------------------------------\n")
    table.insert(fileData, "// "..hook_cpp_class_funcname.."() is called to register classes\n")
    table.insert(fileData, "// ---------------------------------------------------------------------------\n\n")

    local namedBindingTable = {}
    GenerateLuaNameFromIndexedTable(classBindingTable, namedBindingTable)
    local sortedBindings = TableSort(namedBindingTable)

    -- Gather up all of the classnames
    local classNames = {}

    for n = 1, #sortedBindings do
        for i = 1, #sortedBindings[n] do
            classNames[sortedBindings[n][i].LuaName] = sortedBindings[n][i].LuaName
            for _, bc in ipairs(sortedBindings[n][i].BaseClasses or {}) do
                classNames[bc] = bc
            end
        end
    end

    classNames = TableSort(classNames)

    for _, c in pairs_sort(classNames) do
        table.insert(fileData, "static const char* wxluaclassname_"..c.." = \""..c.."\";\n")
    end

    table.insert(fileData, "\n")

    for n = 1, #sortedBindings do
        for i = 1, #sortedBindings[n] do
            if sortedBindings[n][i].BaseClasses then
                local bc_n = 0
                local s = "static const char* wxluabaseclassnames_"..sortedBindings[n][i].LuaName.."[] = {"
                for _, bc in ipairs(sortedBindings[n][i].BaseClasses) do
                    s = s.." wxluaclassname_"..bc..","
                    bc_n = bc_n + 1
                end

                table.insert(fileData, s.." NULL };\n")
                table.insert(fileData, "static wxLuaBindClass* wxluabaseclassbinds_"..sortedBindings[n][i].LuaName.."[] = { "..string.sub(string.rep("NULL, ", bc_n), 1, -3).." };\n")
            end
        end
    end


    -- ------------------------------------------------------------------------
    -- Class Tag Declaration - sorted by condition for the C++ compiler
    -- ------------------------------------------------------------------------

    table.insert(fileData, "// ---------------------------------------------------------------------------\n")
    table.insert(fileData, "// Lua Tag Method Values and Tables for each Class\n")
    table.insert(fileData, "// ---------------------------------------------------------------------------\n\n")

    for condition, classTypeBindingList in pairs_sort(classTypeBindingTable) do
        local indent = ""

        if HasCondition(condition) then
            indent = "    "
            table.insert(fileData, "#if "..condition.."\n")
        end

        for idx, classTypeBinding in pairs_sort(classTypeBindingList) do
            --table.insert(fileData, indent..classTypeBinding.ExternDeclaration)
            table.insert(fileData, indent..classTypeBinding.ExternMethodDeclaration)
            table.insert(fileData, indent..classTypeBinding.ExternMethodCountDeclaration)
            if string.len(classTypeBinding.ExternEnumCountDeclaration) > 0 then
                table.insert(fileData, indent..classTypeBinding.ExternEnumDeclaration)
                table.insert(fileData, indent..classTypeBinding.ExternEnumCountDeclaration)
            end

            if classTypeBinding.BaseClassVtableOffsets then
                table.insert(fileData, indent.."static wxLuaArgType wxluabaseclass_wxluatypes_"..classTypeBinding.LuaName.."[] = "..classTypeBinding.BaseClassTypes.."\n")
                table.insert(fileData, indent.."static wxIntPtr wxluabaseclass_vtable_offsets_"..classTypeBinding.LuaName.."[] = "..classTypeBinding.BaseClassVtableOffsets.."\n")
            end

            table.insert(fileData, indent..classTypeBinding.ExternDeleteFunction)
        end

        if HasCondition(condition) then
            table.insert(fileData, "#endif // "..condition.."\n\n")
        else
            table.insert(fileData, "\n")
        end
    end

    table.insert(fileData, "\n")


    table.insert(fileData, "\n\n")

    table.insert(fileData, "wxLuaBindClass* "..hook_cpp_class_funcname.."(size_t &count)\n{\n")
    table.insert(fileData, "    static wxLuaBindClass classList[] =\n    {\n")

    -- sort the bindings by class name and write them out alphabetically
    GenerateMap(fileData, sortedBindings, "    ")

    table.insert(fileData, "\n")
    table.insert(fileData, "        { 0, 0, 0, 0, 0, 0, 0 }, \n")
    table.insert(fileData, "    };\n")
    table.insert(fileData, "    count = sizeof(classList)/sizeof(wxLuaBindClass) - 1;\n\n")
    table.insert(fileData, "    return classList;\n")
    table.insert(fileData, "}\n\n")

    table.insert(fileData, "// ---------------------------------------------------------------------------\n")
    table.insert(fileData, "// "..hook_cpp_binding_classname.."() - the binding class\n")
    table.insert(fileData, "// ---------------------------------------------------------------------------\n\n")

    if hook_bind_condition then
        table.insert(fileData, "#if "..hook_bind_condition.."\n\n")
    end

    table.insert(fileData, "IMPLEMENT_DYNAMIC_CLASS("..hook_cpp_binding_classname..", wxLuaBinding)\n\n")
    table.insert(fileData, ""..hook_cpp_binding_classname.."::"..hook_cpp_binding_classname.."() : wxLuaBinding()\n")
    table.insert(fileData, "{\n")
    table.insert(fileData, "    m_bindingName   = wxT(\""..hook_cpp_namespace.."\");\n")
    table.insert(fileData, "    m_nameSpace     = wxT(\""..hook_lua_namespace.."\");\n")
    table.insert(fileData, "    m_classArray    = "..hook_cpp_class_funcname.."(m_classCount);\n")
    table.insert(fileData, "    m_numberArray   = "..hook_cpp_define_funcname.."(m_numberCount);\n")
    table.insert(fileData, "    m_stringArray   = "..hook_cpp_string_funcname.."(m_stringCount);\n")
    table.insert(fileData, "    m_eventArray    = "..hook_cpp_event_funcname.."(m_eventCount);\n")
    table.insert(fileData, "    m_objectArray   = "..hook_cpp_object_funcname.."(m_objectCount);\n")
    table.insert(fileData, "    m_functionArray = "..hook_cpp_function_funcname.."(m_functionCount);\n")
    table.insert(fileData, "    InitBinding();\n")
    table.insert(fileData, "}\n\n")

    table.insert(fileData, (wxLuaBinding_class_implementation or "").."\n\n")

    table.insert(fileData, "// ---------------------------------------------------------------------------\n\n")

    table.insert(fileData, "wxLuaBinding* "..hook_cpp_binding_classname.."_init()\n")
    table.insert(fileData, "{\n")
    table.insert(fileData, "    static "..hook_cpp_binding_classname.." m_binding;\n\n")
    table.insert(fileData, "    if (wxLuaBinding::GetBindingArray().Index(&m_binding) == wxNOT_FOUND)\n")
    table.insert(fileData, "        wxLuaBinding::GetBindingArray().Add(&m_binding);\n\n")
    table.insert(fileData, "    return &m_binding;\n")
    table.insert(fileData, "}\n\n")

    if hook_bind_condition then
        table.insert(fileData, "#endif // "..hook_bind_condition.."\n\n")
    end

    table.insert(fileData, "\n")

    return fileData
end

-- ---------------------------------------------------------------------------
-- Write GetDefineList Hook File
-- ---------------------------------------------------------------------------
function GenerateHookDefineFileTable(fileData)
    fileData = fileData or {}

    -- ------------------------------------------------------------------------
    -- GetDefineList
    -- ------------------------------------------------------------------------
    table.insert(fileData, "// ---------------------------------------------------------------------------\n")
    table.insert(fileData, "// "..hook_cpp_define_funcname.."() is called to register #define and enum\n")
    table.insert(fileData, "// ---------------------------------------------------------------------------\n\n")

    table.insert(fileData, "wxLuaBindNumber* "..hook_cpp_define_funcname.."(size_t &count)\n{\n")
    table.insert(fileData, "    static wxLuaBindNumber numberList[] =\n    {\n")

    -- mix the #define and enums together since they're both in the same wxLuaBindNumber struct
    local namedBindingTable = {}
    GenerateLuaNameFromIndexedTable(defineBindingTable, namedBindingTable)
    GenerateLuaNameFromIndexedTable(enumBindingTable, namedBindingTable)

    -- sort the bindings by class name and write them out alphabetically
    local sortedBindings = TableSort(namedBindingTable)
    GenerateMap(fileData, sortedBindings)

    table.insert(fileData, "\n")
    table.insert(fileData, "        { 0, 0 },\n")
    table.insert(fileData, "    };\n")
    table.insert(fileData, "    count = sizeof(numberList)/sizeof(wxLuaBindNumber) - 1;\n")
    table.insert(fileData, "    return numberList;\n")
    table.insert(fileData, "}\n\n")

    -- ------------------------------------------------------------------------
    -- GetStringList
    -- ------------------------------------------------------------------------
    table.insert(fileData, "// ---------------------------------------------------------------------------\n\n")
    table.insert(fileData, "// "..hook_cpp_string_funcname.."() is called to register #define_string\n")
    table.insert(fileData, "// ---------------------------------------------------------------------------\n\n")

    table.insert(fileData, "wxLuaBindString* "..hook_cpp_string_funcname.."(size_t &count)\n{\n")
    table.insert(fileData, "    static wxLuaBindString stringList[] =\n    {\n")

    local namedBindingTable = {}
    GenerateLuaNameFromIndexedTable(stringBindingTable, namedBindingTable)

    -- sort the bindings by class name and write them out alphabetically
    local sortedBindings = TableSort(namedBindingTable)
    GenerateMap(fileData, sortedBindings)

    table.insert(fileData, "\n")
    table.insert(fileData, "        { 0, 0 },\n")
    table.insert(fileData, "    };\n")
    table.insert(fileData, "    count = sizeof(stringList)/sizeof(wxLuaBindString) - 1;\n")
    table.insert(fileData, "    return stringList;\n")
    table.insert(fileData, "}\n\n")

    return fileData
end

-- ---------------------------------------------------------------------------
-- Write GetObjectList Hook File
-- ---------------------------------------------------------------------------
function GenerateHookObjectFileTable(fileData)
    fileData = fileData or {}

    table.insert(fileData, "// ---------------------------------------------------------------------------\n")
    table.insert(fileData, "// "..hook_cpp_object_funcname.."() is called to register object and pointer bindings\n")
    table.insert(fileData, "// ---------------------------------------------------------------------------\n\n")

    -- ------------------------------------------------------------------------
    -- GetObjectList
    -- ------------------------------------------------------------------------
    table.insert(fileData, "wxLuaBindObject* "..hook_cpp_object_funcname.."(size_t &count)\n{\n")
    table.insert(fileData, "    static wxLuaBindObject objectList[] =\n    {\n")

    -- mix %object and %pointer together since they're both in the same wxLuaBindObject struct
    local namedBindingTable = {}
    GenerateLuaNameFromIndexedTable(objectBindingTable, namedBindingTable)
    GenerateLuaNameFromIndexedTable(pointerBindingTable, namedBindingTable)

    -- sort the bindings by class name and write them out alphabetically
    local sortedBindings = TableSort(namedBindingTable)
    GenerateMap(fileData, sortedBindings)

    table.insert(fileData, "\n")
    table.insert(fileData, "        { 0, 0, 0, 0 },\n")
    table.insert(fileData, "    };\n")
    table.insert(fileData, "    count = sizeof(objectList)/sizeof(wxLuaBindObject) - 1;\n")
    table.insert(fileData, "    return objectList;\n")
    table.insert(fileData, "}\n\n")

    return fileData
end

-- ---------------------------------------------------------------------------
-- Write GetEventList Hook File
-- ---------------------------------------------------------------------------
function GenerateHookEventFileTable(fileData)
    fileData = fileData or {}

    table.insert(fileData, "// ---------------------------------------------------------------------------\n")
    table.insert(fileData, "// "..hook_cpp_event_funcname.."() is called to register events\n")
    table.insert(fileData, "// ---------------------------------------------------------------------------\n\n")

    -- ------------------------------------------------------------------------
    -- GetEventList
    -- ------------------------------------------------------------------------
    table.insert(fileData, "wxLuaBindEvent* "..hook_cpp_event_funcname.."(size_t &count)\n{\n")
    table.insert(fileData, "    static wxLuaBindEvent eventList[] =\n    {\n")

    local namedBindingTable = {}
    GenerateLuaNameFromIndexedTable(eventBindingTable, namedBindingTable)
    -- sort the bindings by class name and write them out alphabetically
    local sortedBindings = TableSort(namedBindingTable)
    GenerateMap(fileData, sortedBindings)

    table.insert(fileData, "\n")
    table.insert(fileData, "        { 0, 0, 0 },\n")
    table.insert(fileData, "    };\n")
    table.insert(fileData, "    count = sizeof(eventList)/sizeof(wxLuaBindEvent) - 1;\n")
    table.insert(fileData, "    return eventList;\n")
    table.insert(fileData, "}\n\n")

    return fileData
end

-- ---------------------------------------------------------------------------
-- Write GetCFunctionList Hook File
-- ---------------------------------------------------------------------------
function GenerateHookCFunctionFileTable(fileData)
    fileData = fileData or {}

    table.insert(fileData, "// ---------------------------------------------------------------------------\n")
    table.insert(fileData, "// "..hook_cpp_function_funcname.."() is called to register global functions\n")
    table.insert(fileData, "// ---------------------------------------------------------------------------\n\n")

    -- Don't use #elif to let compiler fail on multiple definitions per condition
    -- since there's a problem with the bindings if that happens

    local namedBindingTable = {}
    GenerateLuaNameFromIndexedTable(functionBindingTable, namedBindingTable)
    -- sort the bindings by class name and write them out alphabetically
    local sortedBindings = TableSort(namedBindingTable)

    local function writeFunc(functionBinding)
        if functionBinding.Method then
            if functionBinding.ArgArrayName and (functionBinding.ArgArrayName ~= "g_wxluaargtypeArray_None") then
                table.insert(fileData, "static wxLuaArgType "..functionBinding.ArgArrayName.."[] = "..functionBinding.ArgArray..";\n")
            end

            table.insert(fileData, table.concat(functionBinding.Method))

            if functionBinding.FuncMapName then
                table.insert(fileData, "static wxLuaBindCFunc "..functionBinding.FuncMapName.."[1] = {"..functionBinding.FuncMap.."};\n\n")
            end
        end
    end
    GenerateMap(fileData, sortedBindings, "    ", writeFunc, true)

    -- ------------------------------------------------------------------------
    -- GetCFunctionList
    -- ------------------------------------------------------------------------

    table.insert(fileData, "// ---------------------------------------------------------------------------\n")
    table.insert(fileData, "// "..hook_cpp_function_funcname.."() is called to register global functions\n")
    table.insert(fileData, "// ---------------------------------------------------------------------------\n\n")

    table.insert(fileData, "wxLuaBindMethod* "..hook_cpp_function_funcname.."(size_t &count)\n{\n")
    table.insert(fileData, "    static wxLuaBindMethod functionList[] =\n    {\n")

    GenerateMap(fileData, sortedBindings, "    ")

    table.insert(fileData, "\n")
    table.insert(fileData, "        { 0, 0, 0, 0 }, \n")
    table.insert(fileData, "    };\n")
    table.insert(fileData, "    count = sizeof(functionList)/sizeof(wxLuaBindMethod) - 1;\n")
    table.insert(fileData, "    return functionList;\n")
    table.insert(fileData, "}\n\n")

    return fileData
end

-- ---------------------------------------------------------------------------
-- Go through the list of bindings for this class and find duplicate, overload, entries
-- ---------------------------------------------------------------------------
function GenerateOverloadBinding(sortedBindings, object)
    local overloadBindings = {}

    for n = 1, #sortedBindings do
        local overload_count = 0
        local methodBindings = sortedBindings[n]

        local paramCount = 0
        local requiredParamCount = 1E6
        local funcType = methodBindings[1].FuncType

        local not_overload = 0

        for i = 1, #methodBindings do
            if methodBindings[i].Method then -- ignore properties
                overload_count = overload_count + 1

                if methodBindings[i].NotOverload == true then
                    not_overload = not_overload + 1
                end

                if methodBindings[i].ParamCount and (paramCount < methodBindings[i].ParamCount) then
                    paramCount = methodBindings[i].ParamCount
                end
                if methodBindings[i].RequiredParamCount and (requiredParamCount > methodBindings[i].RequiredParamCount) then
                    requiredParamCount = methodBindings[i].RequiredParamCount
                end

                for s in string.gmatch(methodBindings[i].FuncType, "[%a_]+") do
                    if (string.find(funcType, s, 1, 1) == nil) then
                        funcType = funcType.."|"..s
                    end
                end
            end
        end

        if (overload_count > 1) and (not_overload < overload_count) and methodBindings[1].CFunctionNameBase then
            --print(n, #methodBindings, methodBindings[1].Map)

            local overload_condition = ""
            local overload_conditions_used = {}
            --if HasCondition(object.Condition) then
            --    overload_conditions_used[object.Condition] = 1
            --end
            local cfuncNameBase = methodBindings[1].CFunctionNameBase

            for i = 1, #methodBindings do
                if HasCondition(methodBindings[i].Condition) and (overload_conditions_used[methodBindings[i].Condition] == nil) then
                    if overload_condition ~= "" then overload_condition = overload_condition.."||" end
                    overload_condition = overload_condition.."("..methodBindings[i].Condition..")"
                    overload_conditions_used[methodBindings[i].Condition] = 1
                end
            end

            local funcName = cfuncNameBase.."_overload"
            local funcMap = {}
            local funcMapName = "s_wxluafunc_"..cfuncNameBase.."_overload"

            CommentBindingTable(funcMap, "// function overload table\n")
            table.insert(funcMap, "static wxLuaBindCFunc "..funcMapName.."[] =\n{\n")
--            table.insert(funcMap, "    { "..funcName..", WXLUAMETHOD_METHOD|WXLUAMETHOD_OVERLOAD, "..tostring(requiredParamCount)..", "..tostring(paramCount)..", g_wxluaargtypeArray_None },\n")
            for i = 1, #methodBindings do
                if HasCondition(methodBindings[i].Condition) and (methodBindings[i].Condition ~= object.Condition) then
                    table.insert(funcMap, "\n#if "..methodBindings[i].Condition.."\n")
                end

                table.insert(funcMap, "    "..methodBindings[i].FuncMap..",\n")

                if HasCondition(methodBindings[i].Condition) and (methodBindings[i].Condition ~= object.Condition) then
                    table.insert(funcMap, "#endif // "..methodBindings[i].Condition.."\n")
                end
            end
            table.insert(funcMap, "};\n")

            table.insert(funcMap, "static int "..funcMapName.."_count = sizeof("..funcMapName..")/sizeof(wxLuaBindCFunc);\n\n")

            local methodMap = "    { \""..methodBindings[1].LuaName.."\", "..funcType..", "..funcMapName..", "..funcMapName.."_count, 0 }"

            local codeList = {}

--            CommentBindingTable(codeList, "// Overloaded function for "..methodBindings[1].ClassName.."::"..methodBindings[1].LuaName.."\n")
--            table.insert(codeList, "static int LUACALL "..funcName.."(lua_State *L)\n{\n")
--            table.insert(codeList, "    static wxLuaBindMethod overload_method = \n")
--            table.insert(codeList, "    "..methodMap..";\n")
--            table.insert(codeList, "    return wxlua_CallOverloadedFunction(L, &overload_method);\n")
--            table.insert(codeList, "}\n")

            local methodBinding =
            {
                Condition = overload_condition,
                CFunctionName = funcName,
                FuncMap = funcMap,
                funcMapName = funcMapName,
                ParamCount = paramCount,
                RequiredParamCount = requiredParamCount,
                Method = codeList,
                Map = methodMap..",\n",
                IsOverload = true
            }

            -- clear and replace the other bindings
            sortedBindings[n] = {}
            table.insert(sortedBindings[n], methodBinding)

            table.insert(overloadBindings, {})
            table.insert(overloadBindings[#overloadBindings], methodBinding)
        end
    end

    return overloadBindings
end

-- ---------------------------------------------------------------------------
-- Write Hook file for an interface file
-- ---------------------------------------------------------------------------
function GenerateBindingFileTable(interface, fileData, add_includes)

    fileData = GenerateHookCppFileHeader(fileData, interface.CPPFileName, add_includes)

    for k, v in pairs_sort(interface.includeFiles) do
        table.insert(fileData, "#include "..v.."\n")
    end
    table.insert(fileData, "\n")

    for o = 1, #interface.objectData do
        local object = interface.objectData[o]

        --print("Output ", object.ObjType, object.Name)

        if (object.ObjType == "objtype_class") or (object.ObjType == "objtype_struct") then
            local ObjectName = object.Name
            local BindTable = object.BindTable
            local OverloadTable = object.OverloadTable

            if object.Condition then
                table.insert(fileData, "\n#if "..object.Condition.."\n")
            end

            -- Output Parsed Object
            table.insert(fileData, "// ---------------------------------------------------------------------------\n")
            table.insert(fileData, "// Bind "..string.sub(object.ObjType, 9).." "..object.Name.."\n")
            table.insert(fileData, "// ---------------------------------------------------------------------------\n\n")

            -- Class Tag Declaration
            table.insert(fileData, object.TagDeclaration)
            table.insert(fileData, "\n")

            local namedBindingTable = {}
            GenerateLuaNameFromIndexedTable(BindTable, namedBindingTable)
            -- sort the bindings by class name and write them out alphabetically
            local sortedBindings = TableSort(namedBindingTable)

            -- Output Bind Methods
            local function writeFunc(functionBinding)
                if functionBinding.Method then
                    if functionBinding.PreDefineCode then
                        table.insert(fileData, functionBinding.PreDefineCode)
                    end
                    if functionBinding.ArgArrayName and (functionBinding.ArgArrayName ~= "g_wxluaargtypeArray_None") then
                        table.insert(fileData, "static wxLuaArgType "..functionBinding.ArgArrayName.."[] = "..functionBinding.ArgArray..";\n")
                    end
                    if functionBinding.FuncMapName then
                        if functionBinding.CFunctionName ~= "wxlua_userdata_delete" then
                            table.insert(fileData, "static int LUACALL "..functionBinding.CFunctionName.."(lua_State *L);\n")
                        end
                        table.insert(fileData, "static wxLuaBindCFunc "..functionBinding.FuncMapName.."[1] = {"..functionBinding.FuncMap.."};\n")
                    end

                    table.insert(fileData, table.concat(functionBinding.Method).."\n")
                end
            end
            GenerateMap(fileData, sortedBindings, "    ", writeFunc, true, object.Condition)

            table.insert(fileData, "\n\n")

            -- Output overloaded functions
            local overloadBindings = GenerateOverloadBinding(sortedBindings, object)

            local function writeFunc(functionBinding)
                if functionBinding.IsOverload then
--                    table.insert(fileData, "static int LUACALL "..functionBinding.CFunctionName.."(lua_State *L);\n")
                    table.insert(fileData, table.concat(functionBinding.FuncMap))
                    table.insert(fileData, table.concat(functionBinding.Method))
                end
            end
            GenerateMap(fileData, overloadBindings, "    ", writeFunc, true, object.Condition)

            -- Generate the C++ delete function

            local wxlua_delete_function_name = "wxLua_"..MakeClassVar(ObjectName).."_delete_function"
            local wxlua_delete_function_code = ""

            if overrideTable[wxlua_delete_function_name] then
                overrideTableUsed[wxlua_delete_function_name] = true
                wxlua_delete_function_code = table.concat(overrideTable[wxlua_delete_function_name])
            else
                wxlua_delete_function_code =
                    "void "..wxlua_delete_function_name.."(void** p)\n{\n"..
                    "    "..ObjectName.."* o = ("..ObjectName.."*)(*p);\n"..
                    "    delete o;\n}\n\n"
            end

            table.insert(fileData, wxlua_delete_function_code);

            -- Output Method Map Table

            CommentBindingTable(fileData, "// Map Lua Class Methods to C Binding Functions\n")

            table.insert(fileData, "wxLuaBindMethod "..MakeClassVar(ObjectName).."_methods[] = {\n")
            GenerateMap(fileData, sortedBindings, "", nil, false, object.Condition)
            table.insert(fileData, "    { 0, 0, 0, 0 },\n")
            table.insert(fileData, "};\n\n")

            -- since there may be conditions count them up afterwards
            table.insert(fileData, "int "..MakeVar(ObjectName).."_methodCount = sizeof("..MakeClassVar(ObjectName).."_methods)/sizeof(wxLuaBindMethod) - 1;\n\n")

            if enumClassBindingTable[MakeClassVar(ObjectName)] then
                table.insert(fileData, "wxLuaBindNumber "..MakeClassVar(ObjectName).."_enums[] = {\n")
                local namedBindingTable = {}
                GenerateLuaNameFromIndexedTable(enumClassBindingTable[MakeClassVar(ObjectName)], namedBindingTable)
                -- sort the bindings by class name and write them out alphabetically
                local sortedBindings = TableSort(namedBindingTable)
                GenerateMap(fileData, sortedBindings)
                table.insert(fileData, "    { NULL, 0, },\n")
                table.insert(fileData, "};\n")

                -- since there may be conditions count them up afterwards
                table.insert(fileData, "int "..MakeVar(ObjectName).."_enumCount = sizeof("..MakeClassVar(ObjectName).."_enums)/sizeof(wxLuaBindNumber) - 1;\n")
            end

            if object.Condition then
                table.insert(fileData, "#endif  // "..object.Condition.."\n")
            end

            table.insert(fileData, "\n")
        end
    end

    RemoveExtra_wxLuaBindCFunc(fileData)

    return fileData
end

function RemoveExtra_wxLuaBindCFunc(fileData)
    local cfuncTable = {}

    for n = 1, #fileData do
        if string.find(fileData[n], "static wxLuaBindCFunc s_wxluafunc", 1, 1) then
            local a, b = string.find(fileData[n], "s_wxluafunc", 1, 1)
            local s = string.sub(fileData[n], a)
            a, b = string.find(s, "[", 1, 1)
            s = string.sub(s, 1, a-1)

            cfuncTable[s] = n
        elseif string.find(fileData[n], "s_wxluafunc", 1, 1) then
            for k, v in pairs_sort(cfuncTable) do
                if string.find(fileData[n], k..",", 1, 1) or string.find(fileData[n], k.." ", 1, 1) then
                    cfuncTable[k] = -1 -- found
                end
            end
        end
    end

    for k, v in pairs_sort(cfuncTable) do
        if v > 0 then
            fileData[v] = "// "..fileData[v]
        end
    end
end

function SerializeDataTypes(filename)
    local fileData = {}

    table.insert(fileData, "-- ---------------------------------------------------------------------------\n")
    table.insert(fileData, "-- "..filename.." was generated by genwxbind.lua \n")
    table.insert(fileData, "-- \n")
    table.insert(fileData, "-- Any changes made to this file will be lost when the file is regenerated  \n")
    table.insert(fileData, "-- ---------------------------------------------------------------------------\n")
    table.insert(fileData, "\n\n")

    table.insert(fileData, "-- ---------------------------------------------------------------------------\n")
    table.insert(fileData, "-- typedefTable\n")
    table.insert(fileData, "-- ---------------------------------------------------------------------------\n")
    table.insert(fileData, hook_cpp_namespace.."_typedefTable =\n")
    table.insert(fileData, Serialize(typedefTable))

    table.insert(fileData, "\n\n")
    table.insert(fileData, "-- ---------------------------------------------------------------------------\n")
    table.insert(fileData, "-- dataTypes\n")
    table.insert(fileData, "-- ---------------------------------------------------------------------------\n")
    table.insert(fileData, hook_cpp_namespace.."_dataTypeTable =\n")
    table.insert(fileData, Serialize(dataTypeTable))

    table.insert(fileData, "\n\n")
    table.insert(fileData, "-- ---------------------------------------------------------------------------\n")
    table.insert(fileData, "-- preprocConditionTable\n")
    table.insert(fileData, "-- ---------------------------------------------------------------------------\n")
    table.insert(fileData, hook_cpp_namespace.."_preprocConditionTable =\n")
    table.insert(fileData, Serialize(preprocConditionTable))

    table.insert(fileData, "\n\n")
    table.insert(fileData, "-- ---------------------------------------------------------------------------\n")
    table.insert(fileData, "-- Cache the dataTypes\n")
    table.insert(fileData, "-- ---------------------------------------------------------------------------\n")
    table.insert(fileData, "    for k, v in pairs("..hook_cpp_namespace.."_typedefTable) do\n")
    table.insert(fileData, "        typedefTable[k] = v\n")
    table.insert(fileData, "    end\n")
    table.insert(fileData, "    for k, v in pairs("..hook_cpp_namespace.."_dataTypeTable) do\n")
    table.insert(fileData, "        dataTypeTable[k] = v\n")
    table.insert(fileData, "    end\n")
    table.insert(fileData, "    for k, v in pairs("..hook_cpp_namespace.."_preprocConditionTable) do\n")
    table.insert(fileData, "        preprocConditionTable[k] = v\n")
    table.insert(fileData, "    end\n")

    WriteTableToFile(filename, fileData, false)
end

-- http://www2.dcs.elf.stuba.sk/TeamProject/2003/team05/produkt/player/utils/serialize/serialize.lua
--! Serialization

--% Serializes a lua variable (good for table visualization)
--@ o (any) Variable to serialize
--@ d (number) INTERNAL (RECURSIVE FUNCTION)
function Serialize(o, d)
    if not d then d = 0 end
    local s = ""

    if type(o) == "number" then
        s = s..o
    elseif type(o) == "string" then
        s = s..string.format("%q", o)
    elseif type(o) == "boolean" then
        if(o) then s = s.."true" else s = s.."false" end
    elseif type(o) == "table" then
        s = s.."{\n"
        for k,v in pairs_sort(o) do

            for f = 1,d do
                s = s.."  "
            end

            if type(k) == "string" and not string.find(k, "[^%w_]") then
                s = s.."  "..k.." = "
            else
                s = s.."  ["
                s = s..Serialize(k)
                s = s.."] = "
            end

            s = s..Serialize(v, d + 1)
            if type(v) ~= "table" then s = s..",\n" end
        end

        for f = 1,d do
            s = s.."  "
        end

        s = s.."}"
        if d ~= 0 then
            s = s..","
        end
        s = s.."\n"
    elseif type(o) == "function" then
        s = s..tostring(o)
    else
        error("cannot serialize a "..type(o))
    end

    return s
end

-- ----------------------------------------------------------------------------
-- main()
--
-- loadfile("rulesFilename"),
--
--
--
-- ----------------------------------------------------------------------------

function main()
    local time1 = os.time()

    -- load rules file
    if not rulesFilename then
        print("ERROR: No rules filename set!")
        do return end
    end

    local rules = loadfile(rulesFilename)
    if rules then
        rules()
        print("Loaded rules file: "..rulesFilename)
        CheckRules()
    else
        dofile(rulesFilename) -- get the error message
        print("ERROR: Unable to load rules file: '"..tostring(rulesFilename).."'")
        do return end
    end

    -- load any cached settings from other wrappers
    if datatype_cache_input_fileTable then
        for key, filename in pairs_sort(datatype_cache_input_fileTable) do
            if FileExists(filename) then
                local cache = loadfile(filename)
                cache() -- run loaded file
                print("Loaded datatypes cache file: "..filename)
            else
                print("ERROR: Unable to load datatypes cache file: '"..filename.."'")
            end
        end
    end

    InitKeywords()
    InitDataTypes()

    if override_fileTable then
        for i = 1, #override_fileTable do
            ReadOverrideFile(override_fileTable[i])
        end
    end

    local updated_files = 0

    if #interface_fileTable > 0 then
        local interfaceList = GenerateInterfaceData()
        updated_files = WriteWrapperFiles(interfaceList)
    end

    -- Write out the data types for these interface files
    if datatypes_cache_output_filename and string.len(datatypes_cache_output_filename) then
        SerializeDataTypes(interface_filepath.."/"..datatypes_cache_output_filename)
    end

    -- Check for any unused overrides and print a warning
    for overrideName, value in pairs_sort(overrideTableUsed) do
        if not value then
            print("WARNING: Overridden function '"..overrideName.."' was not used.")
        end
    end

    print("Done. "..updated_files.." Files were updated in "..os.difftime(os.time(), time1).." seconds.\n")
end

--rulesFilename="wxwidgets/wxadv_rules.lua"

main()
