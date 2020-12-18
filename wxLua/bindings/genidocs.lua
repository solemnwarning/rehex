-------------------------------------------------------------------------------
-- Name:        genidocs.lua
-- Purpose:     This script generates docs from the wxLua interface files
-- Author:      John Labenski
-- Created:     19/05/2006
-- Copyright:   John Labenski
-- Licence:     wxWidgets licence
-------------------------------------------------------------------------------

completeClassRefTable = nil -- a table of names that is a complete list of classes
                            -- from a library the wrapper are for
                            -- For wxWidgets this is taken from the alphabetical
                            -- list of classes in the wxWidgets reference manual
                            -- This is used to print if a class is wrapped or not.

typedefTable          = {} -- filled from the data cache files
dataTypeTable         = {}
preprocConditionTable = {}

colours = {}

colours.class    = "DD0000" -- red
colours.member   = "CC6600" -- orange
colours.rename   = "990099" -- dark pink
colours.override = "BB0055" -- reddish pink
colours.operator = "663300" -- brown

colours.enum     = "0066CC" -- blue
colours.define   = "006666" -- turquoise
colours.event    = "660033" -- purple
colours.func     = "AA0000" -- dark red

colours.comment    = "009900" -- green
colours.blkcomment = "888888" -- grey

colours.in_manual     = "AAFFAA" -- for table showing classes
colours.in_wxlua      = "AAFFAA"
colours.not_in_manual = "FFAAAA"
colours.not_in_wxlua  = "FFAAAA"

-- ----------------------------------------------------------------------------
-- Dummy function that genwxbind.lua has and the XXX_rules.lua might use
-- ----------------------------------------------------------------------------

function AllocDataType() end

-- ----------------------------------------------------------------------------
-- For testing and choosing pleasing colors
-- ----------------------------------------------------------------------------

function GenerateTestColours(fileTable)
    table.insert(fileTable, "<h2>Colours used to denote types</h2>")

    table.insert(fileTable, MakeColour("Comments - //", colours.comment).."<br>")
    table.insert(fileTable, MakeColour("Block Comments - /* ... */", colours.blkcomment).."<br>")

    table.insert(fileTable, MakeColour("Enums - enum", colours.enum).."<br>")
    table.insert(fileTable, MakeColour("Defines - #define [_string] [_object] [_pointer]", colours.define).."<br>")
    table.insert(fileTable, MakeColour("Events - %define_event", colours.event).."<br>")
    table.insert(fileTable, MakeColour("Functions - %function", colours.func).."<br>")

    table.insert(fileTable, MakeColour("Classes - class", colours.class).."<br>")
    table.insert(fileTable, MakeColour("Class Members - %member", colours.member).."<br>")
    table.insert(fileTable, MakeColour("Renamed Functions - %rename", colours.rename).."<br>")
    table.insert(fileTable, MakeColour("Overridden Functions - %override", colours.override).."<br>")
    table.insert(fileTable, MakeColour("Operator Functions - operator", colours.operator).."<br><br>")
end


-- ----------------------------------------------------------------------------
-- Make simple HTML tag items
-- ----------------------------------------------------------------------------

-- color is "RRGGBB" in hex
function MakeColour(str, color, size)
    if size then
        return "<font size=+"..size.." color=#"..color..">"..str.."</font>"
    end

    return "<font color=#"..color..">"..str.."</font>"
end
function MakeBold(str)
    return "<b>"..str.."</b>"
end
function MakeItalic(str)
    return "<i>"..str.."</i>"
end
function MakeLink(link_name, str)
    --<a href="#papers">papers</a>
    return "<a href=\"#"..link_name.."\">"..(str or link_name).."</a>"
end
function MakeTag(link_name, str)
    --<a name="papers">Papers</a>
    return "<a name=\""..link_name.."\">"..(str or link_name).."</a>"
end

-- convert invalid chars to something valid for use in <a name=...
function MakeTagName(name)
    local s = string.lower(name)
    s = string.gsub(s, "%/", "_")
    s = string.gsub(s, "% ", "_")
    s = string.gsub(s, "%(", "_")
    s = string.gsub(s, "%)", "_")
    return s
end

-- replace any chars as necessary before adding our own code
function MakeHTML(str)
    local s = string.gsub(str, "&", "&amp;")
    s = string.gsub(s, ">", "&gt;")
    s = string.gsub(s, "<", "&lt;")
    return s
end

-- ----------------------------------------------------------------------------
-- Make the HTML footer
-- ----------------------------------------------------------------------------

function GenerateFooter(fileTable)
    table.insert(fileTable, "</body>")
    table.insert(fileTable, "</html>")

    return fileTable
end

-- ----------------------------------------------------------------------------
-- Make the Class reference HTML code
-- ----------------------------------------------------------------------------

function GenerateClassReference(fileTable)
    local names = {}

    table.insert(fileTable, "<h2>Classes</h2>")

    local allClasses = {}

    if completeClassRefTable then
        for k, v in pairs(completeClassRefTable) do
            allClasses[k] = false -- for example ALL wxWidgets classes
        end
    end
    for k, v in pairs(dataTypeTable) do
        -- hack for special classes
        if (v.ValueType == "class") or (v.ValueType == "struct") or (v.ValueType == "wx2lua") then
            allClasses[k]      = true -- the ones we wrap
        end
    end

    for k, v in pairs(allClasses) do
        table.insert(names, k)
    end
    table.sort(names)

    --[[
    <table border="1">
        <tr>  <td>row 1, cell 1</td>  <td>row 1, cell 2</td> </tr>
        <tr>  <td>row 2, cell 1</td>  <td>row 2, cell 2</td> </tr>
    </table>
    ]]

    if completeClassRefTable then

        table.insert(fileTable, "<table border=\"1\" summary=\"Table showing what wxWidgets C++ classes are wrapped by wxLua\">")
        table.insert(fileTable, "  <tr><th>Class Name</th> <th>"..completeClassRefColLabel.."</th> <th>Wrapped by wxLua</th> <th>Notes</th></tr>")

        for n = 1, #names do
            local cname = names[n]

            table.insert(fileTable, "<tr>")

            -- link to class in html file
            if allClasses[cname] then
                table.insert(fileTable, "<td>"..MakeLink(cname)) -- optional </td>
            else
                table.insert(fileTable, "<td>"..cname)
            end

            -- in "manual" or complete list of classes
            if completeClassRefTable and completeClassRefTable[cname] then
                table.insert(fileTable, "<td align=\"center\" bgcolor=#"..colours.in_manual..">X")
            else
                table.insert(fileTable, "<td bgcolor=#"..colours.not_in_manual..">&nbsp;")
            end

            -- wrapped by wxLua
            if allClasses[cname] then
                table.insert(fileTable, "<td align=\"center\" bgcolor=#"..colours.in_wxlua..">X")
            else
                table.insert(fileTable, "<td bgcolor=#"..colours.not_in_wxlua..">&nbsp;")
            end

            -- note about the class
            if msgForClassInIndex and msgForClassInIndex[cname] then
                table.insert(fileTable, "<td>"..msgForClassInIndex[cname])
            else
                table.insert(fileTable, "<td>&nbsp;")
            end

            -- table.insert(fileTable, "</tr>") -- optional </tr>
        end

        table.insert(fileTable, "</table><br>")
    else
        for n = 1, #names do
            table.insert(fileTable, MakeLink(names[n]).."<br>")
        end
    end

    table.insert(fileTable, "<br>")

    return fileTable
end

-- ----------------------------------------------------------------------------
-- Make the Enum reference HTML code
-- ----------------------------------------------------------------------------

function GenerateEnumReference(fileTable)
    local names = {}

    table.insert(fileTable, "<h2>Enums</h2>")

    for k, v in pairs(dataTypeTable) do
        if v.ValueType == "enum" then
            table.insert(names, k)
        end
    end
    table.sort(names)
    for n = 1, #names do
        table.insert(fileTable, MakeLink(names[n]).."<br>")
    end

    table.insert(fileTable, "<br>")

    return fileTable
end

-- ----------------------------------------------------------------------------
-- Helper functions
-- ----------------------------------------------------------------------------

local nameChars = {} -- valid chars for C variables for function names
for n = string.byte("a"), string.byte("z") do nameChars[n] = true end
for n = string.byte("A"), string.byte("Z") do nameChars[n] = true end
for n = string.byte("0"), string.byte("9") do nameChars[n] = true end
nameChars[string.byte("_")] = true
nameChars[string.byte(":")] = true

function GetPreviousWord(str, pos)
    local start_pos = 0
    local end_pos = 0
    for n = pos, 0, -1 do
        if not nameChars[string.byte(str, n)] then
            if end_pos ~= 0 then
                start_pos = n+1
                break
            end
        elseif end_pos == 0 then
            end_pos = n
        end
    end
    return string.sub(str, start_pos, end_pos), start_pos
end

-- if the tag in the txt is before the ifbefore_pos then return true
function TagIsBefore(txt, tag, ifbefore_pos)
    local pos = string.find(txt, tag, 1, 1)
    if pos and ((ifbefore_pos == nil) or (pos < ifbefore_pos)) then
        return true
    end
    return false
end


function GetAllComments(str)
    local function FindAllStrings(str, find_txt, tbl)
        local s, e = string.find(str, find_txt, 1, 1)
        while s do
            table.insert(tbl, { ["s"] = s, ["e"] = e, ["txt"] = find_txt })
            s, e = string.find(str, find_txt, e+1, 1)
        end
    end

    local t = {}
    FindAllStrings(str, "//", t)
    FindAllStrings(str, "/*", t)
    FindAllStrings(str, "*/", t)

    table.sort(t, function(t1, t2) return t1.s < t2.s end)

    return t
end

-- ----------------------------------------------------------------------------
-- Read the .i files and convert them to HTML
-- ----------------------------------------------------------------------------

function ReadInterfaceFiles(fileTable)

    table.insert(fileTable, "<h2>Interface files</h2>")

    for i = 1, #interface_fileTable do
        for j = 1, #interface_fileTable[i].files do
            local s = interface_fileTable[i].file_path..interface_fileTable[i].files[j]
            table.insert(fileTable, MakeLink(MakeTagName(s), s).."<br>")
        end
    end

    local strSp = string.byte(" ")

    for i = 1, #interface_fileTable do
    for j = 1, #interface_fileTable[i].files do

        table.insert(fileTable, "<br><HR>\n")
        local filename = interface_fileTable[i].file_path..interface_fileTable[i].files[j]
        table.insert(fileTable, "<h2>"..MakeTag(MakeTagName(filename), filename).." - Lua table = '"..interface_fileTable[i].namespace.."'</h2>")
        table.insert(fileTable, "<HR>\n")

        local in_comment  = false
        local in_class    = false
        local in_enum     = false
        local brace_count = 0
        local in_block    = false

        local line_n = 0

        for line in io.lines(filename) do
            line_n = line_n + 1
            local cname = ""
            local out_line = MakeHTML(line)

            local comment_pos = string.find(line, "//", 1, 1) or 1E6

            -- handle all comments in the order they appear
            local t = GetAllComments(out_line)
            for n = 1, #t do
                if t[n].txt == "//" then
                    out_line = string.sub(out_line, 1, t[n].s-1)..MakeColour(string.sub(out_line, t[n].s), colours.comment)
                    break
                elseif t[n].txt == "/*" then
                    if in_comment then print("ERROR mismatched /* */ in :", filename, line_n, line) end

                    in_comment = true
                    out_line = string.sub(out_line, 1, t[n].s-1).."<font color=#"..colours.blkcomment..">"..string.sub(out_line, t[n].s)
                    t = GetAllComments(out_line)
                elseif t[n].txt == "*/" then
                    if not in_comment then print("ERROR mismatched /* */ in :", filename, line_n, line) end
                    in_comment = false
                    out_line = string.sub(out_line, 1, t[n].s+1).."</font>"..string.sub(out_line, t[n].s+2)
                    t = GetAllComments(out_line)
                end
            end

            local class_pos, class_pos2 = string.find(line, "class ", 1, 1)
            local enum_pos,  enum_pos2  = string.find(line, "enum ", 1, 1)

            if not class_pos then
                class_pos, class_pos2 = string.find(line, "struct ", 1, 1)
            end

            local brace_open_pos  = string.find(line, "{", 1, 1)
            local brace_close_pos = string.find(line, "}", 1, 1)

            if (brace_open_pos and (brace_open_pos < comment_pos)) then
                brace_count = brace_count + 1
            end
            if (brace_close_pos and (brace_close_pos < comment_pos)) then
                brace_count = brace_count - 1
            end

            if (brace_count < 0) then
                print("ERROR - brace mismatch ", filename, line_n, "'"..line.."'") 
            end

            if (class_pos and (class_pos < comment_pos)) or 
               (enum_pos  and (enum_pos  < comment_pos)) then

                in_class = (class_pos ~= nil)
                in_enum  = (enum_pos  ~= nil)

                -- find this class not the base class
                local colon = string.find(line, ":", 1, 1)
                local start_pos = 0
                if class_pos and colon then
                    cname, start_pos = GetPreviousWord(line, colon-1)
                elseif comment_pos < 1E6 then
                    cname, start_pos = GetPreviousWord(line, comment_pos-1)
                else
                    cname, start_pos = GetPreviousWord(line, string.len(line))
                end

                if cname == "enum" then
                    out_line = string.sub(out_line, 1, start_pos-1)..cname..string.sub(out_line, start_pos+string.len(cname))
                else
                    out_line = string.sub(out_line, 1, start_pos-1)..MakeTag(cname)..string.sub(out_line, start_pos+string.len(cname))
                end

                if class_pos then
                    out_line = MakeColour(out_line, colours.class, 1)
                end
                if enum_pos then
                    out_line = MakeColour(out_line, colours.enum, 1)
                end

                out_line = MakeBold(out_line)
            else
                -- priortize the colouring so we don't have to check for every single case

                if TagIsBefore(line, "}", comment_pos) and (brace_count == 0) then
                    --out_line = MakeColour(out_line, colours.class)
                    --end_block = true
                    --class_pos = string.find(line, "}", 1, 1)
                elseif TagIsBefore(line, "%member", comment_pos) then
                    out_line = MakeColour(out_line, colours.member)
                elseif TagIsBefore(line, "%rename", comment_pos) then
                    out_line = MakeColour(out_line, colours.rename)
                elseif TagIsBefore(line, "%override", 1E6) then
                    out_line = MakeColour(out_line, colours.override)
                elseif TagIsBefore(line, "%event", comment_pos) then
                    out_line = MakeColour(out_line, colours.event)
                elseif TagIsBefore(line, "#define", comment_pos) then
                    out_line = MakeColour(out_line, colours.define)
                elseif TagIsBefore(line, "%function", comment_pos) then
                    out_line = MakeColour(out_line, colours.func)
                end
            end

            local used = {}
            used[cname] = true

            for w in string.gmatch(line, "([%w_]+)") do
                if ((string.len(cname) == 0) or (not string.find(w, cname, 1, 1))) and
                    (not used[w]) and
                    dataTypeTable[w] and (dataTypeTable[w].ValueType ~= "number") and
                    (dataTypeTable[w].ValueType ~= "wxtypedef") and (dataTypeTable[w].ValueType ~= "special") then

                    used[w] = true

                    -- replace the classname with a link, but not if it's part of a name
                    --out_line = string.gsub(out_line, w, MakeLink(w))
                    local pat = "[ %&%*%(%)%{%}%[%]%+%-%=%<%>%.%-%+%|%/%,]"
                    -- need extra ending space to find words at end of line
                    local s, e = string.find(out_line.." ", w..pat, 1)
                    while s do
                        local link = MakeLink(w)
                        out_line = string.sub(out_line, 1, s-1)..link..string.sub(out_line, e)
                        s, e = string.find(out_line.." ", w..pat, s+string.len(link))
                    end
                end
            end

            -- italicize the %keywords
            out_line = string.gsub(out_line, "(%%[%w_]+)", function(s) return "<i>"..s.."</i>" end)

--[[
            -- alternate to blockquote, just force the spaces
            local start_spaces = 0

            for n = 1, string.len(out_line) do
                if string.byte(out_line, n) == strSp then
                    start_spaces = start_spaces + 1
                else
                    break
                end
            end
            if start_spaces > 0 then
                out_line = string.rep("&nbsp;", start_spaces)..string.sub(out_line, start_spaces)
            end
]]

            local tail = "<br>"

            local start_block = false
            local end_block   = false

            if (in_class or in_enum) and (not in_block) and (brace_count > 0) then
                start_block = true
            elseif (in_class or in_enum) and in_block and (brace_count == 0) then
                end_block = true
            end

            if start_block then
                tail = "" -- don't add extra space since blockquote already gives a linebreak

                in_block = true

                if in_comment then
                    out_line = out_line.."</font>"
                end

                out_line = out_line.."\n<blockquote>"

                -- need to restart font color after blockquote for "tidy"
                if enum_pos then
                    out_line = out_line.."<font color=#"..colours.enum..">"
                end
                -- restart the block comment after blockquote, overrides enum colour
                if in_comment then
                    out_line = out_line.."<font color=#"..colours.blkcomment..">"
                end
            elseif end_block then
                -- need to restart font color after blockquote for "tidy"

                in_block = false

                if in_class then
                    in_class = false
                    out_line = "</blockquote>"..out_line -- MakeColour(out_line, colours.class)
                end
                if in_enum then
                    in_enum = false
                    out_line = "</font>\n</blockquote>"..out_line --MakeColour(out_line, colours.enum)
                end
                -- restart the block comment after blockquote
                if in_comment then
                    out_line = "</font>"..out_line.."<font color=#"..colours.blkcomment..">"
                end

            end

            table.insert(fileTable, out_line..tail)
        end
    end
    end
end

-- ----------------------------------------------------------------------------
-- Load a file of the classes listed in the wxWidgets manual
-- ----------------------------------------------------------------------------

function LoadCompleteClassRef(filePath)
    for line in io.lines(filePath) do
        -- only create this if necessary
        if not completeClassRefTable then completeClassRefTable = {} end

        for w in string.gmatch(line, "([%w_]+)") do -- strip spaces if any
            completeClassRefTable[w] = true
        end
    end
end

-- ---------------------------------------------------------------------------
-- Do the contents of the file match the strings in the fileData table?
--   the table may contain any number of \n per index
--   returns true for a match or false if not
-- ---------------------------------------------------------------------------
function FileDataIsTableData(filename, fileData)
    local file_handle = io.open(filename)
    if not file_handle then return false end -- ok if it doesn't exist

    local f = file_handle:read("*a")
    local is_same = (f == table.concat(fileData, "\n"))
    io.close(file_handle)
    return is_same
end

-- ---------------------------------------------------------------------------
-- Write the contents of the table fileData (indexes 1.. are line numbers)
--  to the filename, but only write to the file if FileDataIsTableData returns
--  false. If overwrite_always is true then always overwrite the file.
--  returns true if the file was overwritten
-- ---------------------------------------------------------------------------
function WriteTableToFile(filename, fileData, overwrite_always)
    assert(filename and fileData, "Invalid filename or fileData in WriteTableToFile")

    if (not overwrite_always) and FileDataIsTableData(filename, fileData) then
        print("No changes to file : '"..filename.."'")
        return false
    end

    print("Updating file : '"..filename.."'")

    local outfile = io.open(filename, "w+")
    if not outfile then
        print("Unable to open file for writing '"..filename.."'.")
        return
    end

    outfile:write(table.concat(fileData, "\n"))

    outfile:flush()
    outfile:close()
    return true
end

-- ----------------------------------------------------------------------------
-- main()
-- ----------------------------------------------------------------------------

function main()
      -- load rules file
    if not rulesFilename then
        print("Warning: No rules filename set!")
        rulesFilename = ""
    end

    local rules = loadfile("./"..rulesFilename)
    if rules then
        rules()
        print("Loaded rules file: "..rulesFilename)
    else
        print("ERROR : unable to load rules file: "..rulesFilename)
        print("This could mean that either the file cannot be found or there is an error in it.")
        print("The rules file should be valid lua code, try running it with lua directly.")
    end

    for n = 1, #interface_fileTable do
        local datatypes_filename = interface_fileTable[n].file_path..interface_fileTable[n].datatypes_filename
        local datatypes_file = loadfile(datatypes_filename)
        if datatypes_file then
            datatypes_file()
            print("Loaded data types file: "..datatypes_filename)
        else
            print("WARNING: unable to load data types file: "..datatypes_filename)
        end
    end

    dataTypeTable["wxString"].ValueType = "class" -- FIXME hack for wxString DefType as "special"

    if completeClassRefFileTable then
        for n = 1, #completeClassRefFileTable do
            LoadCompleteClassRef(completeClassRefFileTable[n])
            print("Loaded complete class reference : "..completeClassRefFileTable[n])
        end
    end

    fileTable = { htmlHeader }
    GenerateClassReference(fileTable)
    table.insert(fileTable, "<HR>")
    GenerateEnumReference(fileTable)
    table.insert(fileTable, "<HR>")
    GenerateTestColours(fileTable)
    table.insert(fileTable, "<HR>")
    ReadInterfaceFiles(fileTable)
    GenerateFooter(fileTable)


    WriteTableToFile(output_filename , fileTable)
    --for n = 1, #fileTable do print(fileTable[n]) end

end

main()
