-- Copyright 2016 Paul Kulchenko

local usage = "Usage: <version number> [<path to `wxLua/bindings/wxwidgets`> [<path to `wxWidgets/interface/wx`>]]"
local version, wxwidgetspath, wxluapath = (table.unpack or unpack)(arg)
if not version or not version:find("^%d+%.%d+[.%d]*$") then print(usage); os.exit(1) end
local vernum = "%wxchkver_"..version:gsub("%.", "_")
print(("Using %s as the version number (%s)"):format(version, vernum))
-- wxwidgets default is on the same level as wxlua folder
wxwidgetspath = wxwidgetspath and wxwidgetspath:gsub("[/\\]+$","").."/" or "../../../wxWidgets/interface/wx/"
-- wxlua default is relative to wxLua/bindings folder
wxluapath = wxluapath and wxluapath:gsub("[/\\]+$","").."/" or "wxwidgets/"

local steps = {
  wxcore_menutool = {
    wxMenu = "menu.h",
    wxMenuBar = "menu.h",
    wxMenuItem = "menuitem.h",
    wxAcceleratorTable = "accel.h",
    wxAcceleratorEntry = "accel.h",
  },
  wxcore_controls = {
    wxTreeCtrl = "treectrl.h",
    wxTextEntry = "textentry.h",
    wxTextCtrl = "textctrl.h",
    wxButton = "button.h",
    wxAnyButton = "anybutton.h",
    wxBitmapButton = "bmpbuttn.h",
    wxToggleButton = "tglbtn.h",
    wxBitmapToggleButton = "tglbtn.h",
  },
  wxbase_file = {
    wxDir = "dir.h",
    wxStandardPaths = "stdpaths.h",
    wxFileName = "filename.h",
  },
  wxcore_windows = {
    wxWindow = "window.h",
  },
  wxcore_appframe = {
    wxTopLevelWindow = "toplevel.h",
    wxNonOwnedWindow = "nonownedwnd.h",
    wxFrame = "frame.h",
    wxApp = "app.h",
    wxAppConsole = "app.h",
    wxStatusBar = "statusbr.h",
    wxStatusBarPane = "statusbr.h",
  },
  wxbase_base = {
    wxEvtHandler = "event.h",
    wxEvent = "event.h",
    wxEventLoopBase = "evtloop.h",
    wxEventFilter = "eventfilter.h",
  },
  wxcore_gdi = {
    wxColour = "colour.h",
    wxFont = "font.h",
    wxFontInfo = "font.h",
    wxPen = "pen.h",
    wxBrush = "brush.h",
    wxPalette = "palette.h",
    wxIcon = "icon.h",
    wxMask = "bitmap.h",
    wxCursor = "cursor.h",
    wxCaret = "caret.h",
    wxDisplay = "display.h",
    wxBitmap = "bitmap.h",
  },
  wxaui_aui = {
    wxAuiToolBarItem = "aui/auibar.h",
    wxAuiToolBarArt = "aui/auibar.h",
    wxAuiToolBar = "aui/auibar.h",
    wxAuiTabArt = "aui/auibook.h",
    wxAuiNotebook = "aui/auibook.h",
    wxAuiDockArt = "aui/dockart.h",
    wxAuiManager = "aui/framemanager.h",
    wxAuiMDIChildFrame = "aui/tabmdi.h",
    wxAuiFloatingFrame = "aui/floatpane.h",
  },
  wxcore_image = {
    wxImage = "image.h",
  },
  wxcore_defsutils = {
    wxProcess = "process.h",
    wxMouseState = "mousestate.h",
    wxKeyboardState = "kbdstate.h",
  },
  wxhtml_html = {
    wxHtmlCell = "html/htmlcell.h",
    wxHtmlDCRenderer = "html/htmprint.h",
  },
  wxxml_xml = {
    wxXmlNode = "xml/xml.h",
    wxXmlDocument = "xml/xml.h",
    wxXmlAttribute = "xml/xml.h",
  },
}
local overrides = {}

for interface, substeps in pairs(steps) do
  for class, file in pairs(substeps) do
    print(("Processing %s (%s.i)"):format(class, interface))
    local name = wxluapath..interface..".i"
    local header = wxwidgetspath..file
    local process = {
      from = "^class [^:,]*%f[%w]"..class.."%f[%W]%s*:?",
      to = "^};",
      extract = "^(%s*)(.-)(%w%S+%b().*;)"
    }

    local types = {COMMENT = 1, FUNCDEF = 2, INTERNALCLASS = 3}
    local curval = ""
    local curtype
    local function funcmerge(s)
      local ltype = false
      if #curval > 0 and s:find("%)[%s%w=]*;") then -- allow `);`, `) const;`, and ) = 0;
        curval, s, ltype, curtype = "", curval..s, types.FUNCDEF, nil
      elseif s:find("([%w_]+)%(") and not s:find("([%w_]+)%b().*;") or #curval > 0 then
        curval, s, ltype, curtype = curval..s, nil, nil, types.FUNCDEF
      end
      return s and s:gsub("%(%s+","("):gsub("%s+%)",")"), ltype
    end
    local function commentmerge(s)
      local ltype = false
      if #curval > 0 and s:find("%*/") or #curval == 0 and s:find('^%s*//') then
        curval, s, ltype, curtype = "", curval..s, types.COMMENT, nil
      elseif s:find("^%s*/%*") or #curval > 0 then
        curval, s, ltype, curtype = curval..s, nil, nil, types.COMMENT
      end
      return s, ltype
    end
    local function internalclass(s) -- detect internal class or enum definitions
      local ltype = false
      if #curval > 0 and s:find("^%s+%};") then
        curval, s, ltype, curtype = "", curval..s, types.INTERNALCLASS, nil
      elseif s:find("^%s*class%s+([%w_]+)%s*$") or s:find("^%s*enum%s*$") or s:find("^%s*enum%s*%w+%s*$") or #curval > 0 then
        curval, s, ltype, curtype = curval..s, nil, nil, types.INTERNALCLASS
      end
      return s, ltype
    end
    local osqual
    local function preprocess(s)
      local ltype
      if curtype == types.FUNCDEF then
        s, ltype = funcmerge(s)
      elseif curtype == types.INTERNALCLASS then
        s, ltype = internalclass(s)
      else
        s, ltype = commentmerge(s)
        if ltype == types.COMMENT then
          osqual = s:match("@onlyfor%{(%w+)%}")
          s = nil
        elseif ltype == false then
          s, ltype = internalclass(s)
          if ltype == false then
            s, ltype = funcmerge(s)
          end
        end
      end
      if osqual and (ltype == types.FUNCDEF or ltype == false) then
        -- prepend OS qualifier to the current function definition
        local oslabel = ({wxosx = "%mac", wxmsw = "%win", wxgtk = "%gtk"})[osqual] or error("Unexpected OS qualifier: "..osqual)
        osqual = nil -- reset the qualifier
        s = s:gsub("(%S)", "%"..oslabel.." %1", 1)
      elseif (ltype == types.FUNCDEF or ltype == false) and (s:find("%W[Iiss]*MSW[%w_]+%(") or s:find("%W[Iiss]*OSX[%w_]+%(") or s:find("%W[Iiss]*Mac[%w_]+%(")) then
        local oslabel = ({OSX = "%mac", Mac = "%mac", MSW = "%win"})[s:match("%W[Iiss]*(%w%w%w)[%w_]+%(")] or error("Unexpected OS prefix: "..s)
        s = s:gsub("(%S)", "%"..oslabel.." %1", 1)
      end
      if s then s = s:gsub(" virtual "," ") end -- remove "virtual" declaration
      if s then s = s:gsub(" explicit "," ") end -- remove "explicit" declaration
      if s then s = s:gsub("^public:","") end -- remove "public:" declaration
      if s and s:find("template%s*<") then s = "" end -- remove template<> strings
      if s and not s:find("%S") then s = s:gsub("%s+", "") end -- remove trailing spaces from empty lines
      if s then s = s:gsub("%s*=%s*0;$",";") end -- remove `= 0` from pure virtual functions
      if s and ltype == types.INTERNALCLASS then print("  skipped: "..s:gsub(".-(class%s+%S+).*", "%1")); s = nil end -- skip internal classes
      if s and ltype ~= types.COMMENT and s:find("~") then print("  skipped: "..s:gsub("^%s+","")); s = nil end -- skip destructors
      if s and s:find("%Woperator%s*<<%W") then print("  skipped: "..s:gsub("^%s+","")); s = nil end -- skip all operators
      if s and s:find("^%s+public%s+wx%w") then print("  skipped: ... "..s:gsub("^%s+","")); s = nil end -- skip multi-inheritance as it's coded in wxlua
      return s, ltype
    end

    local C = {OBSOLETE = 1, COMMENT = 2, VALUE = 3, MATCH = 4, OVERRIDE = 5}
    local override = overrides[class] or {}

    local function signature(name)
      local sig = (name:gsub("%%%w+","") -- remove wxlua directives
        :gsub("%s*//.+","") -- remove trailing comments
        :gsub("/%*.-%*/","") -- remove comments in declarations
        :gsub('%s*=%s*%-?%s*[%w_"]+',"") -- remove initial values
        :gsub(" wxLua", " wx") -- replace wxLuaClass with wxClass for proper match (for example, wxLuaTreeItemData)
        :gsub("([^,%(%w])[%w_]+,","%1,"):gsub("([^,%(%w])[%w_]+%)","%1)") -- remove parameter names, but make sure to keep things like `LuaTable`
        :gsub("%s+", "") -- drop whitespaces
        :gsub("const;",";")
      )
      return sig:gsub("%f[%w]int%*",""):gsub("%f[%w]constint%*",""):gsub(",,+",","):gsub("%(,","("):gsub(",%)",")"), -- drop * parameters
        (sig:gsub("%f[%w]int%*","int"):gsub("%f[%w]constint%*","int"))
    end
    local function merge(defines, process)
      local infile = false
      local output = {}
      local dups = {}
      for line in io.lines(header) do
        if not infile and line:find(process.from)
        or infile and line:find(process.to) then
          infile = not infile
          -- if the last line was "protected:", then remove it
          if (output[#output] or ""):find("^%s*protected:") then table.remove(output) end
        elseif infile then
          -- if the current line include `public:` and the current fragment is inside `protected:`, then remove `protected:`
          if line and line:find("^%s*public:") and (output[#output] or ""):find("^%s*protected:") then table.remove(output) end

          line = preprocess(line)
          if line and line:find("^%s*{%s*$") then
            line = ""
          elseif line and not (output[#output] or ""):find("^%s*protected:") then -- preprocessor may return `nil` to signal concatenated lines
            local indent, retval, name = line:match(process.extract)
            -- if there is a name, but no return value, it's possible that it's a split definition, like
            --    virtual bool
            --    InformFirstDirection(int direction, ...
            -- so try to merge the lines and parse it again
            if name and not name:find("^%s*"..class) and not retval:find("%S") then
              line = (#output > 0 and table.remove(output) or "")..line:gsub("^%s+"," ")
              print("  merged: "..line:gsub("^%s+", ""):gsub("%s+", " "))
              indent, retval, name = line:match(process.extract)
            end
            if name then
              local funcname = name:match("^([%w_]+)%(")
              -- removes spaces and %-directives
              local defname, altname = signature(name)
              if name:find("::%*") or name:find(" T&") then
                print("  skipped method with templatized parameters: "..name:gsub("^%s+", ""):gsub("%s+", " "))
                line = ""
              elseif name:find("%Wint%s*%*") then
                print(((defines[defname] or defines[altname] or funcname and override[funcname]) and "  skipped" or "  missing")
                  .. " overridden method with return parameters: "..name:gsub("^%s+", ""):gsub("%s+", " "))
                line = "" -- skip those descriptions that include return parameters as they can only be mapped manually
              elseif defines[defname] then
                if defines[defname][1] == C.VALUE or defines[defname][1] == C.COMMENT then defines[defname][1] = C.MATCH end
                line = override[funcname] and override[funcname][defname] or defines[defname][2]
                if line:find("%%override_name%W") ~= nil then
                  line = "" -- skip name overrides as those will be listed at the end
                elseif override[funcname] then
                  override[funcname][defname] = nil
                end
              elseif funcname and type(override[funcname]) == 'table' then
                line, override[funcname][defname] = override[funcname][defname] or "", nil
              else
                line = indent..vernum..(retval:find("^!?%%") and " && " or " ")..retval..name:gsub("%s+", " ") -- collapse whitespaces
              end
            end
            if line:find("%S") and (line:find("%b()") or not line:find(";")) and not dups[line] then
              table.insert(output, line)
            end
            if line:find("%b()") or line:find(";") then dups[line] = true end
          end
        end
      end
      -- process items that are no longer present or have override directives
      local removed = {}
      for _, val in pairs(defines) do
        local indent, prefix, name = val[2]:match(process.extract)
        local luakeep = prefix:find("%%override_name%W") ~= nil or val[2]:find("%%add%W") ~= nil
        local rename = prefix:find("%%rename%W")
        if val[1] ~= C.MATCH and (val[1] ~= C.OVERRIDE or luakeep or rename) then
          table.insert(removed, (val[1] ~= C.VALUE or luakeep or rename or val[2]:find(vernum, 1, true))
            and val[2]
            or indent.."!"..vernum..(prefix:find("^!?%%") and " && " or " ")..prefix..name)
          -- remove if it's been already added
          if dups[removed[#removed]] then table.remove(removed) end
        end
      end
      -- add overrides that don't have any matches
      for _, val in pairs(override) do
        for _, line in pairs(val) do
          table.insert(removed, line)
        end
      end
      table.sort(removed)
      return table.concat(output, "\n")..(#removed > 0 and "\n"..table.concat(removed, "\n") or "")
    end

    local infile = false
    local defines = {}
    local out = {}
    for line in io.lines(name) do
      if not infile and line:find(process.from) then
        defines = {}
        table.insert(out, line)
        infile = not infile
      elseif infile and line:find(process.to) then
        table.insert(out, merge(defines, process))
        table.insert(out, line)
        infile = not infile
      elseif infile then
        local _, prefix, name = line:match(process.extract)
        if name then
          local funcname = name:match("^([%w_]+)%(")
          local luakeep = prefix:match("%%override_name%s+([%w_]+)")
          local modified = line:find("%%[ungc]+") or line:find("%%IncRef") or line:find("%%override%W") or line:match("%%not_overload")
          local rename = prefix:match("%%rename%s+([%w_]+)")
          if rename or luakeep then funcname = rename or luakeep end
          -- removes spaces and %-directives
          name = signature(name)
          if not luakeep and not rename and funcname and (override[funcname] or modified) then
            if not override[funcname] then override[funcname] = {} end
            override[funcname][name] = line
          end
          local kind = (prefix:find("!%%wxchkver") and C.OBSOLETE
            or prefix:find("^//") and C.COMMENT
            or (luakeep or rename or funcname and override[funcname]) and C.OVERRIDE
            or C.VALUE)
          defines[rename or name] = {kind, line}
        elseif line:find("#define") or line:find("^%s*{%s*$") then
          table.insert(out, line)
        end
      else
        table.insert(out, line)
      end
    end
    local f = assert(io.open(name, "w"))
    f:write(table.concat(out, "\n").."\n")
    assert(f:close())
  end
end
