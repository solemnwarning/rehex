-- Copyright 2016 Paul Kulchenko

local usage = "Usage: <version number x.x[.x]> [<path to `wxLua/bindings/wxwidgets`> [<path to `wxWidgets/interface/wx`>]]"
local version, wxwidgetspath, wxluapath = (table.unpack or unpack)(arg)
if not version or not version:find("^%d+%.%d+[.%d]*$") then print(usage); os.exit(1) end
local vernum = "%wxchkver_"..version:gsub("%.", "_")
print(("Using %s as the version number (%s)"):format(version, vernum))
-- wxwidgets default is on the same level as wxlua folder
wxwidgetspath = wxwidgetspath and wxwidgetspath:gsub("[/\\]+$","").."/" or "../../../wxWidgets/interface/wx/"
-- wxlua default is relative to wxLua/bindings folder
wxluapath = wxluapath and wxluapath:gsub("[/\\]+$","").."/" or "wxwidgets/"

local name = wxluapath.."wxstc_stc.i"
local sync = wxwidgetspath.."stc/stc.h"

print(("Processing %s and %s"):format(name, sync))

local temps = ""
local function multilinemerge(s)
  s = s:gsub(" wxOVERRIDE",""):gsub("^(%s*)#", "%1// #")
  if #temps > 0 and s:find("%)[%s%w]*;") then -- allow `);` and `) const;`
    temps, s = "", temps..s
  elseif s:find("([%w_]+)%(") and not s:find("([%w_]+)%b()") or #temps > 0 then
    temps, s = temps..s, nil
  end
  return s
end
local process = {
  {from = " {{{", to = "}}}", extract = "^(%s*)(.*#define%s+)(%w%S+)"},
  {from = " {{{", to = "}}}", extract = "^(%s*)(.*#define%s+)(%w%S+)"},
  {from = " {{{", to = "}}}", extract = "^(%s*)(.-%s+)(%w%S+%b().*)",
    preprocess = multilinemerge},
  {from = "Manually declared methods", to = "wxTextEntryBase pure virtual methods", extract = "^(%s*)(.-%s+)(%w%S+%b().*)",
    preprocess = multilinemerge},
}

local C = {OBSOLETE = 1, COMMENT = 2, VALUE = 3, MATCH = 4, OVERRIDE = 5}
local override = {
  GetCurLine = true, StartStyling = true, MarkerGet = true, MarkerNext = true, MarkerPrevious = true,
  CreateLoader = true, MarkerDefine = true, SetMarginMask = true, FormatRange = true,
  StyleSetFontAttr = true, SendMsg = true,
}

local function signature(name)
  local sig = (name:gsub("%%[%w_]+","") -- remove wxlua directives
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

local function merge(defines, process, target)
  local step = -1
  local output = {}
  for line in io.lines(sync) do
    if step < 0 and -step <= #process and line:find(process[-step].from) then
      step = -step
    elseif step > 0 and line:find(process[step].to) then
      step = -(step + 1)
    elseif step == target then
      if process[step].preprocess then line = process[step].preprocess(line) end
      if line then -- preprocessor may return `nil` to signal concatenated lines
        local indent, define, name = line:match(process[step].extract)
        if name then
          local funcname = name:match("^([%w_]+)%(")
          local defsig = defines[signature((funcname and define:match("([%w_]+)%s*$") or "")..name)]
          if defsig then
            if defsig[1] == C.VALUE then defsig[1] = C.MATCH end
            line = defsig[2]
          elseif funcname and type(override[funcname]) == 'string' then
            line = override[funcname]
          else
            line = indent..vernum..(define:find("!?%%") and " && " or " ")..define..name
          end
        end
        table.insert(output, line)
      end
    end
  end
  -- process items that are no longer present
  local removed = {}
  for _, val in pairs(defines) do
    local indent, define, name = val[2]:match(process[target].extract)
    if val[1] ~= C.MATCH and val[1] ~= C.OVERRIDE then
      table.insert(removed, val[1] ~= C.VALUE and val[2]
        or indent.."!"..vernum..(define:find("!?%%") and " && " or " ")..define..name)
    end
  end
  if #removed > 0 then
    table.sort(removed)
    table.insert(removed, 1, "// deprecated items")
    table.insert(removed,"")
  end
  return table.concat(output, "\n").."\n"..table.concat(removed, "\n")
end

local step = -1
local defines = {}
local out = {}
for line in io.lines(name) do
  if step < 0 and -step <= #process and line:find(process[-step].from) then
    defines = {}
    table.insert(out, line)
    step = -step
  elseif step > 0 and line:find(process[step].to) then
    table.insert(out, merge(defines, process, step))
    table.insert(out, line)
    step = -(step + 1)
  elseif step > 0 then
    local _, prefix, name = line:match(process[step].extract)
    if name then
      local funcname = name:match("^([%w_]+)%(")
      if funcname and override[funcname] then override[funcname] = line end
      local kind = prefix:find("!%%") and C.OBSOLETE or prefix:find("^//") and C.COMMENT or (funcname and override[funcname] and C.OVERRIDE) or C.VALUE
      defines[signature((funcname and prefix:match("([%w_]+)%s*$") or "")..name)] = {kind, line}
    end
  else
    table.insert(out, line)
  end
end

local f = assert(io.open(name, "w"))
f:write(table.concat(out, "\n").."\n")
assert(f:close())

print(("Processed %s lines."):format(#out))
