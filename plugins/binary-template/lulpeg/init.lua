
-- LuLPeg.lua


-- a WIP LPeg implementation in pure Lua, by Pierre-Yves Gérardy
-- released under the Romantic WTF Public License (see the end of the file).

-- remove the global tables from the environment
-- they are restored at the end of the file.
-- standard libraries must be require()d.

--[[DBG]] local debug, print_ = require"debug", print
--[[DBG]] local print = function(...)
--[[DBG]]    print_(debug.traceback(2))
--[[DBG]]    print_("RE print", ...)
--[[DBG]]    return ...
--[[DBG]] end

--[[DBG]] local tmp_globals, globalenv = {}, _ENV or _G
--[[DBG]] if false and not release then
--[[DBG]] for lib, tbl in pairs(globalenv) do
--[[DBG]]     if type(tbl) == "table" then
--[[DBG]]         tmp_globals[lib], globalenv[lib] = globalenv[lib], nil
--[[DBG]]     end
--[[DBG]] end
--[[DBG]] end

--[[DBG]] local pairs = pairs

local getmetatable, setmetatable, pcall
    = getmetatable, setmetatable, pcall

local u = require"util"
local   copy,   map,   nop, t_unpack
    = u.copy, u.map, u.nop, u.unpack

-- The module decorators.
local API, charsets, compiler, constructors
    , datastructures, evaluator, factorizer
    , locale, printers, re
    = t_unpack(map(require,
    { "API", "charsets", "compiler", "constructors"
    , "datastructures", "evaluator", "factorizer"
    , "locale", "printers", "re" }))

local _, package = pcall(require, "package")



local _ENV = u.noglobals() ----------------------------------------------------



-- The LPeg version we emulate.
local VERSION = "0.12"

-- The LuLPeg version.
local LuVERSION = "0.1.0"

local function global(self, env) setmetatable(env,{__index = self}) end
local function register(self, env)
    pcall(function()
        package.loaded.lpeg = self
        package.loaded.re = self.re
    end)
    if env then
        env.lpeg, env.re = self, self.re
    end
    return self
end

local
function LuLPeg(options)
    options = options and copy(options) or {}

    -- LL is the module
    -- Builder keeps the state during the module decoration.
    local Builder, LL
        = { options = options, factorizer = factorizer }
        , { new = LuLPeg
          , version = function () return VERSION end
          , luversion = function () return LuVERSION end
          , setmaxstack = nop --Just a stub, for compatibility.
          }

    LL.util = u
    LL.global = global
    LL.register = register
    ;-- Decorate the LuLPeg object.
    charsets(Builder, LL)
    datastructures(Builder, LL)
    printers(Builder, LL)
    constructors(Builder, LL)
    API(Builder, LL)
    evaluator(Builder, LL)
    ;(options.compiler or compiler)(Builder, LL)
    locale(Builder, LL)
    LL.re = re(Builder, LL)

    return LL
end -- LuLPeg

local LL = LuLPeg()

-- restore the global libraries
--[[DBG]] for lib, tbl in pairs(tmp_globals) do
--[[DBG]]     globalenv[lib] = tmp_globals[lib]
--[[DBG]] end


return LL

--                   The Romantic WTF public license.
--                   --------------------------------
--                   a.k.a. version "<3" or simply v3
--
--
--            Dear user,
--
--            The LuLPeg library
--
--                                             \
--                                              '.,__
--                                           \  /
--                                            '/,__
--                                            /
--                                           /
--                                          /
--                       has been          / released
--                  ~ ~ ~ ~ ~ ~ ~ ~       ~ ~ ~ ~ ~ ~ ~ ~
--                under  the  Romantic   WTF Public License.
--               ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~`,´ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~
--               I hereby grant you an irrevocable license to
--                ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~
--                  do what the gentle caress you want to
--                       ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~
--                           with   this   lovely
--                              ~ ~ ~ ~ ~ ~ ~ ~
--                               / thing...
--                              /  ~ ~ ~ ~
--                             /    Love,
--                        #   /      '.'
--                        #######      ·
--                        #####
--                        ###
--                        #
--
--            -- Pierre-Yves
--
--
--            P.S.: Even though I poured my heart into this work,
--                  I _cannot_ provide any warranty regarding
--                  its fitness for _any_ purpose. You
--                  acknowledge that I will not be held liable
--                  for any damage its use could incur.
