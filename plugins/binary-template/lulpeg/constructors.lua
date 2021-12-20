
-- Constructors

-- Patterns have the following, optional fields:
--
-- - type: the pattern type. ~1 to 1 correspondance with the pattern constructors
--     described in the LPeg documentation.
-- - pattern: the one subpattern held by the pattern, like most captures, or
--     `#pt`, `-pt` and `pt^n`.
-- - aux: any other type of data associated to the pattern. Like the string of a
--     `P"string"`, the range of an `R`, or the list of subpatterns of a `+` or
--     `*` pattern. In some cases, the data is pre-processed. in that case,
--     the `as_is` field holds the data as passed to the constructor.
-- - as_is: see aux.
-- - meta: A table holding meta information about patterns, like their
--     minimal and maximal width, the form they can take when compiled,
--     whether they are terminal or not (no V patterns), and so on.


local getmetatable, ipairs, newproxy, print, setmetatable
    = getmetatable, ipairs, newproxy, print, setmetatable

local t, u, compat
    = require"table", require"util", require"compat"

--[[DBG]] local debug = require"debug"

local t_concat = t.concat

local   copy,   getuniqueid,   id,   map
    ,   weakkey,   weakval
    = u.copy, u.getuniqueid, u.id, u.map
    , u.weakkey, u.weakval



local _ENV = u.noglobals() ----------------------------------------------------



--- The type of cache for each kind of pattern:
--
-- Patterns are memoized using different strategies, depending on what kind of
-- data is associated with them.


local patternwith = {
    constant = {
        "Cp", "true", "false"
    },
    -- only aux
    aux = {
        "string", "any",
        "char", "range", "set",
        "ref", "sequence", "choice",
        "Carg", "Cb"
    },
    -- only sub pattern
    subpt = {
        "unm", "lookahead", "C", "Cf",
        "Cg", "Cs", "Ct", "/zero"
    },
    -- both
    both = {
        "behind", "at least", "at most", "Clb", "Cmt",
        "div_string", "div_number", "div_table", "div_function"
    },
    none = "grammar", "Cc"
}



-------------------------------------------------------------------------------
return function(Builder, LL) --- module wrapper.
--


local S_tostring = Builder.set.tostring


-------------------------------------------------------------------------------
--- Base pattern constructor
--

local newpattern, pattmt
-- This deals with the Lua 5.1/5.2 compatibility, and restricted
-- environements without access to newproxy and/or debug.setmetatable.

-- Augment a pattern with unique identifier.
local next_pattern_id = 1
if compat.proxies and not compat.lua52_len then
    -- Lua 5.1 / LuaJIT without compat.
    local proxycache = weakkey{}
    local __index_LL = {__index = LL}

    local baseproxy = newproxy(true)
    pattmt = getmetatable(baseproxy)
    Builder.proxymt = pattmt

    function pattmt:__index(k)
        return proxycache[self][k]
    end

    function pattmt:__newindex(k, v)
        proxycache[self][k] = v
    end

    function LL.getdirect(p) return proxycache[p] end

    function newpattern(cons)
        local pt = newproxy(baseproxy)
        setmetatable(cons, __index_LL)
        proxycache[pt]=cons
        pt.id = "__ptid" .. next_pattern_id
        next_pattern_id = next_pattern_id + 1
        return pt
    end
else
    -- Fallback if neither __len(table) nor newproxy work
    -- for example in restricted sandboxes.
    if LL.warnings and not compat.lua52_len then
        print("Warning: The `__len` metamethod won't work with patterns, "
            .."use `LL.L(pattern)` for lookaheads.")
    end
    pattmt = LL
    function LL.getdirect (p) return p end

    function newpattern(pt)
        pt.id = "__ptid" .. next_pattern_id
        next_pattern_id = next_pattern_id + 1
        return setmetatable(pt,LL)
    end
end

Builder.newpattern = newpattern

local
function LL_ispattern(pt) return getmetatable(pt) == pattmt end
LL.ispattern = LL_ispattern

function LL.type(pt)
    if LL_ispattern(pt) then
        return "pattern"
    else
        return nil
    end
end


-------------------------------------------------------------------------------
--- The caches
--

local ptcache, meta
local
function resetcache()
    ptcache, meta = {}, weakkey{}
    Builder.ptcache = ptcache
    -- Patterns with aux only.
    for _, p in ipairs(patternwith.aux) do
        ptcache[p] = weakval{}
    end

    -- Patterns with only one sub-pattern.
    for _, p in ipairs(patternwith.subpt) do
        ptcache[p] = weakval{}
    end

    -- Patterns with both
    for _, p in ipairs(patternwith.both) do
        ptcache[p] = {}
    end

    return ptcache
end
LL.resetptcache = resetcache

resetcache()


-------------------------------------------------------------------------------
--- Individual pattern constructor
--

local constructors = {}
Builder.constructors = constructors

constructors["constant"] = {
    truept  = newpattern{ pkind = "true" },
    falsept = newpattern{ pkind = "false" },
    Cppt    = newpattern{ pkind = "Cp" }
}

-- data manglers that produce cache keys for each aux type.
-- `id()` for unspecified cases.
local getauxkey = {
    string = function(aux, as_is) return as_is end,
    table = copy,
    set = function(aux, as_is)
        return S_tostring(aux)
    end,
    range = function(aux, as_is)
        return t_concat(as_is, "|")
    end,
    sequence = function(aux, as_is)
        return t_concat(map(getuniqueid, aux),"|")
    end
}

getauxkey.choice = getauxkey.sequence

constructors["aux"] = function(typ, aux, as_is)
     -- dprint("CONS: ", typ, pt, aux, as_is)
    local cache = ptcache[typ]
    local key = (getauxkey[typ] or id)(aux, as_is)
    local res_pt = cache[key]
    if not res_pt then
        res_pt = newpattern{
            pkind = typ,
            aux = aux,
            as_is = as_is
        }
        cache[key] = res_pt
    end
    return res_pt
end

-- no cache for grammars
constructors["none"] = function(typ, aux)
    -- [[DBG]] print("CONS: ", typ, _, aux)
    -- [[DBG]] print(debug.traceback(1))
    return newpattern{
        pkind = typ,
        aux = aux
    }
end

constructors["subpt"] = function(typ, pt)
    -- [[DP]]print("CONS: ", typ, pt, aux)
    local cache = ptcache[typ]
    local res_pt = cache[pt.id]
    if not res_pt then
        res_pt = newpattern{
            pkind = typ,
            pattern = pt
        }
        cache[pt.id] = res_pt
    end
    return res_pt
end

constructors["both"] = function(typ, pt, aux)
    -- [[DBG]] print("CONS: ", typ, pt, aux)
    local cache = ptcache[typ][aux]
    if not cache then
        ptcache[typ][aux] = weakval{}
        cache = ptcache[typ][aux]
    end
    local res_pt = cache[pt.id]
    if not res_pt then
        res_pt = newpattern{
            pkind = typ,
            pattern = pt,
            aux = aux,
            cache = cache -- needed to keep the cache as long as the pattern exists.
        }
        cache[pt.id] = res_pt
    end
    return res_pt
end

constructors["binary"] = function(typ, a, b)
    -- [[DBG]] print("CONS: ", typ, pt, aux)
    return newpattern{
        a, b;
        pkind = typ,
    }
end

end -- module wrapper

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
