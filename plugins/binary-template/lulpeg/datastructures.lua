local getmetatable, pairs, setmetatable, type
    = getmetatable, pairs, setmetatable, type

--[[DBG]] local debug, print = debug, print

local m, t , u = require"math", require"table", require"util"


local compat = require"compat"
local ffi if compat.luajit then
    ffi = require"ffi"
end



local _ENV = u.noglobals() ----------------------------------------------------



local   extend,   load, u_max
    = u.extend, u.load, u.max

--[[DBG]] local expose = u.expose

local m_max, t_concat, t_insert, t_sort
    = m.max, t.concat, t.insert, t.sort

local structfor = {}

--------------------------------------------------------------------------------
--- Byte sets
--

-- Byte sets are sets whose elements are comprised between 0 and 255.
-- We provide two implemetations. One based on Lua tables, and the
-- other based on a FFI bool array.

local byteset_new, isboolset, isbyteset

local byteset_mt = {}

local
function byteset_constructor (upper)
    local set = setmetatable(load(t_concat{
        "return{ [0]=false",
        (", false"):rep(upper),
        " }"
    })(),
    byteset_mt)
    return set
end

if compat.jit then
    local struct, boolset_constructor = {v={}}

    function byteset_mt.__index(s,i)
        -- [[DBG]] print("GI", s,i)
        -- [[DBG]] print(debug.traceback())
        -- [[DBG]] if i == "v" then error("FOOO") end
        if i == nil or i > s.upper then return nil end
        return s.v[i]
    end
    function byteset_mt.__len(s)
        return s.upper
    end
    function byteset_mt.__newindex(s,i,v)
        -- [[DBG]] print("NI", i, v)
        s.v[i] = v
    end

    boolset_constructor = ffi.metatype('struct { int upper; bool v[?]; }', byteset_mt)

    function byteset_new (t)
        -- [[DBG]] print ("Konstructor", type(t), t)
        if type(t) == "number" then
            local res = boolset_constructor(t+1)
            res.upper = t
            --[[DBG]] for i = 0, res.upper do if res[i] then print("K", i, res[i]) end end
            return res
        end
        local upper = u_max(t)

        struct.upper = upper
        if upper > 255 then error"bool_set overflow" end
        local set = boolset_constructor(upper+1)
        set.upper = upper
        for i = 1, #t do set[t[i]] = true end

        return set
    end

    function isboolset(s) return type(s)=="cdata" and ffi.istype(s, boolset_constructor) end
    isbyteset = isboolset
else
    function byteset_new (t)
        -- [[DBG]] print("Set", t)
        if type(t) == "number" then return byteset_constructor(t) end
        local set = byteset_constructor(u_max(t))
        for i = 1, #t do set[t[i]] = true end
        return set
    end

    function isboolset(s) return false end
    function isbyteset (s)
        return getmetatable(s) == byteset_mt
    end
end

local
function byterange_new (low, high)
    -- [[DBG]] print("Range", low,high)
    high = ( low <= high ) and high or -1
    local set = byteset_new(high)
    for i = low, high do
        set[i] = true
    end
    return set
end


local tmpa, tmpb ={}, {}

local
function set_if_not_yet (s, dest)
    if type(s) == "number" then
        dest[s] = true
        return dest
    else
        return s
    end
end

local
function clean_ab (a,b)
    tmpa[a] = nil
    tmpb[b] = nil
end

local
function byteset_union (a ,b)
    local upper = m_max(
        type(a) == "number" and a or #a,
        type(b) == "number" and b or #b
    )
    local A, B
        = set_if_not_yet(a, tmpa)
        , set_if_not_yet(b, tmpb)

    local res = byteset_new(upper)
    for i = 0, upper do
        res[i] = A[i] or B[i] or false
        -- [[DBG]] print(i, res[i])
    end
    -- [[DBG]] print("BS Un ==========================")
    -- [[DBG]] print"/// A ///////////////////////  "
    -- [[DBG]] expose(a)
    -- [[DBG]] expose(A)
    -- [[DBG]] print"*** B ***********************  "
    -- [[DBG]] expose(b)
    -- [[DBG]] expose(B)
    -- [[DBG]] print"   RES   "
    -- [[DBG]] expose(res)
    clean_ab(a,b)
    return res
end

local
function byteset_difference (a, b)
    local res = {}
    for i = 0, 255 do
        res[i] = a[i] and not b[i]
    end
    return res
end

local
function byteset_tostring (s)
    local list = {}
    for i = 0, 255 do
        -- [[DBG]] print(s[i] == true and i)
        list[#list+1] = (s[i] == true) and i or nil
    end
    -- [[DBG]] print("BS TOS", t_concat(list,", "))
    return t_concat(list,", ")
end



structfor.binary = {
    set ={
        new = byteset_new,
        union = byteset_union,
        difference = byteset_difference,
        tostring = byteset_tostring
    },
    Range = byterange_new,
    isboolset = isboolset,
    isbyteset = isbyteset,
    isset = isbyteset
}

--------------------------------------------------------------------------------
--- Bit sets: TODO? to try, at least.
--

-- From Mike Pall's suggestion found at
-- http://lua-users.org/lists/lua-l/2011-08/msg00382.html

-- local bit = require("bit")
-- local band, bor = bit.band, bit.bor
-- local lshift, rshift, rol = bit.lshift, bit.rshift, bit.rol

-- local function bitnew(n)
--   return ffi.new("int32_t[?]", rshift(n+31, 5))
-- end

-- -- Note: the index 'i' is zero-based!
-- local function bittest(b, i)
--   return band(rshift(b[rshift(i, 5)], i), 1) ~= 0
-- end

-- local function bitset(b, i)
--   local x = rshift(i, 5); b[x] = bor(b[x], lshift(1, i))
-- end

-- local function bitclear(b, i)
--   local x = rshift(i, 5); b[x] = band(b[x], rol(-2, i))
-- end



-------------------------------------------------------------------------------
--- General case:
--

-- Set
--

local set_mt = {}

local
function set_new (t)
    -- optimization for byte sets.
    -- [[BS]] if all(map_all(t, function(e)return type(e) == "number" end))
    -- and u_max(t) <= 255
    -- or #t == 0
    -- then
    --     return byteset_new(t)
    -- end
    local set = setmetatable({}, set_mt)
    for i = 1, #t do set[t[i]] = true end
    return set
end

local -- helper for the union code.
function add_elements(a, res)
    -- [[BS]] if isbyteset(a) then
    --     for i = 0, 255 do
    --         if a[i] then res[i] = true end
    --     end
    -- else
    for k in pairs(a) do res[k] = true end
    return res
end

local
function set_union (a, b)
    -- [[BS]] if isbyteset(a) and isbyteset(b) then
    --     return byteset_union(a,b)
    -- end
    a, b = (type(a) == "number") and set_new{a} or a
         , (type(b) == "number") and set_new{b} or b
    local res = set_new{}
    add_elements(a, res)
    add_elements(b, res)
    return res
end

local
function set_difference(a, b)
    local list = {}
    -- [[BS]] if isbyteset(a) and isbyteset(b) then
    --     return byteset_difference(a,b)
    -- end
    a, b = (type(a) == "number") and set_new{a} or a
         , (type(b) == "number") and set_new{b} or b

    -- [[BS]] if isbyteset(a) then
    --     for i = 0, 255 do
    --         if a[i] and not b[i] then
    --             list[#list+1] = i
    --         end
    --     end
    -- elseif isbyteset(b) then
    --     for el in pairs(a) do
    --         if not byteset_has(b, el) then
    --             list[#list + 1] = i
    --         end
    --     end
    -- else
    for el in pairs(a) do
        if a[el] and not b[el] then
            list[#list+1] = el
        end
    end
    -- [[BS]] end
    return set_new(list)
end

local
function set_tostring (s)
    -- [[BS]] if isbyteset(s) then return byteset_tostring(s) end
    local list = {}
    for el in pairs(s) do
        t_insert(list,el)
    end
    t_sort(list)
    return t_concat(list, ",")
end

local
function isset (s)
    return (getmetatable(s) == set_mt)
        -- [[BS]] or isbyteset(s)
end


-- Range
--

-- For now emulated using sets.

local
function range_new (start, finish)
    local list = {}
    for i = start, finish do
        list[#list + 1] = i
    end
    return set_new(list)
end

-- local
-- function range_overlap (r1, r2)
--     return r1[1] <= r2[2] and r2[1] <= r1[2]
-- end

-- local
-- function range_merge (r1, r2)
--     if not range_overlap(r1, r2) then return nil end
--     local v1, v2 =
--         r1[1] < r2[1] and r1[1] or r2[1],
--         r1[2] > r2[2] and r1[2] or r2[2]
--     return newrange(v1,v2)
-- end

-- local
-- function range_isrange (r)
--     return getmetatable(r) == range_mt
-- end

structfor.other = {
    set = {
        new = set_new,
        union = set_union,
        tostring = set_tostring,
        difference = set_difference,
    },
    Range = range_new,
    isboolset = isboolset,
    isbyteset = isbyteset,
    isset = isset,
    isrange = function(a) return false end
}



return function(Builder, LL)
    local cs = (Builder.options or {}).charset or "binary"
    if type(cs) == "string" then
        cs = (cs == "binary") and "binary" or "other"
    else
        cs = cs.binary and "binary" or "other"
    end
    return extend(Builder, structfor[cs])
end


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
