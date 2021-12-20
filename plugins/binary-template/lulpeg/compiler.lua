local assert, error, pairs, print, rawset, select, setmetatable, tostring, type
    = assert, error, pairs, print, rawset, select, setmetatable, tostring, type

--[[DBG]] local debug, print = debug, print

local s, t, u = require"string", require"table", require"util"



local _ENV = u.noglobals() ----------------------------------------------------



local s_byte, s_sub, t_concat, t_insert, t_remove, t_unpack
    = s.byte, s.sub, t.concat, t.insert, t.remove, u.unpack

local   load,   map,   map_all, t_pack
    = u.load, u.map, u.map_all, u.pack

local expose = u.expose

return function(Builder, LL)
local evaluate, LL_ispattern =  LL.evaluate, LL.ispattern
local charset = Builder.charset



local compilers = {}


local
function compile(pt, ccache)
    -- print("Compile", pt.pkind)
    if not LL_ispattern(pt) then
        --[[DBG]] expose(pt)
        error("pattern expected")
    end
    local typ = pt.pkind
    if typ == "grammar" then
        ccache = {}
    elseif typ == "ref" or typ == "choice" or typ == "sequence" then
        if not ccache[pt] then
            ccache[pt] = compilers[typ](pt, ccache)
        end
        return ccache[pt]
    end
    if not pt.compiled then
        -- [[DBG]] print("Not compiled:")
        -- [[DBG]] LL.pprint(pt)
        pt.compiled = compilers[pt.pkind](pt, ccache)
    end

    return pt.compiled
end
LL.compile = compile


local
function clear_captures(ary, ci)
    -- [[DBG]] print("clear caps, ci = ", ci)
    -- [[DBG]] print("TRACE: ", debug.traceback(1))
    -- [[DBG]] expose(ary)
    for i = ci, #ary do ary[i] = nil end
    -- [[DBG]] expose(ary)
    -- [[DBG]] print("/clear caps --------------------------------")
end


local LL_compile, LL_evaluate, LL_P
    = LL.compile, LL.evaluate, LL.P

local function computeidex(i, len)
    if i == 0 or i == 1 or i == nil then return 1
    elseif type(i) ~= "number" then error"number or nil expected for the stating index"
    elseif i > 0 then return i > len and len + 1 or i
    else return len + i < 0 and 1 or len + i + 1
    end
end


------------------------------------------------------------------------------
--- Match

--[[DBG]] local dbgcapsmt = {__newindex = function(self, k,v)
--[[DBG]]     if k ~= #self + 1 then
--[[DBG]]         print("Bad new cap", k, v)
--[[DBG]]         expose(self)
--[[DBG]]         error""
--[[DBG]]     else
--[[DBG]]         rawset(self,k,v)
--[[DBG]]     end
--[[DBG]] end}

--[[DBG]] local
--[[DBG]] function dbgcaps(t) return setmetatable(t, dbgcapsmt) end
local function newcaps()
    return {
        kind = {},
        bounds = {},
        openclose = {},
        aux = -- [[DBG]] dbgcaps
            {}
    }
end

local
function _match(dbg, pt, sbj, si, ...)
        if dbg then -------------
            print("@!!! Match !!!@", pt)
        end ---------------------

    pt = LL_P(pt)

    assert(type(sbj) == "string", "string expected for the match subject")
    si = computeidex(si, #sbj)

        if dbg then -------------
            print(("-"):rep(30))
            print(pt.pkind)
            LL.pprint(pt)
        end ---------------------

    local matcher = compile(pt, {})
    -- capture accumulator
    local caps = newcaps()
    local matcher_state = {grammars = {}, args = {n = select('#',...),...}, tags = {}}

    local  success, final_si, ci = matcher(sbj, si, caps, 1, matcher_state)

        if dbg then -------------
            print("!!! Done Matching !!! success: ", success,
                "final position", final_si, "final cap index", ci,
                "#caps", #caps.openclose)
        end----------------------

    if success then
            -- if dbg then -------------
                -- print"Pre-clear-caps"
                -- expose(caps)
            -- end ---------------------

        clear_captures(caps.kind, ci)
        clear_captures(caps.aux, ci)

            if dbg then -------------
            print("trimmed cap index = ", #caps + 1)
            -- expose(caps)
            LL.cprint(caps, sbj, 1)
            end ---------------------

        local values, _, vi = LL_evaluate(caps, sbj, 1, 1)

            if dbg then -------------
                print("#values", vi)
                expose(values)
            end ---------------------

        if vi == 0
        then return final_si
        else return t_unpack(values, 1, vi) end
    else
        if dbg then print("Failed") end
        return nil
    end
end

function LL.match(...)
    return _match(false, ...)
end

-- With some debug info.
function LL.dmatch(...)
    return _match(true, ...)
end

------------------------------------------------------------------------------
----------------------------------  ,--. ,--. ,--. |_  ,  , ,--. ,--. ,--.  --
--- Captures                        |    .--| |__' |   |  | |    |--' '--,
--                                  `--' `--' |    `-- `--' '    `--' `--'


-- These are all alike:


for _, v in pairs{
    "C", "Cf", "Cg", "Cs", "Ct", "Clb",
    "div_string", "div_table", "div_number", "div_function"
} do
    compilers[v] = load(([=[
    local compile, expose, type, LL = ...
    return function (pt, ccache)
        -- [[DBG]] print("Compiling", "XXXX")
        -- [[DBG]] expose(LL.getdirect(pt))
        -- [[DBG]] LL.pprint(pt)
        local matcher, this_aux = compile(pt.pattern, ccache), pt.aux
        return function (sbj, si, caps, ci, state)
            -- [[DBG]] print("XXXX: ci = ", ci, "             ", "", ", si = ", si, ", type(this_aux) = ", type(this_aux), this_aux)
            -- [[DBG]] expose(caps)

            local ref_ci = ci

            local kind, bounds, openclose, aux
                = caps.kind, caps.bounds, caps.openclose, caps.aux

            kind      [ci] = "XXXX"
            bounds    [ci] = si
            -- openclose = 0 ==> bound is lower bound of the capture.
            openclose [ci] = 0
            caps.aux       [ci] = (this_aux or false)

            local success

            success, si, ci
                = matcher(sbj, si, caps, ci + 1, state)
            if success then
                -- [[DBG]] print("/XXXX: ci = ", ci, ", ref_ci = ", ref_ci, ", si = ", si)
                if ci == ref_ci + 1 then
                    -- [[DBG]] print("full", si)
                    -- a full capture, ==> openclose > 0 == the closing bound.
                    caps.openclose[ref_ci] = si
                else
                    -- [[DBG]] print("closing", si)
                    kind      [ci] = "XXXX"
                    bounds    [ci] = si
                    -- a closing bound. openclose < 0
                    -- (offset in the capture stack between open and close)
                    openclose [ci] = ref_ci - ci
                    aux       [ci] = this_aux or false
                    ci = ci + 1
                end
                -- [[DBG]] expose(caps)
            else
                ci = ci - 1
                -- [[DBG]] print("///XXXX: ci = ", ci, ", ref_ci = ", ref_ci, ", si = ", si)
                -- [[DBG]] expose(caps)
            end
            return success, si, ci
        end
    end]=]):gsub("XXXX", v), v.." compiler")(compile, expose, type, LL)
end




compilers["Carg"] = function (pt, ccache)
    local n = pt.aux
    return function (sbj, si, caps, ci, state)
        if state.args.n < n then error("reference to absent argument #"..n) end
        caps.kind      [ci] = "value"
        caps.bounds    [ci] = si
        -- trick to keep the aux a proper sequence, so that #aux behaves.
        -- if the value is nil, we set both openclose and aux to
        -- +infinity, and handle it appropriately when it is eventually evaluated.
        -- openclose holds a positive value ==> full capture.
        if state.args[n] == nil then
            caps.openclose [ci] = 1/0
            caps.aux       [ci] = 1/0
        else
            caps.openclose [ci] = si
            caps.aux       [ci] = state.args[n]
        end
        return true, si, ci + 1
    end
end

for _, v in pairs{
    "Cb", "Cc", "Cp"
} do
    compilers[v] = load(([=[
    -- [[DBG]]local expose = ...
    return function (pt, ccache)
        local this_aux = pt.aux
        return function (sbj, si, caps, ci, state)
            -- [[DBG]] print("XXXX: ci = ", ci, ", aux = ", this_aux, ", si = ", si)

            caps.kind      [ci] = "XXXX"
            caps.bounds    [ci] = si
            caps.openclose [ci] = si
            caps.aux       [ci] = this_aux or false

            -- [[DBG]] expose(caps)
            return true, si, ci + 1
        end
    end]=]):gsub("XXXX", v), v.." compiler")(expose)
end


compilers["/zero"] = function (pt, ccache)
    local matcher = compile(pt.pattern, ccache)
    return function (sbj, si, caps, ci, state)
        local success, nsi = matcher(sbj, si, caps, ci, state)

        clear_captures(caps.aux, ci)

        return success, nsi, ci
    end
end


local function pack_Cmt_caps(i,...) return i, t_pack(...) end

-- [[DBG]] local MT = 0
compilers["Cmt"] = function (pt, ccache)
    local matcher, func = compile(pt.pattern, ccache), pt.aux
    -- [[DBG]] local mt, n = MT, 0
    -- [[DBG]] MT = MT + 1
    return function (sbj, si, caps, ci, state)
        -- [[DBG]] n = n + 1
        -- [[DBG]] print("\nCmt start, si = ", si, ", ci = ", ci, ".....",  (" <"..mt.."> "..n):rep(8))
        -- [[DBG]] expose(caps)

        local success, Cmt_si, Cmt_ci = matcher(sbj, si, caps, ci, state)
        if not success then
            -- [[DBG]] print("/Cmt No match", ".....",  (" -"..mt.."- "..n):rep(12))
            -- [[DBG]] n = n - 1
            clear_captures(caps.aux, ci)
            -- [[DBG]] expose(caps)

            return false, si, ci
        end
        -- [[DBG]] print("Cmt match! ci = ", ci, ", Cmt_ci = ", Cmt_ci)
        -- [[DBG]] expose(caps)

        local final_si, values

        if Cmt_ci == ci then
            -- [[DBG]] print("Cmt: simple capture: ", si, Cmt_si, s_sub(sbj, si, Cmt_si - 1))
            final_si, values = pack_Cmt_caps(
                func(sbj, Cmt_si, s_sub(sbj, si, Cmt_si - 1))
            )
        else
            -- [[DBG]] print("Cmt: EVAL: ", ci, Cmt_ci)
            clear_captures(caps.aux, Cmt_ci)
            clear_captures(caps.kind, Cmt_ci)
            local cps, _, nn = evaluate(caps, sbj, ci)
            -- [[DBG]] print("POST EVAL ncaps = ", nn)
            -- [[DBG]] expose(cps)
            -- [[DBG]] print("----------------------------------------------------------------")
                        final_si, values = pack_Cmt_caps(
                func(sbj, Cmt_si, t_unpack(cps, 1, nn))
            )
        end
        -- [[DBG]] print("Cmt values ..."); expose(values)
        -- [[DBG]] print("Cmt, final_si = ", final_si, ", Cmt_si = ", Cmt_si)
        -- [[DBG]] print("SOURCE\n",sbj:sub(Cmt_si-20, Cmt_si+20),"\n/SOURCE")
        if not final_si then
            -- [[DBG]] print("/Cmt No return", ".....",  (" +"..mt.."- "..n):rep(12))
            -- [[DBG]] n = n - 1
            -- clear_captures(caps.aux, ci)
            -- [[DBG]] expose(caps)
            return false, si, ci
        end

        if final_si == true then final_si = Cmt_si end

        if type(final_si) == "number"
        and si <= final_si
        and final_si <= #sbj + 1
        then
            -- [[DBG]] print("Cmt Success", values, values and values.n, ci)
            local kind, bounds, openclose, aux
                = caps.kind, caps.bounds, caps.openclose, caps.aux
            for i = 1, values.n do
                kind      [ci] = "value"
                bounds    [ci] = si
                -- See Carg for the rationale of 1/0.
                if values[i] == nil then
                    caps.openclose [ci] = 1/0
                    caps.aux       [ci] = 1/0
                else
                    caps.openclose [ci] = final_si
                    caps.aux       [ci] = values[i]
                end

                ci = ci + 1
            end
        elseif type(final_si) == "number" then
            error"Index out of bounds returned by match-time capture."
        else
            error("Match time capture must return a number, a boolean or nil"
                .." as first argument, or nothing at all.")
        end
            -- [[DBG]] print("/Cmt success - si = ", si,  ", ci = ", ci, ".....",  (" +"..mt.."+ "..n):rep(8))
            -- [[DBG]] n = n - 1
            -- [[DBG]] expose(caps)
        return true, final_si, ci
    end
end


------------------------------------------------------------------------------
------------------------------------  ,-.  ,--. ,-.     ,--. ,--. ,--. ,--. --
--- Other Patterns                    |  | |  | |  | -- |    ,--| |__' `--.
--                                    '  ' `--' '  '    `--' `--' |    `--'


compilers["string"] = function (pt, ccache)
    local S = pt.aux
    local N = #S
    return function(sbj, si, caps, ci, state)
         -- [[DBG]] print("String    ",caps, caps and caps.kind or "'nil'", ci, si, state) --, sbj)
        local in_1 = si - 1
        for i = 1, N do
            local c
            c = s_byte(sbj,in_1 + i)
            if c ~= S[i] then
         -- [[DBG]] print("%FString    ",caps, caps and caps.kind or "'nil'", ci, si, state) --, sbj)
                return false, si, ci
            end
        end
         -- [[DBG]] print("%SString    ",caps, caps and caps.kind or "'nil'", ci, si, state) --, sbj)
        return true, si + N, ci
    end
end


compilers["char"] = function (pt, ccache)
    return load(([=[
        local s_byte, s_char = ...
        return function(sbj, si, caps, ci, state)
            -- [[DBG]] print("Char "..s_char(__C0__).." ", caps.kind[ci - 1], ", si = "..si, ", ci = "..ci, sbj:sub(1, si - 1))
            local c, nsi = s_byte(sbj, si), si + 1
            if c ~= __C0__ then
                return false, si, ci
            end
            return true, nsi, ci
        end]=]):gsub("__C0__", tostring(pt.aux)))(s_byte, ("").char)
end


local
function truecompiled (sbj, si, caps, ci, state)
     -- [[DBG]] print("True    ",caps, caps and caps.kind or "'nil'", ci, si, state) --, sbj)
    return true, si, ci
end
compilers["true"] = function (pt)
    return truecompiled
end


local
function falsecompiled (sbj, si, caps, ci, state)
     -- [[DBG]] print("False   ",caps, caps and caps.kind or "'nil'", ci, si, state) --, sbj)
    return false, si, ci
end
compilers["false"] = function (pt)
    return falsecompiled
end


local
function eoscompiled (sbj, si, caps, ci, state)
     -- [[DBG]] print("EOS     ",caps, caps and caps.kind or "'nil'", ci, si, state) --, sbj)
    return si > #sbj, si, ci
end
compilers["eos"] = function (pt)
    return eoscompiled
end


local
function onecompiled (sbj, si, caps, ci, state)
    -- [[DBG]] print("One", caps.kind[ci - 1], ", si = "..si, ", ci = "..ci, sbj:sub(1, si - 1))
    local char, _ = s_byte(sbj, si), si + 1
    if char
    then return true, si + 1, ci
    else return false, si, ci end
end

compilers["one"] = function (pt)
    return onecompiled
end


compilers["any"] = function (pt)
    local N = pt.aux
    if N == 1 then
        return onecompiled
    else
        N = pt.aux - 1
        return function (sbj, si, caps, ci, state)
            -- [[DBG]] print("Any", caps.kind[ci - 1], ", si = "..si, ", ci = "..ci, sbj:sub(1, si - 1))
            local n = si + N
            if n <= #sbj then
                -- [[DBG]] print("/Any success", caps.kind[ci - 1], ", si = "..si, ", ci = "..ci, sbj:sub(1, si - 1))
                return true, n + 1, ci
            else
                -- [[DBG]] print("/Any fail", caps.kind[ci - 1], ", si = "..si, ", ci = "..ci, sbj:sub(1, si - 1))
                return false, si, ci
            end
        end
    end
end


do
    local function checkpatterns(g)
        for k,v in pairs(g.aux) do
            if not LL_ispattern(v) then
                error(("rule 'A' is not a pattern"):gsub("A", tostring(k)))
            end
        end
    end

    compilers["grammar"] = function (pt, ccache)
        checkpatterns(pt)
        local gram = map_all(pt.aux, compile, ccache)
        local start = gram[1]
        return function (sbj, si, caps, ci, state)
             -- [[DBG]] print("Grammar ",caps, caps and caps.kind or "'nil'", ci, si, state) --, sbj)
            t_insert(state.grammars, gram)
            local success, nsi, ci = start(sbj, si, caps, ci, state)
            t_remove(state.grammars)
             -- [[DBG]] print("%Grammar ",caps, caps and caps.kind or "'nil'", ci, si, state) --, sbj)
            return success, nsi, ci
        end
    end
end

local dummy_acc = {kind={}, bounds={}, openclose={}, aux={}}
compilers["behind"] = function (pt, ccache)
    local matcher, N = compile(pt.pattern, ccache), pt.aux
    return function (sbj, si, caps, ci, state)
         -- [[DBG]] print("Behind  ",caps, caps and caps.kind or "'nil'", ci, si, state) --, sbj)
        if si <= N then return false, si, ci end

        local success = matcher(sbj, si - N, dummy_acc, ci, state)
        -- note that behid patterns cannot hold captures.
        dummy_acc.aux = {}
        return success, si, ci
    end
end

compilers["range"] = function (pt)
    local ranges = pt.aux
    return function (sbj, si, caps, ci, state)
         -- [[DBG]] print("Range   ",caps, caps and caps.kind or "'nil'", ci, si, state) --, sbj)
        local char, nsi = s_byte(sbj, si), si + 1
        for i = 1, #ranges do
            local r = ranges[i]
            if char and r[char]
            then return true, nsi, ci end
        end
        return false, si, ci
    end
end

compilers["set"] = function (pt)
    local s = pt.aux
    return function (sbj, si, caps, ci, state)
        -- [[DBG]] print("Set, Set!, si = ",si, ", ci = ", ci)
        -- [[DBG]] expose(s)
        local char, nsi = s_byte(sbj, si), si + 1
        -- [[DBG]] print("Set, Set!, nsi = ",nsi, ", ci = ", ci, "char = ", char, ", success = ", (not not s[char]))
        if s[char]
        then return true, nsi, ci
        else return false, si, ci end
    end
end

-- hack, for now.
compilers["range"] = compilers.set

compilers["ref"] = function (pt, ccache)
    local name = pt.aux
    local ref
    return function (sbj, si, caps, ci, state)
         -- [[DBG]] print("Reference",caps, caps and caps.kind or "'nil'", ci, si, state) --, sbj)
        if not ref then
            if #state.grammars == 0 then
                error(("rule 'XXXX' used outside a grammar"):gsub("XXXX", tostring(name)))
            elseif not state.grammars[#state.grammars][name] then
                error(("rule 'XXXX' undefined in given grammar"):gsub("XXXX", tostring(name)))
            end
            ref = state.grammars[#state.grammars][name]
        end
        -- [[DBG]] print("Ref - <"..tostring(name)..">, si = ", si, ", ci = ", ci)
        -- [[DBG]] LL.cprint(caps, 1, sbj)
            local success, nsi, nci = ref(sbj, si, caps, ci, state)
        -- [[DBG]] print("/ref - <"..tostring(name)..">, si = ", si, ", ci = ", ci)
        -- [[DBG]] LL.cprint(caps, 1, sbj)
        return success, nsi, nci
    end
end



-- Unroll the loop using a template:
local choice_tpl = [=[
             -- [[DBG]] print(" Choice XXXX, si = ", si, ", ci = ", ci)
            success, si, ci = XXXX(sbj, si, caps, ci, state)
             -- [[DBG]] print(" /Choice XXXX, si = ", si, ", ci = ", ci, ", success = ", success)
            if success then
                return true, si, ci
            else
                --clear_captures(aux, ci)
            end]=]

local function flatten(kind, pt, ccache)
    if pt[2].pkind == kind then
        return compile(pt[1], ccache), flatten(kind, pt[2], ccache)
    else
        return compile(pt[1], ccache), compile(pt[2], ccache)
    end
end

compilers["choice"] = function (pt, ccache)
    local choices = {flatten("choice", pt, ccache)}
    local names, chunks = {}, {}
    for i = 1, #choices do
        local m = "ch"..i
        names[#names + 1] = m
        chunks[ #names  ] = choice_tpl:gsub("XXXX", m)
    end
    names[#names + 1] = "clear_captures"
    choices[ #names ] = clear_captures
    local compiled = t_concat{
        "local ", t_concat(names, ", "), [=[ = ...
        return function (sbj, si, caps, ci, state)
             -- [[DBG]] print("Choice ", ", si = "..si, ", ci = "..ci, sbj:sub(1, si-1)) --, sbj)
            local aux, success = caps.aux, false
            ]=],
            t_concat(chunks,"\n"),[=[--
             -- [[DBG]] print("/Choice ", ", si = "..si, ", ci = "..ci, sbj:sub(1, si-1)) --, sbj)
            return false, si, ci
        end]=]
    }
    -- print(compiled)
    return load(compiled, "Choice")(t_unpack(choices))
end



local sequence_tpl = [=[
            -- [[DBG]] print(" Seq XXXX , si = ",si, ", ci = ", ci)
            success, si, ci = XXXX(sbj, si, caps, ci, state)
            -- [[DBG]] print(" /Seq XXXX , si = ",si, ", ci = ", ci, ", success = ", success)
            if not success then
                -- clear_captures(caps.aux, ref_ci)
                return false, ref_si, ref_ci
            end]=]
compilers["sequence"] = function (pt, ccache)
    local sequence = {flatten("sequence", pt, ccache)}
    local names, chunks = {}, {}
    -- print(n)
    -- for k,v in pairs(pt.aux) do print(k,v) end
    for i = 1, #sequence do
        local m = "seq"..i
        names[#names + 1] = m
        chunks[ #names  ] = sequence_tpl:gsub("XXXX", m)
    end
    names[#names + 1] = "clear_captures"
    sequence[ #names ] = clear_captures
    local compiled = t_concat{
        "local ", t_concat(names, ", "), [=[ = ...
        return function (sbj, si, caps, ci, state)
            local ref_si, ref_ci, success = si, ci
             -- [[DBG]] print("Sequence ", ", si = "..si, ", ci = "..ci, sbj:sub(1, si-1)) --, sbj)
            ]=],
            t_concat(chunks,"\n"),[=[
             -- [[DBG]] print("/Sequence ", ", si = "..si, ", ci = "..ci, sbj:sub(1, si-1)) --, sbj)
            return true, si, ci
        end]=]
    }
    -- print(compiled)
   return load(compiled, "Sequence")(t_unpack(sequence))
end


compilers["at most"] = function (pt, ccache)
    local matcher, n = compile(pt.pattern, ccache), pt.aux
    n = -n
    return function (sbj, si, caps, ci, state)
         -- [[DBG]] print("At most   ",caps, caps and caps.kind or "'nil'", si) --, sbj)
        local success = true
        for i = 1, n do
            success, si, ci = matcher(sbj, si, caps, ci, state)
            if not success then
                -- clear_captures(caps.aux, ci)
                break
            end
        end
        return true, si, ci
    end
end

compilers["at least"] = function (pt, ccache)
    local matcher, n = compile(pt.pattern, ccache), pt.aux
    if n == 0 then
        return function (sbj, si, caps, ci, state)
            -- [[DBG]] print("Rep  0", caps.kind[ci - 1], ", si = "..si, ", ci = "..ci, sbj:sub(1, si - 1))
            local last_si, last_ci
            while true do
                local success
                -- [[DBG]] print(" rep  0", caps.kind[ci - 1], ", si = "..si, ", ci = "..ci, sbj:sub(1, si - 1))
                -- [[DBG]] N=N+1
                last_si, last_ci = si, ci
                success, si, ci = matcher(sbj, si, caps, ci, state)
                if not success then
                    si, ci = last_si, last_ci
                    break
                end
            end
            -- [[DBG]] print("/rep  0", caps.kind[ci - 1], ", si = "..si, ", ci = "..ci, sbj:sub(1, si - 1))
            -- clear_captures(caps.aux, ci)
            return true, si, ci
        end
    elseif n == 1 then
        return function (sbj, si, caps, ci, state)
            -- [[DBG]] print("At least 1 ",caps, caps and caps.kind or "'nil'", ci, si, state) --, sbj)
            local last_si, last_ci
            local success = true
            -- [[DBG]] print("Rep  1", caps.kind[ci - 1], ", si = "..si, ", ci = "..ci)
            success, si, ci = matcher(sbj, si, caps, ci, state)
            if not success then
            -- [[DBG]] print("/Rep  1 Fail")
                -- clear_captures(caps.aux, ci)
                return false, si, ci
            end
            while true do
                local success
                -- [[DBG]] print(" rep  1", caps.kind[ci - 1], ", si = "..si, ", ci = "..ci, sbj:sub(1, si - 1))
                -- [[DBG]] N=N+1
                last_si, last_ci = si, ci
                success, si, ci = matcher(sbj, si, caps, ci, state)
                if not success then
                    si, ci = last_si, last_ci
                    break
                end
            end
            -- [[DBG]] print("/rep  1", caps.kind[ci - 1], ", si = "..si, ", ci = "..ci, sbj:sub(1, si - 1))
             -- clear_captures(caps.aux, ci)
            return true, si, ci
        end
    else
        return function (sbj, si, caps, ci, state)
            -- [[DBG]] print("At least "..n.." ", caps and caps.kind or "'nil'", ci, si, state) --, sbj)
            local last_si, last_ci
            local success = true
            for _ = 1, n do
                success, si, ci = matcher(sbj, si, caps, ci, state)
                if not success then
                    -- clear_captures(caps.aux, ci)
                    return false, si, ci
                end
            end
            while true do
                local success
                -- [[DBG]] print(" rep  "..n, caps.kind[ci - 1], ", si = "..si, ", ci = "..ci, sbj:sub(1, si - 1))
                last_si, last_ci = si, ci
                success, si, ci = matcher(sbj, si, caps, ci, state)
                if not success then
                    si, ci = last_si, last_ci
                    break
                end
            end
            -- [[DBG]] print("/rep  "..n, caps.kind[ci - 1], ", si = "..si, ", ci = "..ci, sbj:sub(1, si - 1))
            -- clear_captures(caps.aux, ci)
            return true, si, ci
        end
    end
end

compilers["unm"] = function (pt, ccache)
    -- P(-1)
    if pt.pkind == "any" and pt.aux == 1 then
        return eoscompiled
    end
    local matcher = compile(pt.pattern, ccache)
    return function (sbj, si, caps, ci, state)
         -- [[DBG]] print("Unm     ", caps, caps and caps.kind or "'nil'", ci, si, state)
        -- Throw captures away
        local success, _, _ = matcher(sbj, si, caps, ci, state)
        -- clear_captures(caps.aux, ci)
        return not success, si, ci
    end
end

compilers["lookahead"] = function (pt, ccache)
    local matcher = compile(pt.pattern, ccache)
    return function (sbj, si, caps, ci, state)
        -- [[DBG]] print("Look ", caps.kind[ci - 1], ", si = "..si, ", ci = "..ci, sbj:sub(1, si - 1))
        -- Throw captures away
        local success, _, _ = matcher(sbj, si, caps, ci, state)
         -- [[DBG]] print("Look, success = ", success, sbj:sub(1, si - 1))
         -- clear_captures(caps.aux, ci)
        return success, si, ci
    end
end

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
