
-- Capture eval

local select, tonumber, tostring, type
    = select, tonumber, tostring, type

local s, t, u = require"string", require"table", require"util"
local s_sub, t_concat
    = s.sub, t.concat

local t_unpack
    = u.unpack

--[[DBG]] local debug, rawset, setmetatable, error, print, expose
--[[DBG]]     = debug, rawset, setmetatable, error, print, u.expose


local _ENV = u.noglobals() ----------------------------------------------------



return function(Builder, LL) -- Decorator wrapper

--[[DBG]] local cprint = LL.cprint

-- The evaluators and the `insert()` helper take as parameters:
-- * caps: the capture array
-- * sbj:  the subject string
-- * vals: the value accumulator, whose unpacked values will be returned
--         by `pattern:match()`
-- * ci:   the current position in capture array.
-- * vi:   the position of the next value to be inserted in the value accumulator.

local eval = {}

local
function insert (caps, sbj, vals, ci, vi)
    local openclose, kind = caps.openclose, caps.kind
    -- [[DBG]] print("Insert - kind = ", kind[ci])
    while kind[ci] and openclose[ci] >= 0 do
        -- [[DBG]] print("Eval, Pre Insert, kind:", kind[ci], ci)
        ci, vi = eval[kind[ci]](caps, sbj, vals, ci, vi)
        -- [[DBG]] print("Eval, Post Insert, kind:", kind[ci], ci)
    end

    return ci, vi
end

function eval.C (caps, sbj, vals, ci, vi)
    if caps.openclose[ci] > 0 then
        vals[vi] = s_sub(sbj, caps.bounds[ci], caps.openclose[ci] - 1)
        return ci + 1, vi + 1
    end

    vals[vi] = false -- pad it for now
    local cj, vj = insert(caps, sbj, vals, ci + 1, vi + 1)
    vals[vi] = s_sub(sbj, caps.bounds[ci], caps.bounds[cj] - 1)
    return cj + 1, vj
end


local
function lookback (caps, label, ci)
    -- [[DBG]] print("lookback( "..tostring(label).." ), ci = "..ci) --.." ..."); --expose(caps)
    -- [[DBG]] if ci == 9 then error() end
    local aux, openclose, kind= caps.aux, caps.openclose, caps.kind

    repeat
        -- [[DBG]] print("Lookback kind: ", kind[ci], ", ci = "..ci, "oc[ci] = ", openclose[ci], "aux[ci] = ", aux[ci])
        ci = ci - 1
        local auxv, oc = aux[ci], openclose[ci]
        if oc < 0 then ci = ci + oc end
        if oc ~= 0 and kind[ci] == "Clb" and label == auxv then
            -- found.
            return ci
        end
    until ci == 1

    -- not found.
    label = type(label) == "string" and "'"..label.."'" or tostring(label)
    error("back reference "..label.." not found")
end

function eval.Cb (caps, sbj, vals, ci, vi)
    -- [[DBG]] print("Eval Cb, ci = "..ci)
    local Cb_ci = lookback(caps, caps.aux[ci], ci)
    -- [[DBG]] print(" Eval Cb, Cb_ci = "..Cb_ci)
    Cb_ci, vi = eval.Cg(caps, sbj, vals, Cb_ci, vi)
    -- [[DBG]] print("/Eval Cb next kind, ", caps.kind[ci + 1], "Values = ..."); expose(vals)

    return ci + 1, vi
end


function eval.Cc (caps, sbj, vals, ci, vi)
    local these_values = caps.aux[ci]
    -- [[DBG]] print"Eval Cc"; expose(these_values)
    for i = 1, these_values.n do
        vi, vals[vi] = vi + 1, these_values[i]
    end
    return ci + 1, vi
end



eval["Cf"] = function() error("NYI: Cf") end

function eval.Cf (caps, sbj, vals, ci, vi)
    if caps.openclose[ci] > 0 then
        error"No First Value"
    end

    local func, Cf_vals, Cf_vi = caps.aux[ci], {}
    ci = ci + 1
    ci, Cf_vi = eval[caps.kind[ci]](caps, sbj, Cf_vals, ci, 1)

    if Cf_vi == 1 then
        error"No first value"
    end

    local result = Cf_vals[1]

    while caps.kind[ci] and caps.openclose[ci] >= 0 do
        ci, Cf_vi = eval[caps.kind[ci]](caps, sbj, Cf_vals, ci, 1)
        result = func(result, t_unpack(Cf_vals, 1, Cf_vi - 1))
    end
    vals[vi] = result
    return ci +1, vi + 1
end



function eval.Cg (caps, sbj, vals, ci, vi)
    -- [[DBG]] print("Gc - caps", ci, caps.openclose[ci]) expose(caps)
    if caps.openclose[ci] > 0 then
        -- [[DBG]] print("Cg - closed")
        vals[vi] = s_sub(sbj, caps.bounds[ci], caps.openclose[ci] - 1)
        return ci + 1, vi + 1
    end
        -- [[DBG]] print("Cg - open ci = ", ci)

    local cj, vj = insert(caps, sbj, vals, ci + 1, vi)
    if vj == vi then
        -- [[DBG]] print("Cg - no inner values")
        vals[vj] = s_sub(sbj, caps.bounds[ci], caps.bounds[cj] - 1)
        vj = vj + 1
    end
    return cj + 1, vj
end


function eval.Clb (caps, sbj, vals, ci, vi)
    local oc = caps.openclose
    if oc[ci] > 0 then
        return ci + 1, vi
    end

    local depth = 0
    repeat
        if oc[ci] == 0 then depth = depth + 1
        elseif oc[ci] < 0 then depth = depth - 1
        end
        ci = ci + 1
    until depth == 0
    return ci, vi
end


function eval.Cp (caps, sbj, vals, ci, vi)
    vals[vi] = caps.bounds[ci]
    return ci + 1, vi + 1
end


function eval.Ct (caps, sbj, vals, ci, vi)
    local aux, openclose, kind = caps. aux, caps.openclose, caps.kind
    local tbl_vals = {}
    vals[vi] = tbl_vals

    if openclose[ci] > 0 then
        return ci + 1, vi + 1
    end

    local tbl_vi, Clb_vals = 1, {}
    ci = ci + 1

    while kind[ci] and openclose[ci] >= 0 do
        if kind[ci] == "Clb" then
            local label, Clb_vi = aux[ci], 1
            ci, Clb_vi = eval.Cg(caps, sbj, Clb_vals, ci, 1)
            if Clb_vi ~= 1 then tbl_vals[label] = Clb_vals[1] end
        else
            ci, tbl_vi =  eval[kind[ci]](caps, sbj, tbl_vals, ci, tbl_vi)
        end
    end
    return ci + 1, vi + 1
end

local inf = 1/0

function eval.value (caps, sbj, vals, ci, vi)
    local val
    -- nils are encoded as inf in both aux and openclose.
    if caps.aux[ci] ~= inf or caps.openclose[ci] ~= inf
        then val = caps.aux[ci]
        -- [[DBG]] print("Eval value = ", val)
    end

    vals[vi] = val
    return ci + 1, vi + 1
end


function eval.Cs (caps, sbj, vals, ci, vi)
    -- [[DBG]] print("Eval Cs - ci = "..ci..", vi = "..vi)
    if caps.openclose[ci] > 0 then
        vals[vi] = s_sub(sbj, caps.bounds[ci], caps.openclose[ci] - 1)
    else
        local bounds, kind, openclose = caps.bounds, caps.kind, caps.openclose
        local start, buffer, Cs_vals, bi, Cs_vi = bounds[ci], {}, {}, 1, 1
        local last
        ci = ci + 1
        -- [[DBG]] print"eval.CS, openclose: "; expose(openclose)
        -- [[DBG]] print("eval.CS, ci =", ci)
        while openclose[ci] >= 0 do
            -- [[DBG]] print(" eval Cs - ci = "..ci..", bi = "..bi.." - LOOP - Buffer = ...")
            -- [[DBG]] u.expose(buffer)
            -- [[DBG]] print(" eval - Cs kind = "..kind[ci])

            last = bounds[ci]
            buffer[bi] = s_sub(sbj, start, last - 1)
            bi = bi + 1

            ci, Cs_vi = eval[kind[ci]](caps, sbj, Cs_vals, ci, 1)
            -- [[DBG]] print("  Cs post eval ci = "..ci..", Cs_vi = "..Cs_vi)
            if Cs_vi > 1 then
                buffer[bi] = Cs_vals[1]
                bi = bi + 1
                start = openclose[ci-1] > 0 and openclose[ci-1] or bounds[ci-1]
            else
                start = last
            end

        -- [[DBG]] print("eval.CS while, ci =", ci)
        end
        buffer[bi] = s_sub(sbj, start, bounds[ci] - 1)

        vals[vi] = t_concat(buffer)
    end
    -- [[DBG]] print("/Eval Cs - ci = "..ci..", vi = "..vi)

    return ci + 1, vi + 1
end


local
function insert_divfunc_results(acc, val_i, ...)
    local n = select('#', ...)
    for i = 1, n do
        val_i, acc[val_i] = val_i + 1, select(i, ...)
    end
    return val_i
end

function eval.div_function (caps, sbj, vals, ci, vi)
    local func = caps.aux[ci]
    local params, divF_vi

    if caps.openclose[ci] > 0 then
        params, divF_vi = {s_sub(sbj, caps.bounds[ci], caps.openclose[ci] - 1)}, 2
    else
        params = {}
        ci, divF_vi = insert(caps, sbj, params, ci + 1, 1)
    end

    ci = ci + 1 -- skip the closed or closing node.
    vi = insert_divfunc_results(vals, vi, func(t_unpack(params, 1, divF_vi - 1)))
    return ci, vi
end


function eval.div_number (caps, sbj, vals, ci, vi)
    local this_aux = caps.aux[ci]
    local divN_vals, divN_vi

    if caps.openclose[ci] > 0 then
        divN_vals, divN_vi = {s_sub(sbj, caps.bounds[ci], caps.openclose[ci] - 1)}, 2
    else
        divN_vals = {}
        ci, divN_vi = insert(caps, sbj, divN_vals, ci + 1, 1)
    end
    ci = ci + 1 -- skip the closed or closing node.

    if this_aux >= divN_vi then error("no capture '"..this_aux.."' in /number capture.") end
    vals[vi] = divN_vals[this_aux]
    return ci, vi + 1
end


local function div_str_cap_refs (caps, ci)
    local opcl = caps.openclose
    local refs = {open=caps.bounds[ci]}

    if opcl[ci] > 0 then
        refs.close = opcl[ci]
        return ci + 1, refs, 0
    end

    local first_ci = ci
    local depth = 1
    ci = ci + 1
    repeat
        local oc = opcl[ci]
        -- [[DBG]] print("/''refs", caps.kind[ci], ci, oc, depth)
        if depth == 1  and oc >= 0 then refs[#refs+1] = ci end
        if oc == 0 then
            depth = depth + 1
        elseif oc < 0 then
            depth = depth - 1
        end
        ci = ci + 1
    until depth == 0
    -- [[DBG]] print("//''refs", ci, ci - first_ci)
    -- [[DBG]] expose(refs)
    -- [[DBG]] print"caps"
    -- [[DBG]] expose(caps)
    refs.close = caps.bounds[ci - 1]
    return ci, refs, #refs
end

function eval.div_string (caps, sbj, vals, ci, vi)
    -- [[DBG]] print("div_string ci = "..ci..", vi = "..vi )
    local n, refs
    local cached
    local cached, divS_vals = {}, {}
    local the_string = caps.aux[ci]

    ci, refs, n = div_str_cap_refs(caps, ci)
    -- [[DBG]] print("  REFS div_string ci = "..ci..", n = ", n, ", refs = ...")
    -- [[DBG]] expose(refs)
    vals[vi] = the_string:gsub("%%([%d%%])", function (d)
        if d == "%" then return "%" end
        d = tonumber(d)
        if not cached[d] then
            if d > n then
                error("no capture at index "..d.." in /string capture.")
            end
            if d == 0 then
                cached[d] = s_sub(sbj, refs.open, refs.close - 1)
            else
                local _, vi = eval[caps.kind[refs[d]]](caps, sbj, divS_vals, refs[d], 1)
                if vi == 1 then error("no values in capture at index"..d.." in /string capture.") end
                cached[d] = divS_vals[1]
            end
        end
        return cached[d]
    end)
    -- [[DBG]] u.expose(vals)
    -- [[DBG]] print("/div_string ci = "..ci..", vi = "..vi )
    return ci, vi + 1
end


function eval.div_table (caps, sbj, vals, ci, vi)
    -- [[DBG]] print("Div_table ci = "..ci..", vi = "..vi )
    local this_aux = caps.aux[ci]
    local key

    if caps.openclose[ci] > 0 then
        key =  s_sub(sbj, caps.bounds[ci], caps.openclose[ci] - 1)
    else
        local divT_vals, _ = {}
        ci, _ = insert(caps, sbj, divT_vals, ci + 1, 1)
        key = divT_vals[1]
    end

    ci = ci + 1
    -- [[DBG]] print("/div_table ci = "..ci..", vi = "..vi )
    -- [[DBG]] print(type(key), key, "...")
    -- [[DBG]] expose(this_aux)
    if this_aux[key] then
        -- [[DBG]] print("/{} success")
        vals[vi] = this_aux[key]
        return ci, vi + 1
    else
        return ci, vi
    end
end



function LL.evaluate (caps, sbj, ci)
    -- [[DBG]] print("*** Eval", caps, sbj, ci)
    -- [[DBG]] expose(caps)
    -- [[DBG]] cprint(caps, sbj, ci)
    local vals = {}
    -- [[DBG]] vals = setmetatable({}, {__newindex = function(self, k,v)
    -- [[DBG]]     print("set Val, ", k, v, debug.traceback(1)) rawset(self, k, v)
    -- [[DBG]] end})
    local _,  vi = insert(caps, sbj, vals, ci, 1)
    return vals, 1, vi - 1
end


end  -- Decorator wrapper


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
