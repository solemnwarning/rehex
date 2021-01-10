------------------------------------------------
-- cheap Lua 5.2 basic bitwise operators emulation
-- 2 arguments only (and of course relatively slow)
-- from http://lua-users.org/lists/lua-l/2015-05/msg00120.html

return {
    band = function(a, b) return a & b end,
    bor = function(a, b) return a | b end,
    bxor = function(a, b) return a ~ b end,
    bnot = function(a) return ~a end,
    rshift = function(a, n) return a >> n end,
    lshift = function(a, n) return a << n end,
}
------------------------------------------------
