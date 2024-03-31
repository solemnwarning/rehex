-- Constructors

print("rehex.BitOffset():byte() = " .. rehex.BitOffset():byte())
print("rehex.BitOffset():bit() = " .. rehex.BitOffset():bit())

print("rehex.BitOffset(10, 0):byte() = " .. rehex.BitOffset(10, 0):byte())
print("rehex.BitOffset(10, 0):bit() = " .. rehex.BitOffset(10, 0):bit())

print("rehex.BitOffset(10, 2):byte() = " .. rehex.BitOffset(10, 2):byte())
print("rehex.BitOffset(10, 2):bit() = " .. rehex.BitOffset(10, 2):bit())

--- Accessors

print("rehex.BitOffset(0, 0):total_bits() = "    .. rehex.BitOffset(0, 0):total_bits())
print("rehex.BitOffset(10, 0):total_bits() = "   .. rehex.BitOffset(10, 0):total_bits())
print("rehex.BitOffset(10, 3):total_bits() = "   .. rehex.BitOffset(10, 3):total_bits())
print("rehex.BitOffset(-10, 0):total_bits() = "  .. rehex.BitOffset(-10, 0):total_bits())
print("rehex.BitOffset(-10, -3):total_bits() = " .. rehex.BitOffset(-10, -3):total_bits())

print("rehex.BitOffset(0, 0):byte_aligned() = "    .. tostring(rehex.BitOffset(  0,  0):byte_aligned()))
print("rehex.BitOffset(10, 0):byte_aligned() = "   .. tostring(rehex.BitOffset( 10,  0):byte_aligned()))
print("rehex.BitOffset(10, 3):byte_aligned() = "   .. tostring(rehex.BitOffset( 10,  3):byte_aligned()))
print("rehex.BitOffset(-10, 0):byte_aligned() = "  .. tostring(rehex.BitOffset(-10,  0):byte_aligned()))
print("rehex.BitOffset(-10, -3):byte_aligned() = " .. tostring(rehex.BitOffset(-10, -3):byte_aligned()))

print("rehex.BitOffset(0, 0):byte_round_up() = "    .. tostring(rehex.BitOffset(  0,  0):byte_round_up()))
print("rehex.BitOffset(10, 0):byte_round_up() = "   .. tostring(rehex.BitOffset( 10,  0):byte_round_up()))
print("rehex.BitOffset(10, 3):byte_round_up() = "   .. tostring(rehex.BitOffset( 10,  3):byte_round_up()))

--- Comparison operators

print("rehex.BitOffset(10, 0) == rehex.BitOffset(10, 0) = " .. tostring(rehex.BitOffset(10, 0) == rehex.BitOffset(10, 0)))
print("rehex.BitOffset(10, 0) ~= rehex.BitOffset(10, 0) = " .. tostring(rehex.BitOffset(10, 0) ~= rehex.BitOffset(10, 0)))

print("rehex.BitOffset(10, 0) == rehex.BitOffset(20, 0) = " .. tostring(rehex.BitOffset(10, 0) == rehex.BitOffset(20, 0)))
print("rehex.BitOffset(10, 0) ~= rehex.BitOffset(20, 0) = " .. tostring(rehex.BitOffset(10, 0) ~= rehex.BitOffset(20, 0)))

print("rehex.BitOffset(10, 0) < rehex.BitOffset(10, 0) = " .. tostring(rehex.BitOffset(10, 0) < rehex.BitOffset(10, 0)))
print("rehex.BitOffset(10, 0) <= rehex.BitOffset(10, 0) = " .. tostring(rehex.BitOffset(10, 0) <= rehex.BitOffset(10, 0)))
print("rehex.BitOffset(10, 0) > rehex.BitOffset(10, 0) = " .. tostring(rehex.BitOffset(10, 0) > rehex.BitOffset(10, 0)))
print("rehex.BitOffset(10, 0) >= rehex.BitOffset(10, 0) = " .. tostring(rehex.BitOffset(10, 0) >= rehex.BitOffset(10, 0)))

print("rehex.BitOffset(10, 0) < rehex.BitOffset(20, 0) = " .. tostring(rehex.BitOffset(10, 0) < rehex.BitOffset(20, 0)))
print("rehex.BitOffset(10, 0) <= rehex.BitOffset(20, 0) = " .. tostring(rehex.BitOffset(10, 0) <= rehex.BitOffset(20, 0)))
print("rehex.BitOffset(10, 0) > rehex.BitOffset(20, 0) = " .. tostring(rehex.BitOffset(10, 0) > rehex.BitOffset(20, 0)))
print("rehex.BitOffset(10, 0) >= rehex.BitOffset(20, 0) = " .. tostring(rehex.BitOffset(10, 0) >= rehex.BitOffset(20, 0)))

--- Binary operators

print("rehex.BitOffset(1, 0) + rehex.BitOffset(1, 0) = { "
	.. (rehex.BitOffset(1, 0) + rehex.BitOffset(1, 0)):byte() .. ", "
	.. (rehex.BitOffset(1, 0) + rehex.BitOffset(1, 0)):bit() .. " }")

print("rehex.BitOffset(1, 2) + rehex.BitOffset(2, 4) = { "
	.. (rehex.BitOffset(1, 2) + rehex.BitOffset(2, 4)):byte() .. ", "
	.. (rehex.BitOffset(1, 2) + rehex.BitOffset(2, 4)):bit() .. " }")

print("rehex.BitOffset(1, 0) - rehex.BitOffset(1, 0) = { "
	.. (rehex.BitOffset(1, 0) - rehex.BitOffset(1, 0)):byte() .. ", "
	.. (rehex.BitOffset(1, 0) - rehex.BitOffset(1, 0)):bit() .. " }")

print("rehex.BitOffset(1, 2) - rehex.BitOffset(2, 4) = { "
	.. (rehex.BitOffset(1, 2) - rehex.BitOffset(2, 4)):byte() .. ", "
	.. (rehex.BitOffset(1, 2) - rehex.BitOffset(2, 4)):bit() .. " }")

--- Unary operators

print("-(rehex.BitOffset(0, 0)) = { " .. (-rehex.BitOffset(0, 0)):byte() .. ", " .. (-rehex.BitOffset(0, 0)):bit() .. " }")
print("-(rehex.BitOffset(10, 0)) = { " .. (-rehex.BitOffset(10, 0)):byte() .. ", " .. (-rehex.BitOffset(10, 0)):bit() .. " }")
print("-(rehex.BitOffset(10, 7)) = { " .. (-rehex.BitOffset(10, 7)):byte() .. ", " .. (-rehex.BitOffset(10, 7)):bit() .. " }")
print("-(rehex.BitOffset(-10, -7)) = { " .. (-rehex.BitOffset(-10, -7)):byte() .. ", " .. (-rehex.BitOffset(-10, -7)):bit() .. " }")
