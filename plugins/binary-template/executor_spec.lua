-- Binary Template plugin for REHex
-- Copyright (C) 2021-2022 Daniel Collins <solemnwarning@solemnwarning.net>
--
-- This program is free software; you can redistribute it and/or modify it
-- under the terms of the GNU General Public License version 2 as published by
-- the Free Software Foundation.
--
-- This program is distributed in the hope that it will be useful, but WITHOUT
-- ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
-- FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
-- more details.
--
-- You should have received a copy of the GNU General Public License along with
-- this program; if not, write to the Free Software Foundation, Inc., 51
-- Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

local executor = require 'executor'

local function test_interface(data)
	local log = {}
	
	local timeout = os.time() + 5
	
	local interface = {
		set_data_type = function(offset, length, data_type)
			table.insert(log, "set_data_type(" .. offset .. ", " .. length .. ", " .. data_type .. ")")
		end,
		
		set_comment = function(offset, length, comment_text)
			table.insert(log, "set_comment(" .. offset .. ", " .. length .. ", " .. comment_text .. ")")
		end,
		
		yield = function()
			if os.time() >= timeout
			then
				error("Test timeout")
			end
		end,
		
		print = function(s)
			table.insert(log, "print(" .. s .. ")")
		end,
		
		_data = data,
		
		read_data = function(offset, length)
			return data:sub(offset + 1, offset + length)
		end,
		
		file_length = function()
			return data:len()
		end,
	}
	
	return interface, log
end

describe("executor", function()
	it("runs an empty program", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {})
		
		assert.are.same({}, log)
	end)
	
	it("handles top-level variable declarations", function()
		local interface, log = test_interface(string.char(
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00
		))
		
		executor.execute(interface, {
			{ "test.bt", 1, "variable", "int", "foo", nil, nil },
			{ "test.bt", 1, "variable", "int", "bar", nil, { "test.bt", 1, "num", 4 } },
		})
		
		local expect_log = {
			"set_comment(4, 16, bar)",
			"set_data_type(4, 16, s32le)",
			
			"set_comment(0, 4, foo)",
			"set_data_type(0, 4, s32le)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("doesn't set data type on char[] variables", function()
		local interface, log = test_interface(string.char(
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
		))
		
		executor.execute(interface, {
			{ "test.bt", 1, "variable", "char", "single_char", nil, nil },
			{ "test.bt", 1, "variable", "unsigned char", "single_uchar", nil, nil },
			{ "test.bt", 1, "variable", "char", "char_array", nil, { "test.bt", 1, "num", 10 } },
			{ "test.bt", 1, "variable", "unsigned char", "uchar_array", nil, { "test.bt", 1, "num", 10 } },
		})
		
		local expect_log = {
			"set_comment(2, 10, char_array)",
			
			"set_comment(0, 1, single_char)",
			"set_data_type(0, 1, s8)",
			
			"set_comment(1, 1, single_uchar)",
			"set_data_type(1, 1, u8)",
			
			"set_comment(12, 10, uchar_array)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("handles builtin function calls", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "call", "Printf", { { "test.bt", 1, "str", "Hello world" } } },
			{ "test.bt", 1, "call", "Printf", { { "test.bt", 1, "str", "Goodbye world" } } },
		})
		
		local expect_log = {
			"print(Hello world)",
			"print(Goodbye world)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("handles variadic function calls", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "%s %d" },
				{ "test.bt", 1, "str", "test string" },
				{ "test.bt", 1, "num", 1234 } } },
		})
		
		local expect_log = {
			"print(test string 1234)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("handles custom functions", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "function", "void", "foo", {}, {
				{ "test.bt", 1, "call", "Printf", { { "test.bt", 1, "str", "foo called" } } } } },
			{ "test.bt", 1, "function", "void", "bar", {}, {
				{ "test.bt", 1, "call", "Printf", { { "test.bt", 1, "str", "bar called" } } } } },
			
			{ "test.bt", 1, "call", "foo", {} },
			{ "test.bt", 1, "call", "foo", {} },
			{ "test.bt", 1, "call", "bar", {} },
		})
		
		local expect_log = {
			"print(foo called)",
			"print(foo called)",
			"print(bar called)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("handles custom functions with arguments", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "function", "void", "foo", { { "int", "a" }, { "int", "b" }, { "string", "c" } }, {
				{ "test.bt", 1, "call", "Printf", {
					{ "test.bt", 1, "str", "%d, %d, %s" },
					{ "test.bt", 1, "ref", { "a" } },
					{ "test.bt", 1, "ref", { "b" } },
					{ "test.bt", 1, "ref", { "c" } } } } } },
			
			{ "test.bt", 1, "call", "foo", {
				{ "test.bt", 1, "num", 1234 },
				{ "test.bt", 1, "num", 5678 },
				{ "test.bt", 1, "str", "hello" } } },
		})
		
		local expect_log = {
			"print(1234, 5678, hello)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("errors when attempting to call a function with too few arguments", function()
		local interface, log = test_interface()
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 1, "function", "void", "func", { { "int", "a" }, { "int", "b" }, { "string", "c" } }, {} },
				
				{ "test.bt", 2, "call", "func", {
					{ "test.bt", 3, "num", 1 },
					{ "test.bt", 3, "num", 2 } } },
			})
			end, "Attempt to call function func(int, int, string) with incompatible argument types (const int, const int) at test.bt:2")
	end)
	
	it("errors when attempting to call a function with too many arguments", function()
		local interface, log = test_interface()
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 1, "function", "void", "func", { { "int", "a" }, { "int", "b" }, { "string", "c" } }, {} },
				
				{ "test.bt", 2, "call", "func", {
					{ "test.bt", 3, "num", 1 },
					{ "test.bt", 3, "num", 2 },
					{ "test.bt", 3, "str", "x" },
					{ "test.bt", 3, "str", "y" } } },
			})
			end, "Attempt to call function func(int, int, string) with incompatible argument types (const int, const int, const string, const string) at test.bt:2")
	end)
	
	it("errors when attempting to call a function with incompatible argument types", function()
		local interface, log = test_interface()
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 1, "function", "void", "func", { { "int", "a" }, { "int", "b" }, { "string", "c" } }, {} },
				
				{ "test.bt", 2, "call", "func", {
					{ "test.bt", 3, "num", 1 },
					{ "test.bt", 3, "str", "x" },
					{ "test.bt", 3, "str", "y" } } },
			})
			end, "Attempt to call function func(int, int, string) with incompatible argument types (const int, const string, const string) at test.bt:2")
	end)
	
	it("errors when attempting to call a variadic function with too few arguments", function()
		local interface, log = test_interface()
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 1, "call", "Printf", {} },
			})
			end, "Attempt to call function Printf(string, ...) with incompatible argument types () at test.bt:1")
	end)
	
	it("reads int8 values from file", function()
		local interface, log = test_interface(string.char(
			0x00,
			0xFF
		))
		
		executor.execute(interface, {
			{ "test.bt", 1, "variable", "char", "a", nil, nil },
			{ "test.bt", 1, "variable", "char", "b", nil, nil },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "a = %d" },
				{ "test.bt", 1, "ref", { "a" } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "b = %d" },
				{ "test.bt", 1, "ref", { "b" } } } },
		})
		
		local expect_log = {
			"print(a = 0)",
			"print(b = -1)",
			
			"set_comment(0, 1, a)",
			"set_data_type(0, 1, s8)",
			
			"set_comment(1, 1, b)",
			"set_data_type(1, 1, s8)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("reads uint8 values from file", function()
		local interface, log = test_interface(string.char(
			0x00,
			0xFF
		))
		
		executor.execute(interface, {
			{ "test.bt", 1, "variable", "unsigned char", "a", nil, nil },
			{ "test.bt", 1, "variable", "unsigned char", "b", nil, nil },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "a = %d" },
				{ "test.bt", 1, "ref", { "a" } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "b = %d" },
				{ "test.bt", 1, "ref", { "b" } } } },
		})
		
		local expect_log = {
			"print(a = 0)",
			"print(b = 255)",
			
			"set_comment(0, 1, a)",
			"set_data_type(0, 1, u8)",
			
			"set_comment(1, 1, b)",
			"set_data_type(1, 1, u8)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("reads int16 (little-endian) values from file", function()
		local interface, log = test_interface(string.char(
			0xFF, 0x20,
			0xFF, 0xFF
		))
		
		executor.execute(interface, {
			{ "test.bt", 1, "call", "LittleEndian", {} },
			
			{ "test.bt", 1, "variable", "int16_t", "a", nil, nil },
			{ "test.bt", 1, "variable", "int16_t", "b", nil, nil },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "a = %d" },
				{ "test.bt", 1, "ref", { "a" } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "b = %d" },
				{ "test.bt", 1, "ref", { "b" } } } },
		})
		
		local expect_log = {
			"print(a = 8447)",
			"print(b = -1)",
			
			"set_comment(0, 2, a)",
			"set_data_type(0, 2, s16le)",
			
			"set_comment(2, 2, b)",
			"set_data_type(2, 2, s16le)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("reads int16 (big-endian) values from file", function()
		local interface, log = test_interface(string.char(
			0x20, 0xFF,
			0xFF, 0xFF
		))
		
		executor.execute(interface, {
			{ "test.bt", 1, "call", "BigEndian", {} },
			
			{ "test.bt", 1, "variable", "int16_t", "a", nil, nil },
			{ "test.bt", 1, "variable", "int16_t", "b", nil, nil },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "a = %d" },
				{ "test.bt", 1, "ref", { "a" } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "b = %d" },
				{ "test.bt", 1, "ref", { "b" } } } },
		})
		
		local expect_log = {
			"print(a = 8447)",
			"print(b = -1)",
			
			"set_comment(0, 2, a)",
			"set_data_type(0, 2, s16be)",
			
			"set_comment(2, 2, b)",
			"set_data_type(2, 2, s16be)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("reads uint16 (little-endian) values from file", function()
		local interface, log = test_interface(string.char(
			0xFF, 0x20,
			0xFF, 0xFF
		))
		
		executor.execute(interface, {
			{ "test.bt", 1, "call", "LittleEndian", {} },
			
			{ "test.bt", 1, "variable", "uint16_t", "a", nil, nil },
			{ "test.bt", 1, "variable", "uint16_t", "b", nil, nil },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "a = %d" },
				{ "test.bt", 1, "ref", { "a" } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "b = %d" },
				{ "test.bt", 1, "ref", { "b" } } } },
		})
		
		local expect_log = {
			"print(a = 8447)",
			"print(b = 65535)",
			
			"set_comment(0, 2, a)",
			"set_data_type(0, 2, u16le)",
			
			"set_comment(2, 2, b)",
			"set_data_type(2, 2, u16le)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("reads uint16 (big-endian) values from file", function()
		local interface, log = test_interface(string.char(
			0x20, 0xFF,
			0xFF, 0xFF
		))
		
		executor.execute(interface, {
			{ "test.bt", 1, "call", "BigEndian", {} },
			
			{ "test.bt", 1, "variable", "uint16_t", "a", nil, nil },
			{ "test.bt", 1, "variable", "uint16_t", "b", nil, nil },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "a = %u" },
				{ "test.bt", 1, "ref", { "a" } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "b = %u" },
				{ "test.bt", 1, "ref", { "b" } } } },
		})
		
		local expect_log = {
			"print(a = 8447)",
			"print(b = 65535)",
			
			"set_comment(0, 2, a)",
			"set_data_type(0, 2, u16be)",
			
			"set_comment(2, 2, b)",
			"set_data_type(2, 2, u16be)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("reads int32 (little-endian) values from file", function()
		local interface, log = test_interface(string.char(
			0xAA, 0xBB, 0xCC, 0x00,
			0xFF, 0xFF, 0xFF, 0xFF
		))
		
		executor.execute(interface, {
			{ "test.bt", 1, "call", "LittleEndian", {} },
			
			{ "test.bt", 1, "variable", "int32_t", "a", nil, nil },
			{ "test.bt", 1, "variable", "int32_t", "b", nil, nil },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "a = %d" },
				{ "test.bt", 1, "ref", { "a" } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "b = %d" },
				{ "test.bt", 1, "ref", { "b" } } } },
		})
		
		local expect_log = {
			"print(a = 13417386)",
			"print(b = -1)",
			
			"set_comment(0, 4, a)",
			"set_data_type(0, 4, s32le)",
			
			"set_comment(4, 4, b)",
			"set_data_type(4, 4, s32le)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("reads uint64 (little-endian) values from file", function()
		local interface, log = test_interface(string.char(
			0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x00, 0x00, 0x00,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
		))
		
		executor.execute(interface, {
			{ "test.bt", 1, "call", "LittleEndian", {} },
			
			{ "test.bt", 1, "variable", "uint64_t", "a", nil, nil },
			{ "test.bt", 1, "variable", "uint64_t", "b", nil, nil },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "a = %u" },
				{ "test.bt", 1, "ref", { "a" } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "b = %u" },
				{ "test.bt", 1, "ref", { "b" } } } },
		})
		
		local expect_log = {
			"print(a = 1025923398570)",
			"print(b = 18446744073709551615)",
			
			"set_comment(0, 8, a)",
			"set_data_type(0, 8, u64le)",
			
			"set_comment(8, 8, b)",
			"set_data_type(8, 8, u64le)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("reads array values", function()
		local interface, log = test_interface(string.char(
			0x01, 0x00, 0x00, 0x00,
			0x02, 0x00, 0x00, 0x00,
			0x03, 0x00, 0x00, 0x00,
			0x04, 0x00, 0x00, 0x00
		))
		
		executor.execute(interface, {
			{ "test.bt", 1, "call", "LittleEndian", {} },
			
			{ "test.bt", 1, "variable", "int32_t", "a", nil, { "test.bt", 1, "num", 4 } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "a[0] = %d" },
				{ "test.bt", 1, "ref", { "a", { "test.bt", 1, "num", 0 } } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "a[1] = %d" },
				{ "test.bt", 1, "ref", { "a", { "test.bt", 1, "num", 1 } } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "a[2] = %d" },
				{ "test.bt", 1, "ref", { "a", { "test.bt", 1, "num", 2 } } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "a[3] = %d" },
				{ "test.bt", 1, "ref", { "a", { "test.bt", 1, "num", 3 } } } } },
		})
		
		local expect_log = {
			"print(a[0] = 1)",
			"print(a[1] = 2)",
			"print(a[2] = 3)",
			"print(a[3] = 4)",
			
			"set_comment(0, 16, a)",
			"set_data_type(0, 16, s32le)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("errors on invalid array index operands", function()
		local interface, log = test_interface(string.char(
			0x01, 0x00, 0x00, 0x00,
			0x02, 0x00, 0x00, 0x00,
			0x03, 0x00, 0x00, 0x00,
			0x04, 0x00, 0x00, 0x00
		))
		
		assert.has_error(
			function()
				executor.execute(interface, {
					{ "test.bt", 1, "call", "LittleEndian", {} },
					
					{ "test.bt", 1, "variable", "int32_t", "a", nil, { "test.bt", 1, "num", 4 } },
					
					{ "test.bt", 1, "ref", { "a", { "test.bt", 1, "str", "hello" } } },
				})
			end, "Invalid 'const string' operand to '[]' operator - expected a number at test.bt:1")
		
		assert.has_error(
			function()
				executor.execute(interface, {
					{ "test.bt", 1, "call", "LittleEndian", {} },
					
					{ "test.bt", 1, "variable", "int32_t", "a", nil, { "test.bt", 1, "num", 4 } },
					
					{ "test.bt", 1, "ref", { "a", { "test.bt", 1, "num", -1 } } },
				})
			end, "Attempt to access out-of-range array index -1 at test.bt:1")
		
		assert.has_error(
			function()
				executor.execute(interface, {
					{ "test.bt", 1, "call", "LittleEndian", {} },
					
					{ "test.bt", 1, "variable", "int32_t", "a", nil, { "test.bt", 1, "num", 4 } },
					
					{ "test.bt", 1, "ref", { "a", { "test.bt", 1, "num", 4 } } },
				})
			end, "Attempt to access out-of-range array index 4 at test.bt:1")
	end)
	
	it("errors on array access of non-array variable", function()
		local interface, log = test_interface(string.char(
			0x01, 0x00, 0x00, 0x00,
			0x02, 0x00, 0x00, 0x00,
			0x03, 0x00, 0x00, 0x00,
			0x04, 0x00, 0x00, 0x00
		))
		
		assert.has_error(
			function()
				executor.execute(interface, {
					{ "test.bt", 1, "call", "LittleEndian", {} },
					{ "test.bt", 1, "variable", "int32_t", "a", nil, nil },
					{ "test.bt", 1, "ref", { "a", { "test.bt", 1, "num", 0 } } },
				})
			end, "Attempt to access non-array variable as array at test.bt:1")
	end)
	
	it("handles global structs", function()
		local interface, log = test_interface(string.char(
			0x01, 0x00, 0x00, 0x00,
			0x02, 0x00, 0x00, 0x00,
			0x03, 0x00, 0x00, 0x00,
			0x04, 0x00, 0x00, 0x00
		))
		
		executor.execute(interface, {
			{ "test.bt", 1, "call", "LittleEndian", {} },
			
			{ "test.bt", 1, "struct", "mystruct", {},
			{
				{ "test.bt", 1, "variable", "int", "x", nil, nil },
				{ "test.bt", 1, "variable", "int", "y", nil, nil },
				
				{ "test.bt", 1, "call", "Printf", {
					{ "test.bt", 1, "str", "x = %d" },
					{ "test.bt", 1, "ref", { "x" } } } },
				
				{ "test.bt", 1, "call", "Printf", {
					{ "test.bt", 1, "str", "y = %d" },
					{ "test.bt", 1, "ref", { "y" } } } },
			} },
			
			{ "test.bt", 1, "variable", "struct mystruct", "a", nil, nil },
			{ "test.bt", 1, "variable", "struct mystruct", "b", nil, nil },
		})
		
		local expect_log = {
			"print(x = 1)",
			"print(y = 2)",
			
			"print(x = 3)",
			"print(y = 4)",
			
			"set_comment(0, 4, x)",
			"set_comment(4, 4, y)",
			"set_comment(0, 8, a)",
			"set_data_type(0, 4, s32le)",
			"set_data_type(4, 4, s32le)",
			
			"set_comment(8, 4, x)",
			"set_comment(12, 4, y)",
			"set_comment(8, 8, b)",
			"set_data_type(8, 4, s32le)",
			"set_data_type(12, 4, s32le)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("handles global arrays of structs", function()
		local interface, log = test_interface(string.char(
			0x01, 0x00, 0x00, 0x00,
			0x02, 0x00, 0x00, 0x00,
			0x03, 0x00, 0x00, 0x00,
			0x04, 0x00, 0x00, 0x00
		))
		
		executor.execute(interface, {
			{ "test.bt", 1, "call", "LittleEndian", {} },
			
			{ "test.bt", 1, "struct", "mystruct", {},
			{
				{ "test.bt", 1, "variable", "int", "x", nil, nil },
				{ "test.bt", 1, "variable", "int", "y", nil, nil },
				
				{ "test.bt", 1, "call", "Printf", {
					{ "test.bt", 1, "str", "x = %d" },
					{ "test.bt", 1, "ref", { "x" } } } },
				
				{ "test.bt", 1, "call", "Printf", {
					{ "test.bt", 1, "str", "y = %d" },
					{ "test.bt", 1, "ref", { "y" } } } },
			} },
			
			{ "test.bt", 1, "variable", "struct mystruct", "a", nil, { "test.bt", 1, "num", 2 } },
		})
		
		local expect_log = {
			"print(x = 1)",
			"print(y = 2)",
			
			"print(x = 3)",
			"print(y = 4)",
			
			"set_comment(0, 4, x)",
			"set_comment(4, 4, y)",
			"set_comment(0, 8, a[0])",
			
			"set_comment(8, 4, x)",
			"set_comment(12, 4, y)",
			"set_comment(8, 8, a[1])",
			
			"set_data_type(0, 4, s32le)",
			"set_data_type(4, 4, s32le)",
			
			"set_data_type(8, 4, s32le)",
			"set_data_type(12, 4, s32le)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("handles nested structs", function()
		local interface, log = test_interface(string.char(
			0x01, 0x00, 0x00, 0x00,
			0x02, 0x00, 0x00, 0x00,
			0x03, 0x00, 0x00, 0x00,
			0x04, 0x00, 0x00, 0x00
		))
		
		executor.execute(interface, {
			-- LittleEndian();
			{ "test.bt", 1, "call", "LittleEndian", {} },
			
			-- struct mystruct {
			--     struct bstruct {
			--         int x;
			--         int y;
			--
			--         Printf("bstruct x = %d", x);
			--     };
			--
			--     int x;
			--     struct bstruct y;
			--
			--     Printf("mystruct x = %d", x);
			--     Printf("mystruct y.x = %d", y.x);
			--     Printf("mystruct y.y = %d", y.y);
			-- };
			{ "test.bt", 1, "struct", "mystruct", {},
			{
				{ "test.bt", 1, "struct", "bstruct", {},
				{
					{ "test.bt", 1, "variable", "int", "x", nil, nil },
					{ "test.bt", 1, "variable", "int", "y", nil, nil },
					
					{ "test.bt", 1, "call", "Printf", {
						{ "test.bt", 1, "str", "bstruct x = %d" },
						{ "test.bt", 1, "ref", { "x" } } } },
				} },
				
				{ "test.bt", 1, "variable", "int", "x", nil, nil },
				{ "test.bt", 1, "variable", "struct bstruct", "y", nil, nil },
				
				{ "test.bt", 1, "call", "Printf", {
					{ "test.bt", 1, "str", "mystruct x = %d" },
					{ "test.bt", 1, "ref", { "x" } } } },
				
				{ "test.bt", 1, "call", "Printf", {
					{ "test.bt", 1, "str", "mystruct y.x = %d" },
					{ "test.bt", 1, "ref", { "y", "x" } } } },
				
				{ "test.bt", 1, "call", "Printf", {
					{ "test.bt", 1, "str", "mystruct y.y = %d" },
					{ "test.bt", 1, "ref", { "y", "y" } } } },
			} },
			
			-- struct mystruct a;
			{ "test.bt", 1, "variable", "struct mystruct", "a", nil, nil },
		})
		
		local expect_log = {
			"print(bstruct x = 2)",
			
			"print(mystruct x = 1)",
			"print(mystruct y.x = 2)",
			"print(mystruct y.y = 3)",
			
			"set_comment(0, 4, x)",
			"set_comment(4, 4, x)",
			"set_comment(8, 4, y)",
			"set_comment(4, 8, y)",
			"set_comment(0, 12, a)",
			
			"set_data_type(0, 4, s32le)",
			"set_data_type(4, 4, s32le)",
			"set_data_type(8, 4, s32le)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("errors on outer struct member access from nested structs", function()
		local interface, log = test_interface(string.char(
			0x01, 0x00, 0x00, 0x00,
			0x02, 0x00, 0x00, 0x00,
			0x03, 0x00, 0x00, 0x00,
			0x04, 0x00, 0x00, 0x00
		))
		
		assert.has_error(function()
			executor.execute(interface, {
				-- LittleEndian();
				{ "test.bt", 1, "call", "LittleEndian", {} },
				
				-- struct mystruct {
				--     struct bstruct {
				--         int x;
				--         int y;
				--
				--         Printf("bstruct foo = %d", foo);
				--     };
				--
				--     int foo;
				--     struct bstruct bar;
				-- };
				{ "test.bt", 1, "struct", "mystruct", {},
				{
					{ "test.bt", 1, "struct", "bstruct", {},
					{
						{ "test.bt", 1, "variable", "int", "x", nil, nil },
						{ "test.bt", 1, "variable", "int", "y", nil, nil },
						
						{ "test.bt", 1, "call", "Printf", {
							{ "test.bt", 1, "str", "bstruct foo = %d" },
							{ "test.bt", 1, "ref", { "foo" } } } },
					} },
					
					{ "test.bt", 1, "variable", "int", "foo", nil, nil },
					{ "test.bt", 1, "variable", "struct bstruct", "bar", nil, nil },
				} },
				
				-- struct mystruct a;
				{ "test.bt", 1, "variable", "struct mystruct", "a", nil, nil },
			})
			end, "Attempt to use undefined variable 'foo' at test.bt:1")
	end)
	
	it("handles global structs with variable declarations", function()
		local interface, log = test_interface(string.char(
			0x01, 0x00, 0x00, 0x00,
			0x02, 0x00, 0x00, 0x00,
			0x03, 0x00, 0x00, 0x00,
			0x04, 0x00, 0x00, 0x00
		))
		
		executor.execute(interface, {
			{ "test.bt", 1, "call", "LittleEndian", {} },
			
			{ "test.bt", 1, "struct", "mystruct", {},
			{
				{ "test.bt", 1, "variable", "int", "x", nil, nil },
				{ "test.bt", 1, "variable", "int", "y", nil, nil },
				
				{ "test.bt", 1, "call", "Printf", {
					{ "test.bt", 1, "str", "x = %d" },
					{ "test.bt", 1, "ref", { "x" } } } },
				
				{ "test.bt", 1, "call", "Printf", {
					{ "test.bt", 1, "str", "y = %d" },
					{ "test.bt", 1, "ref", { "y" } } } },
			}, nil, { "a", {}, nil } },
		})
		
		local expect_log = {
			"print(x = 1)",
			"print(y = 2)",
			
			"set_comment(0, 4, x)",
			"set_comment(4, 4, y)",
			"set_comment(0, 8, a)",
			
			"set_data_type(0, 4, s32le)",
			"set_data_type(4, 4, s32le)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("handles global structs with array variable declarations", function()
		local interface, log = test_interface(string.char(
			0x01, 0x00, 0x00, 0x00,
			0x02, 0x00, 0x00, 0x00,
			0x03, 0x00, 0x00, 0x00,
			0x04, 0x00, 0x00, 0x00
		))
		
		executor.execute(interface, {
			{ "test.bt", 1, "call", "LittleEndian", {} },
			
			{ "test.bt", 1, "struct", "mystruct", {},
			{
				{ "test.bt", 1, "variable", "int", "x", nil, nil },
				{ "test.bt", 1, "variable", "int", "y", nil, nil },
				
				{ "test.bt", 1, "call", "Printf", {
					{ "test.bt", 1, "str", "x = %d" },
					{ "test.bt", 1, "ref", { "x" } } } },
				
				{ "test.bt", 1, "call", "Printf", {
					{ "test.bt", 1, "str", "y = %d" },
					{ "test.bt", 1, "ref", { "y" } } } },
			}, nil, { "a", {}, { "test.bt", 1, "num", 2 } } },
		})
		
		local expect_log = {
			"print(x = 1)",
			"print(y = 2)",
			
			"print(x = 3)",
			"print(y = 4)",
			
			"set_comment(0, 4, x)",
			"set_comment(4, 4, y)",
			"set_comment(0, 8, a[0])",
			"set_comment(8, 4, x)",
			"set_comment(12, 4, y)",
			"set_comment(8, 8, a[1])",
			
			"set_data_type(0, 4, s32le)",
			"set_data_type(4, 4, s32le)",
			"set_data_type(8, 4, s32le)",
			"set_data_type(12, 4, s32le)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("handles anonymous structs with variable declarations", function()
		local interface, log = test_interface(string.char(
			0x01, 0x00, 0x00, 0x00,
			0x02, 0x00, 0x00, 0x00,
			0x03, 0x00, 0x00, 0x00,
			0x04, 0x00, 0x00, 0x00
		))
		
		executor.execute(interface, {
			{ "test.bt", 1, "call", "LittleEndian", {} },
			
			{ "test.bt", 1, "struct", nil, {},
			{
				{ "test.bt", 1, "variable", "int", "x", nil, nil },
				{ "test.bt", 1, "variable", "int", "y", nil, nil },
				
				{ "test.bt", 1, "call", "Printf", {
					{ "test.bt", 1, "str", "x = %d" },
					{ "test.bt", 1, "ref", { "x" } } } },
				
				{ "test.bt", 1, "call", "Printf", {
					{ "test.bt", 1, "str", "y = %d" },
					{ "test.bt", 1, "ref", { "y" } } } },
			}, nil, { "a", {}, nil } },
		})
		
		local expect_log = {
			"print(x = 1)",
			"print(y = 2)",
			
			"set_comment(0, 4, x)",
			"set_comment(4, 4, y)",
			"set_comment(0, 8, a)",
			
			"set_data_type(0, 4, s32le)",
			"set_data_type(4, 4, s32le)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("errors on struct member redefinition", function()
		local interface, log = test_interface(string.char(
			0x01, 0x00, 0x00, 0x00,
			0x02, 0x00, 0x00, 0x00,
			0x03, 0x00, 0x00, 0x00,
			0x04, 0x00, 0x00, 0x00
		))
		
		assert.has_error(
			function()
				executor.execute(interface, {
					{ "test.bt", 1, "call", "LittleEndian", {} },
					
					{ "test.bt", 1, "struct", "mystruct", {},
					{
						{ "test.bt", 1, "variable", "int", "x", nil, nil },
						{ "test.bt", 1, "variable", "int", "x", nil, nil },
					} },
					
					{ "test.bt", 1, "variable", "struct mystruct", "a", nil, nil },
					{ "test.bt", 1, "variable", "struct mystruct", "b", nil, nil },
				})
			end, "Attempt to redefine struct member 'x' at test.bt:1")
	end)
	
	it("allows passing arguments to a global struct variable definition", function()
		local interface, log = test_interface(string.char(
			0x01, 0x00, 0x00, 0x00,
			0x02, 0x00, 0x00, 0x00,
			0x03, 0x00, 0x00, 0x00,
			0x04, 0x00, 0x00, 0x00
		))
		
		executor.execute(interface, {
			{ "test.bt", 1, "call", "LittleEndian", {} },
			
			{ "test.bt", 1, "struct", "mystruct", { { "int", "a" }, { "int", "b" }, { "string", "c" } },
			{
				{ "test.bt", 1, "variable", "int", "x", nil, nil },
				{ "test.bt", 1, "variable", "int", "y", nil, nil },
				
				{ "test.bt", 1, "call", "Printf", {
					{ "test.bt", 1, "str", "a = %d, b = %d, c = %s" },
					{ "test.bt", 1, "ref", { "a" } },
					{ "test.bt", 1, "ref", { "b" } },
					{ "test.bt", 1, "ref", { "c" } } } },
			} },
			
			{ "test.bt", 1, "variable", "struct mystruct", "a", {
				{ "test.bt", 1, "num", 1234 },
				{ "test.bt", 1, "num", 5678 },
				{ "test.bt", 1, "str", "hello" } } },
		})
		
		local expect_log = {
			"print(a = 1234, b = 5678, c = hello)",
			
			"set_comment(0, 4, x)",
			"set_comment(4, 4, y)",
			"set_comment(0, 8, a)",
			"set_data_type(0, 4, s32le)",
			"set_data_type(4, 4, s32le)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("errors when declaring a struct variable with too few arguments", function()
		local interface, log = test_interface(string.char(
			0x01, 0x00, 0x00, 0x00,
			0x02, 0x00, 0x00, 0x00,
			0x03, 0x00, 0x00, 0x00,
			0x04, 0x00, 0x00, 0x00
		))
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 1, "call", "LittleEndian", {} },
				
				{ "test.bt", 1, "struct", "mystruct", { { "int", "a" }, { "int", "b" }, { "string", "c" } },
				{
					{ "test.bt", 1, "variable", "int", "x", nil, nil },
					{ "test.bt", 1, "variable", "int", "y", nil, nil },
					
					{ "test.bt", 1, "call", "Printf", {
						{ "test.bt", 1, "str", "a = %d, b = %d, c = %s" },
						{ "test.bt", 1, "ref", { "a" } },
						{ "test.bt", 1, "ref", { "b" } },
						{ "test.bt", 1, "ref", { "c" } } } },
				} },
				
				{ "test.bt", 1, "variable", "struct mystruct", "a", {
					{ "test.bt", 1, "num", 1234 },
					{ "test.bt", 1, "num", 5678 } } },
			})
			end, "Attempt to declare struct type 'struct mystruct' with incompatible argument types (const int, const int) - expected (int, int, string) at test.bt:1")
	end)
	
	it("errors when attempting to declare a struct variable with too many arguments", function()
		local interface, log = test_interface(string.char(
			0x01, 0x00, 0x00, 0x00,
			0x02, 0x00, 0x00, 0x00,
			0x03, 0x00, 0x00, 0x00,
			0x04, 0x00, 0x00, 0x00
		))
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 1, "call", "LittleEndian", {} },
				
				{ "test.bt", 1, "struct", "mystruct", { { "int", "a" }, { "int", "b" }, { "string", "c" } },
				{
					{ "test.bt", 1, "variable", "int", "x", nil, nil },
					{ "test.bt", 1, "variable", "int", "y", nil, nil },
					
					{ "test.bt", 1, "call", "Printf", {
						{ "test.bt", 1, "str", "a = %d, b = %d, c = %s" },
						{ "test.bt", 1, "ref", { "a" } },
						{ "test.bt", 1, "ref", { "b" } },
						{ "test.bt", 1, "ref", { "c" } } } },
				} },
				
				{ "test.bt", 1, "variable", "struct mystruct", "a", {
					{ "test.bt", 1, "num", 1234 },
					{ "test.bt", 1, "num", 5678 },
					{ "test.bt", 1, "str", "hello" },
					{ "test.bt", 1, "str", "hello" } } },
			})
			end, "Attempt to declare struct type 'struct mystruct' with incompatible argument types (const int, const int, const string, const string) - expected (int, int, string) at test.bt:1")
	end)
	
	it("errors when attempting to declare a struct variable with incompatible argument types", function()
		local interface, log = test_interface(string.char(
			0x01, 0x00, 0x00, 0x00,
			0x02, 0x00, 0x00, 0x00,
			0x03, 0x00, 0x00, 0x00,
			0x04, 0x00, 0x00, 0x00
		))
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 1, "call", "LittleEndian", {} },
				
				{ "test.bt", 1, "struct", "mystruct", { { "int", "a" }, { "int", "b" }, { "string", "c" } },
				{
					{ "test.bt", 1, "variable", "int", "x", nil, nil },
					{ "test.bt", 1, "variable", "int", "y", nil, nil },
					
					{ "test.bt", 1, "call", "Printf", {
						{ "test.bt", 1, "str", "a = %d, b = %d, c = %s" },
						{ "test.bt", 1, "ref", { "a" } },
						{ "test.bt", 1, "ref", { "b" } },
						{ "test.bt", 1, "ref", { "c" } } } },
				} },
				
				{ "test.bt", 1, "variable", "struct mystruct", "a", {
					{ "test.bt", 1, "num", 1234 },
					{ "test.bt", 1, "str", "hello" },
					{ "test.bt", 1, "str", "hello" } } },
			})
			end, "Attempt to declare struct type 'struct mystruct' with incompatible argument types (const int, const string, const string) - expected (int, int, string) at test.bt:1")
	end)
	
	it("returns return values from functions", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "function", "int", "func1", {},
			{
				{ "test.bt", 1, "return",
					{ "test.bt", 1, "num", 1 } },
			} },
			
			{ "test.bt", 1, "function", "int", "func2", {},
			{
				{ "test.bt", 1, "return",
					{ "test.bt", 1, "num", 2 } },
			} },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "func1() = %d" },
				{ "test.bt", 1, "call", "func1", {} },
			} },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "func2() = %d" },
				{ "test.bt", 1, "call", "func2", {} },
			} },
		})
		
		local expect_log = {
			"print(func1() = 1)",
			"print(func2() = 2)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("allows early return from functions", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "function", "int", "ifunc", {},
			{
				{ "test.bt", 1, "call", "Printf", {
					{ "test.bt", 1, "str", "foo" } } },
				
				{ "test.bt", 1, "return",
					{ "test.bt", 1, "num", 1 } },
				
				{ "test.bt", 1, "call", "Printf", {
					{ "test.bt", 1, "str", "bar" } } },
			} },
			
			{ "test.bt", 1, "function", "void", "vfunc", {},
			{
				{ "test.bt", 1, "call", "Printf", {
					{ "test.bt", 1, "str", "baz" } } },
				
				{ "test.bt", 1, "return" },
				
				{ "test.bt", 1, "call", "Printf", {
					{ "test.bt", 1, "str", "quz" } } },
			} },
			
			{ "test.bt", 1, "call", "ifunc", {} },
			{ "test.bt", 1, "call", "vfunc", {} },
		})
		
		local expect_log = {
			"print(foo)",
			"print(baz)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("errors on incorrect return types", function()
		local interface, log = test_interface()
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 1, "function", "int", "ifunc", {},
				{
					{ "test.bt", 1, "return",
						{ "test.bt", 1, "str", "hello" } },
				} },
				
				{ "test.bt", 1, "call", "ifunc", {} },
			})
		end, "return operand type 'const string' not compatible with function return type 'int' at test.bt:1")
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 1, "function", "int", "ifunc", {},
				{
					{ "test.bt", 1, "return" },
				} },
				
				{ "test.bt", 1, "call", "ifunc", {} },
			})
		end, "return without an operand in function that returns type 'int' at test.bt:1")
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 1, "function", "void", "vfunc", {},
				{
					{ "test.bt", 1, "return",
						{ "test.bt", 1, "num", 0 } },
				} },
				
				{ "test.bt", 1, "call", "vfunc", {} },
			})
		end, "return operand type 'const int' not compatible with function return type 'void' at test.bt:1")
	end)
	
	it("allows return from if statements within functions", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "function", "int", "ifunc", {},
			{
				{ "test.bt", 1, "call", "Printf", {
					{ "test.bt", 1, "str", "foo" } } },
				
				{ "test.bt", 1, "if",
					{ { "test.bt", 1, "num", 1 }, {
						{ "test.bt", 1, "return",
							{ "test.bt", 1, "num", 1 } },
					} } },
				
				{ "test.bt", 1, "call", "Printf", {
					{ "test.bt", 1, "str", "bar" } } },
			} },
			
			{ "test.bt", 1, "function", "void", "vfunc", {},
			{
				{ "test.bt", 1, "call", "Printf", {
					{ "test.bt", 1, "str", "baz" } } },
				
				{ "test.bt", 1, "if",
					{ { "test.bt", 1, "num", 1 }, {
						{ "test.bt", 1, "return" },
					} } },
				
				{ "test.bt", 1, "call", "Printf", {
					{ "test.bt", 1, "str", "quz" } } },
			} },
			
			{ "test.bt", 1, "call", "ifunc", {} },
			{ "test.bt", 1, "call", "vfunc", {} },
		})
		
		local expect_log = {
			"print(foo)",
			"print(baz)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("allows addition of integers with '+' operator", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "10 + 20 = %d" },
				{ "test.bt", 1, "add",
					{ "test.bt", 1, "num", 10 },
					{ "test.bt", 1, "num", 20 } } } },
		})
		
		local expect_log = {
			"print(10 + 20 = 30)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("allows addition of real numbers with '+' operator", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "10.2 + 20.4 = %.2f" },
				{ "test.bt", 1, "add",
					{ "test.bt", 1, "num", 10.2 },
					{ "test.bt", 1, "num", 20.4 } } } },
		})
		
		local expect_log = {
			"print(10.2 + 20.4 = 30.60)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("allows concatenation of strings with '+' operator", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "abc + def = %s" },
				{ "test.bt", 1, "add",
					{ "test.bt", 1, "str", "abc" },
					{ "test.bt", 1, "str", "def" } } } },
		})
		
		local expect_log = {
			"print(abc + def = abcdef)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("allows concatenation of char arrays with '+' operator", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "local-variable", "char", "char_array1", nil, { "test.bt", 1, "num", 10 }, { "test.bt", 1, "str", "abc" } },
			{ "test.bt", 1, "local-variable", "char", "char_array2", nil, { "test.bt", 1, "num", 10 }, { "test.bt", 1, "str", "def" } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "char_array1 + char_array2 = %s" },
				{ "test.bt", 1, "add",
					{ "test.bt", 1, "ref", { "char_array1" } },
					{ "test.bt", 1, "ref", { "char_array2" } } } } },
		})
		
		local expect_log = {
			"print(char_array1 + char_array2 = abcdef)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("allows concatenation of strings and char arrays with '+' operator", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "local-variable", "char", "char_array2", nil, { "test.bt", 1, "num", 10 }, { "test.bt", 1, "str", "def" } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "abc + char_array2 = %s" },
				{ "test.bt", 1, "add",
					{ "test.bt", 1, "str", "abc" },
					{ "test.bt", 1, "ref", { "char_array2" } } } } },
		})
		
		local expect_log = {
			"print(abc + char_array2 = abcdef)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("errors on addition of strings and numbers with '+' operator", function()
		local interface, log = test_interface()
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 1, "add",
					{ "test.bt", 1, "str", "abc" },
					{ "test.bt", 1, "num", 123 } },
			})
			end, "Invalid operands to '+' operator - 'const string' and 'const int' at test.bt:1")
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 1, "add",
					{ "test.bt", 1, "num", 123 },
					{ "test.bt", 1, "str", "abc" } },
			})
			end, "Invalid operands to '+' operator - 'const int' and 'const string' at test.bt:1")
	end)
	
	it("implements > operator", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "1 > 0 = %d" },
				{ "test.bt", 1, "greater-than",
					{ "test.bt", 1, "num", 1 },
					{ "test.bt", 1, "num", 0 }
				} } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "1 > 1 = %d" },
				{ "test.bt", 1, "greater-than",
					{ "test.bt", 1, "num", 1 },
					{ "test.bt", 1, "num", 1 }
				} } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "1 > 2 = %d" },
				{ "test.bt", 1, "greater-than",
					{ "test.bt", 1, "num", 1 },
					{ "test.bt", 1, "num", 2 }
				} } },
		})
		
		local expect_log = {
			"print(1 > 0 = 1)",
			"print(1 > 1 = 0)",
			"print(1 > 2 = 0)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("implements >= operator", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "1 >= 0 = %d" },
				{ "test.bt", 1, "greater-than-or-equal",
					{ "test.bt", 1, "num", 1 },
					{ "test.bt", 1, "num", 0 }
				} } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "1 >= 1 = %d" },
				{ "test.bt", 1, "greater-than-or-equal",
					{ "test.bt", 1, "num", 1 },
					{ "test.bt", 1, "num", 1 }
				} } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "1 >= 2 = %d" },
				{ "test.bt", 1, "greater-than-or-equal",
					{ "test.bt", 1, "num", 1 },
					{ "test.bt", 1, "num", 2 }
				} } },
		})
		
		local expect_log = {
			"print(1 >= 0 = 1)",
			"print(1 >= 1 = 1)",
			"print(1 >= 2 = 0)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
        it("implements < operator", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "0 < 1 = %d" },
				{ "test.bt", 1, "less-than",
					{ "test.bt", 1, "num", 0 },
					{ "test.bt", 1, "num", 1 }
				} } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "1 < 1 = %d" },
				{ "test.bt", 1, "less-than",
					{ "test.bt", 1, "num", 1 },
					{ "test.bt", 1, "num", 1 }
				} } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "2 < 1 = %d" },
				{ "test.bt", 1, "less-than",
					{ "test.bt", 1, "num", 2 },
					{ "test.bt", 1, "num", 1 }
				} } },
		})
		
		local expect_log = {
			"print(0 < 1 = 1)",
			"print(1 < 1 = 0)",
			"print(2 < 1 = 0)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("implements <= operator", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "0 <= 1 = %d" },
				{ "test.bt", 1, "less-than-or-equal",
					{ "test.bt", 1, "num", 0 },
					{ "test.bt", 1, "num", 1 }
				} } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "1 <= 1 = %d" },
				{ "test.bt", 1, "less-than-or-equal",
					{ "test.bt", 1, "num", 1 },
					{ "test.bt", 1, "num", 1 }
				} } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "2 <= 1 = %d" },
				{ "test.bt", 1, "less-than-or-equal",
					{ "test.bt", 1, "num", 2 },
					{ "test.bt", 1, "num", 1 }
				} } },
		})
		
		local expect_log = {
			"print(0 <= 1 = 1)",
			"print(1 <= 1 = 1)",
			"print(2 <= 1 = 0)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("implements == operator", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "0 == 1 = %d" },
				{ "test.bt", 1, "equal",
					{ "test.bt", 1, "num", 0 },
					{ "test.bt", 1, "num", 1 }
				} } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "1 == 1 = %d" },
				{ "test.bt", 1, "equal",
					{ "test.bt", 1, "num", 1 },
					{ "test.bt", 1, "num", 1 }
				} } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "-1 == 1 = %d" },
				{ "test.bt", 1, "equal",
					{ "test.bt", 1, "num", -1 },
					{ "test.bt", 1, "num", 1 }
				} } },
		})
		
		local expect_log = {
			"print(0 == 1 = 0)",
			"print(1 == 1 = 1)",
			"print(-1 == 1 = 0)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("allows comparing strings with == operator", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "abc == abcd = %d" },
				{ "test.bt", 1, "equal",
					{ "test.bt", 1, "str", "abc" },
					{ "test.bt", 1, "str", "abcd" }
				} } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "abc == abc = %d" },
				{ "test.bt", 1, "equal",
					{ "test.bt", 1, "str", "abc" },
					{ "test.bt", 1, "str", "abc" }
				} } },
		})
		
		local expect_log = {
			"print(abc == abcd = 0)",
			"print(abc == abc = 1)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("errors on comparison of strings and numbers with == operator", function()
		local interface, log = test_interface()
		
		assert.has_error(function()
			executor.execute(interface, {
					{ "test.bt", 1, "equal",
						{ "test.bt", 1, "str", "abc" },
						{ "test.bt", 1, "num", 123 }
					},
			})
			end, "Invalid operands to '==' operator - 'const string' and 'const int' at test.bt:1")
		
		assert.has_error(function()
			executor.execute(interface, {
					{ "test.bt", 1, "equal",
						{ "test.bt", 1, "num", 123 },
						{ "test.bt", 1, "str", "abc" }
					},
			})
			end, "Invalid operands to '==' operator - 'const int' and 'const string' at test.bt:1")
	end)
	
	it("implements != operator", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "0 != 1 = %d" },
				{ "test.bt", 1, "not-equal",
					{ "test.bt", 1, "num", 0 },
					{ "test.bt", 1, "num", 1 }
				} } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "1 != 1 = %d" },
				{ "test.bt", 1, "not-equal",
					{ "test.bt", 1, "num", 1 },
					{ "test.bt", 1, "num", 1 }
				} } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "-1 != 1 = %d" },
				{ "test.bt", 1, "not-equal",
					{ "test.bt", 1, "num", -1 },
					{ "test.bt", 1, "num", 1 }
				} } },
		})
		
		local expect_log = {
			"print(0 != 1 = 1)",
			"print(1 != 1 = 0)",
			"print(-1 != 1 = 1)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("allows comparing strings with != operator", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "abc != abcd = %d" },
				{ "test.bt", 1, "not-equal",
					{ "test.bt", 1, "str", "abc" },
					{ "test.bt", 1, "str", "abcd" }
				} } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "abc != abc = %d" },
				{ "test.bt", 1, "not-equal",
					{ "test.bt", 1, "str", "abc" },
					{ "test.bt", 1, "str", "abc" }
				} } },
		})
		
		local expect_log = {
			"print(abc != abcd = 1)",
			"print(abc != abc = 0)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("errors on comparison of strings and numbers with != operator", function()
		local interface, log = test_interface()
		
		assert.has_error(function()
			executor.execute(interface, {
					{ "test.bt", 1, "not-equal",
						{ "test.bt", 1, "str", "abc" },
						{ "test.bt", 1, "num", 123 }
					},
			})
			end, "Invalid operands to '!=' operator - 'const string' and 'const int' at test.bt:1")
		
		assert.has_error(function()
			executor.execute(interface, {
					{ "test.bt", 1, "not-equal",
						{ "test.bt", 1, "num", 123 },
						{ "test.bt", 1, "str", "abc" }
					},
			})
			end, "Invalid operands to '!=' operator - 'const int' and 'const string' at test.bt:1")
	end)
	
	it("executes statements from first true branch in if statement", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "if",
				{ { "test.bt", 1, "num", 1 }, {
					{ "test.bt", 1, "call", "Printf",
						{ { "test.bt", 1, "str", "true branch executed (1)" } } },
				} },
				{ { "test.bt", 1, "num", 1 }, {
					{ "test.bt", 1, "call", "Printf",
						{ { "test.bt", 1, "str", "second true branch executed (2)" } } },
				} } },
			{ "test.bt", 1, "if",
				{ { "test.bt", 1, "num", 0 }, {
					{ "test.bt", 1, "call", "Printf",
						{ { "test.bt", 1, "str", "false branch executed (3)" } } },
				} },
				{ { "test.bt", 1, "num", 1 }, {
					{ "test.bt", 1, "call", "Printf",
						{ { "test.bt", 1, "str", "true branch executed (4)" } } },
				} } },
			{ "test.bt", 1, "if",
				{ { "test.bt", 1, "num", 0 }, {
					{ "test.bt", 1, "call", "Printf",
						{ { "test.bt", 1, "str", "false branch executed (5)" } } },
				} },
				{ { "test.bt", 1, "num", 0 }, {
					{ "test.bt", 1, "call", "Printf",
						{ { "test.bt", 1, "str", "false branch executed (6)" } } },
				} } },
			{ "test.bt", 1, "if",
				{ { "test.bt", 1, "num", 0 }, {
					{ "test.bt", 1, "call", "Printf",
						{ { "test.bt", 1, "str", "false branch executed (7)" } } },
				} },
				{ {
					{ "test.bt", 1, "call", "Printf",
						{ { "test.bt", 1, "str", "fallback branch executed (8)" } } },
				} } },
		})
		
		local expect_log = {
			"print(true branch executed (1))",
			"print(true branch executed (4))",
			"print(fallback branch executed (8))",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("implements && operator", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			-- TRUE && TRUE
			
			{ "test.bt", 1, "function", "int", "true_before_true", {}, {
				{ "test.bt", 1, "call", "Printf",
					{ { "test.bt", 1, "str", "true_before_true() called" } } },
				{ "test.bt", 1, "return", { "test.bt", 1, "num", 1 } },
			} },
			{ "test.bt", 1, "function", "int", "true_after_true", {}, {
				{ "test.bt", 1, "call", "Printf",
					{ { "test.bt", 1, "str", "true_after_true() called" } } },
				{ "test.bt", 1, "return", { "test.bt", 1, "num", 1 } },
			} },
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "true_before_true() && true_after_true() = %d" },
				{ "test.bt", 1, "logical-and",
					{ "test.bt", 1, "call", "true_before_true", {} },
					{ "test.bt", 1, "call", "true_after_true", {} } },
			} },
			
			-- FALSE && TRUE
			
			{ "test.bt", 1, "function", "int", "false_before_true", {}, {
				{ "test.bt", 1, "call", "Printf",
					{ { "test.bt", 1, "str", "false_before_true() called" } } },
				{ "test.bt", 1, "return", { "test.bt", 1, "num", 0 } },
			} },
			{ "test.bt", 1, "function", "int", "true_after_false", {}, {
				{ "test.bt", 1, "call", "Printf",
					{ { "test.bt", 1, "str", "true_after_false() called" } } },
				{ "test.bt", 1, "return", { "test.bt", 1, "num", 1 } },
			} },
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "false_before_true() && true_after_false() = %d" },
				{ "test.bt", 1, "logical-and",
					{ "test.bt", 1, "call", "false_before_true", {} },
					{ "test.bt", 1, "call", "true_after_false", {} } },
			} },
			
			-- TRUE && FALSE
			
			{ "test.bt", 1, "function", "int", "true_before_false", {}, {
				{ "test.bt", 1, "call", "Printf",
					{ { "test.bt", 1, "str", "true_before_false() called" } } },
				{ "test.bt", 1, "return", { "test.bt", 1, "num", 1 } },
			} },
			{ "test.bt", 1, "function", "int", "false_after_true", {}, {
				{ "test.bt", 1, "call", "Printf",
					{ { "test.bt", 1, "str", "false_after_true() called" } } },
				{ "test.bt", 1, "return", { "test.bt", 1, "num", 0 } },
			} },
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "true_before_false() && false_after_true() = %d" },
				{ "test.bt", 1, "logical-and",
					{ "test.bt", 1, "call", "true_before_false", {} },
					{ "test.bt", 1, "call", "false_after_true", {} } },
			} },
			
			-- FALSE && FALSE
			
			{ "test.bt", 1, "function", "int", "false_before_false", {}, {
				{ "test.bt", 1, "call", "Printf",
					{ { "test.bt", 1, "str", "false_before_false() called" } } },
				{ "test.bt", 1, "return", { "test.bt", 1, "num", 0 } },
			} },
			{ "test.bt", 1, "function", "int", "false_after_false", {}, {
				{ "test.bt", 1, "call", "Printf",
					{ { "test.bt", 1, "str", "false_after_false() called" } } },
				{ "test.bt", 1, "return", { "test.bt", 1, "num", 0 } },
			} },
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "false_before_false() && false_after_false() = %d" },
				{ "test.bt", 1, "logical-and",
					{ "test.bt", 1, "call", "false_before_false", {} },
					{ "test.bt", 1, "call", "false_after_false", {} } },
			} },
		})
		
		local expect_log = {
			"print(true_before_true() called)",
			"print(true_after_true() called)",
			"print(true_before_true() && true_after_true() = 1)",
			
			"print(false_before_true() called)",
			"print(false_before_true() && true_after_false() = 0)",
			
			"print(true_before_false() called)",
			"print(false_after_true() called)",
			"print(true_before_false() && false_after_true() = 0)",
			
			"print(false_before_false() called)",
			"print(false_before_false() && false_after_false() = 0)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("errors on incorrect types to && operator", function()
		local interface, log = test_interface()
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 1, "logical-and",
					{ "test.bt", 1, "str", "hello" },
					{ "test.bt", 1, "num", 1 } },
			})
		end, "Invalid left operand to '&&' operator - expected numeric, got 'const string' at test.bt:1")
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 1, "function", "void", "voidfunc", {}, {} },
				
				{ "test.bt", 1, "logical-and",
					{ "test.bt", 1, "num", 1 },
					{ "test.bt", 1, "call", "voidfunc", {} } },
			})
		end, "Invalid right operand to '&&' operator - expected numeric, got 'void' at test.bt:1")
	end)
	
	it("implements || operator", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			-- TRUE || TRUE
			
			{ "test.bt", 1, "function", "int", "true_before_true", {}, {
				{ "test.bt", 1, "call", "Printf",
					{ { "test.bt", 1, "str", "true_before_true() called" } } },
				{ "test.bt", 1, "return", { "test.bt", 1, "num", 1 } },
			} },
			{ "test.bt", 1, "function", "int", "true_after_true", {}, {
				{ "test.bt", 1, "call", "Printf",
					{ { "test.bt", 1, "str", "true_after_true() called" } } },
				{ "test.bt", 1, "return", { "test.bt", 1, "num", 1 } },
			} },
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "true_before_true() || true_after_true() = %d" },
				{ "test.bt", 1, "logical-or",
					{ "test.bt", 1, "call", "true_before_true", {} },
					{ "test.bt", 1, "call", "true_after_true", {} } },
			} },
			
			-- FALSE || TRUE
			
			{ "test.bt", 1, "function", "int", "false_before_true", {}, {
				{ "test.bt", 1, "call", "Printf",
					{ { "test.bt", 1, "str", "false_before_true() called" } } },
				{ "test.bt", 1, "return", { "test.bt", 1, "num", 0 } },
			} },
			{ "test.bt", 1, "function", "int", "true_after_false", {}, {
				{ "test.bt", 1, "call", "Printf",
					{ { "test.bt", 1, "str", "true_after_false() called" } } },
				{ "test.bt", 1, "return", { "test.bt", 1, "num", 1 } },
			} },
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "false_before_true() || true_after_false() = %d" },
				{ "test.bt", 1, "logical-or",
					{ "test.bt", 1, "call", "false_before_true", {} },
					{ "test.bt", 1, "call", "true_after_false", {} } },
			} },
			
			-- TRUE || FALSE
			
			{ "test.bt", 1, "function", "int", "true_before_false", {}, {
				{ "test.bt", 1, "call", "Printf",
					{ { "test.bt", 1, "str", "true_before_false() called" } } },
				{ "test.bt", 1, "return", { "test.bt", 1, "num", 1 } },
			} },
			{ "test.bt", 1, "function", "int", "false_after_true", {}, {
				{ "test.bt", 1, "call", "Printf",
					{ { "test.bt", 1, "str", "false_after_true() called" } } },
				{ "test.bt", 1, "return", { "test.bt", 1, "num", 0 } },
			} },
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "true_before_false() || false_after_true() = %d" },
				{ "test.bt", 1, "logical-or",
					{ "test.bt", 1, "call", "true_before_false", {} },
					{ "test.bt", 1, "call", "false_after_true", {} } },
			} },
			
			-- FALSE || FALSE
			
			{ "test.bt", 1, "function", "int", "false_before_false", {}, {
				{ "test.bt", 1, "call", "Printf",
					{ { "test.bt", 1, "str", "false_before_false() called" } } },
				{ "test.bt", 1, "return", { "test.bt", 1, "num", 0 } },
			} },
			{ "test.bt", 1, "function", "int", "false_after_false", {}, {
				{ "test.bt", 1, "call", "Printf",
					{ { "test.bt", 1, "str", "false_after_false() called" } } },
				{ "test.bt", 1, "return", { "test.bt", 1, "num", 0 } },
			} },
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "false_before_false() || false_after_false() = %d" },
				{ "test.bt", 1, "logical-or",
					{ "test.bt", 1, "call", "false_before_false", {} },
					{ "test.bt", 1, "call", "false_after_false", {} } },
			} },
		})
		
		local expect_log = {
			"print(true_before_true() called)",
			"print(true_before_true() || true_after_true() = 1)",
			
			"print(false_before_true() called)",
			"print(true_after_false() called)",
			"print(false_before_true() || true_after_false() = 1)",
			
			"print(true_before_false() called)",
			"print(true_before_false() || false_after_true() = 1)",
			
			"print(false_before_false() called)",
			"print(false_after_false() called)",
			"print(false_before_false() || false_after_false() = 0)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("errors on incorrect types to || operator", function()
		local interface, log = test_interface()
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 1, "function", "void", "voidfunc", {}, {} },
				
				{ "test.bt", 1, "logical-or",
					{ "test.bt", 1, "call", "voidfunc", {} },
					{ "test.bt", 1, "num", 1 } },
			})
		end, "Invalid left operand to '||' operator - expected numeric, got 'void' at test.bt:1")
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 1, "logical-or",
					{ "test.bt", 1, "num", 0 },
					{ "test.bt", 1, "str", "hello" } },
			})
		end, "Invalid right operand to '||' operator - expected numeric, got 'const string' at test.bt:1")
	end)
	
	it("implements ! operator", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "!0 = %d" },
				{ "test.bt", 1, "logical-not", { "test.bt", 1, "num", 0 } }
			} },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "!1 = %d" },
				{ "test.bt", 1, "logical-not", { "test.bt", 1, "num", 1 } }
			} },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "!2 = %d" },
				{ "test.bt", 1, "logical-not", { "test.bt", 1, "num", 2 } }
			} },
		})
		
		local expect_log = {
			"print(!0 = 1)",
			"print(!1 = 0)",
			"print(!2 = 0)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("errors on incorrect type to ! operator", function()
		local interface, log = test_interface()
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 1, "function", "void", "voidfunc", {}, {} },
				{ "test.bt", 1, "logical-not", { "test.bt", 1, "call", "voidfunc", {} } },
			})
		end, "Invalid operand to '!' operator - expected numeric, got 'void' at test.bt:1")
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 1, "logical-not", { "test.bt", 1, "str", "hello" } },
			})
		end, "Invalid operand to '!' operator - expected numeric, got 'const string' at test.bt:1")
	end)
	
	it("allows defining local variables", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "local-variable", "int", "foo", nil, nil, nil },
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "foo = %d" },
				{ "test.bt", 1, "ref", { "foo" } } } },
		})
		
		local expect_log = {
			"print(foo = 0)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("allows defining and initialising local variables", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "local-variable", "int", "foo", nil, nil, { "test.bt", 1, "num", 1234 } },
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "foo = %d" },
				{ "test.bt", 1, "ref", { "foo" } } } },
		})
		
		local expect_log = {
			"print(foo = 1234)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("allows assigning local variables", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "local-variable", "int", "foo", nil, nil, nil },
			{ "test.bt", 1, "assign",
				{ "test.bt", 1, "ref", { "foo" } },
				{ "test.bt", 1, "num", 5678 } },
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "foo = %d" },
				{ "test.bt", 1, "ref", { "foo" } } } },
		})
		
		local expect_log = {
			"print(foo = 5678)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("allows initialising a char array with a string", function()
		local interface, log = test_interface()
		
		local print_elem = function(i)
			return { "test.bt", 10 + i, "call", "Printf", {
				{ "test.bt", 10 + i, "str", "char_array[" .. i .. "] = %d" },
				{ "test.bt", 10 + i, "ref", { "char_array", { "test.bt", 10 + i, "num", i } } } } }
		end
		
		executor.execute(interface, {
			{ "test.bt", 1, "local-variable", "char", "char_array", nil, { "test.bt", 1, "num", 10 }, { "test.bt", 1, "str", "hello" } },
			
			print_elem(0),
			print_elem(1),
			print_elem(2),
			print_elem(3),
			print_elem(4),
			print_elem(5),
			print_elem(6),
			print_elem(7),
			print_elem(8),
			print_elem(9),
		})
		
		local expect_log = {
			"print(char_array[0] = 104)",
			"print(char_array[1] = 101)",
			"print(char_array[2] = 108)",
			"print(char_array[3] = 108)",
			"print(char_array[4] = 111)",
			"print(char_array[5] = 0)",
			"print(char_array[6] = 0)",
			"print(char_array[7] = 0)",
			"print(char_array[8] = 0)",
			"print(char_array[9] = 0)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("allows assigning a string value to a char array", function()
		local interface, log = test_interface()
		
		local print_elem = function(i)
			return { "test.bt", 10 + i, "call", "Printf", {
				{ "test.bt", 10 + i, "str", "char_array[" .. i .. "] = %d" },
				{ "test.bt", 10 + i, "ref", { "char_array", { "test.bt", 10 + i, "num", i } } } } }
		end
		
		executor.execute(interface, {
			{ "test.bt", 1, "local-variable", "char", "char_array", nil, { "test.bt", 1, "num", 10 }, nil },
			{ "test.bt", 2, "assign", { "test.bt", 1, "ref", { "char_array" } }, { "test.bt", 1, "str", "hello" } },
			
			print_elem(0),
			print_elem(1),
			print_elem(2),
			print_elem(3),
			print_elem(4),
			print_elem(5),
			print_elem(6),
			print_elem(7),
			print_elem(8),
			print_elem(9),
		})
		
		local expect_log = {
			"print(char_array[0] = 104)",
			"print(char_array[1] = 101)",
			"print(char_array[2] = 108)",
			"print(char_array[3] = 108)",
			"print(char_array[4] = 111)",
			"print(char_array[5] = 0)",
			"print(char_array[6] = 0)",
			"print(char_array[7] = 0)",
			"print(char_array[8] = 0)",
			"print(char_array[9] = 0)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("allows initialising a string with a char array", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "local-variable", "char", "char_array", nil, { "test.bt", 1, "num", 10 }, { "test.bt", 1, "str", "hello" } },
			{ "test.bt", 2, "local-variable", "string", "string_var", nil, nil, { "test.bt", 2, "ref", { "char_array" } } },
			
			{ "test.bt", 10, "call", "Printf", {
				{ "test.bt", 10, "str", "string_var = %s" },
				{ "test.bt", 10, "ref", { "string_var" } } } },
		})
		
		local expect_log = {
			"print(string_var = hello)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("allows assigning a char array to a string", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "local-variable", "char", "char_array", nil, { "test.bt", 1, "num", 10 }, { "test.bt", 1, "str", "hello" } },
			{ "test.bt", 2, "local-variable", "string", "string_var", nil, nil, nil },
			{ "test.bt", 3, "assign", { "test.bt", 3, "ref", { "string_var" } }, { "test.bt", 3, "ref", { "char_array" } } },
			
			{ "test.bt", 10, "call", "Printf", {
				{ "test.bt", 10, "str", "string_var = %s" },
				{ "test.bt", 10, "ref", { "string_var" } } } },
		})
		
		local expect_log = {
			"print(string_var = hello)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("errors on initialisation of uchar array from a string", function()
		local interface, log = test_interface()
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 1, "local-variable", "unsigned char", "uchar_array", nil, { "test.bt", 1, "num", 10 }, { "test.bt", 1, "str", "hello" } },
			})
			end, "can't assign 'const string' to type 'unsigned char[]' at test.bt:1")
	end)
	
	it("errors on assignment of string value to uchar array", function()
		local interface, log = test_interface()
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 1, "local-variable", "unsigned char", "uchar_array", nil, { "test.bt", 1, "num", 10 }, nil },
				{ "test.bt", 2, "assign", { "test.bt", 1, "ref", { "uchar_array" } }, { "test.bt", 1, "str", "hello" } },
			})
			end, "can't assign 'const string' to type 'unsigned char[]' at test.bt:2")
	end)
	
	it("errors on initialisation of string from uchar array", function()
		local interface, log = test_interface()
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 1, "local-variable", "unsigned char", "uchar_array", nil, { "test.bt", 1, "num", 10 }, nil },
				{ "test.bt", 2, "local-variable", "string", "string_var", nil, nil, { "test.bt", 2, "ref", { "uchar_array" } } },
			})
			end, "can't assign 'unsigned char[]' to type 'string' at test.bt:2")
	end)
	
	it("errors on assignment of unsigned char array to string", function()
		local interface, log = test_interface()
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 1, "local-variable", "unsigned char", "uchar_array", nil, { "test.bt", 1, "num", 10 }, nil },
				{ "test.bt", 2, "local-variable", "string", "string_var", nil, nil, nil },
				{ "test.bt", 3, "assign", { "test.bt", 3, "ref", { "string_var" } }, { "test.bt", 3, "ref", { "uchar_array" } } },
			})
			end, "can't assign 'unsigned char[]' to type 'string' at test.bt:3")
	end)
	
	it("allows using local array variables", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "local-variable", "int", "foo", nil, { "test.bt", 1, "num", 3 }, nil },
			{ "test.bt", 1, "assign",
				{ "test.bt", 1, "ref", { "foo", { "test.bt", 1, "num", 0 } } },
				{ "test.bt", 1, "num", 1234 } },
			{ "test.bt", 1, "assign",
				{ "test.bt", 1, "ref", { "foo", { "test.bt", 1, "num", 1 } } },
				{ "test.bt", 1, "num", 5678 } },
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "foo[0] = %d" },
				{ "test.bt", 1, "ref", { "foo", { "test.bt", 1, "num", 0 } } } } },
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "foo[1] = %d" },
				{ "test.bt", 1, "ref", { "foo", { "test.bt", 1, "num", 1 } } } } },
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "foo[2] = %d" },
				{ "test.bt", 1, "ref", { "foo", { "test.bt", 1, "num", 2 } } } } },
		})
		
		local expect_log = {
			"print(foo[0] = 1234)",
			"print(foo[1] = 5678)",
			"print(foo[2] = 0)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("implements endianness functions", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			-- Default state
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "IsBigEndian() = %d" },
				{ "test.bt", 1, "call", "IsBigEndian", {} } } },
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "IsLittleEndian() = %d" },
				{ "test.bt", 1, "call", "IsLittleEndian", {} } } },
			
			-- After call to BigEndian()
			
			{ "test.bt", 1, "call", "BigEndian", {} },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "IsBigEndian() = %d" },
				{ "test.bt", 1, "call", "IsBigEndian", {} } } },
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "IsLittleEndian() = %d" },
				{ "test.bt", 1, "call", "IsLittleEndian", {} } } },
			
			-- After call to LittleEndian()
			
			{ "test.bt", 1, "call", "LittleEndian", {} },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "IsBigEndian() = %d" },
				{ "test.bt", 1, "call", "IsBigEndian", {} } } },
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "IsLittleEndian() = %d" },
				{ "test.bt", 1, "call", "IsLittleEndian", {} } } },
		})
		
		local expect_log = {
			"print(IsBigEndian() = 0)",
			"print(IsLittleEndian() = 1)",
			
			"print(IsBigEndian() = 1)",
			"print(IsLittleEndian() = 0)",
			
			"print(IsBigEndian() = 0)",
			"print(IsLittleEndian() = 1)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("implements file position functions", function()
		local interface, log = test_interface(string.char(
			0x01, 0x00, 0x00, 0x00,
			0x02, 0x00, 0x00, 0x00,
			0x03, 0x00, 0x00, 0x00,
			0x04, 0x00, 0x00, 0x00
		))
		
		local printf_FileSize = function()
			return { "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "FileSize() = %d" },
				{ "test.bt", 1, "call", "FileSize", {} } } }
		end
		
		local printf_FEof = function()
			return { "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "FEof() = %d" },
				{ "test.bt", 1, "call", "FEof", {} } } }
		end
		
		local printf_FTell = function()
			return { "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "FTell() = %d" },
				{ "test.bt", 1, "call", "FTell", {} } } }
		end
		
		local FSeek = function(pos)
			return { "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "FSeek(" .. pos .. ") = %d" },
				{ "test.bt", 1, "call", "FSeek", {
					{ "test.bt", 1, "num", pos } } } } }
		end
		
		local FSkip = function(pos)
			return { "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "FSkip(" .. pos .. ") = %d" },
				{ "test.bt", 1, "call", "FSkip", {
					{ "test.bt", 1, "num", pos } } } } }
		end
		
		executor.execute(interface, {
			-- Default state
			
			printf_FileSize(),
			printf_FEof(),
			printf_FTell(),
			
			-- Try seeking to invalid offsets
			
			FSeek(-1),
			printf_FileSize(),
			printf_FEof(),
			printf_FTell(),
			
			FSeek(17),
			printf_FileSize(),
			printf_FEof(),
			printf_FTell(),
			
			-- Seek to a valid offset within the file
			
			FSeek(4),
			printf_FileSize(),
			printf_FEof(),
			printf_FTell(),
			
			-- Seek to the end of the file
			
			FSeek(16),
			printf_FileSize(),
			printf_FEof(),
			printf_FTell(),
			
			-- Skip back to the start of the file
			
			FSkip(-16),
			printf_FileSize(),
			printf_FEof(),
			printf_FTell(),
			
			-- Skip to a position within the file
			
			FSkip(12),
			printf_FileSize(),
			printf_FEof(),
			printf_FTell(),
			
			-- Skip to current position
			
			FSkip(0),
			printf_FileSize(),
			printf_FEof(),
			printf_FTell(),
			
			-- Try skipping before start of file
			
			FSkip(-13),
			printf_FileSize(),
			printf_FEof(),
			printf_FTell(),
			
			-- Try skipping past end of file
			
			FSkip(5),
			printf_FileSize(),
			printf_FEof(),
			printf_FTell(),
			
			-- Skip to end of file
			
			FSkip(4),
			printf_FileSize(),
			printf_FEof(),
			printf_FTell(),
		})
		
		local expect_log = {
			"print(FileSize() = 16)",
			"print(FEof() = 0)",
			"print(FTell() = 0)",
			
			"print(FSeek(-1) = -1)",
			"print(FileSize() = 16)",
			"print(FEof() = 0)",
			"print(FTell() = 0)",
			
			"print(FSeek(17) = -1)",
			"print(FileSize() = 16)",
			"print(FEof() = 0)",
			"print(FTell() = 0)",
			
			"print(FSeek(4) = 0)",
			"print(FileSize() = 16)",
			"print(FEof() = 0)",
			"print(FTell() = 4)",
			
			"print(FSeek(16) = 0)",
			"print(FileSize() = 16)",
			"print(FEof() = 1)",
			"print(FTell() = 16)",
			
			"print(FSkip(-16) = 0)",
			"print(FileSize() = 16)",
			"print(FEof() = 0)",
			"print(FTell() = 0)",
			
			"print(FSkip(12) = 0)",
			"print(FileSize() = 16)",
			"print(FEof() = 0)",
			"print(FTell() = 12)",
			
			"print(FSkip(0) = 0)",
			"print(FileSize() = 16)",
			"print(FEof() = 0)",
			"print(FTell() = 12)",
			
			"print(FSkip(-13) = -1)",
			"print(FileSize() = 16)",
			"print(FEof() = 0)",
			"print(FTell() = 12)",
			
			"print(FSkip(5) = -1)",
			"print(FileSize() = 16)",
			"print(FEof() = 0)",
			"print(FTell() = 12)",
			
			"print(FSkip(4) = 0)",
			"print(FileSize() = 16)",
			"print(FEof() = 1)",
			"print(FTell() = 16)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("implements ReadI8() function", function()
		local interface, log = test_interface(string.char(
			0x01, 0xFF, 0xFE, 0x04
		))
		
		executor.execute(interface, {
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "ReadI8() = %d" },
				{ "test.bt", 1, "call", "ReadI8", {} } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "ReadI8() = %d" },
				{ "test.bt", 1, "call", "ReadI8", {} } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "ReadI8(1) = %d" },
				{ "test.bt", 1, "call", "ReadI8", {
					{ "test.bt", 1, "num", 1 } } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "ReadI8(2) = %d" },
				{ "test.bt", 1, "call", "ReadI8", {
					{ "test.bt", 1, "num", 2 } } } } },
		})
		
		local expect_log = {
			"print(ReadI8() = 1)",
			"print(ReadI8() = 1)",
			"print(ReadI8(1) = -1)",
			"print(ReadI8(2) = -2)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("errors when ReadI8() is called at end of file", function()
		local interface, log = test_interface(string.char(
			0x01, 0xFF, 0xFE, 0x04
		))
		
		assert.has_error(
			function()
				executor.execute(interface, {
					{ "test.bt", 1, "call", "FSeek", {
						{ "test.bt", 1, "num", 4, {} } } },
					
					{ "test.bt", 2, "call", "Printf", {
						{ "test.bt", 2, "str", "ReadI8() = %d" },
						{ "test.bt", 2, "call", "ReadI8", {} } } },
				})
			end, "Attempt to read past end of file in ReadI8 function at test.bt:2")
	end)
	
	it("implements ReadU32() function", function()
		local interface, log = test_interface(string.char(
			0x00, 0x01, 0x00, 0x00,
			0xFF, 0xFF, 0xFF, 0xFF,
			0x00, 0x02, 0x00, 0x00
		))
		
		executor.execute(interface, {
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "ReadU32() = %d" },
				{ "test.bt", 1, "call", "ReadU32", {} } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "ReadU32() = %d" },
				{ "test.bt", 1, "call", "ReadU32", {} } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "ReadU32(4) = %d" },
				{ "test.bt", 1, "call", "ReadU32", {
					{ "test.bt", 1, "num", 4 } } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "ReadU32(8) = %d" },
				{ "test.bt", 1, "call", "ReadU32", {
					{ "test.bt", 1, "num", 8 } } } } },
		})
		
		local expect_log = {
			"print(ReadU32() = 256)",
			"print(ReadU32() = 256)",
			"print(ReadU32(4) = 4294967295)",
			"print(ReadU32(8) = 512)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("errors when ReadU32() is called at end of file", function()
		local interface, log = test_interface(string.char(
			0x01, 0xFF, 0xFE, 0x04
		))
		
		assert.has_error(
			function()
				executor.execute(interface, {
					{ "test.bt", 1, "call", "Printf", {
						{ "test.bt", 1, "str", "ReadU32() = %d" },
						{ "test.bt", 1, "call", "ReadU32", {
							{ "test.bt", 1, "num", 1, {} } } } } },
				})
			end, "Attempt to read past end of file in ReadU32 function at test.bt:1")
	end)
	
	it("allows declaring a struct with a typedef", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "struct", "mystruct", {}, {
				{ "test.bt", 1, "variable", "int", "x", nil, nil },
				{ "test.bt", 1, "variable", "int", "y", nil, nil },
			}, "mystruct_t" },
			
			{ "test.bt", 1, "local-variable", "mystruct_t", "s", nil, nil, nil },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "s.x = %d" },
				{ "test.bt", 1, "ref", { "s", "x" } } } },
		})
		
		local expect_log = {
			"print(s.x = 0)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("allows declaring an anonymous struct with a typedef", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "struct", nil, {}, {
				{ "test.bt", 1, "variable", "int", "x", nil, nil },
				{ "test.bt", 1, "variable", "int", "y", nil, nil },
			}, "mystruct_t" },
			
			{ "test.bt", 1, "local-variable", "mystruct_t", "s", nil, nil, nil },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "s.x = %d" },
				{ "test.bt", 1, "ref", { "s", "x" } } } },
		})
		
		local expect_log = {
			"print(s.x = 0)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("allows assignment between struct type and typedef", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "struct", "mystruct", {}, {
				{ "test.bt", 1, "variable", "int", "x", nil, nil },
				{ "test.bt", 1, "variable", "int", "y", nil, nil },
			}, "mystruct_t" },
			
			{ "test.bt", 1, "local-variable", "struct mystruct", "bvar", nil, nil, nil },
			{ "test.bt", 1, "local-variable", "mystruct_t", "tvar", nil, nil, nil },
			
			-- Write into base struct and assign base to typedef
			
			{ "test.bt", 1, "assign",
				{ "test.bt", 1, "ref", { "bvar", "x" } },
				{ "test.bt", 1, "num", 1234 } },
			
			{ "test.bt", 1, "assign",
				{ "test.bt", 1, "ref", { "tvar" } },
				{ "test.bt", 1, "ref", { "bvar" } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "tvar.x = %d" },
				{ "test.bt", 1, "ref", { "tvar", "x" } } } },
			
			-- Write into typedef struct and assign to base
			
			{ "test.bt", 1, "assign",
				{ "test.bt", 1, "ref", { "tvar", "y" } },
				{ "test.bt", 1, "num", 5678 } },
			
			{ "test.bt", 1, "assign",
				{ "test.bt", 1, "ref", { "bvar" } },
				{ "test.bt", 1, "ref", { "tvar" } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "bvar.y = %d" },
				{ "test.bt", 1, "ref", { "bvar", "y" } } } },
		})
		
		local expect_log = {
			"print(tvar.x = 1234)",
			"print(bvar.y = 5678)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("allows assignment between different typedefs of the same struct", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "struct", "mystruct", {}, {
				{ "test.bt", 1, "variable", "int", "x", nil, nil },
				{ "test.bt", 1, "variable", "int", "y", nil, nil },
			}, "mystruct_t" },
			
			{ "test.bt", 1, "typedef", "struct mystruct", "mystruct_u" },
			
			{ "test.bt", 1, "local-variable", "mystruct_u", "bvar", nil, nil, nil },
			{ "test.bt", 1, "local-variable", "mystruct_t", "tvar", nil, nil, nil },
			
			-- Write into mystruct_u and assign to mystruct_t
			
			{ "test.bt", 1, "assign",
				{ "test.bt", 1, "ref", { "bvar", "x" } },
				{ "test.bt", 1, "num", 1234 } },
			
			{ "test.bt", 1, "assign",
				{ "test.bt", 1, "ref", { "tvar" } },
				{ "test.bt", 1, "ref", { "bvar" } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "tvar.x = %d" },
				{ "test.bt", 1, "ref", { "tvar", "x" } } } },
			
			-- Write into mystruct_t and assign to mystruct_u
			
			{ "test.bt", 1, "assign",
				{ "test.bt", 1, "ref", { "tvar", "y" } },
				{ "test.bt", 1, "num", 5678 } },
			
			{ "test.bt", 1, "assign",
				{ "test.bt", 1, "ref", { "bvar" } },
				{ "test.bt", 1, "ref", { "tvar" } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "bvar.y = %d" },
				{ "test.bt", 1, "ref", { "bvar", "y" } } } },
		})
		
		local expect_log = {
			"print(tvar.x = 1234)",
			"print(bvar.y = 5678)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("errors on attempt to assign between distinct struct definitions", function()
		local interface, log = test_interface()
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 1, "struct", "mystruct1", {}, {
					{ "test.bt", 1, "variable", "int", "x", nil, nil },
					{ "test.bt", 1, "variable", "int", "y", nil, nil },
				}, nil },
				
				{ "test.bt", 1, "struct", "mystruct2", {}, {
					{ "test.bt", 1, "variable", "int", "x", nil, nil },
					{ "test.bt", 1, "variable", "int", "y", nil, nil },
				}, nil },
				
				{ "test.bt", 1, "local-variable", "struct mystruct1", "s1", nil, nil, nil },
				{ "test.bt", 1, "local-variable", "struct mystruct2", "s2", nil, nil, nil },
				
				{ "test.bt", 1, "assign",
					{ "test.bt", 1, "ref", { "s1" } },
					{ "test.bt", 1, "ref", { "s2" } } },
			})
		end, "can't assign 'struct mystruct2' to type 'struct mystruct1' at test.bt:1")
	end)
	
	it("allows defining enums", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "enum", "int", "myenum", {
				{ "FOO" },
				{ "BAR" },
				{ "BAZ" },
				{ "B_FOO", { "UNKNOWN FILE", 1, "num", 1 } },
				{ "B_BAR", { "UNKNOWN FILE", 1, "num", 3 } },
				{ "B_BAZ" },
			}, nil },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "FOO = %d" },
				{ "test.bt", 1, "ref", { "FOO" } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "BAR = %d" },
				{ "test.bt", 1, "ref", { "BAR" } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "BAZ = %d" },
				{ "test.bt", 1, "ref", { "BAZ" } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "B_FOO = %d" },
				{ "test.bt", 1, "ref", { "B_FOO" } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "B_BAR = %d" },
				{ "test.bt", 1, "ref", { "B_BAR" } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "B_BAZ = %d" },
				{ "test.bt", 1, "ref", { "B_BAZ" } } } },
			
			{ "test.bt", 1, "local-variable",
				"enum myenum", "e", nil, nil, { "test.bt", 1, "ref", { "B_BAZ" } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "e = %d" },
				{ "test.bt", 1, "ref", { "e" } } } },
		})
		
		local expect_log = {
			"print(FOO = 0)",
			"print(BAR = 1)",
			"print(BAZ = 2)",
			"print(B_FOO = 1)",
			"print(B_BAR = 3)",
			"print(B_BAZ = 4)",
			"print(e = 4)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("allows defining enums with a typedef", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "enum", "int", "myenum", {
				{ "FOO", { "UNKNOWN FILE", 1, "num", 1234 } },
				{ "BAR" },
			}, "myenum_t" },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "FOO = %d" },
				{ "test.bt", 1, "ref", { "FOO" } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "BAR = %d" },
				{ "test.bt", 1, "ref", { "BAR" } } } },
			
			{ "test.bt", 1, "local-variable",
				"enum myenum", "e1", nil, nil, { "test.bt", 1, "ref", { "FOO" } } },
			
			{ "test.bt", 1, "local-variable",
				"myenum_t", "e2", nil, nil, { "test.bt", 1, "ref", { "BAR" } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "e1 = %d" },
				{ "test.bt", 1, "ref", { "e1" } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "e2 = %d" },
				{ "test.bt", 1, "ref", { "e2" } } } },
		})
		
		local expect_log = {
			"print(FOO = 1234)",
			"print(BAR = 1235)",
			"print(e1 = 1234)",
			"print(e2 = 1235)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("allows defining anonymous enums with a typedef", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "enum", "int", nil, {
				{ "FOO", { "UNKNOWN FILE", 1, "num", 1234 } },
				{ "BAR" },
			}, "myenum_t" },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "FOO = %d" },
				{ "test.bt", 1, "ref", { "FOO" } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "BAR = %d" },
				{ "test.bt", 1, "ref", { "BAR" } } } },
			
			{ "test.bt", 1, "local-variable",
				"myenum_t", "e", nil, nil, { "test.bt", 1, "ref", { "FOO" } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "e = %d" },
				{ "test.bt", 1, "ref", { "e" } } } },
		})
		
		local expect_log = {
			"print(FOO = 1234)",
			"print(BAR = 1235)",
			"print(e = 1234)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("allows defining an enum with a variable", function()
		local interface, log = test_interface(string.char(
			0x01, 0x00, 0x00, 0x00,
			0x02, 0x00, 0x00, 0x00,
			0x03, 0x00, 0x00, 0x00,
			0x04, 0x00, 0x00, 0x00
		))
		
		executor.execute(interface, {
			{ "test.bt", 1, "enum", "int", "myenum", {
				{ "FOO" },
				{ "BAR" },
				{ "BAZ" },
			}, nil, { "e", nil, nil } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "FOO = %d" },
				{ "test.bt", 1, "ref", { "FOO" } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "BAR = %d" },
				{ "test.bt", 1, "ref", { "BAR" } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "BAZ = %d" },
				{ "test.bt", 1, "ref", { "BAZ" } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "e = %d" },
				{ "test.bt", 1, "ref", { "e" } } } },
		})
		
		local expect_log = {
			"print(FOO = 0)",
			"print(BAR = 1)",
			"print(BAZ = 2)",
			"print(e = 1)",
			"set_comment(0, 4, e)",
			"set_data_type(0, 4, s32le)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("allows defining an anonymous enum variable", function()
		local interface, log = test_interface(string.char(
			0x01, 0x00, 0x00, 0x00,
			0x02, 0x00, 0x00, 0x00,
			0x03, 0x00, 0x00, 0x00,
			0x04, 0x00, 0x00, 0x00
		))
		
		executor.execute(interface, {
			{ "test.bt", 1, "enum", "int", nil, {
				{ "FOO" },
				{ "BAR" },
				{ "BAZ" },
			}, nil, { "e", nil, nil } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "FOO = %d" },
				{ "test.bt", 1, "ref", { "FOO" } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "BAR = %d" },
				{ "test.bt", 1, "ref", { "BAR" } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "BAZ = %d" },
				{ "test.bt", 1, "ref", { "BAZ" } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "e = %d" },
				{ "test.bt", 1, "ref", { "e" } } } },
		})
		
		local expect_log = {
			"print(FOO = 0)",
			"print(BAR = 1)",
			"print(BAZ = 2)",
			"print(e = 1)",
			"set_comment(0, 4, e)",
			"set_data_type(0, 4, s32le)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("allows defining an enum with an array variable", function()
		local interface, log = test_interface(string.char(
			0x01, 0x00, 0x00, 0x00,
			0x02, 0x00, 0x00, 0x00,
			0x03, 0x00, 0x00, 0x00,
			0x04, 0x00, 0x00, 0x00
		))
		
		executor.execute(interface, {
			{ "test.bt", 1, "enum", "int", "myenum", {
				{ "FOO" },
				{ "BAR" },
				{ "BAZ" },
			}, nil, { "e", nil, { "test.bt", 1, "num", 3 } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "FOO = %d" },
				{ "test.bt", 1, "ref", { "FOO" } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "BAR = %d" },
				{ "test.bt", 1, "ref", { "BAR" } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "BAZ = %d" },
				{ "test.bt", 1, "ref", { "BAZ" } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "e[0] = %d" },
				{ "test.bt", 1, "ref", { "e", { "test.bt", 1, "num", 0 } } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "e[1] = %d" },
				{ "test.bt", 1, "ref", { "e", { "test.bt", 1, "num", 1 } } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "e[2] = %d" },
				{ "test.bt", 1, "ref", { "e", { "test.bt", 1, "num", 2 } } } } },
		})
		
		local expect_log = {
			"print(FOO = 0)",
			"print(BAR = 1)",
			"print(BAZ = 2)",
			"print(e[0] = 1)",
			"print(e[1] = 2)",
			"print(e[2] = 3)",
			"set_comment(0, 12, e)",
			"set_data_type(0, 12, s32le)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("errors when defining an enum with an undefined type", function()
		local interface, log = test_interface()
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 1, "enum", "nosuch_t", "myenum", {
					{ "FOO" },
				}, nil },
			})
			end, "Use of undefined type 'nosuch_t' at test.bt:1")
	end)
	
	it("errors when defining the same multiple times in an enum", function()
		local interface, log = test_interface()
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 1, "enum", "int", "myenum", {
					{ "FOO" },
					{ "FOO" },
				}, nil },
			})
			end, "Attempt to redefine name 'FOO' at test.bt:1")
	end)
	
	it("errors when reusing an existing variable name as an enum member", function()
		local interface, log = test_interface()
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 1, "local-variable", "int", "FOO", nil, nil, nil },
				
				{ "test.bt", 2, "enum", "int", "myenum", {
					{ "FOO" },
				}, nil },
			})
			end, "Attempt to redefine name 'FOO' at test.bt:2")
	end)
	
	it("errors when redefining an enum type", function()
		local interface, log = test_interface()
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 1, "enum", "int", "myenum", {
					{ "FOO" },
				}, nil },
				
				{ "test.bt", 2, "enum", "int", "myenum", {
					{ "FOO" },
				}, nil },
			})
			end, "Attempt to redefine type 'enum myenum' at test.bt:2")
	end)
	
	it("errors when redefining a type using typedef enum", function()
		local interface, log = test_interface()
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 1, "enum", "int", "myenum", {
					{ "FOO" },
				}, "int" },
			})
			end, "Attempt to redefine type 'int' at test.bt:1")
	end)
	
	it("errors when defining an enum member as a string", function()
		local interface, log = test_interface()
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 1, "enum", "int", "myenum", {
					{ "FOO", { "test.bt", 1, "str", "" } },
				}, nil },
			})
			end, "Invalid type 'const string' for enum member 'FOO' at test.bt:1")
	end)
	
	it("errors when defining an enum member as a void", function()
		local interface, log = test_interface()
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 1, "function", "void", "vfunc", {}, {} },
				
				{ "test.bt", 1, "enum", "int", "myenum", {
					{ "FOO", { "test.bt", 1, "call", "vfunc", {} } },
				}, nil },
			})
			end, "Invalid type 'void' for enum member 'FOO' at test.bt:1")
	end)
	
	it("implements basic for loop behaviour", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "for",
				{ "test.bt", 1, "local-variable", "int", "i", nil, nil, { "test.bt", 1, "num", 0 } },
				{ "test.bt", 1, "less-than",
					{ "test.bt", 1, "ref", { "i" } },
					{ "test.bt", 1, "num", 5 } },
				{ "test.bt", 1, "assign",
					{ "test.bt", 1, "ref", { "i" } },
					{ "test.bt", 1, "add",
						{ "test.bt", 1, "ref", { "i" } },
						{ "test.bt", 1, "num", 1 } } },
				
				{
					{ "test.bt", 1, "call", "Printf", {
						{ "test.bt", 1, "str", "i = %d" },
						{ "test.bt", 1, "ref", { "i" } } } },
				} },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "end" } } },
		})
		
		local expect_log = {
			"print(i = 0)",
			"print(i = 1)",
			"print(i = 2)",
			"print(i = 3)",
			"print(i = 4)",
			"print(end)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("allows breaking out of a for loop", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "for",
				{ "test.bt", 1, "local-variable", "int", "i", nil, nil, { "test.bt", 1, "num", 0 } },
				{ "test.bt", 1, "less-than",
					{ "test.bt", 1, "ref", { "i" } },
					{ "test.bt", 1, "num", 5 } },
				{ "test.bt", 1, "assign",
					{ "test.bt", 1, "ref", { "i" } },
					{ "test.bt", 1, "add",
						{ "test.bt", 1, "ref", { "i" } },
						{ "test.bt", 1, "num", 1 } } },
				
				{
					{ "test.bt", 1, "call", "Printf", {
						{ "test.bt", 1, "str", "i = %d" },
						{ "test.bt", 1, "ref", { "i" } } } },
					
					{ "test.bt", 1, "break" },
				} },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "end" } } },
		})
		
		local expect_log = {
			"print(i = 0)",
			"print(end)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("allows continuing to next iteration of a for loop", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "for",
				{ "test.bt", 1, "local-variable", "int", "i", nil, nil, { "test.bt", 1, "num", 0 } },
				{ "test.bt", 1, "less-than",
					{ "test.bt", 1, "ref", { "i" } },
					{ "test.bt", 1, "num", 5 } },
				{ "test.bt", 1, "assign",
					{ "test.bt", 1, "ref", { "i" } },
					{ "test.bt", 1, "add",
						{ "test.bt", 1, "ref", { "i" } },
						{ "test.bt", 1, "num", 1 } } },
				
				{
					{ "test.bt", 1, "call", "Printf", {
						{ "test.bt", 1, "str", "i = %d" },
						{ "test.bt", 1, "ref", { "i" } } } },
					
					{ "test.bt", 1, "continue" },
					
					{ "test.bt", 1, "call", "Printf", {
						{ "test.bt", 1, "str", "i = %d (2)" },
						{ "test.bt", 1, "ref", { "i" } } } },
				} },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "end" } } },
		})
		
		local expect_log = {
			"print(i = 0)",
			"print(i = 1)",
			"print(i = 2)",
			"print(i = 3)",
			"print(i = 4)",
			"print(end)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("can be broken out of an infinite for loop via yield", function()
		local interface, log = test_interface()
		
		assert.has_error(
			function()
				executor.execute(interface, {
					{ "test.bt", 1, "for", nil, nil, nil, {} },
				})
			end, "Test timeout")
	end)
	
	it("scopes variables defined in for loop initialiser to the loop", function()
		local interface, log = test_interface()
		
		assert.has_error(
			function()
				executor.execute(interface, {
					{ "test.bt", 1, "for",
						{ "test.bt", 1, "local-variable", "int", "i", nil, nil, { "test.bt", 1, "num", 0 } },
						{ "test.bt", 1, "less-than",
							{ "test.bt", 1, "ref", { "i" } },
							{ "test.bt", 1, "num", 5 } },
						{ "test.bt", 1, "assign",
							{ "test.bt", 1, "ref", { "i" } },
							{ "test.bt", 1, "add",
								{ "test.bt", 1, "ref", { "i" } },
								{ "test.bt", 1, "num", 1 } } },
						
						{} },
					
					{ "test.bt", 2, "ref", { "i" } }
				})
			end, "Attempt to use undefined variable 'i' at test.bt:2")
	end)
	
	it("scopes variables defined in for loop to the loop", function()
		local interface, log = test_interface()
		
		assert.has_error(
			function()
				executor.execute(interface, {
					{ "test.bt", 1, "for",
						{ "test.bt", 1, "local-variable", "int", "i", nil, nil, { "test.bt", 1, "num", 0 } },
						{ "test.bt", 1, "less-than",
							{ "test.bt", 1, "ref", { "i" } },
							{ "test.bt", 1, "num", 5 } },
						{ "test.bt", 1, "assign",
							{ "test.bt", 1, "ref", { "i" } },
							{ "test.bt", 1, "add",
								{ "test.bt", 1, "ref", { "i" } },
								{ "test.bt", 1, "num", 1 } } },
						
						{
							{ "test.bt", 1, "local-variable", "int", "j", nil, nil, nil },
						} },
					
					{ "test.bt", 2, "ref", { "j" } }
				})
			end, "Attempt to use undefined variable 'j' at test.bt:2")
	end)
	
	it("allows returning from a loop inside a function", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "function", "int", "myfunc", {}, {
				{ "test.bt", 1, "for",
					{ "test.bt", 1, "local-variable", "int", "i", nil, nil, { "test.bt", 1, "num", 0 } },
					{ "test.bt", 1, "less-than",
						{ "test.bt", 1, "ref", { "i" } },
						{ "test.bt", 1, "num", 5 } },
					{ "test.bt", 1, "assign",
						{ "test.bt", 1, "ref", { "i" } },
						{ "test.bt", 1, "add",
							{ "test.bt", 1, "ref", { "i" } },
							{ "test.bt", 1, "num", 1 } } },
					
					{
						{ "test.bt", 1, "return", { "test.bt", 1, "num", 1234 } },
					},
				} } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "%d" },
				{ "test.bt", 1, "call", "myfunc", {} } } },
		})
		
		local expect_log = {
			"print(1234)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("doesn't allow return from a loop not in a function", function()
		local interface, log = test_interface()
		
		assert.has_error(
			function()
				executor.execute(interface, {
					{ "test.bt", 1, "for",
						{ "test.bt", 1, "local-variable", "int", "i", nil, nil, { "test.bt", 1, "num", 0 } },
						{ "test.bt", 1, "less-than",
							{ "test.bt", 1, "ref", { "i" } },
							{ "test.bt", 1, "num", 5 } },
						{ "test.bt", 1, "assign",
							{ "test.bt", 1, "ref", { "i" } },
							{ "test.bt", 1, "add",
								{ "test.bt", 1, "ref", { "i" } },
								{ "test.bt", 1, "num", 1 } } },
						
						{
							{ "test.bt", 2, "return", { "test.bt", 1, "num", 1234 } },
						},
					},
				})
			end, "'return' statement not allowed here at test.bt:2")
	end)
	
	it("doesn't allow break outside of a loop", function()
		local interface, log = test_interface()
		
		assert.has_error(
			function()
				executor.execute(interface, {
					{ "test.bt", 1, "break" },
				})
			end, "'break' statement not allowed here at test.bt:1")
	end)
	
	it("doesn't allow continue outside of a loop", function()
		local interface, log = test_interface()
		
		assert.has_error(
			function()
				executor.execute(interface, {
					{ "test.bt", 1, "break" },
				})
			end, "'break' statement not allowed here at test.bt:1")
	end)
	
	it("doesn't allow break inside a function call inside a loop", function()
		local interface, log = test_interface()
		
		assert.has_error(
			function()
				executor.execute(interface, {
					{ "test.bt", 1, "function", "int", "breakfunc", {}, {
						{ "test.bt", 2, "break" } } },
					
					{ "test.bt", 1, "for",
						{ "test.bt", 1, "local-variable", "int", "i", nil, nil, { "test.bt", 1, "num", 0 } },
						{ "test.bt", 1, "less-than",
							{ "test.bt", 1, "ref", { "i" } },
							{ "test.bt", 1, "num", 5 } },
						{ "test.bt", 1, "assign",
							{ "test.bt", 1, "ref", { "i" } },
							{ "test.bt", 1, "add",
								{ "test.bt", 1, "ref", { "i" } },
								{ "test.bt", 1, "num", 1 } } },
						
						{
							{ "test.bt", 1, "call", "breakfunc", {} },
						},
					},
				})
			end, "'break' statement not allowed here at test.bt:2")
	end)
	
	it("allows defining typedefs", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "typedef", "int", "myint_t", nil },
			{ "test.bt", 1, "local-variable", "myint_t", "myvar", nil, nil },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "%d" },
				{ "test.bt", 1, "ref", { "myvar" } } } },
		})
		
		local expect_log = {
			"print(0)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("allows defining array typedefs", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "typedef", "int", "myarr_t", { "test.bt", 1, "num", 4 } },
			{ "test.bt", 1, "local-variable", "myarr_t", "myarr", nil, nil },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "%d, %d, %d, %d" },
				{ "test.bt", 1, "ref", { "myarr", { "test.bt", 1, "num", 0 } } },
				{ "test.bt", 1, "ref", { "myarr", { "test.bt", 1, "num", 1 } } },
				{ "test.bt", 1, "ref", { "myarr", { "test.bt", 1, "num", 2 } } },
				{ "test.bt", 1, "ref", { "myarr", { "test.bt", 1, "num", 3 } } } } },
		})
		
		local expect_log = {
			"print(0, 0, 0, 0)"
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("errors when defining an array typedef of an array type", function()
		local interface, log = test_interface()
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 1, "typedef", "int", "myarr_t", { "test.bt", 1, "num", 4 } },
				{ "test.bt", 2, "typedef", "myarr_t", "myarrarr_t", { "test.bt", 2, "num", 4 } },
			})
			end, "Multidimensional arrays are not supported at test.bt:2")
	end)
	
	it("errors when declaring an array variable of an array type", function()
		local interface, log = test_interface()
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 1, "typedef", "int", "myarr_t", { "test.bt", 1, "num", 4 } },
				{ "test.bt", 2, "local-variable", "myarr_t", "myarrarr", nil, { "test.bt", 2, "num", 4 } },
			})
			end, "Multidimensional arrays are not supported at test.bt:2")
	end)
	
	it("executes from matching case in a switch statement", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "switch", { "test.bt", 1, "num", 2 }, {
				{ nil,                        { { "test.bt", 1, "call", "Printf", { { "test.bt", 1, "str", "default" } } } } },
				{ { "test.bt", 1, "num", 1 }, { { "test.bt", 1, "call", "Printf", { { "test.bt", 1, "str", "1" }       } } } },
				{ { "test.bt", 1, "num", 2 }, { { "test.bt", 1, "call", "Printf", { { "test.bt", 1, "str", "2" }       } } } },
				{ { "test.bt", 1, "num", 3 }, { { "test.bt", 1, "call", "Printf", { { "test.bt", 1, "str", "3" }       } } } },
			} },
		})
		
		local expect_log = {
			"print(2)",
			"print(3)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("executes from default case if none match in a switch statement", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "switch", { "test.bt", 1, "num", 4 }, {
				{ nil,                        { { "test.bt", 1, "call", "Printf", { { "test.bt", 1, "str", "default" } } } } },
				{ { "test.bt", 1, "num", 1 }, { { "test.bt", 1, "call", "Printf", { { "test.bt", 1, "str", "1" }       } } } },
				{ { "test.bt", 1, "num", 2 }, { { "test.bt", 1, "call", "Printf", { { "test.bt", 1, "str", "2" }       } } } },
				{ { "test.bt", 1, "num", 3 }, { { "test.bt", 1, "call", "Printf", { { "test.bt", 1, "str", "3" }       } } } },
			} },
		})
		
		local expect_log = {
			"print(default)",
			"print(1)",
			"print(2)",
			"print(3)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("breaks out of a switch statement when a break is encountered", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "switch", { "test.bt", 1, "num", 2 }, {
				{ nil,                        { { "test.bt", 1, "call", "Printf", { { "test.bt", 1, "str", "default" } } } } },
				{ { "test.bt", 1, "num", 1 }, { { "test.bt", 1, "call", "Printf", { { "test.bt", 1, "str", "1" }       } } } },
				{ { "test.bt", 1, "num", 2 }, { { "test.bt", 1, "call", "Printf", { { "test.bt", 1, "str", "2" }       } }, { "test.bt", 1, "break" } } },
				{ { "test.bt", 1, "num", 3 }, { { "test.bt", 1, "call", "Printf", { { "test.bt", 1, "str", "3" }       } } } },
			} },
			
			{ "test.bt", 1, "call", "Printf", { { "test.bt", 1, "str", "end" } } },
		})
		
		local expect_log = {
			"print(2)",
			"print(end)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("supports using a switch statement with a string", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "switch", { "test.bt", 1, "str", "0" }, {
				{ { "test.bt", 1, "str", "00"  }, { { "test.bt", 1, "call", "Printf", { { "test.bt", 1, "str", "00"  }       } } } },
				{ { "test.bt", 1, "str", "0"   }, { { "test.bt", 1, "call", "Printf", { { "test.bt", 1, "str", "0"   }       } } } },
				{ { "test.bt", 1, "str", "000" }, { { "test.bt", 1, "call", "Printf", { { "test.bt", 1, "str", "000" }       } } } },
			} },
		})
		
		local expect_log = {
			"print(0)",
			"print(000)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("errors when using an unsupported type with a switch statement", function()
		local interface, log = test_interface()
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 1, "function", "void", "vfunc", {}, {} },
				
				{ "test.bt", 2, "switch", { "test.bt", 2, "call", "vfunc", {} }, {
					{ nil,                        { { "test.bt", 1, "call", "Printf", { { "test.bt", 1, "str", "default" } } } } },
					{ { "test.bt", 1, "num", 1 }, { { "test.bt", 1, "call", "Printf", { { "test.bt", 1, "str", "1" }       } } } },
					{ { "test.bt", 1, "num", 2 }, { { "test.bt", 1, "call", "Printf", { { "test.bt", 1, "str", "2" }       } }, { "test.bt", 1, "break" } } },
					{ { "test.bt", 1, "num", 3 }, { { "test.bt", 1, "call", "Printf", { { "test.bt", 1, "str", "3" }       } } } },
				} },
			})
			end, "Unexpected type 'void' passed to 'switch' statement (expected number or string) at test.bt:2")
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 1, "struct", "mystruct", {},
				{
					{ "test.bt", 1, "variable", "int", "x", nil, nil },
				} },
				
				{ "test.bt", 1, "local-variable", "struct mystruct", "a", nil, nil, nil },
				
				{ "test.bt", 2, "switch", { "test.bt", 2, "ref", { "a" } }, {
					{ nil,                        { { "test.bt", 1, "call", "Printf", { { "test.bt", 1, "str", "default" } } } } },
					{ { "test.bt", 1, "num", 1 }, { { "test.bt", 1, "call", "Printf", { { "test.bt", 1, "str", "1" }       } } } },
					{ { "test.bt", 1, "num", 2 }, { { "test.bt", 1, "call", "Printf", { { "test.bt", 1, "str", "2" }       } }, { "test.bt", 1, "break" } } },
					{ { "test.bt", 1, "num", 3 }, { { "test.bt", 1, "call", "Printf", { { "test.bt", 1, "str", "3" }       } } } },
				} },
			})
			end, "Unexpected type 'struct mystruct' passed to 'switch' statement (expected number or string) at test.bt:2")
	end)
	
	it("errors when using a different type in a switch/case statement", function()
		local interface, log = test_interface()
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 1, "function", "void", "vfunc", {}, {} },
				
				{ "test.bt", 2, "switch", { "test.bt", 2, "num", 0, {} }, {
					{ { "test.bt", 3, "call", "vfunc", {} }, {} },
					{ { "test.bt", 1, "num", 2 }, {} },
					{ { "test.bt", 1, "num", 3 }, {} },
				} },
			})
			end, "Unexpected type 'void' passed to 'case' statement (expected 'const int') at test.bt:3")
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 2, "switch", { "test.bt", 2, "num", 0, {} }, {
					{ { "test.bt", 3, "str", "hello" }, {} },
					{ { "test.bt", 1, "num", 2 }, {} },
					{ { "test.bt", 1, "num", 3 }, {} },
				} },
			})
			end, "Unexpected type 'const string' passed to 'case' statement (expected 'const int') at test.bt:3")
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 1, "function", "void", "vfunc", {}, {} },
				
				{ "test.bt", 2, "switch", { "test.bt", 2, "str", "hello", {} }, {
					{ { "test.bt", 3, "call", "vfunc", {} }, {} },
					{ { "test.bt", 1, "num", 2 }, {} },
					{ { "test.bt", 1, "num", 3 }, {} },
				} },
			})
			end, "Unexpected type 'void' passed to 'case' statement (expected 'const string') at test.bt:3")
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 2, "switch", { "test.bt", 2, "str", "hello", {} }, {
					{ { "test.bt", 3, "num", 1 }, {} },
					{ { "test.bt", 1, "num", 2 }, {} },
					{ { "test.bt", 1, "num", 3 }, {} },
				} },
			})
			end, "Unexpected type 'const int' passed to 'case' statement (expected 'const string') at test.bt:3")
	end)
	
	it("allows casting between different integer types", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "local-variable", "int", "i", nil, nil, { "test.bt", 1, "num", 100 } },
			{ "test.bt", 1, "local-variable", "int", "c", nil, nil, { "test.bt", 1, "num", 100 } },
			
			{ "test.bt", 1, "call", "Printf", { { "test.bt", 1, "str", "(char)(i) = %d" },           { "test.bt", 1, "cast", "char",          { "test.bt", 1, "ref", { "i" }  } } } },
			{ "test.bt", 1, "call", "Printf", { { "test.bt", 1, "str", "(unsigned char)(i) = %d" },  { "test.bt", 1, "cast", "unsigned char", { "test.bt", 1, "ref", { "i" }  } } } },
			{ "test.bt", 1, "call", "Printf", { { "test.bt", 1, "str", "(signed char)(i) = %d" },    { "test.bt", 1, "cast", "signed char",   { "test.bt", 1, "ref", { "i" }  } } } },
			{ "test.bt", 1, "call", "Printf", { { "test.bt", 1, "str", "(int)(c) = %d"    },         { "test.bt", 1, "cast", "int",           { "test.bt", 1, "ref", { "c" }  } } } },
			{ "test.bt", 1, "call", "Printf", { { "test.bt", 1, "str", "(unsigned int)(c) = %d"  },  { "test.bt", 1, "cast", "unsigned int",  { "test.bt", 1, "ref", { "c" }  } } } },
			{ "test.bt", 1, "call", "Printf", { { "test.bt", 1, "str", "(signed int)(c) = %d"  },    { "test.bt", 1, "cast", "signed int",    { "test.bt", 1, "ref", { "c" }  } } } },
		})
		
		local expect_log = {
			"print((char)(i) = 100)",
			"print((unsigned char)(i) = 100)",
			"print((signed char)(i) = 100)",
			"print((int)(c) = 100)",
			"print((unsigned int)(c) = 100)",
			"print((signed int)(c) = 100)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("handles overflow when casting to unsigned types", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "call", "Printf", { { "test.bt", 1, "str", "(unsigned char)(522) = %d" },     { "test.bt", 1, "cast", "unsigned char",  { "test.bt", 1, "num", 522 } } } },
			{ "test.bt", 1, "call", "Printf", { { "test.bt", 1, "str", "(uint16_t)(66536) = %d" },  { "test.bt", 1, "cast", "uint16_t", { "test.bt", 1, "num", 66536 } } } },
		})
		
		local expect_log = {
			"print((unsigned char)(522) = 10)",
			"print((uint16_t)(66536) = 1000)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("handles underflow when casting to unsigned types", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "call", "Printf", { { "test.bt", 1, "str", "(unsigned char)(-1) = %d" },   { "test.bt", 1, "cast", "unsigned char",  { "test.bt", 1, "num", -1 } } } },
			{ "test.bt", 1, "call", "Printf", { { "test.bt", 1, "str", "(unsigned char)(-128) = %d" }, { "test.bt", 1, "cast", "unsigned char",  { "test.bt", 1, "num", -128 } } } },
			{ "test.bt", 1, "call", "Printf", { { "test.bt", 1, "str", "(unsigned char)(-129) = %d" }, { "test.bt", 1, "cast", "unsigned char",  { "test.bt", 1, "num", -129 } } } },
			{ "test.bt", 1, "call", "Printf", { { "test.bt", 1, "str", "(unsigned char)(-255) = %d" }, { "test.bt", 1, "cast", "unsigned char",  { "test.bt", 1, "num", -255 } } } },
			{ "test.bt", 1, "call", "Printf", { { "test.bt", 1, "str", "(unsigned char)(-256) = %d" }, { "test.bt", 1, "cast", "unsigned char",  { "test.bt", 1, "num", -256 } } } },
			{ "test.bt", 1, "call", "Printf", { { "test.bt", 1, "str", "(unsigned char)(-257) = %d" }, { "test.bt", 1, "cast", "unsigned char",  { "test.bt", 1, "num", -257 } } } },
		})
		
		local expect_log = {
			"print((unsigned char)(-1) = 255)",
			"print((unsigned char)(-128) = 128)",
			"print((unsigned char)(-129) = 127)",
			"print((unsigned char)(-255) = 1)",
			"print((unsigned char)(-256) = 0)",
			"print((unsigned char)(-257) = 255)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("implements postfix increment operator", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "local-variable", "char", "i", nil, nil, { "test.bt", 1, "num", -2 } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "i = %d" },
				{ "test.bt", 1, "ref", { "i" } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "i++ = %d" },
				{ "test.bt", 1, "postfix-increment", { "test.bt", 1, "ref", { "i" } } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "i = %d" },
				{ "test.bt", 1, "ref", { "i" } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "i++ = %d" },
				{ "test.bt", 1, "postfix-increment", { "test.bt", 1, "ref", { "i" } } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "i = %d" },
				{ "test.bt", 1, "ref", { "i" } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "i++ = %d" },
				{ "test.bt", 1, "postfix-increment", { "test.bt", 1, "ref", { "i" } } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "i = %d" },
				{ "test.bt", 1, "ref", { "i" } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "i++ = %d" },
				{ "test.bt", 1, "postfix-increment", { "test.bt", 1, "ref", { "i" } } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "i = %d" },
				{ "test.bt", 1, "ref", { "i" } } } },
		})
		
		local expect_log = {
			"print(i = -2)",
			"print(i++ = -2)",
			"print(i = -1)",
			"print(i++ = -1)",
			"print(i = 0)",
			"print(i++ = 0)",
			"print(i = 1)",
			"print(i++ = 1)",
			"print(i = 2)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("wraps values when postfix increment of an unsigned integer overflows", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "local-variable", "uint16_t", "i", nil, nil, { "test.bt", 1, "num", 65534 } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "i = %d" },
				{ "test.bt", 1, "ref", { "i" } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "i++ = %d" },
				{ "test.bt", 1, "postfix-increment", { "test.bt", 1, "ref", { "i" } } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "i++ = %d" },
				{ "test.bt", 1, "postfix-increment", { "test.bt", 1, "ref", { "i" } } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "i++ = %d" },
				{ "test.bt", 1, "postfix-increment", { "test.bt", 1, "ref", { "i" } } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "i = %d" },
				{ "test.bt", 1, "ref", { "i" } } } },
		})
		
		local expect_log = {
			"print(i = 65534)",
			"print(i++ = 65534)",
			"print(i++ = 65535)",
			"print(i++ = 0)",
			"print(i = 1)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("implements postfix decrement operator", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "local-variable", "char", "i", nil, nil, { "test.bt", 1, "num", 1 } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "i = %d" },
				{ "test.bt", 1, "ref", { "i" } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "i-- = %d" },
				{ "test.bt", 1, "postfix-decrement", { "test.bt", 1, "ref", { "i" } } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "i = %d" },
				{ "test.bt", 1, "ref", { "i" } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "i-- = %d" },
				{ "test.bt", 1, "postfix-decrement", { "test.bt", 1, "ref", { "i" } } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "i = %d" },
				{ "test.bt", 1, "ref", { "i" } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "i-- = %d" },
				{ "test.bt", 1, "postfix-decrement", { "test.bt", 1, "ref", { "i" } } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "i = %d" },
				{ "test.bt", 1, "ref", { "i" } } } },
		})
		
		local expect_log = {
			"print(i = 1)",
			"print(i-- = 1)",
			"print(i = 0)",
			"print(i-- = 0)",
			"print(i = -1)",
			"print(i-- = -1)",
			"print(i = -2)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("wraps when postfix decrement of an unsigned integer overflows", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "local-variable", "uint16_t", "i", nil, nil, { "test.bt", 1, "num", 1 } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "i = %d" },
				{ "test.bt", 1, "ref", { "i" } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "i-- = %d" },
				{ "test.bt", 1, "postfix-decrement", { "test.bt", 1, "ref", { "i" } } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "i-- = %d" },
				{ "test.bt", 1, "postfix-decrement", { "test.bt", 1, "ref", { "i" } } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "i-- = %d" },
				{ "test.bt", 1, "postfix-decrement", { "test.bt", 1, "ref", { "i" } } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "i = %d" },
				{ "test.bt", 1, "ref", { "i" } } } },
		})
		
		local expect_log = {
			"print(i = 1)",
			"print(i-- = 1)",
			"print(i-- = 0)",
			"print(i-- = 65535)",
			"print(i = 65534)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("doesn't modify the original variable when a copy is modified", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "local-variable", "int", "i1", nil, nil, { "test.bt", 1, "num", 1 } },
			{ "test.bt", 1, "local-variable", "int", "i2", nil, nil, { "test.bt", 1, "ref", { "i1" } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "i1 = %d, i2 = %d" },
				{ "test.bt", 1, "ref", { "i1" } },
				{ "test.bt", 1, "ref", { "i2" } } } },
			
			{ "test.bt", 1, "assign",
				{ "test.bt", 1, "ref", { "i2" } },
				{ "test.bt", 1, "num", 2 } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "i1 = %d, i2 = %d" },
				{ "test.bt", 1, "ref", { "i1" } },
				{ "test.bt", 1, "ref", { "i2" } } } },
		})
		
		local expect_log = {
			"print(i1 = 1, i2 = 1)",
			"print(i1 = 1, i2 = 2)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("doesn't modify copies when a variable is modified", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "local-variable", "int", "i1", nil, nil, { "test.bt", 1, "num", 1 } },
			{ "test.bt", 1, "local-variable", "int", "i2", nil, nil, { "test.bt", 1, "ref", { "i1" } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "i1 = %d, i2 = %d" },
				{ "test.bt", 1, "ref", { "i1" } },
				{ "test.bt", 1, "ref", { "i2" } } } },
			
			{ "test.bt", 1, "assign",
				{ "test.bt", 1, "ref", { "i1" } },
				{ "test.bt", 1, "num", 2 } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "i1 = %d, i2 = %d" },
				{ "test.bt", 1, "ref", { "i1" } },
				{ "test.bt", 1, "ref", { "i2" } } } },
		})
		
		local expect_log = {
			"print(i1 = 1, i2 = 1)",
			"print(i1 = 2, i2 = 1)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("modifies the original variable when a reference is modified", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "local-variable", "int", "i1", nil, nil, { "test.bt", 1, "num", 1 } },
			{ "test.bt", 1, "local-variable", "int &", "i2", nil, nil, { "test.bt", 1, "ref", { "i1" } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "i1 = %d, i2 = %d" },
				{ "test.bt", 1, "ref", { "i1" } },
				{ "test.bt", 1, "ref", { "i2" } } } },
			
			{ "test.bt", 1, "assign",
				{ "test.bt", 1, "ref", { "i2" } },
				{ "test.bt", 1, "num", 2 } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "i1 = %d, i2 = %d" },
				{ "test.bt", 1, "ref", { "i1" } },
				{ "test.bt", 1, "ref", { "i2" } } } },
		})
		
		local expect_log = {
			"print(i1 = 1, i2 = 1)",
			"print(i1 = 2, i2 = 2)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("modifies references when the original variable is modified", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "local-variable", "int", "i1", nil, nil, { "test.bt", 1, "num", 1 } },
			{ "test.bt", 1, "local-variable", "const int &", "i2", nil, nil, { "test.bt", 1, "ref", { "i1" } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "i1 = %d, i2 = %d" },
				{ "test.bt", 1, "ref", { "i1" } },
				{ "test.bt", 1, "ref", { "i2" } } } },
			
			{ "test.bt", 1, "assign",
				{ "test.bt", 1, "ref", { "i1" } },
				{ "test.bt", 1, "num", 2 } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "i1 = %d, i2 = %d" },
				{ "test.bt", 1, "ref", { "i1" } },
				{ "test.bt", 1, "ref", { "i2" } } } },
		})
		
		local expect_log = {
			"print(i1 = 1, i2 = 1)",
			"print(i1 = 2, i2 = 2)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("errors on assignment to a const variable", function()
		local interface, log = test_interface()
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 1, "local-variable", "const int", "i1", nil, nil, { "test.bt", 1, "num", 1 } },
				
				{ "test.bt", 1, "assign",
					{ "test.bt", 1, "ref", { "i1" } },
					{ "test.bt", 1, "num", 2 } },
			})
			end, "Attempted modification of const type 'const int' at test.bt:1")
	end)
	
	it("errors on assignment to a const reference to a non-const variable", function()
		local interface, log = test_interface()
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 1, "local-variable", "int", "i1", nil, nil, { "test.bt", 1, "num", 1 } },
				{ "test.bt", 1, "local-variable", "const int &", "i2", nil, nil, { "test.bt", 1, "ref", { "i1" } } },
				
				{ "test.bt", 1, "assign",
					{ "test.bt", 1, "ref", { "i2" } },
					{ "test.bt", 1, "num", 2 } },
			})
			end, "Attempted modification of const type 'const int&' at test.bt:1")
	end)
	
	it("errors on making a non-const reference to a const variable", function()
		local interface, log = test_interface()
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 1, "local-variable", "const int", "i1", nil, nil, { "test.bt", 1, "num", 1 } },
				{ "test.bt", 1, "local-variable", "int &", "i2", nil, nil, { "test.bt", 1, "ref", { "i1" } } },
			})
			end, "can't assign 'const int' to type 'int&' at test.bt:1")
	end)
	
	it("doesn't modify the original array when a copy is modified", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "local-variable", "int", "a1", nil, { "test.bt", 1, "num", 4 }, nil },
			
			{ "test.bt", 1, "assign",
				{ "test.bt", 1, "ref", { "a1", { "test.bt", 1, "num", 0 } } },
				{ "test.bt", 1, "num", 5 } },
			
			{ "test.bt", 1, "assign",
				{ "test.bt", 1, "ref", { "a1", { "test.bt", 1, "num", 1 } } },
				{ "test.bt", 1, "num", 6 } },
			
			{ "test.bt", 1, "assign",
				{ "test.bt", 1, "ref", { "a1", { "test.bt", 1, "num", 2 } } },
				{ "test.bt", 1, "num", 7 } },
			
			{ "test.bt", 1, "assign",
				{ "test.bt", 1, "ref", { "a1", { "test.bt", 1, "num", 3 } } },
				{ "test.bt", 1, "num", 8 } },
			
			{ "test.bt", 1, "local-variable", "int", "a2", nil, { "test.bt", 1, "num", 4 }, { "test.bt", 1, "ref", { "a1" } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "a1 = { %d, %d, %d, %d }" },
				{ "test.bt", 1, "ref", { "a1", { "test.bt", 1, "num", 0 } } },
				{ "test.bt", 1, "ref", { "a1", { "test.bt", 1, "num", 1 } } },
				{ "test.bt", 1, "ref", { "a1", { "test.bt", 1, "num", 2 } } },
				{ "test.bt", 1, "ref", { "a1", { "test.bt", 1, "num", 3 } } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "a2 = { %d, %d, %d, %d }" },
				{ "test.bt", 1, "ref", { "a2", { "test.bt", 1, "num", 0 } } },
				{ "test.bt", 1, "ref", { "a2", { "test.bt", 1, "num", 1 } } },
				{ "test.bt", 1, "ref", { "a2", { "test.bt", 1, "num", 2 } } },
				{ "test.bt", 1, "ref", { "a2", { "test.bt", 1, "num", 3 } } } } },
			
			{ "test.bt", 1, "assign",
				{ "test.bt", 1, "ref", { "a2", { "test.bt", 1, "num", 0 } } },
				{ "test.bt", 1, "num", 1 } },
			
			{ "test.bt", 1, "assign",
				{ "test.bt", 1, "ref", { "a2", { "test.bt", 1, "num", 1 } } },
				{ "test.bt", 1, "num", 2 } },
			
			{ "test.bt", 1, "assign",
				{ "test.bt", 1, "ref", { "a2", { "test.bt", 1, "num", 2 } } },
				{ "test.bt", 1, "num", 3 } },
			
			{ "test.bt", 1, "assign",
				{ "test.bt", 1, "ref", { "a2", { "test.bt", 1, "num", 3 } } },
				{ "test.bt", 1, "num", 4 } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "a1 = { %d, %d, %d, %d }" },
				{ "test.bt", 1, "ref", { "a1", { "test.bt", 1, "num", 0 } } },
				{ "test.bt", 1, "ref", { "a1", { "test.bt", 1, "num", 1 } } },
				{ "test.bt", 1, "ref", { "a1", { "test.bt", 1, "num", 2 } } },
				{ "test.bt", 1, "ref", { "a1", { "test.bt", 1, "num", 3 } } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "a2 = { %d, %d, %d, %d }" },
				{ "test.bt", 1, "ref", { "a2", { "test.bt", 1, "num", 0 } } },
				{ "test.bt", 1, "ref", { "a2", { "test.bt", 1, "num", 1 } } },
				{ "test.bt", 1, "ref", { "a2", { "test.bt", 1, "num", 2 } } },
				{ "test.bt", 1, "ref", { "a2", { "test.bt", 1, "num", 3 } } } } },
		})
		
		local expect_log = {
			"print(a1 = { 5, 6, 7, 8 })",
			"print(a2 = { 5, 6, 7, 8 })",
			
			"print(a1 = { 5, 6, 7, 8 })",
			"print(a2 = { 1, 2, 3, 4 })",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("modifies the original array when a reference is modified", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "local-variable", "int", "a1", nil, { "test.bt", 1, "num", 4 }, nil },
			
			{ "test.bt", 1, "assign",
				{ "test.bt", 1, "ref", { "a1", { "test.bt", 1, "num", 0 } } },
				{ "test.bt", 1, "num", 5 } },
			
			{ "test.bt", 1, "assign",
				{ "test.bt", 1, "ref", { "a1", { "test.bt", 1, "num", 1 } } },
				{ "test.bt", 1, "num", 6 } },
			
			{ "test.bt", 1, "assign",
				{ "test.bt", 1, "ref", { "a1", { "test.bt", 1, "num", 2 } } },
				{ "test.bt", 1, "num", 7 } },
			
			{ "test.bt", 1, "assign",
				{ "test.bt", 1, "ref", { "a1", { "test.bt", 1, "num", 3 } } },
				{ "test.bt", 1, "num", 8 } },
			
			{ "test.bt", 1, "local-variable", "int [] &", "a2", nil, nil, { "test.bt", 1, "ref", { "a1" } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "a1 = { %d, %d, %d, %d }" },
				{ "test.bt", 1, "ref", { "a1", { "test.bt", 1, "num", 0 } } },
				{ "test.bt", 1, "ref", { "a1", { "test.bt", 1, "num", 1 } } },
				{ "test.bt", 1, "ref", { "a1", { "test.bt", 1, "num", 2 } } },
				{ "test.bt", 1, "ref", { "a1", { "test.bt", 1, "num", 3 } } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "a2 = { %d, %d, %d, %d }" },
				{ "test.bt", 1, "ref", { "a2", { "test.bt", 1, "num", 0 } } },
				{ "test.bt", 1, "ref", { "a2", { "test.bt", 1, "num", 1 } } },
				{ "test.bt", 1, "ref", { "a2", { "test.bt", 1, "num", 2 } } },
				{ "test.bt", 1, "ref", { "a2", { "test.bt", 1, "num", 3 } } } } },
			
			{ "test.bt", 1, "assign",
				{ "test.bt", 1, "ref", { "a2", { "test.bt", 1, "num", 0 } } },
				{ "test.bt", 1, "num", 1 } },
			
			{ "test.bt", 1, "assign",
				{ "test.bt", 1, "ref", { "a2", { "test.bt", 1, "num", 1 } } },
				{ "test.bt", 1, "num", 2 } },
			
			{ "test.bt", 1, "assign",
				{ "test.bt", 1, "ref", { "a2", { "test.bt", 1, "num", 2 } } },
				{ "test.bt", 1, "num", 3 } },
			
			{ "test.bt", 1, "assign",
				{ "test.bt", 1, "ref", { "a2", { "test.bt", 1, "num", 3 } } },
				{ "test.bt", 1, "num", 4 } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "a1 = { %d, %d, %d, %d }" },
				{ "test.bt", 1, "ref", { "a1", { "test.bt", 1, "num", 0 } } },
				{ "test.bt", 1, "ref", { "a1", { "test.bt", 1, "num", 1 } } },
				{ "test.bt", 1, "ref", { "a1", { "test.bt", 1, "num", 2 } } },
				{ "test.bt", 1, "ref", { "a1", { "test.bt", 1, "num", 3 } } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "a2 = { %d, %d, %d, %d }" },
				{ "test.bt", 1, "ref", { "a2", { "test.bt", 1, "num", 0 } } },
				{ "test.bt", 1, "ref", { "a2", { "test.bt", 1, "num", 1 } } },
				{ "test.bt", 1, "ref", { "a2", { "test.bt", 1, "num", 2 } } },
				{ "test.bt", 1, "ref", { "a2", { "test.bt", 1, "num", 3 } } } } },
		})
		
		local expect_log = {
			"print(a1 = { 5, 6, 7, 8 })",
			"print(a2 = { 5, 6, 7, 8 })",
			
			"print(a1 = { 1, 2, 3, 4 })",
			"print(a2 = { 1, 2, 3, 4 })",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("doesn't modify the original variable when a pass-by-copy function parameter is modified", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "function", "void", "func", { { "int", "param" } }, {
				{ "test.bt", 1, "call", "Printf", {
					{ "test.bt", 1, "str", "param = %d" },
					{ "test.bt", 1, "ref", { "param" } } } },
				
				{ "test.bt", 1, "assign",
					{ "test.bt", 1, "ref", { "param" } },
					{ "test.bt", 1, "num", 2 } },
				
				{ "test.bt", 1, "call", "Printf", {
					{ "test.bt", 1, "str", "param = %d" },
					{ "test.bt", 1, "ref", { "param" } } } },
			} },
			
			{ "test.bt", 1, "local-variable", "int", "i", nil, nil, { "test.bt", 1, "num", 1 } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "i = %d" },
				{ "test.bt", 1, "ref", { "i" } } } },
			
			{ "test.bt", 1, "call", "func", { { "test.bt", 1, "ref", { "i" } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "i = %d" },
				{ "test.bt", 1, "ref", { "i" } } } },
		})
		
		local expect_log = {
			"print(i = 1)",
			"print(param = 1)",
			"print(param = 2)",  
			"print(i = 1)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("modifies the original variable when a pass-by-reference function parameter is modified", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "function", "void", "func", { { "int &", "param" } }, {
				{ "test.bt", 1, "call", "Printf", {
					{ "test.bt", 1, "str", "param = %d" },
					{ "test.bt", 1, "ref", { "param" } } } },
				
				{ "test.bt", 1, "assign",
					{ "test.bt", 1, "ref", { "param" } },
					{ "test.bt", 1, "num", 2 } },
				
				{ "test.bt", 1, "call", "Printf", {
					{ "test.bt", 1, "str", "param = %d" },
					{ "test.bt", 1, "ref", { "param" } } } },
			} },
			
			{ "test.bt", 1, "local-variable", "int", "i", nil, nil, { "test.bt", 1, "num", 1 } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "i = %d" },
				{ "test.bt", 1, "ref", { "i" } } } },
			
			{ "test.bt", 1, "call", "func", { { "test.bt", 1, "ref", { "i" } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "i = %d" },
				{ "test.bt", 1, "ref", { "i" } } } },
		})
		
		local expect_log = {
			"print(i = 1)",
			"print(param = 1)",
			"print(param = 2)",  
			"print(i = 2)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("errors on assignment to a const pass-by-copy function parameter", function()
		local interface, log = test_interface()
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 1, "function", "void", "func", { { "const int", "param" } }, {
					{ "test.bt", 1, "assign",
						{ "test.bt", 1, "ref", { "param" } },
						{ "test.bt", 1, "num", 2 } },
				} },
				
				{ "test.bt", 1, "local-variable", "int", "i", nil, nil, { "test.bt", 1, "num", 1 } },
				
				{ "test.bt", 1, "call", "func", { { "test.bt", 1, "ref", { "i" } } } },
			})
			end, "Attempted modification of const type 'const int' at test.bt:1")
	end)
	
	it("errors on assignment to a const pass-by-reference function parameter", function()
		local interface, log = test_interface()
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 1, "function", "void", "func", { { "const int &", "param" } }, {
					{ "test.bt", 1, "assign",
						{ "test.bt", 1, "ref", { "param" } },
						{ "test.bt", 1, "num", 2 } },
				} },
				
				{ "test.bt", 1, "local-variable", "int", "i", nil, nil, { "test.bt", 1, "num", 1 } },
				
				{ "test.bt", 1, "call", "func", { { "test.bt", 1, "ref", { "i" } } } },
			})
			end, "Attempted modification of const type 'const int&' at test.bt:1")
	end)
	
	it("errors when passing a const variable to a function that takes a non-const reference", function()
		local interface, log = test_interface()
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 1, "function", "void", "func", { { "int &", "param" } }, {} },
				
				{ "test.bt", 1, "local-variable", "const int", "i", nil, nil, { "test.bt", 1, "num", 1 } },
				
				{ "test.bt", 1, "call", "func", { { "test.bt", 1, "ref", { "i" } } } },
			})
			end, "Attempt to call function func(int&) with incompatible argument types (const int) at test.bt:1")
	end)
	
	it("errors when passing an immediate value to a function that takes a non-const reference", function()
		local interface, log = test_interface()
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 1, "function", "void", "func", { { "int &", "param" } }, {} },
				{ "test.bt", 1, "call", "func", { { "test.bt", 1, "num", 1 } } },
			})
			end, "Attempt to call function func(int&) with incompatible argument types (const int) at test.bt:1")
	end)
	
	it("scopes variables to containing blocks", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "local-variable", "int", "i", nil, nil, { "test.bt", 1, "num", 1 } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "i = %d (1)" },
				{ "test.bt", 1, "ref", { "i" } } } },
			
			{ "test.bt", 1, "block", {
				{ "test.bt", 1, "local-variable", "int", "i", nil, nil, { "test.bt", 1, "num", 2 } },
				
				{ "test.bt", 1, "call", "Printf", {
					{ "test.bt", 1, "str", "i = %d (2)" },
					{ "test.bt", 1, "ref", { "i" } } } },
				
				{ "test.bt", 1, "assign",
					{ "test.bt", 1, "ref", { "i" } },
					{ "test.bt", 1, "num", 3 } },
				
				{ "test.bt", 1, "call", "Printf", {
					{ "test.bt", 1, "str", "i = %d (3)" },
					{ "test.bt", 1, "ref", { "i" } } } },
			} },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "i = %d (4)" },
				{ "test.bt", 1, "ref", { "i" } } } },
		})
		
		local expect_log = {
			"print(i = 1 (1))",
			"print(i = 2 (2))",
			"print(i = 3 (3))",
			"print(i = 1 (4))",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("errors on function definitions inside blocks", function()
		local interface, log = test_interface()
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 1, "block", {
					{ "test.bt", 1, "function", "void", "func", { { "int &", "param" } }, {} },
				} },
			})
			end, "Attempt to define function inside another block at test.bt:1")
	end)
	
	it("errors on function definitions inside an if statement", function()
		local interface, log = test_interface()
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 1, "if",
					{ { "test.bt", 1, "num", 1 }, {
						{ "test.bt", 1, "function", "void", "func", { { "int &", "param" } }, {} },
					} },
				},
			})
			end, "Attempt to define function inside another block at test.bt:1")
	end)
	
	it("errors on function definitions inside another function", function()
		local interface, log = test_interface()
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 1, "function", "void", "func1", {}, {
					{ "test.bt", 1, "function", "void", "func2", {}, {} },
				} },
				
				{ "test.bt", 1, "call", "func1", {} },
			})
			end, "Attempt to define function inside another block at test.bt:1")
	end)
	
	it("doesn't modify the original when an array passed by copy into a function is modified", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "local-variable", "int", "a1", nil, { "test.bt", 1, "num", 4 }, nil },
			
			{ "test.bt", 2, "assign",
				{ "test.bt", 2, "ref", { "a1", { "test.bt", 2, "num", 0 } } },
				{ "test.bt", 2, "num", 5 } },
			
			{ "test.bt", 2, "assign",
				{ "test.bt", 2, "ref", { "a1", { "test.bt", 2, "num", 1 } } },
				{ "test.bt", 2, "num", 6 } },
			
			{ "test.bt", 2, "assign",
				{ "test.bt", 2, "ref", { "a1", { "test.bt", 2, "num", 2 } } },
				{ "test.bt", 2, "num", 7 } },
			
			{ "test.bt", 2, "assign",
				{ "test.bt", 2, "ref", { "a1", { "test.bt", 2, "num", 3 } } },
				{ "test.bt", 2, "num", 8 } },
			
			{ "test.bt", 3, "function", "void", "func", { { "int []", "param" } }, {
				{ "test.bt", 4, "call", "Printf", {
					{ "test.bt", 4, "str", "param = { %d, %d, %d, %d }" },
					{ "test.bt", 4, "ref", { "param", { "test.bt", 4, "num", 0 } } },
					{ "test.bt", 4, "ref", { "param", { "test.bt", 4, "num", 1 } } },
					{ "test.bt", 4, "ref", { "param", { "test.bt", 4, "num", 2 } } },
					{ "test.bt", 4, "ref", { "param", { "test.bt", 4, "num", 3 } } } } },
				
				{ "test.bt", 5, "assign",
					{ "test.bt", 5, "ref", { "param", { "test.bt", 5, "num", 0 } } },
					{ "test.bt", 5, "num", 1 } },
				
				{ "test.bt", 6, "assign",
					{ "test.bt", 6, "ref", { "param", { "test.bt", 6, "num", 1 } } },
					{ "test.bt", 6, "num", 2 } },
				
				{ "test.bt", 7, "assign",
					{ "test.bt", 7, "ref", { "param", { "test.bt", 7, "num", 2 } } },
					{ "test.bt", 7, "num", 3 } },
				
				{ "test.bt", 8, "assign",
					{ "test.bt", 8, "ref", { "param", { "test.bt", 8, "num", 3 } } },
					{ "test.bt", 8, "num", 4 } },
				
				{ "test.bt", 9, "call", "Printf", {
					{ "test.bt", 9, "str", "param = { %d, %d, %d, %d }" },
					{ "test.bt", 9, "ref", { "param", { "test.bt", 9, "num", 0 } } },
					{ "test.bt", 9, "ref", { "param", { "test.bt", 9, "num", 1 } } },
					{ "test.bt", 9, "ref", { "param", { "test.bt", 9, "num", 2 } } },
					{ "test.bt", 9, "ref", { "param", { "test.bt", 9, "num", 3 } } } } },
			} },
			
			{ "test.bt", 10, "call", "Printf", {
				{ "test.bt", 10, "str", "a1 = { %d, %d, %d, %d }" },
				{ "test.bt", 10, "ref", { "a1", { "test.bt", 10, "num", 0 } } },
				{ "test.bt", 10, "ref", { "a1", { "test.bt", 10, "num", 1 } } },
				{ "test.bt", 10, "ref", { "a1", { "test.bt", 10, "num", 2 } } },
				{ "test.bt", 10, "ref", { "a1", { "test.bt", 10, "num", 3 } } } } },
			
			{ "test.bt", 11, "call", "func", {
				{ "test.bt", 11, "ref", { "a1" } },
			} },
			
			{ "test.bt", 12, "call", "Printf", {
				{ "test.bt", 12, "str", "a1 = { %d, %d, %d, %d }" },
				{ "test.bt", 12, "ref", { "a1", { "test.bt", 12, "num", 0 } } },
				{ "test.bt", 12, "ref", { "a1", { "test.bt", 12, "num", 1 } } },
				{ "test.bt", 12, "ref", { "a1", { "test.bt", 12, "num", 2 } } },
				{ "test.bt", 12, "ref", { "a1", { "test.bt", 12, "num", 3 } } } } },
		})
		
		local expect_log = {
			"print(a1 = { 5, 6, 7, 8 })",
			"print(param = { 5, 6, 7, 8 })",
			"print(param = { 1, 2, 3, 4 })",
			"print(a1 = { 5, 6, 7, 8 })",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("modifies the original when an array passed by reference into a function is modified", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "local-variable", "int", "a1", nil, { "test.bt", 1, "num", 4 }, nil },
			
			{ "test.bt", 2, "assign",
				{ "test.bt", 2, "ref", { "a1", { "test.bt", 2, "num", 0 } } },
				{ "test.bt", 2, "num", 5 } },
			
			{ "test.bt", 2, "assign",
				{ "test.bt", 2, "ref", { "a1", { "test.bt", 2, "num", 1 } } },
				{ "test.bt", 2, "num", 6 } },
			
			{ "test.bt", 2, "assign",
				{ "test.bt", 2, "ref", { "a1", { "test.bt", 2, "num", 2 } } },
				{ "test.bt", 2, "num", 7 } },
			
			{ "test.bt", 2, "assign",
				{ "test.bt", 2, "ref", { "a1", { "test.bt", 2, "num", 3 } } },
				{ "test.bt", 2, "num", 8 } },
			
			{ "test.bt", 3, "function", "void", "func", { { "int [] &", "param" } }, {
				{ "test.bt", 4, "call", "Printf", {
					{ "test.bt", 4, "str", "param = { %d, %d, %d, %d }" },
					{ "test.bt", 4, "ref", { "param", { "test.bt", 4, "num", 0 } } },
					{ "test.bt", 4, "ref", { "param", { "test.bt", 4, "num", 1 } } },
					{ "test.bt", 4, "ref", { "param", { "test.bt", 4, "num", 2 } } },
					{ "test.bt", 4, "ref", { "param", { "test.bt", 4, "num", 3 } } } } },
				
				{ "test.bt", 5, "assign",
					{ "test.bt", 5, "ref", { "param", { "test.bt", 5, "num", 0 } } },
					{ "test.bt", 5, "num", 1 } },
				
				{ "test.bt", 6, "assign",
					{ "test.bt", 6, "ref", { "param", { "test.bt", 6, "num", 1 } } },
					{ "test.bt", 6, "num", 2 } },
				
				{ "test.bt", 7, "assign",
					{ "test.bt", 7, "ref", { "param", { "test.bt", 7, "num", 2 } } },
					{ "test.bt", 7, "num", 3 } },
				
				{ "test.bt", 8, "assign",
					{ "test.bt", 8, "ref", { "param", { "test.bt", 8, "num", 3 } } },
					{ "test.bt", 8, "num", 4 } },
				
				{ "test.bt", 9, "call", "Printf", {
					{ "test.bt", 9, "str", "param = { %d, %d, %d, %d }" },
					{ "test.bt", 9, "ref", { "param", { "test.bt", 9, "num", 0 } } },
					{ "test.bt", 9, "ref", { "param", { "test.bt", 9, "num", 1 } } },
					{ "test.bt", 9, "ref", { "param", { "test.bt", 9, "num", 2 } } },
					{ "test.bt", 9, "ref", { "param", { "test.bt", 9, "num", 3 } } } } },
			} },
			
			{ "test.bt", 10, "call", "Printf", {
				{ "test.bt", 10, "str", "a1 = { %d, %d, %d, %d }" },
				{ "test.bt", 10, "ref", { "a1", { "test.bt", 10, "num", 0 } } },
				{ "test.bt", 10, "ref", { "a1", { "test.bt", 10, "num", 1 } } },
				{ "test.bt", 10, "ref", { "a1", { "test.bt", 10, "num", 2 } } },
				{ "test.bt", 10, "ref", { "a1", { "test.bt", 10, "num", 3 } } } } },
			
			{ "test.bt", 11, "call", "func", {
				{ "test.bt", 11, "ref", { "a1" } },
			} },
			
			{ "test.bt", 12, "call", "Printf", {
				{ "test.bt", 12, "str", "a1 = { %d, %d, %d, %d }" },
				{ "test.bt", 12, "ref", { "a1", { "test.bt", 12, "num", 0 } } },
				{ "test.bt", 12, "ref", { "a1", { "test.bt", 12, "num", 1 } } },
				{ "test.bt", 12, "ref", { "a1", { "test.bt", 12, "num", 2 } } },
				{ "test.bt", 12, "ref", { "a1", { "test.bt", 12, "num", 3 } } } } },
		})
		
		local expect_log = {
			"print(a1 = { 5, 6, 7, 8 })",
			"print(param = { 5, 6, 7, 8 })",
			"print(param = { 1, 2, 3, 4 })",
			"print(a1 = { 1, 2, 3, 4 })",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("doesn't modify the original variable when a pass-by-copy struct parameter is modified", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "struct", "mystruct", { { "int", "param" } },
			{
				{ "test.bt", 1, "call", "Printf", {
					{ "test.bt", 1, "str", "param = %d" },
					{ "test.bt", 1, "ref", { "param" } } } },
				
				{ "test.bt", 1, "assign",
					{ "test.bt", 1, "ref", { "param" } },
					{ "test.bt", 1, "num", 2 } },
				
				{ "test.bt", 1, "call", "Printf", {
					{ "test.bt", 1, "str", "param = %d" },
					{ "test.bt", 1, "ref", { "param" } } } },
			} },
			
			{ "test.bt", 1, "local-variable", "int", "i", nil, nil, { "test.bt", 1, "num", 1 } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "i = %d" },
				{ "test.bt", 1, "ref", { "i" } } } },
			
			{ "test.bt", 1, "local-variable", "struct mystruct", "a", {
				{ "test.bt", 1, "ref", { "i" } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "i = %d" },
				{ "test.bt", 1, "ref", { "i" } } } },
		})
		
		local expect_log = {
			"print(i = 1)",
			"print(param = 1)",
			"print(param = 2)",
			"print(i = 1)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("modifies the original variable when a pass-by-reference function parameter is modified", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "struct", "mystruct", { { "int &", "param" } },
			{
				{ "test.bt", 1, "call", "Printf", {
					{ "test.bt", 1, "str", "param = %d" },
					{ "test.bt", 1, "ref", { "param" } } } },
				
				{ "test.bt", 1, "assign",
					{ "test.bt", 1, "ref", { "param" } },
					{ "test.bt", 1, "num", 2 } },
				
				{ "test.bt", 1, "call", "Printf", {
					{ "test.bt", 1, "str", "param = %d" },
					{ "test.bt", 1, "ref", { "param" } } } },
			} },
			
			{ "test.bt", 1, "local-variable", "int", "i", nil, nil, { "test.bt", 1, "num", 1 } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "i = %d" },
				{ "test.bt", 1, "ref", { "i" } } } },
			
			{ "test.bt", 1, "local-variable", "struct mystruct", "a", {
				{ "test.bt", 1, "ref", { "i" } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "i = %d" },
				{ "test.bt", 1, "ref", { "i" } } } },
		})
		
		local expect_log = {
			"print(i = 1)",
			"print(param = 1)",
			"print(param = 2)",
			"print(i = 2)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("errors on assignment to a const pass-by-copy struct parameter", function()
		local interface, log = test_interface()
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 1, "struct", "mystruct", { { "const int", "param" } },
				{
					{ "test.bt", 1, "assign",
						{ "test.bt", 1, "ref", { "param" } },
						{ "test.bt", 1, "num", 2 } },
				} },
				
				{ "test.bt", 1, "local-variable", "int", "i", nil, nil, { "test.bt", 1, "num", 1 } },
				
				{ "test.bt", 1, "local-variable", "struct mystruct", "a", {
					{ "test.bt", 1, "ref", { "i" } } } },
			})
			end, "Attempted modification of const type 'const int' at test.bt:1")
	end)
	
	it("errors on assignment to a const pass-by-reference function parameter", function()
		local interface, log = test_interface()
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 1, "struct", "mystruct", { { "const int &", "param" } },
				{
					{ "test.bt", 1, "assign",
						{ "test.bt", 1, "ref", { "param" } },
						{ "test.bt", 1, "num", 2 } },
				} },
				
				{ "test.bt", 1, "local-variable", "int", "i", nil, nil, { "test.bt", 1, "num", 1 } },
				
				{ "test.bt", 1, "local-variable", "struct mystruct", "a", {
					{ "test.bt", 1, "ref", { "i" } } } },
			})
			end, "Attempted modification of const type 'const int&' at test.bt:1")
	end)
	
	it("errors when passing a const variable to a struct that takes a non-const reference", function()
		local interface, log = test_interface()
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 1, "struct", "mystruct", { { "int &", "param" } }, {} },
				
				{ "test.bt", 1, "local-variable", "const int", "i", nil, nil, { "test.bt", 1, "num", 1 } },
				
				{ "test.bt", 1, "local-variable", "struct mystruct", "a", {
					{ "test.bt", 1, "ref", { "i" } } } },
			})
			end, "Attempt to declare struct type 'struct mystruct' with incompatible argument types (const int) - expected (int&) at test.bt:1")
	end)
	
	it("errors when passing an immediate value to a struct that takes a non-const reference", function()
		local interface, log = test_interface()
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 1, "struct", "mystruct", { { "int &", "param" } }, {} },
				{ "test.bt", 1, "local-variable", "struct mystruct", "a", { { "test.bt", 1, "num", 1 } } },
			})
			end, "Attempt to declare struct type 'struct mystruct' with incompatible argument types (const int) - expected (int&) at test.bt:1")
	end)
	
	it("doesn't modify the original when an array passed by copy into a struct is modified", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "local-variable", "int", "a1", nil, { "test.bt", 1, "num", 4 }, nil },
			
			{ "test.bt", 2, "assign",
				{ "test.bt", 2, "ref", { "a1", { "test.bt", 2, "num", 0 } } },
				{ "test.bt", 2, "num", 5 } },
			
			{ "test.bt", 2, "assign",
				{ "test.bt", 2, "ref", { "a1", { "test.bt", 2, "num", 1 } } },
				{ "test.bt", 2, "num", 6 } },
			
			{ "test.bt", 2, "assign",
				{ "test.bt", 2, "ref", { "a1", { "test.bt", 2, "num", 2 } } },
				{ "test.bt", 2, "num", 7 } },
			
			{ "test.bt", 2, "assign",
				{ "test.bt", 2, "ref", { "a1", { "test.bt", 2, "num", 3 } } },
				{ "test.bt", 2, "num", 8 } },
			
			{ "test.bt", 1, "struct", "mystruct", { { "int []", "param" } }, {
				{ "test.bt", 4, "call", "Printf", {
					{ "test.bt", 4, "str", "param = { %d, %d, %d, %d }" },
					{ "test.bt", 4, "ref", { "param", { "test.bt", 4, "num", 0 } } },
					{ "test.bt", 4, "ref", { "param", { "test.bt", 4, "num", 1 } } },
					{ "test.bt", 4, "ref", { "param", { "test.bt", 4, "num", 2 } } },
					{ "test.bt", 4, "ref", { "param", { "test.bt", 4, "num", 3 } } } } },
				
				{ "test.bt", 5, "assign",
					{ "test.bt", 5, "ref", { "param", { "test.bt", 5, "num", 0 } } },
					{ "test.bt", 5, "num", 1 } },
				
				{ "test.bt", 6, "assign",
					{ "test.bt", 6, "ref", { "param", { "test.bt", 6, "num", 1 } } },
					{ "test.bt", 6, "num", 2 } },
				
				{ "test.bt", 7, "assign",
					{ "test.bt", 7, "ref", { "param", { "test.bt", 7, "num", 2 } } },
					{ "test.bt", 7, "num", 3 } },
				
				{ "test.bt", 8, "assign",
					{ "test.bt", 8, "ref", { "param", { "test.bt", 8, "num", 3 } } },
					{ "test.bt", 8, "num", 4 } },
				
				{ "test.bt", 9, "call", "Printf", {
					{ "test.bt", 9, "str", "param = { %d, %d, %d, %d }" },
					{ "test.bt", 9, "ref", { "param", { "test.bt", 9, "num", 0 } } },
					{ "test.bt", 9, "ref", { "param", { "test.bt", 9, "num", 1 } } },
					{ "test.bt", 9, "ref", { "param", { "test.bt", 9, "num", 2 } } },
					{ "test.bt", 9, "ref", { "param", { "test.bt", 9, "num", 3 } } } } },
			} },
			
			{ "test.bt", 10, "call", "Printf", {
				{ "test.bt", 10, "str", "a1 = { %d, %d, %d, %d }" },
				{ "test.bt", 10, "ref", { "a1", { "test.bt", 10, "num", 0 } } },
				{ "test.bt", 10, "ref", { "a1", { "test.bt", 10, "num", 1 } } },
				{ "test.bt", 10, "ref", { "a1", { "test.bt", 10, "num", 2 } } },
				{ "test.bt", 10, "ref", { "a1", { "test.bt", 10, "num", 3 } } } } },
			
			{ "test.bt", 1, "local-variable", "struct mystruct", "a", {
				{ "test.bt", 11, "ref", { "a1" } } } },
			
			{ "test.bt", 12, "call", "Printf", {
				{ "test.bt", 12, "str", "a1 = { %d, %d, %d, %d }" },
				{ "test.bt", 12, "ref", { "a1", { "test.bt", 12, "num", 0 } } },
				{ "test.bt", 12, "ref", { "a1", { "test.bt", 12, "num", 1 } } },
				{ "test.bt", 12, "ref", { "a1", { "test.bt", 12, "num", 2 } } },
				{ "test.bt", 12, "ref", { "a1", { "test.bt", 12, "num", 3 } } } } },
		})
		
		local expect_log = {
			"print(a1 = { 5, 6, 7, 8 })",
			"print(param = { 5, 6, 7, 8 })",
			"print(param = { 1, 2, 3, 4 })",
			"print(a1 = { 5, 6, 7, 8 })",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("modifies the original when an array passed by reference into a struct is modified", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "local-variable", "int", "a1", nil, { "test.bt", 1, "num", 4 }, nil },
			
			{ "test.bt", 2, "assign",
				{ "test.bt", 2, "ref", { "a1", { "test.bt", 2, "num", 0 } } },
				{ "test.bt", 2, "num", 5 } },
			
			{ "test.bt", 2, "assign",
				{ "test.bt", 2, "ref", { "a1", { "test.bt", 2, "num", 1 } } },
				{ "test.bt", 2, "num", 6 } },
			
			{ "test.bt", 2, "assign",
				{ "test.bt", 2, "ref", { "a1", { "test.bt", 2, "num", 2 } } },
				{ "test.bt", 2, "num", 7 } },
			
			{ "test.bt", 2, "assign",
				{ "test.bt", 2, "ref", { "a1", { "test.bt", 2, "num", 3 } } },
				{ "test.bt", 2, "num", 8 } },
			
			{ "test.bt", 1, "struct", "mystruct", { { "int & []", "param" } }, {
				{ "test.bt", 4, "call", "Printf", {
					{ "test.bt", 4, "str", "param = { %d, %d, %d, %d }" },
					{ "test.bt", 4, "ref", { "param", { "test.bt", 4, "num", 0 } } },
					{ "test.bt", 4, "ref", { "param", { "test.bt", 4, "num", 1 } } },
					{ "test.bt", 4, "ref", { "param", { "test.bt", 4, "num", 2 } } },
					{ "test.bt", 4, "ref", { "param", { "test.bt", 4, "num", 3 } } } } },
				
				{ "test.bt", 5, "assign",
					{ "test.bt", 5, "ref", { "param", { "test.bt", 5, "num", 0 } } },
					{ "test.bt", 5, "num", 1 } },
				
				{ "test.bt", 6, "assign",
					{ "test.bt", 6, "ref", { "param", { "test.bt", 6, "num", 1 } } },
					{ "test.bt", 6, "num", 2 } },
				
				{ "test.bt", 7, "assign",
					{ "test.bt", 7, "ref", { "param", { "test.bt", 7, "num", 2 } } },
					{ "test.bt", 7, "num", 3 } },
				
				{ "test.bt", 8, "assign",
					{ "test.bt", 8, "ref", { "param", { "test.bt", 8, "num", 3 } } },
					{ "test.bt", 8, "num", 4 } },
				
				{ "test.bt", 9, "call", "Printf", {
					{ "test.bt", 9, "str", "param = { %d, %d, %d, %d }" },
					{ "test.bt", 9, "ref", { "param", { "test.bt", 9, "num", 0 } } },
					{ "test.bt", 9, "ref", { "param", { "test.bt", 9, "num", 1 } } },
					{ "test.bt", 9, "ref", { "param", { "test.bt", 9, "num", 2 } } },
					{ "test.bt", 9, "ref", { "param", { "test.bt", 9, "num", 3 } } } } },
			} },
			
			{ "test.bt", 10, "call", "Printf", {
				{ "test.bt", 10, "str", "a1 = { %d, %d, %d, %d }" },
				{ "test.bt", 10, "ref", { "a1", { "test.bt", 10, "num", 0 } } },
				{ "test.bt", 10, "ref", { "a1", { "test.bt", 10, "num", 1 } } },
				{ "test.bt", 10, "ref", { "a1", { "test.bt", 10, "num", 2 } } },
				{ "test.bt", 10, "ref", { "a1", { "test.bt", 10, "num", 3 } } } } },
			
			{ "test.bt", 1, "local-variable", "struct mystruct", "a", {
				{ "test.bt", 11, "ref", { "a1" } } } },
			
			{ "test.bt", 12, "call", "Printf", {
				{ "test.bt", 12, "str", "a1 = { %d, %d, %d, %d }" },
				{ "test.bt", 12, "ref", { "a1", { "test.bt", 12, "num", 0 } } },
				{ "test.bt", 12, "ref", { "a1", { "test.bt", 12, "num", 1 } } },
				{ "test.bt", 12, "ref", { "a1", { "test.bt", 12, "num", 2 } } },
				{ "test.bt", 12, "ref", { "a1", { "test.bt", 12, "num", 3 } } } } },
		})
		
		local expect_log = {
			"print(a1 = { 5, 6, 7, 8 })",
			"print(param = { 5, 6, 7, 8 })",
			"print(param = { 1, 2, 3, 4 })",
			"print(a1 = { 1, 2, 3, 4 })",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("passes numeric values through unary '+' without modification", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "+1 = %d" },
				{ "test.bt", 1, "plus", { "test.bt", 1, "num", 1 } } } },
			
			{ "test.bt", 2, "call", "Printf", {
				{ "test.bt", 2, "str", "+1.0 = %.1f" },
				{ "test.bt", 2, "plus", { "test.bt", 2, "num", 1.0 } } } },
			
			{ "test.bt", 3, "call", "Printf", {
				{ "test.bt", 3, "str", "+1.5 = %.1f" },
				{ "test.bt", 3, "plus", { "test.bt", 3, "num", 1.5 } } } },
			
			{ "test.bt", 4, "local-variable", "int", "i", nil, nil,
				{ "test.bt", 4, "num", 1 } },
			
			{ "test.bt", 5, "call", "Printf", {
				{ "test.bt", 5, "str", "+i = %d" },
				{ "test.bt", 5, "plus", { "test.bt", 5, "ref", { "i" } } } } },
		})
		
		local expect_log = {
			"print(+1 = 1)",
			"print(+1.0 = 1.0)",
			"print(+1.5 = 1.5)",
			"print(+i = 1)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("errors if unary '+' is used on a string value", function()
		local interface, log = test_interface()
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 1, "plus", { "test.bt", 1, "str", "hello" } },
			})
			end, "Invalid operand to unary '+' operator - expected numeric, got 'const string' at test.bt:1")
	end)
	
	it("negates numeric values with unary '-' operator", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "-1 = %d" },
				{ "test.bt", 1, "minus", { "test.bt", 1, "num", 1 } } } },
			
			{ "test.bt", 2, "call", "Printf", {
				{ "test.bt", 2, "str", "-1.0 = %.1f" },
				{ "test.bt", 2, "minus", { "test.bt", 2, "num", 1.0 } } } },
			
			{ "test.bt", 3, "call", "Printf", {
				{ "test.bt", 3, "str", "-1.5 = %.1f" },
				{ "test.bt", 3, "minus", { "test.bt", 3, "num", 1.5 } } } },
			
			{ "test.bt", 4, "local-variable", "int", "i", nil, nil,
				{ "test.bt", 4, "num", 1 } },
			
			{ "test.bt", 5, "call", "Printf", {
				{ "test.bt", 5, "str", "-i = %d" },
				{ "test.bt", 5, "minus", { "test.bt", 5, "ref", { "i" } } } } },
		})
		
		local expect_log = {
			"print(-1 = -1)",
			"print(-1.0 = -1.0)",
			"print(-1.5 = -1.5)",
			"print(-i = -1)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("errors if unary '-' is used on a string value", function()
		local interface, log = test_interface()
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 1, "minus", { "test.bt", 1, "str", "hello" } },
			})
			end, "Invalid operand to unary '-' operator - expected numeric, got 'const string' at test.bt:1")
	end)
	
	it("yields truth branch from ternary when condition is true", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "%d" },
				{ "test.bt", 1, "ternary",
					{ "test.bt", 1, "num", 1 },
					{ "test.bt", 1, "num", 2 },
					{ "test.bt", 1, "num", 3 } } } },
		})
		
		local expect_log = {
			"print(2)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("yields false branch from ternary when condition is true", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "%d" },
				{ "test.bt", 1, "ternary",
					{ "test.bt", 1, "num", 0 },
					{ "test.bt", 1, "num", 2 },
					{ "test.bt", 1, "num", 3 } } } },
		})
		
		local expect_log = {
			"print(3)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("errors if expressions of incorrect type are used as ternary condition", function()
		local interface, log = test_interface()
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 1, "function", "void", "vfunc", {}, {} },
				{ "test.bt", 1, "ternary",
					{ "test.bt", 1, "call", "vfunc", {} },
					{ "test.bt", 1, "num", 2 },
					{ "test.bt", 1, "num", 3 } }
			})
			end, "Invalid condition operand to ternary operator - expected numeric, got 'void' at test.bt:1")
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 1, "ternary",
					{ "test.bt", 1, "str", "hello" },
					{ "test.bt", 1, "num", 2 },
					{ "test.bt", 1, "num", 3 } }
			})
			end, "Invalid condition operand to ternary operator - expected numeric, got 'const string' at test.bt:1")
	end)
	
	it("returns the size of arrays (in elements) from ArrayLength()", function()
		local interface, log = test_interface(string.char(
			0x01, 0x00, 0x00, 0x00,
			0x02, 0x00, 0x00, 0x00,
			0x03, 0x00, 0x00, 0x00,
			0x04, 0x00, 0x00, 0x00
		))
		
		executor.execute(interface, {
			{ "test.bt", 1, "local-variable", "char",      "a", nil, { "test.bt", 1, "num", 3 }, nil },
			{ "test.bt", 2, "local-variable", "const int", "b", nil, { "test.bt", 1, "num", 3 }, nil },
			{ "test.bt", 3, "local-variable", "int",       "c", nil, { "test.bt", 1, "num", 0 }, nil },
			
			{ "test.bt", 4, "call", "Printf", {
				{ "test.bt", 4, "str", "ArrayLength(a) = %d" },
				{ "test.bt", 4, "call", "ArrayLength", { { "test.bt", 4, "ref", { "a", } } } } } },
			
			{ "test.bt", 5, "call", "Printf", {
				{ "test.bt", 5, "str", "ArrayLength(b) = %d" },
				{ "test.bt", 5, "call", "ArrayLength", { { "test.bt", 5, "ref", { "b", } } } } } },
			
			{ "test.bt", 6, "call", "Printf", {
				{ "test.bt", 6, "str", "ArrayLength(c) = %d" },
				{ "test.bt", 6, "call", "ArrayLength", { { "test.bt", 6, "ref", { "c", } } } } } },
			
			{ "test.bt", 7, "variable", "int", "d", nil, { "test.bt", 7, "num", 2 } },
			
			{ "test.bt", 8, "call", "Printf", {
				{ "test.bt", 8, "str", "ArrayLength(d) = %d" },
				{ "test.bt", 8, "call", "ArrayLength", { { "test.bt", 8, "ref", { "d", } } } } } },
		})
		
		local expect_log = {
			"print(ArrayLength(a) = 3)",
			"print(ArrayLength(b) = 3)",
			"print(ArrayLength(c) = 0)",
			
			"print(ArrayLength(d) = 2)",
			
			"set_comment(0, 8, d)",
			"set_data_type(0, 8, s32le)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("errors if ArrayLength() is called with the wrong arguments", function()
		local interface, log = test_interface()
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 1, "function", "void", "vfunc", {}, {} },
				{ "test.bt", 2, "call", "ArrayLength", { { "test.bt", 2, "call", "vfunc", {} } } },
			})
			end, "Attempt to call function ArrayLength(<any array type>) with incompatible argument types (void) at test.bt:2")
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 2, "call", "ArrayLength", { { "test.bt", 2, "str", "hello" } } },
			})
			end, "Attempt to call function ArrayLength(<any array type>) with incompatible argument types (const string) at test.bt:2")
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 1, "local-variable", "char", "a", nil, { "test.bt", 1, "num", 3 }, nil },
				{ "test.bt", 1, "function", "void", "vfunc", {}, {} },
				{ "test.bt", 2, "call", "ArrayLength", { { "test.bt", 2, "ref", { "a" } }, { "test.bt", 2, "call", "vfunc", {} } } },
			})
			end, "Attempt to call function ArrayLength(<any array type>) with incompatible argument types (char[], void) at test.bt:2")
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 2, "call", "ArrayLength", {} },
			})
			end, "Attempt to call function ArrayLength(<any array type>) with incompatible argument types () at test.bt:2")
	end)
	
	it("allows arbitrarily resizing local arrays with ArrayResize()", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			-- local int a[0];
			{ "test.bt", 1, "local-variable", "int", "a", nil, { "test.bt", 1, "num", 0 }, nil },
			
			-- Printf("ArrayLength(a) = %d", ArrayLength(a));
			{ "test.bt", 2, "call", "Printf", {
				{ "test.bt", 2, "str", "ArrayLength(a) = %d" },
				{ "test.bt", 2, "call", "ArrayLength", { { "test.bt", 2, "ref", { "a" } } } } } },
			
			-- ArrayResize(a, 4);
			{ "test.bt", 3, "call", "ArrayResize", {
				{ "test.bt", 3, "ref", { "a" } },
				{ "test.bt", 3, "num", 4 } } },
			
			-- Printf("ArrayLength(a) = %d", ArrayLength(a));
			{ "test.bt", 4, "call", "Printf", {
				{ "test.bt", 4, "str", "ArrayLength(a) = %d" },
				{ "test.bt", 4, "call", "ArrayLength", { { "test.bt", 4, "ref", { "a" } } } } } },
			
			-- Printf("a = { %d, %d, %d, %d }", a[0], a[1], a[2], a[3]);
			{ "test.bt", 5, "call", "Printf", {
				{ "test.bt", 4, "str", "a = { %d, %d, %d, %d }" },
				{ "test.bt", 5, "ref", { "a", { "test.bt", 5, "num", 0 } } },
				{ "test.bt", 5, "ref", { "a", { "test.bt", 5, "num", 1 } } },
				{ "test.bt", 5, "ref", { "a", { "test.bt", 5, "num", 2 } } },
				{ "test.bt", 5, "ref", { "a", { "test.bt", 5, "num", 3 } } } } },
			
			-- a[0] = 100;
			{ "test.bt", 6, "assign",
				{ "test.bt", 6, "ref", { "a", { "test.bt", 6, "num", 0 } } },
				{ "test.bt", 6, "num", 100 } },
			
			-- a[1] = 101;
			{ "test.bt", 7, "assign",
				{ "test.bt", 7, "ref", { "a", { "test.bt", 7, "num", 1 } } },
				{ "test.bt", 7, "num", 101 } },
			
			-- a[2] = 102;
			{ "test.bt", 8, "assign",
				{ "test.bt", 8, "ref", { "a", { "test.bt", 8, "num", 2 } } },
				{ "test.bt", 8, "num", 102 } },
			
			-- a[3] = 103;
			{ "test.bt", 9, "assign",
				{ "test.bt", 9, "ref", { "a", { "test.bt", 9, "num", 3 } } },
				{ "test.bt", 9, "num", 103 } },
			
			-- Printf("a = { %d, %d, %d, %d }", a[0], a[1], a[2], a[3]);
			{ "test.bt", 10, "call", "Printf", {
				{ "test.bt", 4, "str", "a = { %d, %d, %d, %d }" },
				{ "test.bt", 10, "ref", { "a", { "test.bt", 10, "num", 0 } } },
				{ "test.bt", 10, "ref", { "a", { "test.bt", 10, "num", 1 } } },
				{ "test.bt", 10, "ref", { "a", { "test.bt", 10, "num", 2 } } },
				{ "test.bt", 10, "ref", { "a", { "test.bt", 10, "num", 3 } } } } },
			
			-- ArrayResize(a, 3);
			{ "test.bt", 11, "call", "ArrayResize", {
				{ "test.bt", 11, "ref", { "a" } },
				{ "test.bt", 11, "num", 3 } } },
			
			-- Printf("ArrayLength(a) = %d", ArrayLength(a));
			{ "test.bt", 12, "call", "Printf", {
				{ "test.bt", 12, "str", "ArrayLength(a) = %d" },
				{ "test.bt", 12, "call", "ArrayLength", { { "test.bt", 12, "ref", { "a" } } } } } },
			
			-- Printf("a = { %d, %d, %d }", a[0], a[1], a[2]);
			{ "test.bt", 13, "call", "Printf", {
				{ "test.bt", 4, "str", "a = { %d, %d, %d }" },
				{ "test.bt", 13, "ref", { "a", { "test.bt", 13, "num", 0 } } },
				{ "test.bt", 13, "ref", { "a", { "test.bt", 13, "num", 1 } } },
				{ "test.bt", 13, "ref", { "a", { "test.bt", 13, "num", 2 } } } } },
			
			-- ArrayResize(a, 5);
			{ "test.bt", 14, "call", "ArrayResize", {
				{ "test.bt", 14, "ref", { "a" } },
				{ "test.bt", 14, "num", 5 } } },
			
			-- Printf("ArrayLength(a) = %d", ArrayLength(a));
			{ "test.bt", 15, "call", "Printf", {
				{ "test.bt", 15, "str", "ArrayLength(a) = %d" },
				{ "test.bt", 15, "call", "ArrayLength", { { "test.bt", 15, "ref", { "a" } } } } } },
			
			-- Printf("a = { %d, %d, %d, %d, %d }", a[0], a[1], a[2], a[3], a[4]);
			{ "test.bt", 16, "call", "Printf", {
				{ "test.bt", 4, "str", "a = { %d, %d, %d, %d, %d }" },
				{ "test.bt", 16, "ref", { "a", { "test.bt", 16, "num", 0 } } },
				{ "test.bt", 16, "ref", { "a", { "test.bt", 16, "num", 1 } } },
				{ "test.bt", 16, "ref", { "a", { "test.bt", 16, "num", 2 } } },
				{ "test.bt", 16, "ref", { "a", { "test.bt", 16, "num", 3 } } },
				{ "test.bt", 16, "ref", { "a", { "test.bt", 16, "num", 4 } } } } },
		})
		
		local expect_log = {
			"print(ArrayLength(a) = 0)",
			"print(ArrayLength(a) = 4)",
			"print(a = { 0, 0, 0, 0 })",
			"print(a = { 100, 101, 102, 103 })",
			"print(ArrayLength(a) = 3)",
			"print(a = { 100, 101, 102 })",
			"print(ArrayLength(a) = 5)",
			"print(a = { 100, 101, 102, 0, 0 })",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("errors if ArrayResize() is called with the wrong arguments", function()
		local interface, log = test_interface()
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 1, "function", "void", "vfunc", {}, {} },
				{ "test.bt", 2, "call", "ArrayResize", { { "test.bt", 2, "call", "vfunc", {} }, { "test.bt", 2, "num", 4 } } },
			})
			end, "Attempt to call function ArrayResize(<any array type>, <number>) with incompatible argument types (void, const int) at test.bt:2")
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 2, "call", "ArrayResize", { { "test.bt", 2, "str", "hello" }, { "test.bt", 2, "num", 4 } } },
			})
			end, "Attempt to call function ArrayResize(<any array type>, <number>) with incompatible argument types (const string, const int) at test.bt:2")
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 1, "local-variable", "char", "a", nil, { "test.bt", 1, "num", 3 }, nil },
				{ "test.bt", 1, "function", "void", "vfunc", {}, {} },
				{ "test.bt", 2, "call", "ArrayResize", { { "test.bt", 2, "ref", { "a" } }, { "test.bt", 2, "num", 4 }, { "test.bt", 2, "call", "vfunc", {} } } },
			})
			end, "Attempt to call function ArrayResize(<any array type>, <number>) with incompatible argument types (char[], const int, void) at test.bt:2")
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 1, "local-variable", "char", "a", nil, { "test.bt", 1, "num", 3 }, nil },
				{ "test.bt", 2, "call", "ArrayResize", { { "test.bt", 2, "ref", { "a" } } } },
			})
			end, "Attempt to call function ArrayResize(<any array type>, <number>) with incompatible argument types (char[]) at test.bt:2")
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 1, "local-variable", "char", "a", nil, { "test.bt", 1, "num", 3 }, nil },
				{ "test.bt", 1, "function", "void", "vfunc", {}, {} },
				{ "test.bt", 2, "call", "ArrayResize", { { "test.bt", 2, "ref", { "a" } }, { "test.bt", 2, "call", "vfunc", {} } } },
			})
			end, "Attempt to call function ArrayResize(<any array type>, <number>) with incompatible argument types (char[], void) at test.bt:2")
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 1, "local-variable", "char", "a", nil, { "test.bt", 1, "num", 3 }, nil },
				{ "test.bt", 2, "call", "ArrayResize", { { "test.bt", 2, "ref", { "a" } }, { "test.bt", 2, "str", "4" } } },
			})
			end, "Attempt to call function ArrayResize(<any array type>, <number>) with incompatible argument types (char[], const string) at test.bt:2")
	end)
	
	it("errors if ArrayResize() is called on a const array", function()
		local interface, log = test_interface()
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 1, "local-variable", "const char", "a", nil, { "test.bt", 1, "num", 3 }, nil },
				{ "test.bt", 2, "call", "ArrayResize", { { "test.bt", 2, "ref", { "a" } }, { "test.bt", 2, "num", 4 } } },
			})
			end, "Attempt to modify 'const' array at test.bt:2")
	end)
	
	it("allows arbitrarily resizing local arrays with ArrayExtend()", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			-- local int a[0];
			{ "test.bt", 1, "local-variable", "int", "a", nil, { "test.bt", 1, "num", 0 }, nil },
			
			-- Printf("ArrayLength(a) = %d", ArrayLength(a));
			{ "test.bt", 2, "call", "Printf", {
				{ "test.bt", 2, "str", "ArrayLength(a) = %d" },
				{ "test.bt", 2, "call", "ArrayLength", { { "test.bt", 2, "ref", { "a" } } } } } },
			
			-- ArrayExtend(a, 4);
			{ "test.bt", 3, "call", "ArrayExtend", {
				{ "test.bt", 3, "ref", { "a" } },
				{ "test.bt", 3, "num", 4 } } },
			
			-- Printf("ArrayLength(a) = %d", ArrayLength(a));
			{ "test.bt", 4, "call", "Printf", {
				{ "test.bt", 4, "str", "ArrayLength(a) = %d" },
				{ "test.bt", 4, "call", "ArrayLength", { { "test.bt", 4, "ref", { "a" } } } } } },
			
			-- Printf("a = { %d, %d, %d, %d }", a[0], a[1], a[2], a[3]);
			{ "test.bt", 5, "call", "Printf", {
				{ "test.bt", 4, "str", "a = { %d, %d, %d, %d }" },
				{ "test.bt", 5, "ref", { "a", { "test.bt", 5, "num", 0 } } },
				{ "test.bt", 5, "ref", { "a", { "test.bt", 5, "num", 1 } } },
				{ "test.bt", 5, "ref", { "a", { "test.bt", 5, "num", 2 } } },
				{ "test.bt", 5, "ref", { "a", { "test.bt", 5, "num", 3 } } } } },
			
			-- a[0] = 100;
			{ "test.bt", 6, "assign",
				{ "test.bt", 6, "ref", { "a", { "test.bt", 6, "num", 0 } } },
				{ "test.bt", 6, "num", 100 } },
			
			-- a[1] = 101;
			{ "test.bt", 7, "assign",
				{ "test.bt", 7, "ref", { "a", { "test.bt", 7, "num", 1 } } },
				{ "test.bt", 7, "num", 101 } },
			
			-- a[2] = 102;
			{ "test.bt", 8, "assign",
				{ "test.bt", 8, "ref", { "a", { "test.bt", 8, "num", 2 } } },
				{ "test.bt", 8, "num", 102 } },
			
			-- a[3] = 103;
			{ "test.bt", 9, "assign",
				{ "test.bt", 9, "ref", { "a", { "test.bt", 9, "num", 3 } } },
				{ "test.bt", 9, "num", 103 } },
			
			-- Printf("a = { %d, %d, %d, %d }", a[0], a[1], a[2], a[3]);
			{ "test.bt", 10, "call", "Printf", {
				{ "test.bt", 4, "str", "a = { %d, %d, %d, %d }" },
				{ "test.bt", 10, "ref", { "a", { "test.bt", 10, "num", 0 } } },
				{ "test.bt", 10, "ref", { "a", { "test.bt", 10, "num", 1 } } },
				{ "test.bt", 10, "ref", { "a", { "test.bt", 10, "num", 2 } } },
				{ "test.bt", 10, "ref", { "a", { "test.bt", 10, "num", 3 } } } } },
			
			-- ArrayExtend(a, -1);
			{ "test.bt", 11, "call", "ArrayExtend", {
				{ "test.bt", 11, "ref", { "a" } },
				{ "test.bt", 11, "num", -1 } } },
			
			-- Printf("ArrayLength(a) = %d", ArrayLength(a));
			{ "test.bt", 12, "call", "Printf", {
				{ "test.bt", 12, "str", "ArrayLength(a) = %d" },
				{ "test.bt", 12, "call", "ArrayLength", { { "test.bt", 12, "ref", { "a" } } } } } },
			
			-- Printf("a = { %d, %d, %d }", a[0], a[1], a[2]);
			{ "test.bt", 13, "call", "Printf", {
				{ "test.bt", 4, "str", "a = { %d, %d, %d }" },
				{ "test.bt", 13, "ref", { "a", { "test.bt", 13, "num", 0 } } },
				{ "test.bt", 13, "ref", { "a", { "test.bt", 13, "num", 1 } } },
				{ "test.bt", 13, "ref", { "a", { "test.bt", 13, "num", 2 } } } } },
			
			-- ArrayExtend(a, 2);
			{ "test.bt", 14, "call", "ArrayExtend", {
				{ "test.bt", 14, "ref", { "a" } },
				{ "test.bt", 14, "num", 2 } } },
			
			-- Printf("ArrayLength(a) = %d", ArrayLength(a));
			{ "test.bt", 15, "call", "Printf", {
				{ "test.bt", 15, "str", "ArrayLength(a) = %d" },
				{ "test.bt", 15, "call", "ArrayLength", { { "test.bt", 15, "ref", { "a" } } } } } },
			
			-- Printf("a = { %d, %d, %d, %d, %d }", a[0], a[1], a[2], a[3], a[4]);
			{ "test.bt", 16, "call", "Printf", {
				{ "test.bt", 4, "str", "a = { %d, %d, %d, %d, %d }" },
				{ "test.bt", 16, "ref", { "a", { "test.bt", 16, "num", 0 } } },
				{ "test.bt", 16, "ref", { "a", { "test.bt", 16, "num", 1 } } },
				{ "test.bt", 16, "ref", { "a", { "test.bt", 16, "num", 2 } } },
				{ "test.bt", 16, "ref", { "a", { "test.bt", 16, "num", 3 } } },
				{ "test.bt", 16, "ref", { "a", { "test.bt", 16, "num", 4 } } } } },
		})
		
		local expect_log = {
			"print(ArrayLength(a) = 0)",
			"print(ArrayLength(a) = 4)",
			"print(a = { 0, 0, 0, 0 })",
			"print(a = { 100, 101, 102, 103 })",
			"print(ArrayLength(a) = 3)",
			"print(a = { 100, 101, 102 })",
			"print(ArrayLength(a) = 5)",
			"print(a = { 100, 101, 102, 0, 0 })",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("allows extending file arrays with ArrayExtend()", function()
		local interface, log = test_interface(string.char(
			0x01, 0x00, 0x00, 0x00,
			0x02, 0x00, 0x00, 0x00,
			0x03, 0x00, 0x00, 0x00,
			0x04, 0x00, 0x00, 0x00,
			0x05, 0x00, 0x00, 0x00,
			0x06, 0x00, 0x00, 0x00
		))
		
		executor.execute(interface, {
			-- int a[0];
			{ "test.bt", 1, "variable", "int", "a", nil, { "test.bt", 1, "num", 0 } },
			
			-- Printf("ArrayLength(a) = %d", ArrayLength(a));
			{ "test.bt", 2, "call", "Printf", {
				{ "test.bt", 2, "str", "ArrayLength(a) = %d" },
				{ "test.bt", 2, "call", "ArrayLength", { { "test.bt", 2, "ref", { "a" } } } } } },
			
			-- ArrayResize(a, 2);
			{ "test.bt", 7, "call", "ArrayResize", {
				{ "test.bt", 7, "ref", { "a" } },
				{ "test.bt", 7, "num", 2 } } },
			
			-- Printf("ArrayLength(a) = %d", ArrayLength(a));
			{ "test.bt", 2, "call", "Printf", {
				{ "test.bt", 2, "str", "ArrayLength(a) = %d" },
				{ "test.bt", 2, "call", "ArrayLength", { { "test.bt", 2, "ref", { "a" } } } } } },
			
			-- Printf("a = { %d, %d }", a[0], a[1]);
			{ "test.bt", 3, "call", "Printf", {
				{ "test.bt", 3, "str", "a = { %d, %d }" },
				{ "test.bt", 3, "ref", { "a", { "test.bt", 3, "num", 0 } } },
				{ "test.bt", 3, "ref", { "a", { "test.bt", 3, "num", 1 } } } } },
			
			-- ArrayExtend(a);
			{ "test.bt", 4, "call", "ArrayExtend", {
				{ "test.bt", 4, "ref", { "a" } } } },
			
			-- Printf("ArrayLength(a) = %d", ArrayLength(a));
			{ "test.bt", 5, "call", "Printf", {
				{ "test.bt", 5, "str", "ArrayLength(a) = %d" },
				{ "test.bt", 5, "call", "ArrayLength", { { "test.bt", 5, "ref", { "a" } } } } } },
			
			-- Printf("a = { %d, %d, %d }", a[0], a[1], a[2]);
			{ "test.bt", 6, "call", "Printf", {
				{ "test.bt", 6, "str", "a = { %d, %d, %d }" },
				{ "test.bt", 6, "ref", { "a", { "test.bt", 6, "num", 0 } } },
				{ "test.bt", 6, "ref", { "a", { "test.bt", 6, "num", 1 } } },
				{ "test.bt", 6, "ref", { "a", { "test.bt", 6, "num", 2 } } } } },
			
			-- ArrayExtend(a, 1);
			{ "test.bt", 7, "call", "ArrayExtend", {
				{ "test.bt", 7, "ref", { "a" } },
				{ "test.bt", 7, "num", 1 } } },
			
			-- Printf("ArrayLength(a) = %d", ArrayLength(a));
			{ "test.bt", 8, "call", "Printf", {
				{ "test.bt", 8, "str", "ArrayLength(a) = %d" },
				{ "test.bt", 8, "call", "ArrayLength", { { "test.bt", 8, "ref", { "a" } } } } } },
			
			-- Printf("a = { %d, %d, %d, %d }", a[0], a[1], a[2], a[3]);
			{ "test.bt", 9, "call", "Printf", {
				{ "test.bt", 9, "str", "a = { %d, %d, %d, %d }" },
				{ "test.bt", 9, "ref", { "a", { "test.bt", 9, "num", 0 } } },
				{ "test.bt", 9, "ref", { "a", { "test.bt", 9, "num", 1 } } },
				{ "test.bt", 9, "ref", { "a", { "test.bt", 9, "num", 2 } } },
				{ "test.bt", 9, "ref", { "a", { "test.bt", 9, "num", 3 } } } } },
			
			-- ArrayExtend(a, 2);
			{ "test.bt", 10, "call", "ArrayExtend", {
				{ "test.bt", 10, "ref", { "a" } },
				{ "test.bt", 10, "num", 2 } } },
			
			-- Printf("ArrayLength(a) = %d", ArrayLength(a));
			{ "test.bt", 11, "call", "Printf", {
				{ "test.bt", 11, "str", "ArrayLength(a) = %d" },
				{ "test.bt", 11, "call", "ArrayLength", { { "test.bt", 11, "ref", { "a" } } } } } },
			
			-- Printf("a = { %d, %d, %d, %d, %d, %d }", a[0], a[1], a[2], a[3], a[4], a[5]);
			{ "test.bt", 12, "call", "Printf", {
				{ "test.bt", 12, "str", "a = { %d, %d, %d, %d, %d, %d }" },
				{ "test.bt", 12, "ref", { "a", { "test.bt", 12, "num", 0 } } },
				{ "test.bt", 12, "ref", { "a", { "test.bt", 12, "num", 1 } } },
				{ "test.bt", 12, "ref", { "a", { "test.bt", 12, "num", 2 } } },
				{ "test.bt", 12, "ref", { "a", { "test.bt", 12, "num", 3 } } },
				{ "test.bt", 12, "ref", { "a", { "test.bt", 12, "num", 4 } } },
				{ "test.bt", 12, "ref", { "a", { "test.bt", 12, "num", 5 } } } } },
		})
		
		local expect_log = {
			"print(ArrayLength(a) = 0)",
			"print(ArrayLength(a) = 2)",
			"print(a = { 1, 2 })",
			"print(ArrayLength(a) = 3)",
			"print(a = { 1, 2, 3 })",
			"print(ArrayLength(a) = 4)",
			"print(a = { 1, 2, 3, 4 })",
			"print(ArrayLength(a) = 6)",
			"print(a = { 1, 2, 3, 4, 5, 6 })",
			"set_comment(0, 24, a)",
			"set_data_type(0, 24, s32le)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("errors on shrinking a file array with ArrayResize()", function()
		local interface, log = test_interface(string.char(
			0x01, 0x00, 0x00, 0x00,
			0x02, 0x00, 0x00, 0x00,
			0x03, 0x00, 0x00, 0x00,
			0x04, 0x00, 0x00, 0x00,
			0x05, 0x00, 0x00, 0x00,
			0x06, 0x00, 0x00, 0x00
		))
		
		assert.has_error(function()
			executor.execute(interface, {
				-- int a[2];
				{ "test.bt", 1, "variable", "int", "a", nil, { "test.bt", 1, "num", 2 } },
				
				-- ArrayResize(a, 1);
				{ "test.bt", 7, "call", "ArrayResize", {
					{ "test.bt", 7, "ref", { "a" } },
					{ "test.bt", 7, "num", 1 } } },
			})
			end, "Invalid attempt to shrink non-local array at test.bt:7")
	end)
	
	it("errors on growing a file array after declaring other variables", function()
		local interface, log = test_interface(string.char(
			0x01, 0x00, 0x00, 0x00,
			0x02, 0x00, 0x00, 0x00,
			0x03, 0x00, 0x00, 0x00,
			0x04, 0x00, 0x00, 0x00,
			0x05, 0x00, 0x00, 0x00,
			0x06, 0x00, 0x00, 0x00
		))
		
		assert.has_error(function()
			executor.execute(interface, {
				-- int a[2];
				{ "test.bt", 1, "variable", "int", "a", nil, { "test.bt", 1, "num", 2 } },
				
				-- int b;
				{ "test.bt", 1, "variable", "int", "b", nil, nil },
				
				-- ArrayResize(a, 3);
				{ "test.bt", 7, "call", "ArrayResize", {
					{ "test.bt", 7, "ref", { "a" } },
					{ "test.bt", 7, "num", 3 } } },
			})
			end, "Invalid attempt to grow non-local array after declaring other variables at test.bt:7")
	end)
	
	it("errors if ArrayExtend() is called with the wrong arguments", function()
		local interface, log = test_interface()
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 1, "function", "void", "vfunc", {}, {} },
				{ "test.bt", 2, "call", "ArrayExtend", { { "test.bt", 2, "call", "vfunc", {} }, { "test.bt", 2, "num", 4 } } },
			})
			end, "Attempt to call function ArrayExtend(<any array type>, <number>) with incompatible argument types (void, const int) at test.bt:2")
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 2, "call", "ArrayExtend", { { "test.bt", 2, "str", "hello" }, { "test.bt", 2, "num", 4 } } },
			})
			end, "Attempt to call function ArrayExtend(<any array type>, <number>) with incompatible argument types (const string, const int) at test.bt:2")
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 1, "local-variable", "char", "a", nil, { "test.bt", 1, "num", 3 }, nil },
				{ "test.bt", 1, "function", "void", "vfunc", {}, {} },
				{ "test.bt", 2, "call", "ArrayExtend", { { "test.bt", 2, "ref", { "a" } }, { "test.bt", 2, "num", 4 }, { "test.bt", 2, "call", "vfunc", {} } } },
			})
			end, "Attempt to call function ArrayExtend(<any array type>, <number>) with incompatible argument types (char[], const int, void) at test.bt:2")
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 1, "local-variable", "char", "a", nil, { "test.bt", 1, "num", 3 }, nil },
				{ "test.bt", 1, "function", "void", "vfunc", {}, {} },
				{ "test.bt", 2, "call", "ArrayExtend", { { "test.bt", 2, "ref", { "a" } }, { "test.bt", 2, "call", "vfunc", {} } } },
			})
			end, "Attempt to call function ArrayExtend(<any array type>, <number>) with incompatible argument types (char[], void) at test.bt:2")
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 1, "local-variable", "char", "a", nil, { "test.bt", 1, "num", 3 }, nil },
				{ "test.bt", 2, "call", "ArrayExtend", { { "test.bt", 2, "ref", { "a" } }, { "test.bt", 2, "str", "4" } } },
			})
			end, "Attempt to call function ArrayExtend(<any array type>, <number>) with incompatible argument types (char[], const string) at test.bt:2")
	end)
	
	it("errors if ArrayExtend() is called on a const array", function()
		local interface, log = test_interface()
		
		assert.has_error(function()
			executor.execute(interface, {
				{ "test.bt", 1, "local-variable", "const char", "a", nil, { "test.bt", 1, "num", 3 }, nil },
				{ "test.bt", 2, "call", "ArrayExtend", { { "test.bt", 2, "ref", { "a" } }, { "test.bt", 2, "num", 4 } } },
			})
			end, "Attempt to modify 'const' array at test.bt:2")
	end)
	
	it("allows extending file struct arrays with ArrayExtend()", function()
		local interface, log = test_interface(string.char(
			0x01, 0x00, 0x00, 0x00,
			0x02, 0x00, 0x00, 0x00,
			0x03, 0x00, 0x00, 0x00,
			0x04, 0x00, 0x00, 0x00,
			0x05, 0x00, 0x00, 0x00,
			0x06, 0x00, 0x00, 0x00,
			0x07, 0x00, 0x00, 0x00,
			0x08, 0x00, 0x00, 0x00
		))
		
		executor.execute(interface, {
			{ "test.bt", 1, "struct", "mystruct", {},
			{
				{ "test.bt", 1, "variable", "int", "x", nil, nil },
				{ "test.bt", 1, "variable", "int", "y", nil, nil },
			} },
			
			-- struct mystruct a[0];
			{ "test.bt", 1, "variable", "struct mystruct", "a", nil, { "test.bt", 1, "num", 0 } },
			
			-- Printf("ArrayLength(a) = %d", ArrayLength(a));
			{ "test.bt", 2, "call", "Printf", {
				{ "test.bt", 2, "str", "ArrayLength(a) = %d" },
				{ "test.bt", 2, "call", "ArrayLength", { { "test.bt", 2, "ref", { "a" } } } } } },
			
			-- ArrayResize(a, 1);
			{ "test.bt", 3, "call", "ArrayResize", {
				{ "test.bt", 3, "ref", { "a" } },
				{ "test.bt", 3, "num", 1 } } },
			
			-- Printf("ArrayLength(a) = %d", ArrayLength(a));
			{ "test.bt", 4, "call", "Printf", {
				{ "test.bt", 4, "str", "ArrayLength(a) = %d" },
				{ "test.bt", 4, "call", "ArrayLength", { { "test.bt", 4, "ref", { "a" } } } } } },
			
			-- Printf("a = { { %d, %d } }", a[0].x, a[0].y);
			{ "test.bt", 5, "call", "Printf", {
				{ "test.bt", 5, "str", "a = { { %d, %d } }" },
				{ "test.bt", 5, "ref", { "a", { "test.bt", 5, "num", 0 }, "x" } },
				{ "test.bt", 5, "ref", { "a", { "test.bt", 5, "num", 0 }, "y" } } } },
			
			-- ArrayExtend(a);
			{ "test.bt", 6, "call", "ArrayExtend", {
				{ "test.bt", 6, "ref", { "a" } } } },
			
			-- Printf("ArrayLength(a) = %d", ArrayLength(a));
			{ "test.bt", 7, "call", "Printf", {
				{ "test.bt", 7, "str", "ArrayLength(a) = %d" },
				{ "test.bt", 7, "call", "ArrayLength", { { "test.bt", 7, "ref", { "a" } } } } } },
			
			-- Printf("a = { { %d, %d }, { %d, %d } }", a[0].x, a[0].y, a[1].x, a[1].y);
			{ "test.bt", 8, "call", "Printf", {
				{ "test.bt", 8, "str", "a = { { %d, %d }, { %d, %d } }" },
				{ "test.bt", 8, "ref", { "a", { "test.bt", 8, "num", 0 }, "x" } },
				{ "test.bt", 8, "ref", { "a", { "test.bt", 8, "num", 0 }, "y" } },
				{ "test.bt", 8, "ref", { "a", { "test.bt", 8, "num", 1 }, "x" } },
				{ "test.bt", 8, "ref", { "a", { "test.bt", 8, "num", 1 }, "y" } } } },
			
			-- ArrayExtend(a, 2);
			{ "test.bt", 9, "call", "ArrayExtend", {
				{ "test.bt", 9, "ref", { "a" } },
				{ "test.bt", 9, "num", 2 } } },
			
			-- Printf("ArrayLength(a) = %d", ArrayLength(a));
			{ "test.bt", 10, "call", "Printf", {
				{ "test.bt", 10, "str", "ArrayLength(a) = %d" },
				{ "test.bt", 10, "call", "ArrayLength", { { "test.bt", 10, "ref", { "a" } } } } } },
			
			-- Printf("a = { { %d, %d }, { %d, %d }, { %d, %d }, { %d, %d } }",
			--     a[0].x, a[0].y, a[1].x, a[1].y, a[2].x, a[2].y, a[3].x, a[3].y);
			{ "test.bt", 11, "call", "Printf", {
				{ "test.bt", 11, "str", "a = { { %d, %d }, { %d, %d }, { %d, %d }, { %d, %d } }" },
				{ "test.bt", 11, "ref", { "a", { "test.bt", 11, "num", 0 }, "x" } },
				{ "test.bt", 11, "ref", { "a", { "test.bt", 11, "num", 0 }, "y" } },
				{ "test.bt", 11, "ref", { "a", { "test.bt", 11, "num", 1 }, "x" } },
				{ "test.bt", 11, "ref", { "a", { "test.bt", 11, "num", 1 }, "y" } },
				{ "test.bt", 11, "ref", { "a", { "test.bt", 11, "num", 2 }, "x" } },
				{ "test.bt", 11, "ref", { "a", { "test.bt", 11, "num", 2 }, "y" } },
				{ "test.bt", 11, "ref", { "a", { "test.bt", 11, "num", 3 }, "x" } },
				{ "test.bt", 11, "ref", { "a", { "test.bt", 11, "num", 3 }, "y" } } } },
		})
		
		local expect_log = {
			"print(ArrayLength(a) = 0)",
			"print(ArrayLength(a) = 1)",
			"print(a = { { 1, 2 } })",
			"print(ArrayLength(a) = 2)",
			"print(a = { { 1, 2 }, { 3, 4 } })",
			"print(ArrayLength(a) = 4)",
			"print(a = { { 1, 2 }, { 3, 4 }, { 5, 6 }, { 7, 8 } })",
			"set_comment(0, 4, x)",
			"set_comment(4, 4, y)",
			"set_comment(0, 8, a[0])",
			"set_comment(8, 4, x)",
			"set_comment(12, 4, y)",
			"set_comment(8, 8, a[1])",
			"set_comment(16, 4, x)",
			"set_comment(20, 4, y)",
			"set_comment(16, 8, a[2])",
			"set_comment(24, 4, x)",
			"set_comment(28, 4, y)",
			"set_comment(24, 8, a[3])",
			"set_data_type(0, 4, s32le)",
			"set_data_type(4, 4, s32le)",
			"set_data_type(8, 4, s32le)",
			"set_data_type(12, 4, s32le)",
			"set_data_type(16, 4, s32le)",
			"set_data_type(20, 4, s32le)",
			"set_data_type(24, 4, s32le)",
			"set_data_type(28, 4, s32le)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("allows extending local struct arrays with ArrayExtend()", function()
		local interface, log = test_interface(string.char(
			0x01, 0x00, 0x00, 0x00,
			0x02, 0x00, 0x00, 0x00,
			0x03, 0x00, 0x00, 0x00,
			0x04, 0x00, 0x00, 0x00,
			0x05, 0x00, 0x00, 0x00,
			0x06, 0x00, 0x00, 0x00,
			0x07, 0x00, 0x00, 0x00,
			0x08, 0x00, 0x00, 0x00
		))
		
		executor.execute(interface, {
			{ "test.bt", 1, "struct", "mystruct", {},
			{
				{ "test.bt", 1, "variable", "int", "x", nil, nil },
				{ "test.bt", 1, "variable", "int", "y", nil, nil },
			} },
			
			-- local struct mystruct a[0];
			{ "test.bt", 1, "local-variable", "struct mystruct", "a", nil, { "test.bt", 1, "num", 0 }, nil },
			
			-- Printf("ArrayLength(a) = %d", ArrayLength(a));
			{ "test.bt", 2, "call", "Printf", {
				{ "test.bt", 2, "str", "ArrayLength(a) = %d" },
				{ "test.bt", 2, "call", "ArrayLength", { { "test.bt", 2, "ref", { "a" } } } } } },
			
			-- ArrayResize(a, 1);
			{ "test.bt", 3, "call", "ArrayResize", {
				{ "test.bt", 3, "ref", { "a" } },
				{ "test.bt", 3, "num", 1 } } },
			
			-- Printf("ArrayLength(a) = %d", ArrayLength(a));
			{ "test.bt", 4, "call", "Printf", {
				{ "test.bt", 4, "str", "ArrayLength(a) = %d" },
				{ "test.bt", 4, "call", "ArrayLength", { { "test.bt", 4, "ref", { "a" } } } } } },
			
			-- Printf("a = { { %d, %d } }", a[0].x, a[0].y);
			{ "test.bt", 5, "call", "Printf", {
				{ "test.bt", 5, "str", "a = { { %d, %d } }" },
				{ "test.bt", 5, "ref", { "a", { "test.bt", 5, "num", 0 }, "x" } },
				{ "test.bt", 5, "ref", { "a", { "test.bt", 5, "num", 0 }, "y" } } } },
			
			-- ArrayExtend(a);
			{ "test.bt", 6, "call", "ArrayExtend", {
				{ "test.bt", 6, "ref", { "a" } } } },
			
			-- Printf("ArrayLength(a) = %d", ArrayLength(a));
			{ "test.bt", 7, "call", "Printf", {
				{ "test.bt", 7, "str", "ArrayLength(a) = %d" },
				{ "test.bt", 7, "call", "ArrayLength", { { "test.bt", 7, "ref", { "a" } } } } } },
			
			-- Printf("a = { { %d, %d }, { %d, %d } }", a[0].x, a[0].y, a[1].x, a[1].y);
			{ "test.bt", 8, "call", "Printf", {
				{ "test.bt", 8, "str", "a = { { %d, %d }, { %d, %d } }" },
				{ "test.bt", 8, "ref", { "a", { "test.bt", 8, "num", 0 }, "x" } },
				{ "test.bt", 8, "ref", { "a", { "test.bt", 8, "num", 0 }, "y" } },
				{ "test.bt", 8, "ref", { "a", { "test.bt", 8, "num", 1 }, "x" } },
				{ "test.bt", 8, "ref", { "a", { "test.bt", 8, "num", 1 }, "y" } } } },
			
			-- ArrayExtend(a, 2);
			{ "test.bt", 9, "call", "ArrayExtend", {
				{ "test.bt", 9, "ref", { "a" } },
				{ "test.bt", 9, "num", 2 } } },
			
			-- Printf("ArrayLength(a) = %d", ArrayLength(a));
			{ "test.bt", 10, "call", "Printf", {
				{ "test.bt", 10, "str", "ArrayLength(a) = %d" },
				{ "test.bt", 10, "call", "ArrayLength", { { "test.bt", 10, "ref", { "a" } } } } } },
			
			-- Printf("a = { { %d, %d }, { %d, %d }, { %d, %d }, { %d, %d } }",
			--     a[0].x, a[0].y, a[1].x, a[1].y, a[2].x, a[2].y, a[3].x, a[3].y);
			{ "test.bt", 11, "call", "Printf", {
				{ "test.bt", 11, "str", "a = { { %d, %d }, { %d, %d }, { %d, %d }, { %d, %d } }" },
				{ "test.bt", 11, "ref", { "a", { "test.bt", 11, "num", 0 }, "x" } },
				{ "test.bt", 11, "ref", { "a", { "test.bt", 11, "num", 0 }, "y" } },
				{ "test.bt", 11, "ref", { "a", { "test.bt", 11, "num", 1 }, "x" } },
				{ "test.bt", 11, "ref", { "a", { "test.bt", 11, "num", 1 }, "y" } },
				{ "test.bt", 11, "ref", { "a", { "test.bt", 11, "num", 2 }, "x" } },
				{ "test.bt", 11, "ref", { "a", { "test.bt", 11, "num", 2 }, "y" } },
				{ "test.bt", 11, "ref", { "a", { "test.bt", 11, "num", 3 }, "x" } },
				{ "test.bt", 11, "ref", { "a", { "test.bt", 11, "num", 3 }, "y" } } } },
		})
		
		local expect_log = {
			"print(ArrayLength(a) = 0)",
			"print(ArrayLength(a) = 1)",
			"print(a = { { 0, 0 } })",
			"print(ArrayLength(a) = 2)",
			"print(a = { { 0, 0 }, { 0, 0 } })",
			"print(ArrayLength(a) = 4)",
			"print(a = { { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 } })",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("converts string to char[] function argument", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			-- local string s = "hello";
			{ "test.bt", 1, "local-variable", "string", "s", nil, nil, { "test.bt", 1, "str", "hello" } },
			
			-- void foo(char[] a) { ... }
			{ "test.bt", 2, "function", "void", "foo", { { "char []", "a" } }, {
				-- Printf("%c%c%c%c%c", a[0], a[1], a[2], a[3], a[4]);
				{ "test.bt", 3, "call", "Printf", {
					{ "test.bt", 3, "str", "%c%c%c%c%c" },
					{ "test.bt", 3, "ref", { "a", { "test.bt", 3, "num", 0 } } },
					{ "test.bt", 3, "ref", { "a", { "test.bt", 3, "num", 1 } } },
					{ "test.bt", 3, "ref", { "a", { "test.bt", 3, "num", 2 } } },
					{ "test.bt", 3, "ref", { "a", { "test.bt", 3, "num", 3 } } },
					{ "test.bt", 3, "ref", { "a", { "test.bt", 3, "num", 4 } } } } }
			} },
			
			-- foo(s);
			{ "test.bt", 5, "call", "foo", {
				{ "test.bt", 5, "ref", { "s" } } } },
		})
		
		local expect_log = {
			"print(hello)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("converts char[] to string function argument", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			-- local char s[10] = "hello";
			{ "test.bt", 1, "local-variable", "char", "s", nil, { "test.bt", 1, "num", 10 }, { "test.bt", 1, "str", "hello" } },
			
			-- void foo(string a) { ... }
			{ "test.bt", 2, "function", "void", "foo", { { "string", "a" } }, {
				-- Printf("%s", a);
				{ "test.bt", 3, "call", "Printf", {
					{ "test.bt", 3, "str", "%s" },
					{ "test.bt", 3, "ref", { "a" } } } }
			} },
			
			-- foo(s);
			{ "test.bt", 5, "call", "foo", {
				{ "test.bt", 5, "ref", { "s" } } } },
		})
		
		local expect_log = {
			"print(hello)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("allows printing a char[] using the Printf '%s' format", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			-- local char s[10] = "hello";
			{ "test.bt", 1, "local-variable", "char", "s", nil, { "test.bt", 1, "num", 10 }, { "test.bt", 1, "str", "hello" } },
			
			-- Printf("s = '%s'", s);
			{ "test.bt", 5, "call", "Printf", {
				{ "test.bt", 5, "str", "s = '%s'" },
				{ "test.bt", 5, "ref", { "s" } } } },
		})
		
		local expect_log = {
			"print(s = 'hello')",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("accomodates the full range of int8_t values", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			-- local int8_t x = 0;
			{ "test.bt", 1, "local-variable", "int8_t", "x", nil, nil, { "test.bt", 1, "num", 0 } },
			
			-- x = x - 100;
			{ "test.bt", 2, "assign",
				{ "test.bt", 2, "ref", { "x" } },
				{ "test.bt", 2, "subtract",
					{ "test.bt", 2, "ref", { "x" } },
					{ "test.bt", 2, "num", 100 } } },
			
			-- Printf("x = %d", x);
			{ "test.bt", 3, "call", "Printf", {
				{ "test.bt", 3, "str", "x = %d" },
				{ "test.bt", 3, "ref", { "x" } } } },
			
			-- x = x + -28;
			{ "test.bt", 4, "assign",
				{ "test.bt", 4, "ref", { "x" } },
				{ "test.bt", 4, "add",
					{ "test.bt", 4, "ref", { "x" } },
					{ "test.bt", 4, "num", -28 } } },
			
			-- Printf("x = %d", x);
			{ "test.bt", 5, "call", "Printf", {
				{ "test.bt", 5, "str", "x = %d" },
				{ "test.bt", 5, "ref", { "x" } } } },
			
			-- x = x + 200;
			{ "test.bt", 6, "assign",
				{ "test.bt", 6, "ref", { "x" } },
				{ "test.bt", 6, "add",
					{ "test.bt", 6, "ref", { "x" } },
					{ "test.bt", 6, "num", 200 } } },
			
			-- Printf("x = %d", x);
			{ "test.bt", 7, "call", "Printf", {
				{ "test.bt", 7, "str", "x = %d" },
				{ "test.bt", 7, "ref", { "x" } } } },
			
			-- x = x - -55;
			{ "test.bt", 8, "assign",
				{ "test.bt", 8, "ref", { "x" } },
				{ "test.bt", 8, "subtract",
					{ "test.bt", 8, "ref", { "x" } },
					{ "test.bt", 8, "num", -55 } } },
			
			-- Printf("x = %d", x);
			{ "test.bt", 9, "call", "Printf", {
				{ "test.bt", 9, "str", "x = %d" },
				{ "test.bt", 9, "ref", { "x" } } } },
		})
		
		local expect_log = {
			"print(x = -100)",
			"print(x = -128)",
			"print(x = 72)",
			"print(x = 127)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("accomodates the full range of uint8_t values", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			-- local uint8_t x = 0;
			{ "test.bt", 1, "local-variable", "uint8_t", "x", nil, nil, { "test.bt", 1, "num", 0 } },
			
			-- x = x + 200;
			{ "test.bt", 2, "assign",
				{ "test.bt", 2, "ref", { "x" } },
				{ "test.bt", 2, "add",
					{ "test.bt", 2, "ref", { "x" } },
					{ "test.bt", 2, "num", 200 } } },
			
			-- Printf("x = %u", x);
			{ "test.bt", 3, "call", "Printf", {
				{ "test.bt", 3, "str", "x = %u" },
				{ "test.bt", 3, "ref", { "x" } } } },
			
			-- x = x + 55;
			{ "test.bt", 4, "assign",
				{ "test.bt", 4, "ref", { "x" } },
				{ "test.bt", 4, "add",
					{ "test.bt", 4, "ref", { "x" } },
					{ "test.bt", 4, "num", 55 } } },
			
			-- Printf("x = %u", x);
			{ "test.bt", 5, "call", "Printf", {
				{ "test.bt", 5, "str", "x = %u" },
				{ "test.bt", 5, "ref", { "x" } } } },
		})
		
		local expect_log = {
			"print(x = 200)",
			"print(x = 255)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("handles uint8_t overflow on addition/assignment", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			-- local uint8_t x = 254;
			{ "test.bt", 1, "local-variable", "uint8_t", "x", nil, nil, { "test.bt", 1, "num", 254 } },
			
			-- x = x + 4;
			{ "test.bt", 2, "assign",
				{ "test.bt", 2, "ref", { "x" } },
				{ "test.bt", 2, "add",
					{ "test.bt", 2, "ref", { "x" } },
					{ "test.bt", 2, "num", 4 } } },
			
			-- Printf("x = %u", x);
			{ "test.bt", 3, "call", "Printf", {
				{ "test.bt", 3, "str", "x = %u" },
				{ "test.bt", 3, "ref", { "x" } } } },
		})
		
		local expect_log = {
			"print(x = 2)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("handles uint8_t underflow on subtraction/assignment", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			-- local uint8_t x = 2;
			{ "test.bt", 1, "local-variable", "uint8_t", "x", nil, nil, { "test.bt", 1, "num", 2 } },
			
			-- x = x - 10;
			{ "test.bt", 2, "assign",
				{ "test.bt", 2, "ref", { "x" } },
				{ "test.bt", 2, "subtract",
					{ "test.bt", 2, "ref", { "x" } },
					{ "test.bt", 2, "num", 10 } } },
			
			-- Printf("x = %u", x);
			{ "test.bt", 3, "call", "Printf", {
				{ "test.bt", 3, "str", "x = %u" },
				{ "test.bt", 3, "ref", { "x" } } } },
		})
		
		local expect_log = {
			"print(x = 248)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("accomodates the full range of int32_t values", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			-- local int32_t x = 0;
			{ "test.bt", 1, "local-variable", "int32_t", "x", nil, nil, { "test.bt", 1, "num", 0 } },
			
			-- x = x - 2,000,000,000;
			{ "test.bt", 2, "assign",
				{ "test.bt", 2, "ref", { "x" } },
				{ "test.bt", 2, "subtract",
					{ "test.bt", 2, "ref", { "x" } },
					{ "test.bt", 2, "num", 2000000000 } } },
			
			-- Printf("x = %d", x);
			{ "test.bt", 3, "call", "Printf", {
				{ "test.bt", 3, "str", "x = %d" },
				{ "test.bt", 3, "ref", { "x" } } } },
			
			-- x = x - 147,483,648;
			{ "test.bt", 4, "assign",
				{ "test.bt", 4, "ref", { "x" } },
				{ "test.bt", 4, "subtract",
					{ "test.bt", 4, "ref", { "x" } },
					{ "test.bt", 4, "num", 147483648 } } },
			
			-- Printf("x = %d", x);
			{ "test.bt", 5, "call", "Printf", {
				{ "test.bt", 5, "str", "x = %d" },
				{ "test.bt", 5, "ref", { "x" } } } },
			
			-- x = x + 4,000,000,000;
			{ "test.bt", 6, "assign",
				{ "test.bt", 6, "ref", { "x" } },
				{ "test.bt", 6, "add",
					{ "test.bt", 6, "ref", { "x" } },
					{ "test.bt", 6, "num", 4000000000 } } },
			
			-- Printf("x = %d", x);
			{ "test.bt", 7, "call", "Printf", {
				{ "test.bt", 7, "str", "x = %d" },
				{ "test.bt", 7, "ref", { "x" } } } },
			
			-- x = x + 294,967,295;
			{ "test.bt", 8, "assign",
				{ "test.bt", 8, "ref", { "x" } },
				{ "test.bt", 8, "add",
					{ "test.bt", 8, "ref", { "x" } },
					{ "test.bt", 8, "num", 294967295 } } },
			
			-- Printf("x = %d", x);
			{ "test.bt", 9, "call", "Printf", {
				{ "test.bt", 9, "str", "x = %d" },
				{ "test.bt", 9, "ref", { "x" } } } },
		})
		
		local expect_log = {
			"print(x = -2000000000)",
			"print(x = -2147483648)",
			"print(x = 1852516352)",
			"print(x = 2147483647)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("accomodates the full range of uint32_t values", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			-- local uint32_t x = 0;
			{ "test.bt", 1, "local-variable", "uint32_t", "x", nil, nil, { "test.bt", 1, "num", 0 } },
			
			-- x = x + 4,000,000,000;
			{ "test.bt", 2, "assign",
				{ "test.bt", 2, "ref", { "x" } },
				{ "test.bt", 2, "add",
					{ "test.bt", 2, "ref", { "x" } },
					{ "test.bt", 2, "num", 4000000000 } } },
			
			-- Printf("x = %u", x);
			{ "test.bt", 3, "call", "Printf", {
				{ "test.bt", 3, "str", "x = %u" },
				{ "test.bt", 3, "ref", { "x" } } } },
			
			-- x = x + 294,967,295;
			{ "test.bt", 4, "assign",
				{ "test.bt", 4, "ref", { "x" } },
				{ "test.bt", 4, "add",
					{ "test.bt", 4, "ref", { "x" } },
					{ "test.bt", 4, "num", 294967295 } } },
			
			-- Printf("x = %u", x);
			{ "test.bt", 5, "call", "Printf", {
				{ "test.bt", 5, "str", "x = %u" },
				{ "test.bt", 5, "ref", { "x" } } } },
		})
		
		local expect_log = {
			"print(x = 4000000000)",
			"print(x = 4294967295)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("handles uint32_t overflow on addition/assignment", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			-- local uint32_t x = 4294967294;
			{ "test.bt", 1, "local-variable", "uint32_t", "x", nil, nil, { "test.bt", 1, "num", 4294967294 } },
			
			-- x = x + 4;
			{ "test.bt", 2, "assign",
				{ "test.bt", 2, "ref", { "x" } },
				{ "test.bt", 2, "add",
					{ "test.bt", 2, "ref", { "x" } },
					{ "test.bt", 2, "num", 4 } } },
			
			-- Printf("x = %u", x);
			{ "test.bt", 3, "call", "Printf", {
				{ "test.bt", 3, "str", "x = %u" },
				{ "test.bt", 3, "ref", { "x" } } } },
		})
		
		local expect_log = {
			"print(x = 2)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("handles uint32_t underflow on subtraction/assignment", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			-- local uint32_t x = 4;
			{ "test.bt", 1, "local-variable", "uint32_t", "x", nil, nil, { "test.bt", 1, "num", 4 } },
			
			-- x = x - 10;
			{ "test.bt", 2, "assign",
				{ "test.bt", 2, "ref", { "x" } },
				{ "test.bt", 2, "subtract",
					{ "test.bt", 2, "ref", { "x" } },
					{ "test.bt", 2, "num", 10 } } },
			
			-- Printf("x = %u", x);
			{ "test.bt", 3, "call", "Printf", {
				{ "test.bt", 3, "str", "x = %u" },
				{ "test.bt", 3, "ref", { "x" } } } },
		})
		
		local expect_log = {
			"print(x = 4294967290)",
		}
		
		assert.are.same(expect_log, log)
	end)
end)
