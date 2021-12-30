-- Binary Template plugin for REHex
-- Copyright (C) 2021 Daniel Collins <solemnwarning@solemnwarning.net>
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
	
	local interface = {
		set_data_type = function(offset, length, data_type)
			table.insert(log, "set_data_type(" .. offset .. ", " .. length .. ", " .. data_type .. ")")
		end,
		
		set_comment = function(offset, length, comment_text)
			table.insert(log, "set_comment(" .. offset .. ", " .. length .. ", " .. comment_text .. ")")
		end,
		
		yield = function()
			table.insert(log, "yield()")
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
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "variable", "int", "foo", {} },
			{ "test.bt", 1, "variable", "int", "bar", { { "test.bt", 1, "num", 4 } } },
		})
		
		local expect_log = {
			"set_data_type(0, 4, s32le)",
			"set_comment(0, 4, foo)",
			
			"set_data_type(4, 4, s32le)",
			"set_comment(4, 4, bar[0])",
			
			"set_data_type(8, 4, s32le)",
			"set_comment(8, 4, bar[1])",
			
			"set_data_type(12, 4, s32le)",
			"set_comment(12, 4, bar[2])",
			
			"set_data_type(16, 4, s32le)",
			"set_comment(16, 4, bar[3])",
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
	
	it("reads int8 values from file", function()
		local interface, log = test_interface(string.char(
			0x00,
			0xFF
		))
		
		executor.execute(interface, {
			{ "test.bt", 1, "variable", "char", "a", {}, },
			{ "test.bt", 1, "variable", "char", "b", {}, },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "a = %d" },
				{ "test.bt", 1, "ref", { "a" } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "b = %d" },
				{ "test.bt", 1, "ref", { "b" } } } },
		})
		
		local expect_log = {
			"set_data_type(0, 1, s8)",
			"set_comment(0, 1, a)",
			
			"set_data_type(1, 1, s8)",
			"set_comment(1, 1, b)",
			
			"print(a = 0)",
			"print(b = -1)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("reads uint8 values from file", function()
		local interface, log = test_interface(string.char(
			0x00,
			0xFF
		))
		
		executor.execute(interface, {
			{ "test.bt", 1, "variable", "uchar", "a", {}, },
			{ "test.bt", 1, "variable", "uchar", "b", {}, },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "a = %d" },
				{ "test.bt", 1, "ref", { "a" } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "b = %d" },
				{ "test.bt", 1, "ref", { "b" } } } },
		})
		
		local expect_log = {
			"set_data_type(0, 1, u8)",
			"set_comment(0, 1, a)",
			
			"set_data_type(1, 1, u8)",
			"set_comment(1, 1, b)",
			
			"print(a = 0)",
			"print(b = 255)",
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
			
			{ "test.bt", 1, "variable", "int16", "a", {}, },
			{ "test.bt", 1, "variable", "int16", "b", {}, },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "a = %d" },
				{ "test.bt", 1, "ref", { "a" } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "b = %d" },
				{ "test.bt", 1, "ref", { "b" } } } },
		})
		
		local expect_log = {
			"set_data_type(0, 2, s16le)",
			"set_comment(0, 2, a)",
			
			"set_data_type(2, 2, s16le)",
			"set_comment(2, 2, b)",
			
			"print(a = 8447)",
			"print(b = -1)",
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
			
			{ "test.bt", 1, "variable", "int16", "a", {}, },
			{ "test.bt", 1, "variable", "int16", "b", {}, },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "a = %d" },
				{ "test.bt", 1, "ref", { "a" } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "b = %d" },
				{ "test.bt", 1, "ref", { "b" } } } },
		})
		
		local expect_log = {
			"set_data_type(0, 2, s16be)",
			"set_comment(0, 2, a)",
			
			"set_data_type(2, 2, s16be)",
			"set_comment(2, 2, b)",
			
			"print(a = 8447)",
			"print(b = -1)",
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
			
			{ "test.bt", 1, "variable", "uint16", "a", {}, },
			{ "test.bt", 1, "variable", "uint16", "b", {}, },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "a = %d" },
				{ "test.bt", 1, "ref", { "a" } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "b = %d" },
				{ "test.bt", 1, "ref", { "b" } } } },
		})
		
		local expect_log = {
			"set_data_type(0, 2, u16le)",
			"set_comment(0, 2, a)",
			
			"set_data_type(2, 2, u16le)",
			"set_comment(2, 2, b)",
			
			"print(a = 8447)",
			"print(b = 65535)",
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
			
			{ "test.bt", 1, "variable", "uint16", "a", {}, },
			{ "test.bt", 1, "variable", "uint16", "b", {}, },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "a = %u" },
				{ "test.bt", 1, "ref", { "a" } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "b = %u" },
				{ "test.bt", 1, "ref", { "b" } } } },
		})
		
		local expect_log = {
			"set_data_type(0, 2, u16be)",
			"set_comment(0, 2, a)",
			
			"set_data_type(2, 2, u16be)",
			"set_comment(2, 2, b)",
			
			"print(a = 8447)",
			"print(b = 65535)",
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
			
			{ "test.bt", 1, "variable", "int32", "a", {}, },
			{ "test.bt", 1, "variable", "int32", "b", {}, },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "a = %d" },
				{ "test.bt", 1, "ref", { "a" } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "b = %d" },
				{ "test.bt", 1, "ref", { "b" } } } },
		})
		
		local expect_log = {
			"set_data_type(0, 4, s32le)",
			"set_comment(0, 4, a)",
			
			"set_data_type(4, 4, s32le)",
			"set_comment(4, 4, b)",
			
			"print(a = 13417386)",
			"print(b = -1)",
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
			
			{ "test.bt", 1, "variable", "uint64", "a", {}, },
			{ "test.bt", 1, "variable", "uint64", "b", {}, },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "a = %u" },
				{ "test.bt", 1, "ref", { "a" } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "b = %u" },
				{ "test.bt", 1, "ref", { "b" } } } },
		})
		
		local expect_log = {
			"set_data_type(0, 8, u64le)",
			"set_comment(0, 8, a)",
			
			"set_data_type(8, 8, u64le)",
			"set_comment(8, 8, b)",
			
			"print(a = 1025923398570)",
			"print(b = 18446744073709551615)",
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
			
			{ "test.bt", 1, "variable", "int32", "a", {
				{ "test.bt", 1, "num", 4 }, } },
			
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
			"set_data_type(0, 4, s32le)",
			"set_comment(0, 4, a[0])",
			
			"set_data_type(4, 4, s32le)",
			"set_comment(4, 4, a[1])",
			
			"set_data_type(8, 4, s32le)",
			"set_comment(8, 4, a[2])",
			
			"set_data_type(12, 4, s32le)",
			"set_comment(12, 4, a[3])",
			
			"print(a[0] = 1)",
			"print(a[1] = 2)",
			"print(a[2] = 3)",
			"print(a[3] = 4)",
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
					
					{ "test.bt", 1, "variable", "int32", "a", {
						{ "test.bt", 1, "num", 4 }, } },
					
					{ "test.bt", 1, "ref", { "a", { "test.bt", 1, "str", "hello" } } },
				})
			end, "Invalid 'string' operand to '[]' operator - expected a number at test.bt:1")
		
		assert.has_error(
			function()
				executor.execute(interface, {
					{ "test.bt", 1, "call", "LittleEndian", {} },
					
					{ "test.bt", 1, "variable", "int32", "a", {
						{ "test.bt", 1, "num", 4 }, } },
					
					{ "test.bt", 1, "ref", { "a", { "test.bt", 1, "num", -1 } } },
				})
			end, "Attempt to access out-of-range array index -1 at test.bt:1")
		
		assert.has_error(
			function()
				executor.execute(interface, {
					{ "test.bt", 1, "call", "LittleEndian", {} },
					
					{ "test.bt", 1, "variable", "int32", "a", {
						{ "test.bt", 1, "num", 4 }, } },
					
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
					{ "test.bt", 1, "variable", "int32", "a", {} },
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
				{ "test.bt", 1, "variable", "int", "x", {} },
				{ "test.bt", 1, "variable", "int", "y", {} },
				
				{ "test.bt", 1, "call", "Printf", {
					{ "test.bt", 1, "str", "x = %d" },
					{ "test.bt", 1, "ref", { "x" } } } },
				
				{ "test.bt", 1, "call", "Printf", {
					{ "test.bt", 1, "str", "y = %d" },
					{ "test.bt", 1, "ref", { "y" } } } },
			} },
			
			{ "test.bt", 1, "variable", "struct mystruct", "a", {} },
			{ "test.bt", 1, "variable", "struct mystruct", "b", {} },
		})
		
		local expect_log = {
			"set_data_type(0, 4, s32le)",
			"set_comment(0, 4, x)",
			
			"set_data_type(4, 4, s32le)",
			"set_comment(4, 4, y)",
			
			"print(x = 1)",
			"print(y = 2)",
			
			"set_comment(0, 8, a)",
			
			"set_data_type(8, 4, s32le)",
			"set_comment(8, 4, x)",
			
			"set_data_type(12, 4, s32le)",
			"set_comment(12, 4, y)",
			
			"print(x = 3)",
			"print(y = 4)",
			
			"set_comment(8, 8, b)",
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
				{ "test.bt", 1, "variable", "int", "x", {} },
				{ "test.bt", 1, "variable", "int", "y", {} },
				
				{ "test.bt", 1, "call", "Printf", {
					{ "test.bt", 1, "str", "x = %d" },
					{ "test.bt", 1, "ref", { "x" } } } },
				
				{ "test.bt", 1, "call", "Printf", {
					{ "test.bt", 1, "str", "y = %d" },
					{ "test.bt", 1, "ref", { "y" } } } },
			} },
			
			{ "test.bt", 1, "variable", "struct mystruct", "a", {
				{ "test.bt", 1, "num", 2 } } },
		})
		
		local expect_log = {
			"set_data_type(0, 4, s32le)",
			"set_comment(0, 4, x)",
			
			"set_data_type(4, 4, s32le)",
			"set_comment(4, 4, y)",
			
			"print(x = 1)",
				"print(y = 2)",
			
			"set_comment(0, 8, a[0])",
			
			"set_data_type(8, 4, s32le)",
			"set_comment(8, 4, x)",
			
			"set_data_type(12, 4, s32le)",
			"set_comment(12, 4, y)",
			
			"print(x = 3)",
			"print(y = 4)",
			
			"set_comment(8, 8, a[1])",
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
			{ "test.bt", 1, "call", "LittleEndian", {} },
			
			{ "test.bt", 1, "struct", "mystruct", {},
			{
				{ "test.bt", 1, "struct", "bstruct", {},
				{
					{ "test.bt", 1, "variable", "int", "x", {} },
					{ "test.bt", 1, "variable", "int", "y", {} },
					
					{ "test.bt", 1, "call", "Printf", {
						{ "test.bt", 1, "str", "bstruct x = %d" },
						{ "test.bt", 1, "ref", { "x" } } } },
				} },
				
				{ "test.bt", 1, "variable", "int", "x", {} },
				{ "test.bt", 1, "variable", "struct bstruct", "y", {} },
				
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
			
			{ "test.bt", 1, "variable", "struct mystruct", "a", {} },
		})
		
		local expect_log = {
			"set_data_type(0, 4, s32le)",
			"set_comment(0, 4, x)",
			
			"set_data_type(4, 4, s32le)",
			"set_comment(4, 4, x)",
			
			"set_data_type(8, 4, s32le)",
			"set_comment(8, 4, y)",
			
			"print(bstruct x = 2)",
			
			"set_comment(4, 8, y)",
			
			"print(mystruct x = 1)",
			"print(mystruct y.x = 2)",
			"print(mystruct y.y = 3)",
			
			"set_comment(0, 12, a)",
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
						{ "test.bt", 1, "variable", "int", "x", {} },
						{ "test.bt", 1, "variable", "int", "x", {} },
					} },
					
					{ "test.bt", 1, "variable", "struct mystruct", "a", {} },
					{ "test.bt", 1, "variable", "struct mystruct", "b", {} },
				})
			end, "Attempt to redefine struct member 'x' at test.bt:1")
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
		end, "return operand type 'string' not compatible with function return type 'int' at test.bt:1")
		
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
		end, "return operand type 'int' not compatible with function return type 'void' at test.bt:1")
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
		end, "Invalid left operand to '&&' operator - expected numeric, got 'string' at test.bt:1")
		
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
		end, "Invalid right operand to '||' operator - expected numeric, got 'string' at test.bt:1")
	end)
	
	it("allows defining local variables", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "local-variable", "int", "foo", {}, {} },
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
			{ "test.bt", 1, "local-variable", "int", "foo", {}, { { "test.bt", 1, "num", 1234 } } },
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
			{ "test.bt", 1, "local-variable", "int", "foo", {}, {} },
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
	
	it("allows using local array variables", function()
		local interface, log = test_interface()
		
		executor.execute(interface, {
			{ "test.bt", 1, "local-variable", "int", "foo", { { "test.bt", 1, "num", 3} }, {} },
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
	
	it("implements ReadByte() function", function()
		local interface, log = test_interface(string.char(
			0x01, 0xFF, 0xFE, 0x04
		))
		
		executor.execute(interface, {
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "ReadByte() = %d" },
				{ "test.bt", 1, "call", "ReadByte", {} } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "ReadByte() = %d" },
				{ "test.bt", 1, "call", "ReadByte", {} } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "ReadByte(1) = %d" },
				{ "test.bt", 1, "call", "ReadByte", {
					{ "test.bt", 1, "num", 1 } } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "ReadByte(2) = %d" },
				{ "test.bt", 1, "call", "ReadByte", {
					{ "test.bt", 1, "num", 2 } } } } },
		})
		
		local expect_log = {
			"print(ReadByte() = 1)",
			"print(ReadByte() = 1)",
			"print(ReadByte(1) = -1)",
			"print(ReadByte(2) = -2)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("errors when ReadByte() is called at end of file", function()
		local interface, log = test_interface(string.char(
			0x01, 0xFF, 0xFE, 0x04
		))
		
		assert.has_error(
			function()
				executor.execute(interface, {
					{ "test.bt", 1, "call", "FSeek", {
						{ "test.bt", 1, "num", 4, {} } } },
					
					{ "test.bt", 1, "call", "Printf", {
						{ "test.bt", 1, "str", "ReadByte() = %d" },
						{ "test.bt", 1, "call", "ReadByte", {} } } },
				})
			end, "Attempt to read past end of file in ReadByte function")
	end)
	
	it("implements ReadUInt() function", function()
		local interface, log = test_interface(string.char(
			0x00, 0x01, 0x00, 0x00,
			0xFF, 0xFF, 0xFF, 0xFF,
			0x00, 0x02, 0x00, 0x00
		))
		
		executor.execute(interface, {
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "ReadUInt() = %d" },
				{ "test.bt", 1, "call", "ReadUInt", {} } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "ReadUInt() = %d" },
				{ "test.bt", 1, "call", "ReadUInt", {} } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "ReadUInt(4) = %d" },
				{ "test.bt", 1, "call", "ReadUInt", {
					{ "test.bt", 1, "num", 4 } } } } },
			
			{ "test.bt", 1, "call", "Printf", {
				{ "test.bt", 1, "str", "ReadUInt(8) = %d" },
				{ "test.bt", 1, "call", "ReadUInt", {
					{ "test.bt", 1, "num", 8 } } } } },
		})
		
		local expect_log = {
			"print(ReadUInt() = 256)",
			"print(ReadUInt() = 256)",
			"print(ReadUInt(4) = 4294967295)",
			"print(ReadUInt(8) = 512)",
		}
		
		assert.are.same(expect_log, log)
	end)
	
	it("errors when ReadUInt() is called at end of file", function()
		local interface, log = test_interface(string.char(
			0x01, 0xFF, 0xFE, 0x04
		))
		
		assert.has_error(
			function()
				executor.execute(interface, {
					{ "test.bt", 1, "call", "Printf", {
						{ "test.bt", 1, "str", "ReadUInt() = %d" },
						{ "test.bt", 1, "call", "ReadUInt", {
							{ "test.bt", 1, "num", 1, {} } } } } },
				})
			end, "Attempt to read past end of file in ReadUInt function")
	end)
end)
