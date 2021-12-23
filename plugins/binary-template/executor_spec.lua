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
end)
