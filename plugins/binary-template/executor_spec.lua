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

local function test_interface()
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
end)
