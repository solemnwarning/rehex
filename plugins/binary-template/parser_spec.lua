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

local parser = require 'parser'

describe("parser", function()
	it("parses numbers", function()
		assert.are.same({ { "UNKNOWN FILE", 1, "num", 1 } }, parser.parse_text("1;"));
		assert.are.same({ { "UNKNOWN FILE", 1, "num", 1 } }, parser.parse_text("1.0;"));
		assert.are.same({ { "UNKNOWN FILE", 1, "num", 1.5 } }, parser.parse_text("1.5;"));
		assert.are.same({ { "UNKNOWN FILE", 1, "num", -1 } }, parser.parse_text("-1;"));
	end);
	
	it("parses a function call", function()
		assert.are.same({ { "UNKNOWN FILE", 1, "call", "testfunc", {} } }, parser.parse_text("testfunc();"));
		assert.are.same({ { "UNKNOWN FILE", 1, "call", "testfunc", { { "UNKNOWN FILE", 1, "num", 1 } } } }, parser.parse_text("testfunc(1);"));
		assert.are.same({ { "UNKNOWN FILE", 1, "call", "testfunc", { { "UNKNOWN FILE", 1, "ref", "i" } } } }, parser.parse_text("testfunc(i);"));
	end);
	
	it("parses arithmetic expressions", function()
		local got;
		local expect;
		
		got = parser.parse_text("1 + 2 * 3 - 4 / 5 + 6;");
		expect = {
			{ "UNKNOWN FILE", 1, "add",
				{ "UNKNOWN FILE", 1, "num", 1 },
				{ "UNKNOWN FILE", 1, "subtract",
					{ "UNKNOWN FILE", 1, "multiply",
						{ "UNKNOWN FILE", 1, "num", 2 },
						{ "UNKNOWN FILE", 1, "num", 3 },
					},
					{ "UNKNOWN FILE", 1, "add",
						{ "UNKNOWN FILE", 1, "divide",
							{ "UNKNOWN FILE", 1, "num", 4 },
							{ "UNKNOWN FILE", 1, "num", 5 },
						},
						{ "UNKNOWN FILE", 1, "num", 6 },
					},
				},
			},
		};
		
		assert.are.same(expect, got);
		
		got = parser.parse_text("(1 + 2) * (3 - 4) / (5 + 6);");
		expect = {
			{ "UNKNOWN FILE", 1, "multiply",
				{ "UNKNOWN FILE", 1, "add",
					{ "UNKNOWN FILE", 1, "num", 1 },
					{ "UNKNOWN FILE", 1, "num", 2 },
				},
				{ "UNKNOWN FILE", 1, "divide",
					{ "UNKNOWN FILE", 1, "subtract",
						{ "UNKNOWN FILE", 1, "num", 3 },
						{ "UNKNOWN FILE", 1, "num", 4 },
					},
					{ "UNKNOWN FILE", 1, "add",
						{ "UNKNOWN FILE", 1, "num", 5 },
						{ "UNKNOWN FILE", 1, "num", 6 },
					},
				},
			},
		};
		
		assert.are.same(expect, got);
		
		got = parser.parse_text("((1 + 2) * (3 - 4)) / (5 + 6);");
		expect = {
			{ "UNKNOWN FILE", 1, "divide",
				{ "UNKNOWN FILE", 1, "multiply",
					{ "UNKNOWN FILE", 1, "add",
						{ "UNKNOWN FILE", 1, "num", 1 },
						{ "UNKNOWN FILE", 1, "num", 2 },
					},
					{ "UNKNOWN FILE", 1, "subtract",
						{ "UNKNOWN FILE", 1, "num", 3 },
						{ "UNKNOWN FILE", 1, "num", 4 },
					},
				},
				{ "UNKNOWN FILE", 1, "add",
					{ "UNKNOWN FILE", 1, "num", 5 },
					{ "UNKNOWN FILE", 1, "num", 6 },
				},
			},
		};
		
		assert.are.same(expect, got);
	end);
	
	it("parses variable definitions", function()
		assert.are.same({ { "UNKNOWN FILE", 1, "variable", "int", "var", {} } }, parser.parse_text("int var;"));
		assert.are.same({ { "UNKNOWN FILE", 1, "variable", "int", "array", { { "UNKNOWN FILE", 1, "num", 10 } } } }, parser.parse_text("int array[10];"));
	end);
	
	it("parses local variable definitions", function()
		local got;
		local expect;
		
		got = parser.parse_text("local int var;");
		expect = {
			{ "UNKNOWN FILE", 1, "local-variable", "int", "var", {}, {} },
		};
		
		assert.are.same(expect, got);
		
		got = parser.parse_text("local int array[10];");
		expect = {
			{ "UNKNOWN FILE", 1, "local-variable", "int", "array", { { "UNKNOWN FILE", 1, "num", 10 } }, {} },
		};
		
		assert.are.same(expect, got);
		
		got = parser.parse_text("local int foo = 0;");
		expect = {
			{ "UNKNOWN FILE", 1, "local-variable", "int", "foo", {}, { { "UNKNOWN FILE", 1, "num", 0 } } },
		};
		
		assert.are.same(expect, got);
	end);
	
	it("parses an empty struct", function()
		local got = parser.parse_text("struct mystruct{};");
		
		local expect = {
			{ "UNKNOWN FILE", 1, "struct", "mystruct", {}, {} },
		};
		
		assert.are.same(expect, got);
	end);
	
	it("parses a struct with some members", function()
		local got = parser.parse_text("struct mystruct {\nint x;\nint y;\n};");
		
		local expect = {
			{ "UNKNOWN FILE", 1, "struct", "mystruct", {},
			{
				{ "UNKNOWN FILE", 2, "variable", "int", "x", {} },
				{ "UNKNOWN FILE", 3, "variable", "int", "y", {} },
			} },
		};
		
		assert.are.same(expect, got);
	end);
	
	it("parses a struct with an empty argument list", function()
		local got = parser.parse_text("struct mystruct() {\nint x;\nint y;\n};");
		
		local expect = {
			{ "UNKNOWN FILE", 1, "struct", "mystruct", {},
			{
				{ "UNKNOWN FILE", 2, "variable", "int", "x", {} },
				{ "UNKNOWN FILE", 3, "variable", "int", "y", {} },
			} },
		};
		
		assert.are.same(expect, got);
	end);
	
	it("parses a struct with an argument list", function()
		local got = parser.parse_text("struct mystruct(int a, int b) {\nint x;\nint y;\n};");
		
		local expect = {
			{ "UNKNOWN FILE", 1, "struct", "mystruct",
			{
				{ "int", "a" },
				{ "int", "b" },
			},
			{
				{ "UNKNOWN FILE", 2, "variable", "int", "x", {} },
				{ "UNKNOWN FILE", 3, "variable", "int", "y", {} },
			} },
		};
		
		assert.are.same(expect, got);
	end);
	
	it("parses a function with no arguments or body", function()
		local got = parser.parse_text("int myfunc(){}");
		
		local expect = {
			{ "UNKNOWN FILE", 1, "function", "int", "myfunc", {}, {} },
		};
		
		assert.are.same(expect, got);
	end);
	
	it("parses a function with a body", function()
		local got = parser.parse_text("void myfunc () {\nlocal int i = 0;\notherfunc(1234);\n}\n");
		
		local expect = {
			{ "UNKNOWN FILE", 1, "function", "void", "myfunc", {},
			{
				{ "UNKNOWN FILE", 2, "local-variable", "int", "i", {}, { { "UNKNOWN FILE", 2, "num", 0 } } },
				{ "UNKNOWN FILE", 3, "call", "otherfunc", { { "UNKNOWN FILE", 3, "num", 1234 } } },
			} },
		};
		
		assert.are.same(expect, got);
	end);
	
	it("parses a function with arguments", function()
		local got = parser.parse_text("void myfunc(int x, int y, int z) {}\n");
		
		local expect = {
			{ "UNKNOWN FILE", 1, "function", "void", "myfunc",
			{
				{ "int", "x" },
				{ "int", "y" },
				{ "int", "z" }
			},
			{} },
		};
		
		assert.are.same(expect, got);
	end);
	
	it("parses #file directives", function()
		local got = parser.parse_text("#file foo.bt 10\nint x;\nint y;\n#file bar.bt 1\nint z;\n");
		
		local expect = {
			{ "foo.bt", 10, "variable", "int", "x", {} },
			{ "foo.bt", 11, "variable", "int", "y", {} },
			{ "bar.bt",  1, "variable", "int", "z", {} },
		};
		
		assert.are.same(expect, got);
	end);
end);
