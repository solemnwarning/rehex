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

local preprocessor = require 'preprocessor'

describe("preprocessor", function()
	it("loads a file with some text", function()
		local expect = "#file preprocessor-tests/basic-test-1.bt 1\n" ..
			"local int i = 0;\n" ..
			"local int j = 0;\n" ..
			"\n" ..
			"hello();\n"
		
		local got = preprocessor.preprocess_file("preprocessor-tests/basic-test-1.bt", error)
		
		assert.are.same(expect, got)
	end)
	
	it("expands macros", function()
		local expect =
			"#file preprocessor-tests/macro-test-1.bt 1\n" ..
			"#file preprocessor-tests/macro-test-1.bt 2\n" ..
			"#file preprocessor-tests/macro-test-1.bt 3\n" ..
			"\n" ..
			"FOOMACRO %1\n" ..
			"BARMACRO %2 FOOMACRO %1\n" ..
			"FOOMACRO %1 BARMACRO %2 FOOMACRO %1 BARMACRO %2 FOOMACRO %1\n"
		
		local got = preprocessor.preprocess_file("preprocessor-tests/macro-test-1.bt", error)
		
		assert.are.same(expect, got)
	end)
	
	it("errors on cyclic macros", function()
		assert.has_error(
			function() preprocessor.preprocess_file("preprocessor-tests/cyclic-macro-test.bt", error) end,
			"Exceeded recursion limit when expanding macro 'FOO' at preprocessor-tests/cyclic-macro-test.bt:4")
	end)
	
	it("Excludes blocks using #ifdef/#ifndef/#else", function()
		local expect =
			"#file preprocessor-tests/ifdef-test-1.bt 1\n" ..
			"#file preprocessor-tests/ifdef-test-1.bt 2\n" ..
			"\n" ..
			"#file preprocessor-tests/ifdef-test-1.bt 4\n" ..
			"should-see-this\n" ..
			"#file preprocessor-tests/ifdef-test-1.bt 6\n" ..
			"\n" ..
			"#file preprocessor-tests/ifdef-test-1.bt 10\n" ..
			"\n" ..
			"#file preprocessor-tests/ifdef-test-1.bt 12\n" ..
			"should-see-this\n" ..
			"#file preprocessor-tests/ifdef-test-1.bt 16\n" ..
			"\n" ..
			"#file preprocessor-tests/ifdef-test-1.bt 20\n" ..
			"should-see-this\n" ..
			"#file preprocessor-tests/ifdef-test-1.bt 22\n"
		
		local got = preprocessor.preprocess_file("preprocessor-tests/ifdef-test-1.bt", error)
		
		assert.are.same(expect, got)
	end)
	
	it("processes #include directives", function()
		local expect =
			"#file preprocessor-tests/include-test-1.bt 1\n" ..
			"main file\n" ..
			"#file preprocessor-tests/include-test-1a.h 1\n" ..
			"included file include-test-1a.h\n" ..
			"#file preprocessor-tests/include-test-1.bt 3\n" ..
			"#file preprocessor-tests/include-test-1b.h 1\n" ..
			"included file include-test-1b.h\n" ..
			"#file preprocessor-tests/include-test-1.bt 4\n" ..
			"hello\n"
		
		local got = preprocessor.preprocess_file("preprocessor-tests/include-test-1.bt", error)
		
		assert.are.same(expect, got)
	end)
	
	it("processes nested #include directives", function()
		local expect =
			"#file preprocessor-tests/include-test-2.bt 1\n" ..
			"main file\n" ..
			"#file preprocessor-tests/include-test-2a.h 1\n" ..
			"included file include-test-2a.h\n" ..
			"#file preprocessor-tests/include-test-2b.h 1\n" ..
			"included file include-test-2b.h\n" ..
			"#file preprocessor-tests/include-test-2a.h 3\n" ..
			"#file preprocessor-tests/include-test-2.bt 3\n" ..
			"hello\n"
		
		local got = preprocessor.preprocess_file("preprocessor-tests/include-test-2.bt", error)
		
		assert.are.same(expect, got)
	end)
	
	it("errors on unmatched #ifdef/#ifndef/#else/#endif directives", function()
		assert.has_error(
			function() preprocessor.preprocess_file("preprocessor-tests/unmatched-ifdef-test.bt", error) end,
			"Expected '#endif' to terminate '#ifdef FOO' at preprocessor-tests/unmatched-ifdef-test.bt:1")
		
		assert.has_error(
			function() preprocessor.preprocess_file("preprocessor-tests/unmatched-ifndef-test.bt", error) end,
			"Expected '#endif' to terminate '#ifndef FOO' at preprocessor-tests/unmatched-ifndef-test.bt:1")
		
		assert.has_error(
			function() preprocessor.preprocess_file("preprocessor-tests/unmatched-endif-test.bt", error) end,
			"'#endif' with no matching '#ifdef' or '#ifndef' at preprocessor-tests/unmatched-endif-test.bt:1")
		
		assert.has_error(
			function() preprocessor.preprocess_file("preprocessor-tests/unmatched-else-test.bt", error) end,
			"'#else' with no matching '#ifdef' or '#ifndef' at preprocessor-tests/unmatched-else-test.bt:1")
	end)
end)
