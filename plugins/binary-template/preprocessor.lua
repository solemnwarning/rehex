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

local M = {}

local _MACRO_RECURSION_LIMIT = 64

local function _expand_macros(s, context, filename, line_num, stack)
	local expanded_a_macro = true
	
	if stack == nil
	then
		stack = {}
	end
	
	if #stack > _MACRO_RECURSION_LIMIT
	then
		error("Exceeded recursion limit when expanding macro '" .. stack[1] .. "' at " .. filename .. ":" .. line_num)
	end
	
	-- Wrap string in spaces so we can match on %sMACRO%s
	s = " " .. s .. " "
	
	for name, value in pairs(context.macros)
	do
		local expr = "(%s)" .. name .. "(%s)";
		
		if s:match(expr)
		then
			-- Expand nested macros
			table.insert(stack, name)
			value = _expand_macros(value, context, filename, line_num, stack)
			table.remove(stack)
			
			-- Escape any %1 %2 etc in macro
			value = string.gsub(value, "%%", "%%%%")
			
			-- Repeat gsub() so adjacent macros are replaced
			while s:match(expr)
			do
				s = string.gsub(s, expr, "%1" .. value .. "%2")
			end
		end
	end
	
	-- Strip off the spaces we added
	s = s:sub(2, -2)
	
	return s
end

local function _preprocess_file(filename, context)
	local include_base = string.gsub(filename, "[^\\/]+$", "")
	if include_base == ""
	then
		include_base = "./";
	end
	
	local file, err = io.open(filename, "r")
	if not file
	then
		error("Unable to open " .. filename .. ": " .. err)
	end
	
	local line_num = 0
	local in_comment = false
	local defining_macro_name = nil
	local defining_macro_val
	
	local output = ""
	
	local reset_pos = function()
		output = output .. "#file " .. filename .. " " .. (line_num + 1) .. "\n"
	end
	
	reset_pos()
	
	for line in file:lines()
	do
		line_num = line_num + 1
		
		line = string.gsub(line, "\r$", "")
		
		if in_comment and line:match("%*/")
		then
			line = string.gsub(line, "^.*\\*/", "", 1)
			in_comment = false
		end
		
		local trailing_slash = line:match("\\$")
		
		line = string.gsub(line, "/%*.*%*/", "")
		line = string.gsub(line, "//.*$", "")
		
		local entering_comment = false
		if line:match("/%*")
		then
			line = string.gsub(line, "/%*.*$", "")
			entering_comment = true
		end
		
		local define_p1, define_p2 = line:match("^%s*#%s*define%s+([^%s]+)%s*(.*)$")
		local ifdef_p              = line:match("^%s*#%s*ifdef%s+([^%s]+)%s*$")
		local ifndef_p             = line:match("^%s*#%s*ifndef%s+([^%s]+)%s*$")
		local include_p            = line:match("^%s*#%s*include%s+\"([^\"]*)\"%s*$") or line:match("^%s*#%s*include%s+<([^>]*)>%s*$")
		local error_p              = line:match("^%s*#%s*error%s+(.*)$")
		local warning_p            = line:match("^%s*#%s*warning%s+(.*)$")
		
		if defining_macro_name ~= nil
		then
			-- Strip trailing slash (if present)
			line = string.gsub(line, "\\$", "")
			
			-- Strip any trailing/leading whitespace
			line = string.gsub(line, "^%s+", "")
			line = string.gsub(line, "%s+$", "")
			
			if not in_comment
			then
				if defining_macro_val ~= ""
				then
					defining_macro_val = defining_macro_val .. " " .. line
				else
					defining_macro_val = line
				end
			end
			
			if not trailing_slash
			then
				context.macros[defining_macro_name] = defining_macro_val
				
				defining_macro_name = nil
				defining_macro_val  = nil
				
				reset_pos()
			end
		elseif in_comment
		then
			-- Keep the line number correct
			output = output .. "\n"
		elseif line:match("^%s*#%s*endif%s*$")
		then
			-- #endif
			
			if #context.if_stack < 1
			then
				error("'#endif' with no matching '#ifdef' or '#ifndef' at " .. filename .. ":" .. line_num)
			end
			
			table.remove(context.if_stack)
			
			if context.no_depth == 1
			then
				context.no_depth = 0
			elseif context.no_depth > 1
			then
				context.no_depth = context.no_depth - 1
			end
			
			if context.no_depth == 0
			then
				reset_pos()
			end
		elseif line:match("^%s*#%s*else%s*$")
		then
			-- #else
			
			if #context.if_stack == 0
			then
				error("'#else' with no matching '#ifdef' or '#ifndef' at " .. filename .. ":" .. line_num)
			end
			
			-- Take over the context for error reporting
			context.if_stack[#context.if_stack].filename  = filename;
			context.if_stack[#context.if_stack].line_num  = line_num;
			context.if_stack[#context.if_stack].statement = line;
			
			if context.no_depth == 1
			then
				context.no_depth = 0
				reset_pos()
			elseif context.no_depth == 0
			then
				context.no_depth = 1
			end
			
		elseif context.no_depth > 0
		then
			-- Do nothing
		elseif define_p1
		then
			-- #define (define_p1) (define_p2)
			
			-- Strip trailing slash (if present)
			define_p2 = string.gsub(define_p2, "\\$", "")
			
			-- Strip any trailing whitespace
			define_p2 = string.gsub(define_p2, "%s+$", "")
			
			if trailing_slash
			then
				defining_macro_name = define_p1
				defining_macro_val = define_p2
			else
				context.macros[define_p1] = define_p2;
				reset_pos()
			end
		elseif ifdef_p
		then
			-- #ifdef (ifdef_p)
			
			if context.macros[ifdef_p] == nil or context.no_depth > 0
			then
				context.no_depth = context.no_depth + 1
			end
			
			table.insert(context.if_stack,
			{
				filename = filename,
				line_num = line_num,
				
				statement = line,
			})
			
			if context.no_depth == 0
			then
				reset_pos()
			end
		elseif ifndef_p
		then
			-- #ifndef (ifndef_p)
			
			if context.macros[ifndef_p] ~= nil or context.no_depth > 0
			then
				context.no_depth = context.no_depth + 1
			end
			
			table.insert(context.if_stack,
			{
				filename = filename,
				line_num = line_num,
				
				statement = line,
			})
			
			if context.no_depth == 0
			then
				reset_pos()
			end
		elseif include_p
		then
			-- #include "include_p" OR #include <include_p>
			
			output = output .. _preprocess_file(include_base .. include_p, context)
			reset_pos()
		elseif error_p
		then
			-- #error (error_p?)
			
			error("#error " .. error_p .. " at " .. filename .. ":" .. line_num)
		elseif warning_p
		then
			-- #warning (warning_p?)
			
			context.print_func("#warning " .. warning_p .. " at " .. filename .. ":" .. line_num)
			reset_pos()
		elseif line:match("^%s*#")
		then
			error("Unknown preprocessor directive '" .. line .. "' at " .. filename .. ":" .. line_num)
		else
			output = output .. _expand_macros(line, context, filename, line_num) .. "\n"
		end
		
		if entering_comment
		then
			in_comment = true
		end
	end
	
	return output;
end

M.preprocess_file = function(filename, print_func)
	local context = {}
	
	context.if_stack = {}
	context.no_depth = 0
	context.macros = {}
	context.print_func = print_func
	
	local result = _preprocess_file(filename, context)
	
	if #context.if_stack > 0
	then
		local if_ctx = context.if_stack[#context.if_stack]
		error("Expected '#endif' to terminate '" .. if_ctx.statement .. "' at " .. if_ctx.filename .. ":" .. if_ctx.line_num)
	end
	
	return result
end

return M;
