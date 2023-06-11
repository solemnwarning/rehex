-- Binary Template plugin for REHex
-- Copyright (C) 2023 Daniel Collins <solemnwarning@solemnwarning.net>
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

local util = {}

function util.deep_copy_table(v)
	if type(v) == "table"
	then
		local cv = {}
		
		for key, elem in pairs(v)
		do
			cv[key] = util.deep_copy_table(elem)
		end
		
		return cv
	else
		return v
	end
end

function util.visit_statement_children(statement, func)
	local do_array = function(statements)
		for _, statement in ipairs(statements)
		do
			func(statement)
		end
	end
	
	local do_optional = function(statement)
		if statement ~= nil
		then
			func(statement)
		end
	end
	
	local op = statement[3]
	
	if op == "ref"
	then
		local path = statement[4]
		
		for i = 2, #path
		do
			if type(path[i]) == "table"
			then
				-- This is a statement to be evalulated and used as an array index.
				func(path[i])
			end
		end
		
	elseif op == "variable"
	then
		local struct_args = statement[6]
		local array_size  = statement[7]
		local attributes  = statement[8]
		
		if struct_args ~= nil
		then
			do_array(struct_args)
		end
		
		do_optional(array_size)
		
		if attributes ~= nil
		then
			for i = 1, #attributes
			do
				local attr_value = attributes[i][4]
				do_optional(attr_value)
			end
		end
		
	elseif op == "local-variable"
	then
		local struct_args = statement[6]
		local array_size = statement[7]
		local initial_value = statement[8]
		
		if struct_args ~= nil
		then
			do_array(struct_args)
		end
		
		do_optional(array_size)
		do_optional(initial_value)
		
	elseif op == "assign"
	then
		func(statement[4]) -- dst_expr
		func(statement[5]) -- src_expr
		
	elseif op == "call"
	then
		local func_args = statement[5]
		do_array(func_args)
		
	elseif op == "return"
	then
		local retval = statement[4]
		do_optional(retval)
		
	elseif op == "function"
	then
		local func_statements = statement[7]
		do_array(func_statements)
		
	elseif op == "struct"
	then
		local struct_statements = statement[6]
		local var_decl          = statement[8]
		
		do_array(struct_statements)
		
		if var_decl ~= nil
		then
			local var_args   = var_decl[2]
			local array_size = var_decl[3]
			
			do_array(var_args)
			do_optional(array_size)
		end
		
	elseif op == "typedef"
	then
		local array_size   = statement[6]
		do_optional(array_size)
		
	elseif op == "enum"
	then
		local members  = statement[6]
		local var_decl = statement[8]
		
		for _, member_pair in pairs(members)
		do
			local member_name, member_expr = table.unpack(member_pair)
			do_optional(member_expr)
		end
		
		if var_decl ~= nil
		then
			local var_args   = var_decl[2]
			local array_size = var_decl[3]
			
			if var_args ~= nil
			then
				do_array(var_args)
			end
			
			do_optional(array_size)
		end
	elseif op == "if"
	then
		for i = 4, #statement
		do
			local cond = statement[i][2] and statement[i][1] or nil
			local code = statement[i][2] or statement[i][1]
			
			do_optional(cond)
			do_array(code)
		end
		
	elseif op == "for"
	then
		local init_expr = statement[4]
		local cond_expr = statement[5]
		local iter_expr = statement[6]
		local body      = statement[7]
		
		do_optional(init_expr)
		do_optional(cond_expr)
		do_optional(iter_expr)
		
		do_array(body)
		
	elseif op == "switch"
	then
		local expr = statement[4]
		local cases = statement[5]
		
		func(expr)
		
		for _, case in ipairs(cases)
		do
			local case_expr = case[1]
			local case_body = case[2]
			
			do_optional(case_expr)
			do_array(case_body)
		end
		
	elseif op == "block"
	then
		do_array(statement[4])
		
	elseif op == "cast"
	then
		func(statement[5]) -- value_expr
		
	elseif op == "ternary"
	then
		func(statement[4]) -- cond_expr
		func(statement[5]) -- if_true_expr
		func(statement[6]) -- if_false_expr
		
	elseif op == "add"
		or op == "subtract"
		or op == "multiply"
		or op == "divide"
		or op == "mod"
		or op == "left-shift"
		or op == "right-shift"
		or op == "bitwise-and"
		or op == "bitwise-xor"
		or op == "bitwise-or"
		or op == "less-than"
		or op == "less-than-or-equal"
		or op == "greater-than"
		or op == "greater-than-or-equal"
		or op == "equal"
		or op == "not-equal"
		or op == "logical-and"
		or op == "logical-or"
	then
		func(statement[4])
		func(statement[5])
		
	elseif op == "bitwise-not"
		or op == "logical-not"
		or op == "postfix-increment"
		or op == "postfix-decrement"
		or op == "plus"
		or op == "minus"
	then
		func(statement[4])
	end
end

return util
