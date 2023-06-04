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

local util = require 'executor.util'

local TypeMapper = {}
TypeMapper.__index = TypeMapper

local function _template_error(context, error_message, filename, line_num)
	error(error_message .. " at " .. filename .. ":" .. line_num, 0)
end

function TypeMapper:new(value)
	local root_scope = {
		types = {},
	}
	
	local self = {
		scopes = {
			{ types = {} },
		},
	}
	
	setmetatable(self, TypeMapper)
	
	return self
end

function TypeMapper:process_statement(statement)
	local op = statement[3]
	
	if op == "function"
	then
		local func_ret_type   = statement[4]
		local func_name       = statement[5]
		local func_args       = statement[6]
		local func_statements = statement[7]
		
		statement.return_type_info = self:resolve_type(func_ret_type, statement[1], statement[2])
		
		for arg_idx, arg in ipairs(func_args)
		do
			local type_info = self:resolve_type(arg[1], statement[1], statement[2])
			arg.type_info = type_info
		end
		
	elseif op == "struct"
	then
		local struct_name       = statement[4]
		local struct_args       = statement[5]
		local struct_statements = statement[6]
		local typedef_name      = statement[7]
		local var_decl          = statement[8]
		
		local args = {}
		for arg_idx, arg in ipairs(struct_args)
		do
			arg.type_info = self:resolve_type(arg[1], statement[1], statement[2])
			table.insert(args, { arg[2], arg.type_info, var_slot = arg.var_slot })
		end
		
		local type_info = {
			base      = "struct",
			arguments = args,
			code      = struct_statements,
			
			struct_name = struct_name,
			type_key  = {}, -- Uniquely-identifiable table reference used to check if struct
					-- types are derived from the same root (and thus compatible)
			
			allocate_slots = statement.allocate_slots,
		}
		
		if struct_name ~= nil
		then
			self:define_type("struct " .. struct_name, type_info, statement[1], statement[2])
		end
		
		if typedef_name ~= nil
		then
			self:define_type(typedef_name, type_info, statement[1], statement[2])
		end
		
		statement.type_info = type_info
	
	elseif op == "typedef"
	then
		local type_name    = statement[4]
		local typedef_name = statement[5]
		local array_size   = statement[6]
		
		local base_type_info = self:resolve_type(type_name)
		if base_type_info == nil
		then
			_template_error(nil, "Use of undefined type '" .. type_name .. "'", statement[1], statement[2])
		end
		
		local type_info = util.make_named_type(typedef_name, base_type_info)
		
		if array_size ~= nil
		then
			if base_type_info.array_size ~= nil
			then
				_template_error(nil, "Multidimensional arrays are not supported", statement[1], statement[2])
			end
			
			-- Explicitly copy as util.make_array_type() will return a shared object
			-- which we don't want to taint with our size.
			type_info = util.shallow_copy_table(type_info)
			
			type_info.is_array = true
			type_info.array_size = {}
		end
		
		self:define_type(typedef_name, type_info, statement[1], statement[2])
		statement.type_info = type_info
		
	elseif op == "enum"
	then
		local type_name    = statement[4]
		local enum_name    = statement[5]
		local members      = statement[6]
		local typedef_name = statement[7]
		local var_decl     = statement[8]
		
		local type_info = self:resolve_type(type_name, statement[1], statement[2])
		if type_info == nil
		then
			_template_error(nil, "Use of undefined type '" .. type_name .. "'", statement[1], statement[2])
		end
		
		if enum_name ~= nil
		then
			local enum_typename = "enum " .. enum_name
			
			type_info = util.make_named_type(enum_typename, type_info)
			self:define_type(enum_typename, type_info, statement[1], statement[2])
		end
		
		if typedef_name ~= nil
		then
			self:define_type(typedef_name, type_info, statement[1], statement[2])
		end
		
		statement.type_info = type_info
		
	elseif op == "if"
	then
		for i = 4, #statement
		do
			local cond = statement[i][2] and statement[i][1] or nil
			local code = statement[i][2] or statement[i][1]
			
			self:process_optional_statement(cond)
			
			self:process_scope(function()
				self:process_statements(code)
			end)
		end
		
		return
		
	elseif op == "variable" or op == "local-variable"
	then
		local var_type = statement[4]
		
		local type_info = self:resolve_type(var_type)
		if type_info == nil
		then
			_template_error(nil, "Unknown type '" .. var_type .. "'", statement[1], statement[2])
		end
		
		statement.type_info = type_info
		
	elseif op == "cast"
	then
		local type_name = statement[4]
		
		local type_info = self:resolve_type(type_name)
		if type_info == nil
		then
			_template_error(nil, "Unknown type '" .. type_name .. "' used in cast", statement[1], statement[2])
		end
		
		statement.type_info = type_info
	end
	
	self:process_scope(function()
		util.visit_statement_children(statement, function(statement) self:process_statement(statement) end)
	end)
end

function TypeMapper:process_optional_statement(statement)
	if statement ~= nil
	then
		self:process_statement(statement)
	end
end

function TypeMapper:process_statements(statements)
	for _, statement in ipairs(statements)
	do
		self:process_statement(statement)
	end
end

function TypeMapper:process_scope(func)
	local scope = {
		types = {},
	}
	
	table.insert(self.scopes, scope)
	
	func()
	
	table.remove(self.scopes)
end

function TypeMapper:resolve_type(type_name)
	type_name = " " .. type_name .. " "
	
	local make_unsigned = false
	local make_signed = false
	local make_ref = false
	local make_const = false
	local make_array = false
	
	if type_name:find(" unsigned ") ~= nil
	then
		make_unsigned = true
		type_name = type_name:gsub(" unsigned ", " ", 1)
	elseif type_name:find(" signed ") ~= nil
	then
		make_signed = true
		type_name = type_name:gsub(" signed ", " ", 1)
	end
	
	if type_name:find(" & ") ~= nil
	then
		make_ref = true
		type_name = type_name:gsub(" & ", " ", 1)
	end
	
	if type_name:find(" const ") ~= nil
	then
		make_const = true
		type_name = type_name:gsub(" const ", " ", 1)
	end
	
	if type_name:find(" %[%] ") ~= nil
	then
		make_array = true
		type_name = type_name:gsub(" %[%] ", " ", 1)
	end
	
	type_name = type_name:sub(2, -2)
	
	local type_info = nil
	
	for i = #self.scopes, 1, -1
	do
		local scope = self.scopes[i]
		
		if scope.types[type_name] ~= nil
		then
			type_info = scope.types[type_name]
			break
		end
	end
	
	if type_info ~= nil
	then
		if make_unsigned then type_info = util.make_unsigned_type(context, type_info)  end
		if make_signed   then type_info = util.make_signed_type(context, type_info)    end
		if make_ref      then type_info = util.make_ref_type(type_info)                end
		if make_const    then type_info = util.make_const_type(type_info)              end
		if make_array    then type_info = util.make_array_type(type_info)              end
	end
	
	return type_info
end

function TypeMapper:define_type(name, type_info, filename, line_num)
	local scope = self.scopes[#self.scopes]
	
	if scope.types[name] ~= nil
	then
		_template_error(context, "Attempt to redefine type '" .. name .. "'", filename, line_num)
	end
	
	scope.types[name] = type_info
end

function TypeMapper._resolve_types(context, statements, _builtin_types)
	local self = TypeMapper:new()
	
	for k, v in pairs(_builtin_types)
	do
		self:define_type(k, v, debug.getinfo(1,'S').source, debug.getinfo(1, 'l').currentline)
	end
	
	self:process_statements(statements)
end

return TypeMapper
