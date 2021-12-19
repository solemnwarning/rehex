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

local _find_type;

local _numeric_op_func;
local _eval_variable;
local _eval_call;
local _eval_func_defn;
local _eval_statement;
local _exec_statements;

local function _x(context, statement)
	return "int", statement[4]
end

_numeric_op_func = function(func)
	return function(context, statement)
		local filename = statement[1]
		local line_num = statement[2]
		
		local v1 = _eval_statement(context, statement[4])
		local v2 = _eval_statement(context, statement[5])
		
		return func(v1, v2)
	end
end

local _ops

local _builtin_type_int8    = { rehex_type_le = "s8",    rehex_type_be = "s8",    length = 1 }
local _builtin_type_uint8   = { rehex_type_le = "u8",    rehex_type_be = "u8",    length = 1 }
local _builtin_type_int16   = { rehex_type_le = "s16le", rehex_type_be = "s16be", length = 2 }
local _builtin_type_uint16  = { rehex_type_le = "u16le", rehex_type_be = "u16be", length = 2 }
local _builtin_type_int32   = { rehex_type_le = "s32le", rehex_type_be = "s32be", length = 4 }
local _builtin_type_uint32  = { rehex_type_le = "u32le", rehex_type_be = "u32be", length = 4 }
local _builtin_type_int64   = { rehex_type_le = "s64le", rehex_type_be = "s64be", length = 8 }
local _builtin_type_uint64  = { rehex_type_le = "u64le", rehex_type_be = "u64be", length = 8 }
local _builtin_type_float32 = { rehex_type_le = "f32le", rehex_type_be = "f32be", length = 4 }
local _builtin_type_float64 = { rehex_type_le = "f64le", rehex_type_be = "f64be", length = 8 }

local _builtin_types = {
	char = _builtin_type_int8,
	byte = _builtin_type_int8,
	CHAR = _builtin_type_int8,
	BYTE = _builtin_type_int8,
	
	uchar = _builtin_type_uint8,
	ubyte = _builtin_type_uint8,
	UCHAR = _builtin_type_uint8,
	UBYTE = _builtin_type_uint8,
	
	short = _builtin_type_int16,
	int16 = _builtin_type_int16,
	SHORT = _builtin_type_int16,
	INT16 = _builtin_type_int16,
	
	ushort = _builtin_type_uint16,
	uint16 = _builtin_type_uint16,
	USHORT = _builtin_type_uint16,
	UINT16 = _builtin_type_uint16,
	WORD   = _builtin_type_uint16,
	
	int   = _builtin_type_int32,
	int32 = _builtin_type_int32,
	long  = _builtin_type_int32,
	INT   = _builtin_type_int32,
	INT32 = _builtin_type_int32,
	LONG  = _builtin_type_int32,
	
	uint   = _builtin_type_uint32,
	uint32 = _builtin_type_uint32,
	ulong  = _builtin_type_uint32,
	UINT   = _builtin_type_uint32,
	UINT32 = _builtin_type_uint32,
	ULONG  = _builtin_type_uint32,
	DWORD  = _builtin_type_uint32,
	
	int64   = _builtin_type_int64,
	quad    = _builtin_type_int64,
	QUAD    = _builtin_type_int64,
	INT64   = _builtin_type_int64,
	__int64 = _builtin_type_int64,
	
	uint64   = _builtin_type_uint64,
	uquad    = _builtin_type_uint64,
	UQUAD    = _builtin_type_uint64,
	UINT64   = _builtin_type_uint64,
	QWORD    = _builtin_type_uint64,
	__uint64 = _builtin_type_uint64,
	
	float = _builtin_type_float32,
	FLOAT = _builtin_type_float32,
	
	double = _builtin_type_float64,
	DOUBLE = _builtin_type_float64,
}

local function _builtin_function_BigEndian(context, argv)
	context.big_endian = true
end

local function _builtin_function_LittleEndian(context, argv)
	context.big_endian = false
end

-- Table of builtin functions - gets copied into new interpreter contexts
--
-- Each key is a function name, the value is a table with the following values:
--
-- Table of argument types (arguments)
-- Function implementation (impl)

local _builtin_functions = {
	BigEndian    = { arguments = {}, impl = _builtin_function_BigEndian },
	LittleEndian = { arguments = {}, impl = _builtin_function_LittleEndian },
}

_find_type = function(context, type_name)
	for i = #context.stack, 1, -1
	do
		for k, v in pairs(context.stack[i].var_types)
		do
			if k == type_name
			then
				return v
			end
		end
	end
end

_eval_variable = function(context, statement)
	local filename = statement[1]
	local line_num = statement[2]
	
	local v_type = statement[4]
	local v_name = statement[5]
	local v_length = statement[6][1]
	
	local type_info = _find_type(context, v_type)
	if type_info == nil
	then
		error("Unknown variable type '" .. v_type .. "' at " .. filename .. ":" .. line_num)
	end
	
	local data_type_key = context.big_endian and type_info.rehex_type_be or type_info.rehex_type_le
	
	if v_length == nil
	then
		context.interface.set_data_type(context.next_variable, type_info.length, data_type_key)
		context.interface.set_comment(context.next_variable, type_info.length, v_name)
		
		context.next_variable = context.next_variable + type_info.length
	else
		local array_length_type, array_length_val = _eval_statement(context, v_length)
		if array_length_type ~= "int"
		then
			error("Expected 'int' type for array size, got '" .. array_length_type .. "' at " .. filename .. ":" .. line_num)
		end
		
		for i = 0, array_length_val
		do
			context.interface.set_data_type(context.next_variable, type_info.length, data_type_key)
			context.interface.set_comment(context.next_variable, type_info.length, v_name .. "[" .. i .. "]")
			
			context.next_variable = context.next_variable + type_info.length
		end
	end
end

_eval_call = function(context, statement)
	local filename = statement[1]
	local line_num = statement[2]
	
	local func_name = statement[4]
	local func_args = statement[5]
	
	local func_defn = context.functions[func_name]
	if func_defn == nil
	then
		error("Attempt to call undefined function '" .. func_name .. "' at " .. filename .. ":" .. line_num)
	end
	
	local func_arg_values = {}
	
	for i = 1, #func_args
	do
		func_arg_values[i] = _eval_statement(context, func_args[i])
		-- TODO: Check for type compatibility
	end
	
	return func_defn.impl(context, func_arg_values)
end

_eval_func_defn = function(context, statement)
	local filename = statement[1]
	local line_num = statement[2]
	
	local func_ret_type   = statement[4]
	local func_name       = statement[5]
	local func_arg_types  = statement[6]
	local func_statements = statement[7]
	
	if context.functions[func_name] ~= nil
	then
		error("Attempt to redefine function '" .. func_name .. "' at " .. filename .. ":" .. line_num)
	end
	
	local ret_type = _find_type(context, func_ret_type)
	if ret_type == nil
	then
		error("Attempt to define function '" .. func_name .. "' with undefined return type '" .. func_ret_type .. "' at " .. filename .. ":" .. line_num)
	end
	
	local arg_types = {}
	for i = 1, #func_arg_types
	do
		local type_info = _find_type(context, func_arg_types[i])
		if type_info == nil
		then
			error("Attempt to define function '" .. func_name .. "' with undefined argument type '" .. func_arg_values[i] .. "' at " .. filename .. ":" .. line_num)
		end
		
		table.insert(arg_types, type_info)
	end
	
	local impl_func = function(context, arguments)
		local frame = {
			frame_type = "call",
			var_types = {},
		}
		
		table.insert(context.stack, frame)
		
		-- TODO: Handle early return, return value
		
		_exec_statements(context, func_statements)
		
		table.remove(context.stack)
	end
	
	context.functions[func_name] = {
		arguments = arg_types,
		impl      = impl_func,
	}
end

_eval_statement = function(context, statement)
	local filename = statement[1]
	local line_num = statement[2]
	
	-- TODO: Call yield() periodically
	
	local op = statement[3]
	
	if _ops[op] ~= nil
	then
		return _ops[op](context, statement)
	else
		error("Internal error: unexpected op '" .. op .. "' at " .. filename .. ":" .. line_num)
	end
	
end

_exec_statements = function(context, statements)
	for _, statement in ipairs(statements)
	do
		_eval_statement(context, statement)
	end
end

_ops = {
	num = _x,
	
	variable     = _eval_variable,
	call         = _eval_call,
	["function"] = _eval_func_defn,
	
	subtract = _numeric_op_func(function(v1, v2) return v1 + v2 end),
	multiply = _numeric_op_func(function(v1, v2) return v1 * v2 end),
	divide   = _numeric_op_func(function(v1, v2) return v1 / v2 end),
}

--- External entry point into the interpreter
-- @function execute
--
-- @param interface Table of interface functions to be used by the interpreter.
-- @param statements AST table as returned by the parser.
--
-- The interface table must have the following functions:
--
-- interface.set_data_type(offset, length, data_type)
-- interface.set_comment(offset, length, comment_text)
--
-- Thin wrappers around the REHex APIs, to allow for testing.
--
-- interface.yield()
--
-- Periodically called by the executor to allow processing UI events.
-- An error() may be raised within to abort the interpreter.

local function execute(interface, statements)
	local context = {
		interface = interface,
		
		functions = {},
		stack = {},
		
		next_variable = 0,
		
		-- Are we currently accessing variables from the file as big endian? Toggled by
		-- the built-in BigEndian() and LittleEndian() functions.
		big_endian = false,
	}
	
	for k, v in pairs(_builtin_functions)
	do
		context.functions[k] = v
	end
	
	local base_types = {};
	for k, v in pairs(_builtin_types)
	do
		base_types[k] = v
	end
	
	table.insert(context.stack, {
		frame_type = "base",
		
		var_types = base_types,
	})
	
	_exec_statements(context, statements)
end

M.execute = execute

return M
