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

local VarAllocator = {}
VarAllocator.__index = VarAllocator

local ScopeType = {
	FUNCTION = 1,
	NORMAL = 2,
	TRANSPARENT = 3,
}

local function _template_error(context, error_message, filename, line_num)
	error(error_message .. " at " .. filename .. ":" .. line_num, 0)
end

function VarAllocator:new(value)
	local root_scope = {
		names_used = {},
		
		slots = { num_slots = 0 },
		
		allocate_slots = 0,
		
		initialise_slots_from = 1,
		initialise_slots_to = 0,
	}
	
	root_scope.allocator = root_scope
	root_scope.initialiser = root_scope
	
	local self = {
		scopes = { root_scope },
		
		global_end = 1,
		func_base = nil,
	}
	
	setmetatable(self, VarAllocator)
	
	return self
end

function VarAllocator:process_statement(statement)
	local op = statement[3]
	
	if op == "function"
	then
		local func_args       = statement[6]
		local func_statements = statement[7]
		
		local allocate_slots, initialise_slots_from, initialise_slots_to = self:process_scope(ScopeType.FUNCTION, function()
			for arg_idx, arg in ipairs(func_args)
			do
				local var_slot = self:alloc_var_slot(arg[2], statement[1], statement[2])
				arg.var_slot = var_slot
			end
			
			self:process_statements(func_statements)
		end)
		
		statement.allocate_slots = allocate_slots
		statement.initialise_slots_from = initialise_slots_from
		statement.initialise_slots_to = initialise_slots_to
		
	elseif op == "struct"
	then
		local struct_args       = statement[5]
		local struct_statements = statement[6]
		local var_decl          = statement[8]
		
		local allocate_slots, initialise_slots_from, initialise_slots_to = self:process_scope(ScopeType.FUNCTION, function()
			for arg_idx, arg in ipairs(struct_args)
			do
				local var_slot = self:alloc_var_slot(arg[2], statement[1], statement[2])
				arg.var_slot = var_slot
			end
			
			self:process_statements(struct_statements)
		end)
		
		statement.allocate_slots = allocate_slots
		statement.initialise_slots_from = initialise_slots_from
		statement.initialise_slots_to = initialise_slots_to
		
		if var_decl ~= nil
		then
			local var_name   = var_decl[1]
			local var_args   = var_decl[2]
			local array_size = var_decl[3]
			
			local var_slot = self:alloc_var_slot(var_name, statement[1], statement[2])
			statement.var_slot = var_slot
			
			if var_args ~= nil
			then
				self:process_statements(var_args)
			end
			
			self:process_optional_statement(array_size)
		end
		
	elseif op == "enum"
	then
		local members  = statement[6]
		local var_decl = statement[8]
		
		for _, member_pair in pairs(members)
		do
			local member_name, member_expr = table.unpack(member_pair)
			
			local member_slot = self:alloc_var_slot(member_name, statement[1], statement[2])
			member_pair.var_slot = member_slot
			
			self:process_optional_statement(member_expr)
		end
		
		if var_decl ~= nil
		then
			local var_name   = var_decl[1]
			local var_args   = var_decl[2]
			local array_size = var_decl[3]
			
			local var_slot = self:alloc_var_slot(var_name, statement[1], statement[2])
			statement.var_slot = var_slot
			
			if var_args ~= nil
			then
				self:process_statements(var_args)
			end
			
			self:process_optional_statement(array_size)
		end
		
	elseif op == "if"
	then
		for i = 4, #statement
		do
			local cond = statement[i][2] and statement[i][1] or nil
			local code = statement[i][2] or statement[i][1]
			
			self:process_optional_statement(cond)
			
			self:process_scope(ScopeType.TRANSPARENT, function()
				self:process_statements(code)
			end)
		end
		
	elseif op == "for"
	then
		local init_expr = statement[4]
		local cond_expr = statement[5]
		local iter_expr = statement[6]
		local body      = statement[7]
		
		local outer_allocate_slots, outer_borrow_slots_base, outer_borrow_slots_num
		local inner_allocate_slots, inner_borrow_slots_base, inner_borrow_slots_num
		
		outer_allocate_slots, outer_borrow_slots_base, outer_borrow_slots_num = self:process_scope(ScopeType.NORMAL, function()
			self:process_optional_statement(init_expr)
			self:process_optional_statement(cond_expr)
			self:process_optional_statement(iter_expr)
			
			inner_allocate_slots, inner_borrow_slots_base, inner_borrow_slots_num = self:process_scope(ScopeType.NORMAL, function()
				self:process_statements(body)
			end)
		end)
		
		statement.outer_borrow_slots_base = outer_borrow_slots_base
		statement.outer_borrow_slots_num = outer_borrow_slots_num
		
		statement.inner_borrow_slots_base = inner_borrow_slots_base
		statement.inner_borrow_slots_num = inner_borrow_slots_num
		
	elseif op == "switch"
	then
		local expr = statement[4]
		local cases = statement[5]
		
		self:process_statement(expr)
		
		for _, case in ipairs(cases)
		do
			local case_expr = case[1]
			local case_body = case[2]
			
			self:process_optional_statement(case_expr)
			
			self:process_scope(ScopeType.TRANSPARENT, function()
				self:process_statements(case_body)
			end)
		end
		
	elseif op == "block"
	then
		local allocate_slots, borrow_slots_base, borrow_slots_num = self:process_scope(ScopeType.NORMAL, function()
			self:process_statements(statement[4])
		end)
		
		statement.borrow_slots_base = borrow_slots_base
		statement.borrow_slots_num = borrow_slots_num
	elseif op == "ref"
	then
		local path = statement[4]
		
		local var_slot = self:find_var_slot(path[1], statement[1], statement[2])
		statement.var_slot = var_slot
		
		for i = 2, #path
		do
			if type(path[i]) == "table"
			then
				-- This is a statement to be evalulated and used as an array index.
				self:process_statement(path[i])
			end
		end
		
	elseif op == "variable" or op == "local-variable"
	then
		local var_name = statement[5]
		
		local var_slot = self:alloc_var_slot(var_name, statement[1], statement[2])
		statement.var_slot = var_slot
		
		util.visit_statement_children(statement, function(statement) self:process_statement(statement) end)
		
	else
		util.visit_statement_children(statement, function(statement) self:process_statement(statement) end)
	end
end

function VarAllocator:process_optional_statement(statement)
	if statement ~= nil
	then
		self:process_statement(statement)
	end
end

function VarAllocator:process_statements(statements)
	for _, statement in ipairs(statements)
	do
		self:process_statement(statement)
	end
end

function VarAllocator:process_scope(scope_type, func)
	local top = self.scopes[#self.scopes]
	
	local scope = {
		names_used = {},
		
		allocator = top.allocator,
		initialiser = top.initialiser,
	}
	
	if scope_type == ScopeType.TRANSPARENT
	then
		scope.slots = top.slots
		
	elseif scope_type == ScopeType.FUNCTION
	then
		scope.slots = { num_slots = 0 }
		
	else
		scope.slots = { num_slots = top.slots.num_slots }
	end
	
	if scope_type == ScopeType.FUNCTION
	then
		scope.allocate_slots = 0
		scope.allocator = scope
	end
	
	if scope_type == ScopeType.NORMAL
	then
		scope.initialise_slots_from = scope.slots.num_slots + 1
		scope.initialise_slots_to = scope.slots.num_slots
		
		scope.initialiser = scope
	end
	
	table.insert(self.scopes, scope)
	
	local allocate_slots = nil
	local borrow_slots_base = nil
	local borrow_slots_num = nil
	
	if scope_type == ScopeType.FUNCTION
	then
		local old_func_base = self.func_base
		self.func_base = #self.scopes
		
		func()
		
		allocate_slots = scope.allocate_slots
		
		self.func_base = old_func_base
		
	elseif self.func_base == nil
	then
		assert(self.global_end + 1 == #self.scopes)
		self.global_end = self.global_end + 1
		
		if scope_type == ScopeType.NORMAL
		then
			borrow_slots_base = scope.initialise_slots_from
		end
		
		func()
		
		if scope_type == ScopeType.NORMAL
		then
			borrow_slots_num = scope.initialise_slots_to - scope.initialise_slots_from + 1
		end
		
		self.global_end = self.global_end - 1
	else
		if scope_type == ScopeType.NORMAL
		then
			borrow_slots_base = 1 - scope.initialise_slots_from
		end
		
		func()
		
		if scope_type == ScopeType.NORMAL
		then
			borrow_slots_num = scope.initialise_slots_to - scope.initialise_slots_from + 1
		end
	end
	
	table.remove(self.scopes)
	
	return allocate_slots, borrow_slots_base, borrow_slots_num
end

function VarAllocator:find_var_slot(name, filename, line_num)
	if self.func_base ~= nil
	then
		for i = #self.scopes, self.func_base, -1
		do
			if self.scopes[i].slots[name] ~= nil
			then
				return 1 - self.scopes[i].slots[name]
			end
		end
	end
	
	for i = self.global_end, 1, -1
	do
		if self.scopes[i].slots[name] ~= nil
		then
			return self.scopes[i].slots[name]
		end
	end
	
	_template_error(context, "Attempt to use undefined variable '" .. name .. "'", filename, line_num)
end

function VarAllocator:alloc_var_slot(name, filename, line_num)
	local scope = self.scopes[#self.scopes]
	
	if scope.names_used[name] ~= nil
	then
		_template_error(context, "Attempt to redefine variable '" .. name .. "'", filename, line_num)
	end
	
	scope.names_used[name] = true
	
	if scope.slots[name] == nil
	then
		scope.slots.num_slots = scope.slots.num_slots + 1
		scope.slots[name] = scope.slots.num_slots
		
		if scope.allocator.allocate_slots < scope.slots.num_slots
		then
			scope.allocator.allocate_slots = scope.slots.num_slots
		end
		
		if scope.initialiser.initialise_slots_to < scope.slots.num_slots
		then
			scope.initialiser.initialise_slots_to = scope.slots.num_slots
		end
	end
	
	local slot = scope.slots[name]
	
	if self.func_base ~= nil
	then
		return 1 - slot
	else
		return slot
	end
end

function VarAllocator._allocate_variables(context, statements, _builtin_variables, _initialised_variable_placeholder)
	local self = VarAllocator:new()
	
	for k, v in pairs(_builtin_variables)
	do
		local var_slot = self:alloc_var_slot(k, debug.getinfo(1,'S').source, debug.getinfo(1, 'l').currentline)
		
		assert(var_slot == #context.var_stack + 1)
		table.insert(context.var_stack, v(context))
	end
	
	self:process_statements(statements)
	
	local root_scope = self.scopes[1]
	
	for i = #context.var_stack + 1, root_scope.allocate_slots
	do
		table.insert(context.var_stack, _initialised_variable_placeholder)
	end
end

return VarAllocator
