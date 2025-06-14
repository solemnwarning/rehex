-- stable sorting routines for lua
--
--	modifies the global table namespace so you don't have
--	to re-require it everywhere.
--
--		table.stable_sort
--			a fast stable sort
--		table.unstable_sort
--			alias for the builtin unstable table.sort
--		table.insertion_sort
--			an insertion sort, should you prefer it
--

--this is based on MIT licensed code from Dirk Laurie and Steve Fisher
--license as follows:

--[[
	Copyright © 2013 Dirk Laurie and Steve Fisher.

	Permission is hereby granted, free of charge, to any person obtaining a
	copy of this software and associated documentation files (the "Software"),
	to deal in the Software without restriction, including without limitation
	the rights to use, copy, modify, merge, publish, distribute, sublicense,
	and/or sell copies of the Software, and to permit persons to whom the
	Software is furnished to do so, subject to the following conditions:

	The above copyright notice and this permission notice shall be included in
	all copies or substantial portions of the Software.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
	FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
	DEALINGS IN THE SOFTWARE.
]]

-- (modifications by Max Cahill 2018)

local _sort_core = {}

--tunable size for
_sort_core.max_chunk_size = 24

function _sort_core.insertion_sort_impl( array, first, last, less )
	for i = first + 1, last do
		local k = first
		local v = array[i]
		for j = i, first + 1, -1 do
			if less( v, array[j-1] ) then
				array[j] = array[j-1]
			else
				k = j
				break
			end
		end
		array[k] = v
	end
end

function _sort_core.merge( array, workspace, low, middle, high, less )
	local i, j, k
	i = 1
	-- copy first half of array to auxiliary array
	for j = low, middle do
		workspace[ i ] = array[ j ]
		i = i + 1
	end
	-- sieve through
	i = 1
	j = middle + 1
	k = low
	while true do
		if (k >= j) or (j > high) then
			break
		end
		if less( array[ j ], workspace[ i ] )  then
			array[ k ] = array[ j ]
			j = j + 1
		else
			array[ k ] = workspace[ i ]
			i = i + 1
		end
		k = k + 1
	end
	-- copy back any remaining elements of first half
	for k = k, j-1 do
		array[ k ] = workspace[ i ]
		i = i + 1
	end
end


function _sort_core.merge_sort_impl(array, workspace, low, high, less)
	if high - low <= _sort_core.max_chunk_size then
		_sort_core.insertion_sort_impl( array, low, high, less )
	else
		local middle = math.floor((low + high)/2)
		_sort_core.merge_sort_impl( array, workspace, low, middle, less )
		_sort_core.merge_sort_impl( array, workspace, middle + 1, high, less )
		_sort_core.merge( array, workspace, low, middle, high, less )
	end
end

--inline common setup stuff
function _sort_core.sort_setup(array, less)
	local n = #array
	local trivial = false
	--trivial cases; empty or 1 element
	if n <= 1 then
		trivial = true
	else
		--default less
		less = less or function (a, b)
			return a < b
		end
		--check less
		if less(array[1], array[1]) then
		  error("invalid order function for sorting")
		end
	end
	--setup complete
	return trivial, n, less
end

function _sort_core.stable_sort(array, less)
	--setup
	local trivial, n, less = _sort_core.sort_setup(array, less)
	if not trivial then
		--temp storage
		local workspace = {}
		workspace[ math.floor( (n+1)/2 ) ] = array[1]
		--dive in
		_sort_core.merge_sort_impl( array, workspace, 1, n, less )
	end
	return array
end

function _sort_core.insertion_sort(array, less)
	--setup
	local trivial, n, less = _sort_core.sort_setup(array, less)
	if not trivial then
		_sort_core.insertion_sort_impl(array, 1, n, less)
	end
	return array
end

--export sort core
table.insertion_sort = _sort_core.insertion_sort
table.stable_sort = _sort_core.stable_sort
table.unstable_sort = table.sort
