/* Reverse Engineer's Hex Editor
 * Copyright (C) 2018 Daniel Collins <solemnwarning@solemnwarning.net>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#ifndef REHEX_SEARCH_HPP
#define REHEX_SEARCH_HPP

#include <string>
#include <sys/types.h>

#include "document.hpp"

namespace REHex {
	class Search {
		public:
			class Text;
			class ByteSequence;
			class Value;
			
		protected:
			REHex::Document &doc;
			
			off_t range_begin, range_end;
			off_t align_to, align_from;
			
			Search(REHex::Document &doc);
			
			virtual bool test(off_t offset, off_t max_length) = 0;
			
		public:
			void limit_range(off_t range_begin, off_t range_end);
			void require_alignment(off_t alignment, off_t relative_to_offset = 0);
			
			virtual off_t find_next(off_t from_offset);
	};
	
	class Search::Text: public Search
	{
		private:
			std::string search_for;
			bool case_sensitive;
			
		public:
			Text(REHex::Document &doc, const std::string &search_for = "", bool case_sensitive = true);
			
		protected:
			virtual bool test(off_t offset, off_t max_length);
	};
	
	class Search::ByteSequence: public Search
	{
		
	};
	
	class Search::Value: public Search
	{
		
	};
}

#endif /* !REHEX_SEARCH_HPP */
