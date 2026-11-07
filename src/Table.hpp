#ifndef REHEX_TABLE_HPP
#define REHEX_TABLE_HPP

#include <list>
#include <stdexcept>
#include <string>

namespace REHex
{
	namespace Table
	{
		class TextFragment
		{
			private:
				std::string m_text;
				
			public:
				TextFragment(const std::string &text):
					m_text(text) {}
				
				const std::string &text() const
				{
					return m_text;
				}
		};
		
		class Cell
		{
			private:
				std::list<TextFragment> m_fragments;
				
			public:
				Cell &operator<<(const TextFragment &fragment)
				{
					m_fragments.push_back(fragment);
					return *this;
				}
				
				const std::list<TextFragment> &fragments() const
				{
					return m_fragments;
				}
		};
		
		class Row
		{
			private:
				std::list<Cell> m_cells;
				
			public:
				Row &operator<<(const Cell &cell)
				{
					m_cells.push_back(cell);
					return *this;
				}
				
				const std::list<Cell> &cells() const
				{
					return m_cells;
				}
		};
	}
	
	class TableIStream
	{
		public:
			class no_more_rows: public std::runtime_error
			{
				public:
					no_more_rows(): runtime_error("No more rows in table") {}
			};
			
			virtual TableIStream &operator>>(Table::Row &row) = 0;
	};
	
	class TableOStream
	{
		public:
			virtual TableOStream &operator<<(const Table::Row &row) = 0;
	};
}

#endif /* !REHEX_TABLE_HPP */
