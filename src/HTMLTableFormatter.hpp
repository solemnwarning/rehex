#ifndef REHEX_HTMLTABLEFORMATTER_HPP
#define REHEX_HTMLTABLEFORMATTER_HPP

#include <iostream>

#include "Table.hpp"

namespace REHex
{
	class HTMLTableFormatter: public TableOStream
	{
		private:
			std::ostream &m_output;
			
		public:
			HTMLTableFormatter(std::ostream &output);
			
			virtual TableOStream &operator<<(const Table::Row &row) override;
	};
}

#endif /* !REHEX_HTMLTABLEFORMATTER_HPP */
