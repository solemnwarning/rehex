#ifndef REHEX_TABLEJOINER_HPP
#define REHEX_TABLEJOINER_HPP

#include "Table.hpp"

namespace REHex
{
	class TableJoiner: public TableIStream
	{
		private:
			class InputTable: public TableOStream
			{
				public:
					int m_columns;
					std::list<Table::Row> m_rows;
					
					InputTable(int columns):
						m_columns(columns) {}
					
					virtual TableOStream &operator<<(const Table::Row &row) override
					{
						m_rows.push_back(row);
						return *this;
					}
			};
			
			std::list<InputTable> m_tables;
			
		public:
			TableOStream &AddTable(int columns);
			
			virtual TableIStream &operator>>(Table::Row &row) override;
	};
}

#endif /* !REHEX_TABLEJOINER_HPP */
