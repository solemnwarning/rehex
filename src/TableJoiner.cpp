#include "platform.hpp"

#include "TableJoiner.hpp"

REHex::TableOStream &REHex::TableJoiner::AddTable(int columns)
{
	m_tables.emplace_back(columns);
	return m_tables.back();
}

REHex::TableIStream &REHex::TableJoiner::operator>>(Table::Row &row)
{
	Table::Row new_row;
	bool row_ok = false;
	
	for(auto t = m_tables.begin(); t != m_tables.end(); ++t)
	{
		if(!t->m_rows.empty())
		{
			// TODO: Move Cell objects
			for(auto c = t->m_rows.front().cells().begin(); c != t->m_rows.front().cells().end(); ++c)
			{
				new_row << *c;
			}
			
			for(int i = t->m_rows.front().cells().size(); i < t->m_columns; ++i)
			{
				new_row << Table::Cell();
			}
			
			t->m_rows.pop_front();
			row_ok = true;
		}
	}
	
	if(row_ok)
	{
		row = std::move(new_row);
	}
	else{
		throw TableIStream::no_more_rows();
	}
	
	return *this;
}
