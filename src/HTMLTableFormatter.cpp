#include "platform.hpp"

#include "HTMLTableFormatter.hpp"

REHex::HTMLTableFormatter::HTMLTableFormatter(std::ostream &output):
	m_output(output) {}

REHex::TableOStream &REHex::HTMLTableFormatter::operator<<(const Table::Row &row)
{
	m_output << "<tr>";
	
	for(auto c = row.cells().begin(); c != row.cells().end(); ++c)
	{
		m_output << "<td>";
		
		for(auto f = c->fragments().begin(); f != c->fragments().end(); ++f)
		{
			for(auto ch = f->text().begin(); ch != f->text().end(); ++ch)
			{
				switch(*ch)
				{
					case '<':
						m_output << "&lt;";
						break;
						
					case '>':
						m_output << "&gt;";
						break;
						
					case '&':
						m_output << "&amp;";
						break;
						
					case ' ':
						m_output << "&nbsp;";
						break;
						
					default:
						m_output << *ch;
						break;
				}
			}
		}
		
		m_output << "</td>";
	}
	
	m_output << "</tr>\n";
	
	return *this;
}
