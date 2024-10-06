#include <algorithm>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>

#include "../src/App.hpp"
#include "../src/ByteAccumulator.hpp"
#include "../src/HierarchicalByteAccumulator.hpp"
#include "../src/SharedDocumentPointer.hpp"
#include "../src/ThreadPool.hpp"
#include "../src/util.hpp"

using namespace REHex;

REHex::App &wxGetApp()
{
	return *(REHex::App*)(wxTheApp);
}

static void verify_result(const std::vector<unsigned char> &reference_data, HierarchicalByteAccumulator &hba, int line_num)
{
	ByteAccumulator reference_result;
	for(size_t i = 0; i < reference_data.size(); ++i)
	{
		reference_result.add_byte(reference_data[i]);
	}
	
	hba.wait_for_completion();
	
	if(reference_result != hba.get_result())
	{
		fprintf(stderr, "Incorrect result detected at line %d!\n", line_num);
		abort();
	}
}

int main(int argc, char **argv)
{
	char line[128];
	
	if(fgets(line, sizeof(line), stdin) == NULL)
	{
		fprintf(stderr, "Unexpected end of file\n");
		return 1;
	}
	
	errno = 0;
	
	char *ifs_endp;
	unsigned long initial_file_size = strtoul(line, &ifs_endp, 10);
	
	char *ro_endp;
	long range_offset = strtol(ifs_endp, &ro_endp, 10);
	
	char *rl_endp;
	long range_length = strtol(ro_endp, &rl_endp, 10);
	
	char *ns_endp;
	unsigned long num_shards = strtoul(rl_endp, &ns_endp, 10);
	
	if(errno != 0 || *ns_endp != '\n')
	{
		fprintf(stderr, "Invalid input at line 1\n");
		return 1;
	}
	
	REHex::App *app = new REHex::App();
	
	wxApp::SetInstance(app);
	wxInitializer wxinit;
	
	app->thread_pool = new REHex::ThreadPool(8);
	
	SharedDocumentPointer document = SharedDocumentPointer::make();
	std::unique_ptr<HierarchicalByteAccumulator> hba;
	
	if(range_offset < 0)
	{
		hba.reset(new HierarchicalByteAccumulator(document, num_shards));
	}
	else{
		if((range_offset + range_length) > initial_file_size)
		{
			fprintf(stderr, "Invalid range specified at line 1\n");
			return 1;
		}
		
		hba.reset(new HierarchicalByteAccumulator(document, range_offset, range_length, num_shards));
	}
	
	std::vector<unsigned char> data(initial_file_size, 0);
	document->insert_data(0, data.data(), data.size());
	
	verify_result(data, *hba, 1);
	
	int line_num = 1;
	
	while(fgets(line, sizeof(line), stdin) != NULL)
	{
		++line_num;
		
		if(line[0] == 'O' || line[0] == 'I')
		{
			errno = 0;
			
			char *off_endp;
			unsigned long offset = strtoul((line + 1), &off_endp, 10);
			
			if(errno != 0 || *off_endp == '\0')
			{
				fprintf(stderr, "Invalid input at line %d\n", line_num);
				return 1;
			}
			
			/* skip over space */
			++off_endp;
			
			std::vector<unsigned char> line_data;
			try {
				line_data = parse_hex_string(off_endp);
			}
			catch(const ParseError &e)
			{
				fprintf(stderr, "Invalid input at line %d\n", line_num);
				return 1;
			}
			
			if(line[0] == 'O')
			{
				if((offset + line_data.size()) > data.size())
				{
					fprintf(stderr, "Attempted to overwrite past end of file at line %d\n", line_num);
					return 1;
				}
				
				memcpy((data.data() + offset), line_data.data(), line_data.size());
				document->overwrite_data(offset, line_data.data(), line_data.size());
			}
			else if(line[0] == 'I')
			{
				if(offset > data.size())
				{
					fprintf(stderr, "Attempted to insert past end of file at line %d\n", line_num);
					return 1;
				}
				
				data.insert(std::next(data.begin(), offset), line_data.begin(), line_data.end());
				document->insert_data(offset, line_data.data(), line_data.size());
			}
			
			verify_result(data, *hba, line_num);
		}
		else if(line[0] == 'E')
		{
			errno = 0;
			
			char *off_endp;
			unsigned long offset = strtoul((line + 1), &off_endp, 10);
			
			char *length_endp;
			unsigned long length = strtoul(off_endp, &length_endp, 10);
			
			if(errno != 0 || *length_endp != '\n')
			{
				fprintf(stderr, "Invalid input at line %d\n", line_num);
				return 1;
			}
			
			if((offset + length) > data.size())
			{
				fprintf(stderr, "Attempted to erase past end of file at line %d\n", line_num);
				return 1;
			}
			
			data.erase(std::next(data.begin(), offset), std::next(data.begin(), (offset + length)));
			document->erase_data(offset, length);
			
			verify_result(data, *hba, line_num);;
		}
		else{
			fprintf(stderr, "Invalid input at line %d\n", line_num);
			return 1;
		}
	}
	
	return 0;
}

bool REHex::App::OnInit()
{
	return true;
}

int REHex::App::OnExit()
{
	return 0;
}

int REHex::App::OnRun()
{
	return wxApp::OnRun();
}
