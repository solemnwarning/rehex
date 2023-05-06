/* Reverse Engineer's Hex Editor
 * Copyright (C) 2023 Daniel Collins <solemnwarning@solemnwarning.net>
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

/* This is a fuzzer for the ByteRangeTree class. It doesn't do any functional tests itself,
 * instead relying on the internal sanity checks (or crashes) to shake out any inconsistencies
 * arising from particular sequences of operations.
*/

#include <list>
#include <memory>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sysexits.h>
#include <time.h>
#include <thread>
#include <unistd.h>
#include <utility>
#include <vector>

/* Enable extra sanity checks (expensive) in ByteRangeTree. */
#define REHEX_BYTERANGETREE_CHECKS

#include "../src/ByteRangeTree.hpp"

static const int MAX_RUN_SECONDS = 3600;
static const int MAX_INITIAL_SPACE = 0x40000000; /* 1GiB */
static const unsigned MIN_ELEMENTS_BEFORE_DELETE = 100;

static volatile bool stop = false;
static volatile size_t op_count = 0;

static void stop_plz(int)
{
	stop = true;
}

static void run(unsigned int seed)
{
	printf("Starting fuzz with seed %u\n", seed);
	
	int run_seconds = rand_r(&seed) % MAX_RUN_SECONDS;
	off_t current_space = rand_r(&seed) % MAX_INITIAL_SPACE;
	bool delete_enabled = false;
	
	std::unique_ptr< REHex::ByteRangeTree<int> > tree(new REHex::ByteRangeTree<int>);
	
	printf("%d seconds max time\n", run_seconds);
	
	auto random_range = [&]()
	{
		off_t begin = rand_r(&seed) % (current_space - 1);
		off_t end = begin + (rand_r(&seed) % (current_space - begin));
		
		return REHex::ByteRangeTreeKey(begin, end - begin);
	};
	
	auto random_node = [&]()
	{
		size_t idx = tree->size() >= 1
			? rand_r(&seed) % tree->size()
			: 0;
		
		return std::next(tree->begin(), idx);
	};
	
	signal(SIGALRM, &stop_plz);
	alarm(run_seconds);
	
	while(!stop)
	{
		if(tree->size() >= MIN_ELEMENTS_BEFORE_DELETE)
		{
			delete_enabled = true;
		}
		
		int op = rand_r(&seed) % 100;
		
		/* Low chance of major ops (copy/assignment/clear) */
		
		if(op == 0)
		{
			/* Test copy c'tor. */
			REHex::ByteRangeTree<int> *new_tree = new REHex::ByteRangeTree<int>(*tree);
			tree.reset(new_tree);
		}
		else if(op == 1)
		{
			/* Test copy assignment. */
			REHex::ByteRangeTree<int> *new_tree = new REHex::ByteRangeTree<int>;
			*new_tree = *tree;
			tree.reset(new_tree);
		}
		else if(op == 2)
		{
			tree->clear();
		}
		else{
			/* Distribute the remaining chance roughly equally between minor ops. */
			
			switch(op % 6)
			{
				case 0:
				case 1:
				{
					auto range = random_range();
					tree->set(range.offset, range.length, 0);
					
					break;
				}
				
				case 2:
				{
					if(tree->empty() || !delete_enabled)
					{
						break;
					}
					
					auto it = random_node();
					tree->erase(it);
					
					break;
				}
				
				case 3:
				{
					if(tree->empty() || !delete_enabled)
					{
						break;
					}
					
					auto it = random_node();
					tree->erase_recursive(it);
					
					break;
				}
				
				case 4:
				{
					auto range = random_range();
					tree->data_inserted(range.offset, range.length);
					break;
				}
				
				case 5:
				{
					auto range = random_range();
					tree->data_erased(range.offset, range.length);
					break;
				}
			}
		}
		
		++op_count;
	}
}

struct Worker
{
	pid_t pid;
	int fd;
	unsigned int seed;
};

int main(int argc, char **argv)
{
	if(argc > 2)
	{
		fprintf(stderr, "Usage: %s [<seed to run>]\n", argv[0]);
		return EX_USAGE;
	}
	
	setbuf(stdout, NULL);
	
	if(argc == 2)
	{
		unsigned int seed = strtoul(argv[1], NULL, 10);
		run(seed);
	}
	else{
		signal(SIGINT, &stop_plz);
		
		unsigned int target_workers = std::thread::hardware_concurrency();
		std::list<Worker> workers;
		
		srand(time(NULL));
		
		while(!stop)
		{
			while(workers.size() < target_workers)
			{
				unsigned int seed = rand();
				
				int pipefd[2];
				if(pipe(pipefd) != 0)
				{
					perror("pipe");
					stop = true;
					break;
				}
				
				pid_t p = fork();
				if(p < 0)
				{
					perror("fork");
					stop = true;
					break;
				}
				else if(p == 0)
				{
					dup2(pipefd[1], fileno(stdout));
					dup2(pipefd[1], fileno(stderr));
					close(pipefd[0]);
					
					run(seed);
					return 0;
				}
				else{
					close(pipefd[1]);
					
					Worker w;
					w.pid = p;
					w.fd = pipefd[0];
					w.seed = seed;
					
					workers.push_back(w);
				}
			}
			
			std::vector<struct pollfd> pfds;
			pfds.reserve(workers.size());
			
			for(auto w = workers.begin(); w != workers.end(); ++w)
			{
				struct pollfd p = { w->fd, POLLIN, 0 };
				pfds.push_back(p);
			}
			
			int p = poll(pfds.data(), pfds.size(), -1);
			if(p < 0)
			{
				perror("poll");
				break;
			}
			
			auto pfd = pfds.begin();
			auto w = workers.begin();
			
			for(; pfd != pfds.end(); ++pfd)
			{
				if(pfd->revents != 0)
				{
					char line[1024];
					int line_data = 0;
					
					do {
						p = read(pfd->fd, line + line_data, sizeof(line) - line_data);
						if(p < 0)
						{
							perror("read");
							stop = true;
							break;
						}
						else if(p == 0)
						{
							close(w->fd);
							
							int status;
							waitpid(w->pid, &status, 0);
							
							if(WIFEXITED(status))
							{
								if(WEXITSTATUS(status) == 0)
								{
									printf("\x1B[92mProcess %d (seed %u) exited with status %d\x1B[0m\n", (int)(w->pid), w->seed, (int)(WEXITSTATUS(status)));
								}
								else{
									printf("\x1B[91mProcess %d (seed %u) exited with status %d\x1B[0m\n", (int)(w->pid), w->seed, (int)(WEXITSTATUS(status)));
								}
							}
							else if(WIFSIGNALED(status))
							{
								printf("\x1B[91mProcess %d (seed %u) was killed by signal %d\x1B[0m\n", (int)(w->pid), w->seed, (int)(WTERMSIG(status)));
							}
							else{
								printf("\x1B[91mProcess %d (seed %u) died of unknown causes\x1B[0m\n", (int)(w->pid), w->seed);
							}
							
							w = workers.erase(w);
							goto NEXT_FD;
						}
						else{
							line_data += p;
							
							char *nl;
							while((nl = (char*)(memchr(line, '\n', line_data))) != NULL)
							{
								size_t line_len = nl - line;
								
								std::string l(line, line_len);
								printf("[%d] %s\n", (int)(w->pid), l.c_str());
								
								memmove(line, nl + 1, line_len);
								line_data -= line_len + 1;
							}
						}
					} while(line_data > 0);
				}
				
				++w;
				NEXT_FD:
				;
			}
		}
		
		if(workers.size() > 0)
		{
			printf("Killing remaining workers...\n");
			
			for(auto w = workers.begin(); w != workers.end(); ++w)
			{
				kill(w->pid, SIGKILL);
			}
		}
	}
	
	return 0;
}
