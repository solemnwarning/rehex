/* gtest-multi - Execute Google Test tests in parallel
 * Copyright (C) 2026 Daniel Collins <solemnwarning@solemnwarning.net>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 *   Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 *   Neither the name of the copyright holder nor the names of its contributors
 *   may be used to endorse or promote products derived from this software
 *   without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#ifdef _WIN32
#include <Windows.h>
#endif

#include <assert.h>
#include <errno.h>
#include <stdexcept>
#include <stdio.h>
#include <string>
#include <string.h>
#include <thread>
#include <vector>

#ifndef _WIN32
#include <fcntl.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#ifndef _WIN32
class Pipe
{
public:
	Pipe();
	~Pipe();

	int read_fd() const;
	int release_read();
	void close_read();

	int write_fd() const;
	int release_write();
	void close_write();

private:
	int m_pipefd[2];
};
#endif

class TestRunner
{
public:
	static int run_tests(const std::string &test_exe, const std::vector<std::string> &test_names, unsigned int max_jobs);
	TestRunner(const std::string &test_exe, const std::string &test_name);
	
private:
	std::string test_exe;
	std::string test_name;

#ifdef _WIN32
	HANDLE output_pipe;
	HANDLE process;
	DWORD pid;

#else
	int stdout_fileno;
	std::string stdout_pending;
	
	int stderr_fileno;
	std::string stderr_pending;
	
	pid_t pid;
#endif
	
	static std::vector<TestRunner> g_runners;
	static int g_exit_code;
	
	static void process_tests();
	static bool read_output(TestRunner *runner, int pipefd, std::string *pending);
	static void finalise(TestRunner *runner);
};

std::vector<TestRunner> TestRunner::g_runners;
int TestRunner::g_exit_code;

static void print_usage(const char *argv0, FILE *fh);
static std::vector<std::string> discover_tests(const char *test_exe, const char *gtest_filter);

int main(int argc, char **argv)
{
	unsigned int max_jobs = 0;
	
	const char *test_exe = NULL;
	const char *gtest_filter = NULL;
	bool process_switches = true;
	
	for(int i = 1; i < argc; ++i)
	{
		if(argv[i][0] == '-' && process_switches)
		{
			if(strcmp(argv[i], "--") == 0)
			{
				process_switches = false;
			}
			else if(strcmp(argv[i], "-j") == 0 && (i + 1) < argc)
			{
				max_jobs = strtoul(argv[i + 1], NULL, 10);
				++i;
			}
			else if(strncmp(argv[i], "--gtest_filter=", strlen("--gtest_filter=")) == 0)
			{
				gtest_filter = argv[i] + strlen("--gtest_filter=");
			}
			else if(strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0)
			{
				print_usage(argv[0], stdout);
				return 0;
			}
			else{
				print_usage(argv[0], stderr);
				return 1;
			}
		}
		else if(test_exe == NULL)
		{
			test_exe = argv[i];
		}
		else{
			print_usage(argv[0], stderr);
			return 1;
		}
	}
	
	if(max_jobs == 0)
	{
		max_jobs = std::thread::hardware_concurrency();
		if(max_jobs == 0)
		{
			fprintf(stderr, "Unable to determine number of available CPUs, tests will not run in parallel\n");
			max_jobs = 1;
		}
	}
	
	std::vector<std::string> tests = discover_tests(test_exe, gtest_filter);
	
	return TestRunner::run_tests(test_exe, tests, max_jobs);
}

static void print_usage(const char *argv0, FILE *fh)
{
	fprintf(fh, "Usage: %s [-j <num>] [--gtest_filter=<filter>] <test executable>\n", argv0);
}

static std::vector<std::string> discover_tests(const char *test_exe, const char *gtest_filter)
{
	std::vector<std::string> tests;
	
	FILE *stdout_stream;
	
	#ifdef _WIN32
	std::string cmd = std::string("\"") + test_exe + "\" --gtest_list_tests";
	
	if(gtest_filter != NULL)
	{
		cmd += " --gtest_filter=";
		cmd += gtest_filter;
	}
	
	stdout_stream = _popen(cmd.c_str(), "rb");
	if(stdout_stream == NULL)
	{
		fprintf(stderr, "%s: %s\n", test_exe, strerror(errno));
		exit(1);
	}
	#else
	int stdout_pipe[2];
	if(pipe(stdout_pipe) != 0)
	{
		perror("pipe");
		exit(1);
	}
	
	pid_t pid = fork();
	if(pid < 0)
	{
		perror("fork");
		exit(1);
	}
	else if(pid == 0)
	{
		/* Child process. */
		
		close(stdout_pipe[0]);
		stdout_pipe[0] = -1;
		
		int devnull = open("/dev/null", O_RDONLY);
		
		if(dup2(devnull, STDIN_FILENO) < 0 || dup2(stdout_pipe[1], STDOUT_FILENO) < 0)
		{
			perror("dup2");
			exit(1);
		}
		
		close(devnull);
		close(stdout_pipe[1]);
		
		std::vector<char*> gtest_argv = { strdup(test_exe), strdup("--gtest_list_tests") };
		
		if(gtest_filter != NULL)
		{
			gtest_argv.emplace_back(strdup((std::string("--gtest_filter=") + gtest_filter).c_str()));
		}
		
		gtest_argv.emplace_back(nullptr);
		
		execvp(test_exe, gtest_argv.data());
		perror(test_exe);
		
		exit(1);
	}
	else{
		/* Parent process. */
		
		close(stdout_pipe[1]);
		stdout_pipe[1] = -1;
		
		stdout_stream = fdopen(stdout_pipe[0], "r");
		if(stdout_stream == NULL)
		{
			perror("fdopen");
			exit(1);
		}
		
		stdout_pipe[0] = -1;
	}
	#endif
	
	char line[1024];
	std::string group;
	
	while(fgets(line, sizeof(line), stdout_stream))
	{
		int len = strlen(line);
		if(line[len - 1] == '\n')
		{
			line[--len] = '\0';
		}
		if(line[len - 1] == '\r')
		{
			line[--len] = '\0';
		}
		
		if(isalnum(line[0]) && line[len - 1] == '.')
		{
			group = std::string(line, (len - 1));
		}
		else if(line[0] == ' ' && isalpha(line[strspn(line, " ")]))
		{
			tests.emplace_back(group + "." + (line + strspn(line, " ")));
		}
		else{
			fprintf(stderr, "Unexpected line '%s' read from %s --gtest_list_tests\n", line, test_exe);
		}
	}
	
	if(ferror(stdout_stream))
	{
		perror("read");
		exit(1);
	}
	
	#ifdef _WIN32
	int status = _pclose(stdout_stream);
	if(status < 0)
	{
		fprintf(stderr, "Unexpected error: %s\n", strerror(errno));
	}
	else if(status > 0)
	{
		fprintf(stderr, "%s --gtest_list_tests exited with status %d\n", test_exe, status);
		exit(1);
	}
	
	#else
	
	fclose(stdout_stream);
	
	int status;
	if(waitpid(pid, &status, 0) != pid)
	{
		perror("waitpid");
		exit(1);
	}
	
	if(status != 0)
	{
		fprintf(stderr, "Unexpected exit status from text executable: %d\n", status);
		exit(1);
	}
	#endif
	
	return tests;
}

#ifdef _WIN32
TestRunner::TestRunner(const std::string &test_exe, const std::string &test_name) :
	test_exe(test_exe),
	test_name(test_name)
{
	HANDLE output_wpipe;

	SECURITY_ATTRIBUTES pipe_sa;
	pipe_sa.nLength = sizeof(pipe_sa);
	pipe_sa.bInheritHandle = TRUE;
	pipe_sa.lpSecurityDescriptor = NULL;

	if(CreatePipe(&output_pipe, &output_wpipe, &pipe_sa, 1024 * 1024 * 4) == FALSE)
	{
		throw std::runtime_error("CreatePipe");// TODO
	}

	/* Prevent test runner from inheriting the read end of the output pipe. */
	SetHandleInformation(output_pipe, HANDLE_FLAG_INHERIT, 0);

	std::string cmd = std::string("\"") + test_exe + "\" --gtest_filter=" + test_name;

	STARTUPINFO si;
	memset(&si, 0, sizeof(si));

	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
	si.hStdOutput = output_wpipe;
	si.hStdError = output_wpipe;

	PROCESS_INFORMATION pi;

	//printf("Launching test runner for %s\n", test_name.c_str());

	if(CreateProcess(NULL, (char*)(cmd.c_str()), NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi) == FALSE)
	{
		CloseHandle(output_wpipe);
		CloseHandle(output_pipe);

		throw std::runtime_error("CreateProcess"); // TODO
	}

	CloseHandle(output_wpipe);
	CloseHandle(pi.hThread);

	process = pi.hProcess;
	pid = pi.dwProcessId;
}
#else
TestRunner::TestRunner(const std::string &test_exe, const std::string &test_name):
	test_exe(test_exe),
	test_name(test_name)
{
	Pipe stdout_pipe, stderr_pipe;
	
	pid = fork();
	if(pid < 0)
	{
		int fork_err = errno;
		throw std::runtime_error(std::string("pipe: ") + strerror(fork_err));
	}
	else if(pid == 0)
	{
		int devnull = open("/dev/null", O_RDONLY);
		if(devnull == -1)
		{
			perror("/dev/null");
			exit(1);
		}
		
		stderr_pipe.close_read();
		stdout_pipe.close_read();
		
		if(dup2(devnull, STDIN_FILENO) < 0 || dup2(stdout_pipe.write_fd(), STDOUT_FILENO) < 0 || dup2(stderr_pipe.write_fd(), STDERR_FILENO) < 0)
		{
			perror("dup2");
			exit(1);
		}
		
		stderr_pipe.close_write();
		stdout_pipe.close_write();
		close(devnull);
		
		execlp(test_exe.c_str(), test_exe.c_str(), ("--gtest_filter=" + test_name).c_str(), NULL);
		perror(test_exe.c_str());
		
		exit(1);
	}
	
	stdout_pipe.close_write();
	stderr_pipe.close_write();
	
	stdout_fileno = stdout_pipe.release_read();
	stderr_fileno = stderr_pipe.release_read();
}
#endif

int TestRunner::run_tests(const std::string &test_exe, const std::vector<std::string> &test_names, unsigned int max_jobs)
{
	assert(g_runners.empty());
	g_exit_code = 0;
	
	size_t next_test = 0;
	
	while(next_test < test_names.size() || g_runners.size() > 0)
	{
		while(next_test < test_names.size() && g_runners.size() < max_jobs)
		{
			/* Spawn another test. */
			
			std::string filter = test_names[next_test];
			++next_test;
			
			for(int i = 1; i < 8 && next_test < test_names.size(); ++i)
			{
				filter += ":";
				filter += test_names[i];
				++next_test;
			}
			
			g_runners.emplace_back(test_exe, filter);
		}
		
		process_tests();
	}
	
	return g_exit_code;
}

#ifdef _WIN32
void TestRunner::process_tests()
{
	/* TODO: Figure out a way to stream output from the tests like we do on UNIX otherwise
	 * tests will hang if/when they fill up the 4MiB pipe buffer.
	*/

	std::vector<HANDLE> process_handles;
	process_handles.reserve(g_runners.size());

	for(auto i = g_runners.begin(); i != g_runners.end(); ++i)
	{
		process_handles.emplace_back(i->process);
	}

	DWORD wait_result = WaitForMultipleObjects(process_handles.size(), process_handles.data(), FALSE, INFINITE);
	if(wait_result == WAIT_FAILED)
	{
		abort(); // TODO
	}

	DWORD runner_idx = wait_result - WAIT_OBJECT_0;
	TestRunner *runner = &(g_runners[runner_idx]);

	std::string output;

	while(true)
	{
		static std::vector<char> readbuf(4096);
		DWORD numbytes;
		
		if(ReadFile(runner->output_pipe, readbuf.data(), readbuf.size(), &numbytes, NULL) == FALSE)
		{
			DWORD err = GetLastError();

			if(err == ERROR_BROKEN_PIPE)
			{
				break;
			}
			else {
				abort(); // TODO
			}
		}

		output += std::string(readbuf.data(), numbytes);
	}

	for(size_t i = 0; i < output.length();)
	{
		size_t next_break = output.find('\n', i);
		if(next_break == std::string::npos)
		{
			next_break = output.length();
		}

		size_t line_end = next_break;
		if(line_end > i && output[line_end - 1] == '\r')
		{
			--line_end;
		}

		printf("[%u] %s\n", (unsigned)(runner->pid), output.substr(i, (line_end - i)).c_str());

		i = next_break + 1;
	}

	DWORD exit_code;
	if(GetExitCodeProcess(runner->process, &exit_code) == FALSE)
	{
		abort(); // TODO
	}

	if(exit_code != 0)
	{
		printf("[%u] Test process exited with status %u\n", (unsigned)(runner->pid), (unsigned)(exit_code));

		if(g_exit_code == 0)
		{
			g_exit_code = exit_code;
		}
	}

	CloseHandle(runner->output_pipe);
	CloseHandle(runner->process);

	g_runners.erase(std::next(g_runners.begin(), runner_idx));
}
#else
void TestRunner::process_tests()
{
	std::vector<struct pollfd> pfds;
	pfds.reserve(g_runners.size() * 2);
	
	for(auto i = g_runners.begin(); i != g_runners.end(); ++i)
	{
		if(i->stdout_fileno >= 0)
		{
			struct pollfd stdout_pfd;
			stdout_pfd.fd = i->stdout_fileno;
			stdout_pfd.events = POLLIN;
			
			pfds.emplace_back(stdout_pfd);
		}
		
		if(i->stderr_fileno >= 0)
		{
			struct pollfd stderr_pfd;
			stderr_pfd.fd = i->stderr_fileno;
			stderr_pfd.events = POLLIN;
			
			pfds.emplace_back(stderr_pfd);
		}
	}
	
	int poll_result = poll(pfds.data(), pfds.size(), -1);
	if(poll_result < 0)
	{
		perror("poll");
		exit(1);
	}
	
	int next_pfd = 0;
	auto next_runner = g_runners.begin();
	
	for(int n = 0; n < poll_result; ++next_pfd)
	{
		assert(next_runner != g_runners.end());
		assert(next_pfd < pfds.size());
		
		assert(pfds[next_pfd].fd == next_runner->stdout_fileno || pfds[next_pfd].fd == next_runner->stderr_fileno);
		
		if(pfds[next_pfd].fd == next_runner->stdout_fileno)
		{
			if(pfds[next_pfd].revents != 0)
			{
				bool stdout_finished = read_output(&(*next_runner), next_runner->stdout_fileno, &(next_runner->stdout_pending));
				if(stdout_finished)
				{
					close(next_runner->stdout_fileno);
					next_runner->stdout_fileno = -1;
					
					if(next_runner->stderr_fileno < 0)
					{
						/* stderr is already closed, finalise runner. */
						
						finalise(&(*next_runner));
						next_runner = g_runners.erase(next_runner);
					}
				}
				else{
					if(next_runner->stderr_fileno < 0)
					{
						/* stderr is already closed, advance to next runner. */
						++next_runner;
					}
				}
			}
			else{
				if(next_runner->stderr_fileno < 0)
				{
					/* stderr is already closed, advance to next runner. */
					++next_runner;
				}
			}
		}
		else if(pfds[next_pfd].fd == next_runner->stderr_fileno)
		{
			if(pfds[next_pfd].revents != 0)
			{
				bool stderr_finished = read_output(&(*next_runner), next_runner->stderr_fileno, &(next_runner->stderr_pending));
				if(stderr_finished)
				{
					close(next_runner->stderr_fileno);
					next_runner->stderr_fileno = -1;
					
					if(next_runner->stdout_fileno < 0)
					{
						/* stdout is already closed, finalise runner. */
						
						finalise(&(*next_runner));
						next_runner = g_runners.erase(next_runner);
					}
					else{
						++next_runner;
					}
				}
				else{
					++next_runner;
				}
			}
			else{
				++next_runner;
			}
		}
		
		if(pfds[next_pfd].revents != 0)
		{
			++n;
		}
	}
}

bool TestRunner::read_output(TestRunner *runner, int pipefd, std::string *pending)
{
	static std::vector<char> readbuf(4096);
	
	int read_result = read(pipefd, readbuf.data(), readbuf.size());
	if(read_result <= 0)
	{
		if(read_result < 0)
		{
			perror("read");
		}
		
		if(!(pending->empty()))
		{
			printf("[%d] %s\n", (int)(runner->pid), pending->c_str());
			pending->clear();
		}
		
		return true;
	}
	else{
		*pending += std::string(readbuf.data(), read_result);
		
		size_t next_break;
		while((next_break = pending->find('\n')) != std::string::npos)
		{
			size_t line_len = next_break;
			if(line_len > 0 && (*pending)[line_len - 1] == '\r')
			{
				--line_len;
			}
			
			printf("[%d] %s\n", (int)(runner->pid), pending->substr(0, line_len).c_str());
			pending->erase(0, (next_break + 1));
		}
		
		return false;
	}
}

void TestRunner::finalise(TestRunner *runner)
{
	int status;
	int waitpid_result = waitpid(runner->pid, &status, 0);
	
	if(waitpid_result < 0)
	{
		perror("waitpid");
		
		if(g_exit_code == 0)
		{
			g_exit_code = 1;
		}
		
		return;
	}
	
	if(WIFEXITED(status))
	{
		int exit_code = WEXITSTATUS(status);
		
		if(exit_code != 0)
		{
			fprintf(stderr, "[%d] Test process exited with status %d\n", (int)(runner->pid), exit_code);
			
			if(g_exit_code == 0)
			{
				g_exit_code = exit_code;
			}
		}
	}
	else if(WIFSIGNALED(status))
	{
		int exit_signal = WTERMSIG(status);
		
		fprintf(stderr, "[%d] Test process terminated by signal %d\n", (int)(runner->pid), exit_signal);
		
		if(g_exit_code == 0)
		{
			g_exit_code = 1;
		}
	}
	else{
		fprintf(stderr, "[%d] Test process exited with unknown status %d\n", (int)(runner->pid), status);
		
		if(g_exit_code != 0)
		{
			g_exit_code = 1;
		}
	}
}
#endif

#ifndef _WIN32
Pipe::Pipe()
{
	if(pipe(m_pipefd) != 0)
	{
		char error[128];
		snprintf(error, sizeof(error), "pipe: %s", strerror(errno));
		
		throw std::runtime_error(error);
	}
}

Pipe::~Pipe()
{
	if(m_pipefd[1] >= 0)
	{
		close(m_pipefd[1]);
	}
	
	if(m_pipefd[0] >= 0)
	{
		close(m_pipefd[0]);
	}
}

int Pipe::read_fd() const
{
	return m_pipefd[0];
}

int Pipe::release_read()
{
	assert(m_pipefd[0] >= 0);
	
	int fd = m_pipefd[0];
	m_pipefd[0] = -1;
	
	return fd;
}

void Pipe::close_read()
{
	assert(m_pipefd[0] >= 0);
	
	if(m_pipefd[0] >= 0)
	{
		close(m_pipefd[0]);
		m_pipefd[0] = -1;
	}
}

int Pipe::write_fd() const
{
	return m_pipefd[1];
}

int Pipe::release_write()
{
	assert(m_pipefd[1] >= 0);
	
	int fd = m_pipefd[1];
	m_pipefd[1] = -1;
	
	return fd;
}

void Pipe::close_write()
{
	assert(m_pipefd[1] >= 0);
	
	if(m_pipefd[1] >= 0)
	{
		close(m_pipefd[1]);
		m_pipefd[1] = -1;
	}
}
#endif
