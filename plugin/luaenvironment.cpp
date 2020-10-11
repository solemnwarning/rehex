
#include "platform.hpp"

#include "luaenvironment.hpp"
#include "hooks.hpp"


// modeled after luaB_print
void lua_print(sol::this_state s, sol::variadic_args va, IPlugin* plugin)
{
	sol::state_view lua(s);
	std::stringstream ss;

	for (auto arg : va)
	{
		if (arg.stack_index() != va.stack_index())
		{
			ss << "\t";
		}

		if (arg.is<std::string>())
		{
			ss << arg.as<std::string>();
		}
		else
		{
			std::string str = lua["tostring"](arg.get<sol::object>());
			ss << str;
		}
	}
	ss << std::endl;

	plugin_hooks::log(plugin, ss.str());
}

std::string lua_read_data(REHex::Document* doc, sol::this_state s, sol::variadic_args va)
{
	std::string result;

	for (auto arg : va)
	{
		if (arg.is<std::string>())
		{
			std::string cmd = arg.as<std::string>();
			if ((cmd.length() > 1 && cmd[0] == '*' && cmd[1] == 'a') ||
				cmd.length() > 0 && cmd[0] == 'a')
			{
				// all
				std::vector<unsigned char> data = doc->read_data(0, doc->buffer_length());
				result.assign((char*)data.data(), data.size());
				return result;
			}
			else
			{
				assert(false);
				__debugbreak();
			}
		}
		else
		{
			assert(false);
			__debugbreak();
		}
	}

	return std::string();
}

void luaenvironment::initvm(sol::state& lua)
{
	lua.open_libraries(
		sol::lib::base,		// print, assert, and other base functions
		sol::lib::package,	// require and other package functions
		sol::lib::string,	// string library
		sol::lib::table,	// the table manipulator and observer functions
		sol::lib::utf8		//
	);

	// Register a document
	lua.new_usertype<REHex::Document>("Document",
		"get_title", &REHex::Document::get_title,
		"get_filename", &REHex::Document::get_filename,

		"is_dirty", &REHex::Document::is_dirty,

		"buffer_length", &REHex::Document::buffer_length,

		"read_data", &lua_read_data

	);
}


void luaenvironment::exitvm(sol::state& lua)
{
//	lua.collect_garbage();
}

void luaenvironment::initenv(sol::environment& env, IPlugin* plugin)
{
	// Register a plugin specific print function
	env.set_function("print",
		[plugin](sol::this_state s, sol::variadic_args va)
		{
			lua_print(s, va, plugin);
		});
}

void luaenvironment::exitenv(sol::environment& env)
{
	// Clean out this environment
	env = sol::environment();
}

