
#include "platform.hpp"

#define SOL_ALL_SAFETIES_ON 1
#include <sol/sol.hpp>

#include "luaenvironment.hpp"
#include "hooks.hpp"


// modeled after luaB_print
void lua_print(sol::this_state s, sol::variadic_args va)
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
	plugin_hooks::log(ss.str());
}

void register_lua(sol::state& lua)
{
	lua.open_libraries(
		sol::lib::base,		// print, assert, and other base functions
		sol::lib::package,	// require and other package functions
		sol::lib::string,	// string library
		sol::lib::table		// the table manipulator and observer functions
	);

	// Replace the print function
	lua.set_function("print", lua_print);
}


void luaenvironment::init(const wxString& program)
{
	sol::state lua;

	register_lua(lua);

	lua.script("print('Hello', 'from lua!')");
}


void luaenvironment::exit()
{
}
