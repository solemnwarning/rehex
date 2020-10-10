#pragma once

class IPlugin;

namespace luaenvironment
{
	void init(sol::state& lua, IPlugin* plugin);
	void exit(sol::state& lua);
}

