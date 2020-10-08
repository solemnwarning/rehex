
#include "platform.hpp"

#include "hooks.hpp"
#include "luaenvironment.hpp"


void plugin_hooks::init(const wxString& program)
{
	luaenvironment::init(program);

	log("Initializing plugins:");
}


void plugin_hooks::exit()
{
	luaenvironment::exit();
}
