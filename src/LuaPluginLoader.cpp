#include "platform.hpp"

#include <assert.h>
#include <list>
#include <string>
#include <wx/dir.h>
#include <wx/event.h>
#include <wx/filename.h>

#include <wxlua/debugger/wxluadebugger_bind.h>
#include <wxlua/wxbind/include/wxadv_bind.h>
#include <wxlua/wxbind/include/wxaui_bind.h>
#include <wxlua/wxbind/include/wxbase_bind.h>
#include <wxlua/wxbind/include/wxbinddefs.h>
#include <wxlua/wxbind/include/wxgl_bind.h>
#include <wxlua/wxbind/include/wxhtml_bind.h>
#include <wxlua/wxbind/include/wxmedia_bind.h>
#include <wxlua/wxbind/include/wxxml_bind.h>
#include <wxlua/wxbind/include/wxxrc_bind.h>
#include <wxlua/wxbind/include/wxstc_bind.h>
#include <wxlua/wxlua.h>

#include "app.hpp"
#include "lua-bindings/rehex_bind.h"
#include "mainwindow.hpp"

static std::list<wxLuaState> states;

static void load_lua_plugins()
{
	wxDir dir("./");
	wxString filename;
	
	WXLUA_IMPLEMENT_BIND_ALL
	
	wxLuaBinding_rehex_init();
	
	if (dir.GetFirst(&filename, "*.lua", wxDIR_FILES))
	{
		do
		{
			wxFileName file_path(dir.GetName(), filename);
			
			wxEvtHandler *eh = new wxEvtHandler;
			
			eh->Bind(wxEVT_LUA_ERROR, [&](wxLuaEvent &event)
			{
				fprintf(stderr, "wxEVT_LUA_ERROR: %s\n", event.GetString().mb_str().data());
				return;
			});
			
			wxLuaState s(eh);
			int x = s.RunFile(file_path.GetFullPath());
			
			fprintf(stderr, "s.RunFile(\"%s\") returned %d\n", file_path.GetFullPath().mb_str().data(), x);
			
			if(x == 0)
			{
				states.push_back(s);
			}
			else{
				fprintf(stderr, "wxlua_LUA_ERR_msg: %s\n", wxlua_LUA_ERR_msg(x).mb_str().data());
			}
			
			int top1 = s.lua_GetTop();
			
			s.lua_GetGlobal("init");
			assert(s.lua_IsFunction(-1));
			
			x = s.LuaPCall(0 /* arguments */, 0 /* return values */);
			if(x != 0)
			{
				fprintf(stderr, "init function failed...\n");
			}
			
			/* assert(s.lua_IsBoolean(-1));
			s.lua_Pop(1); */
			
			s.lua_Pop(1);
			
			s.lua_SetTop(top1);
		} while (dir.GetNext(&filename));
	}
}

static REHex::App::SetupHookRegistration load_lua_plugins_hook(
	REHex::App::SetupPhase::READY,
	&load_lua_plugins);
