/**
 * Application entry point towards extensions
 */


#ifndef REHEX_PLUGIN_HOOKS_HPP
#define REHEX_PLUGIN_HOOKS_HPP

#include <vector>
#include <wx/string.h>

//class IPlugin
//{
//public:
//	virtual ~IPlugin() { ; }
//
//	virtual void init(const wxString& program) = 0;
//	virtual void exit() = 0;
//};

#ifndef REHEX_DISABLE_PLUGINS

namespace plugin_hooks
{
	void init(const wxString& program);
	void exit();

	//void document_opened(...);
	//void document_closed(...);


	// PluginPanel.cpp
	void log(const wxString& output);
}

#else

namespace plugin_hooks
{
	inline void init(const wxString&) { ; }
	inline void exit() { ; }
	void log(const wxString&) { ; }
}


#endif


#endif /* !REHEX_PLUGIN_HOOKS_HPP */
