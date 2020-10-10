/**
 * Application entry point towards extensions
 */


#ifndef REHEX_PLUGIN_HOOKS_HPP
#define REHEX_PLUGIN_HOOKS_HPP


#ifndef REHEX_DISABLE_PLUGINS

#include <wx/string.h>
#include <wx/config.h>
#include "../src/SharedDocumentPointer.hpp"


/// <summary>
/// Communication object for plugins
/// Destroy it before the document is going away, so plugins can shut down
/// </summary>
class IPlugin
{
public:

	virtual ~IPlugin() { ; }

	virtual void document_initialized() = 0;

	virtual void log(const wxString& output) = 0;
};


namespace plugin_hooks
{
	void init(const wxString& defaultPluginsDir, wxConfig* config);
	void exit();

	/// <summary>
	/// Notifies the plugin system of a new document being opened
	/// </summary>
	/// <param name="doc">The document pointer that can be used by plugins</param>
	/// <returns>A new IPlugin instance that can be used to communicate with the plugins</returns>
	IPlugin* document_opened(REHex::SharedDocumentPointer& doc);
	//void document_closed(REHex::SharedDocumentPointer& doc);


	inline void document_initialized(IPlugin* plugin)
	{
		if (plugin)
			plugin->document_initialized();
	}


	inline void log(IPlugin* plugin, const wxString& output)
	{
		if (plugin)
			plugin->log(output);
	}
}

#else

namespace plugin_hooks
{
	inline void init(...) { ; }
	inline void exit(...) { ; }
	void log(...) { ; }
}


#endif


#endif /* !REHEX_PLUGIN_HOOKS_HPP */
