/**
 * Application entry point towards extensions
 */


#ifndef REHEX_PLUGINMANAGER_HPP
#define REHEX_PLUGINMANAGER_HPP

#include <list>
#include <memory>
#include <wx/string.h>


IPlugin* plugin_factory(REHex::SharedDocumentPointer& doc, const wxString& plugins_dir);

//struct PluginScript;

//namespace REHex
//{
//	class PluginPanel;
//}
//
//class PluginManager
//{
//private:
//	wxString plugin_dir;
//	//
//	std::list<class IPlugin*> plugins;
//
//public:
//	PluginManager(const wxString& defaultPluginsDir, class wxConfig* config);
//	~PluginManager();
//
//	REHex::PluginPanel* panel_factory(wxWindow* parent, REHex::SharedDocumentPointer& document);
//
//	IPlugin* document_opened(REHex::SharedDocumentPointer& doc);
//	void document_closed(IPlugin* plugin);
//};


#endif /* !REHEX_PLUGINMANAGER_HPP */
