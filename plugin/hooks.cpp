
#include "platform.hpp"

#include "hooks.hpp"
#include "PluginInstance.hpp"


wxString plugins_dir;

void plugin_hooks::init(const wxString& defaultPluginsDir, wxConfig* config)
{
	config->SetPath("/");
	plugins_dir = config->Read("plugin-dir", defaultPluginsDir);
}

void plugin_hooks::exit()
{
}

IPlugin* plugin_hooks::document_opened(REHex::SharedDocumentPointer& doc)
{
	return plugin_factory(doc, plugins_dir);
}

