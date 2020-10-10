
#include "platform.hpp"
#include "hooks.hpp"
#include "PluginInstance.hpp"
#include "PluginScript.hpp"

#include <wx/dir.h>
#include <wx/filename.h>

wxString plugins_dir;
int first_plugin_id = 0;
std::vector<PluginScript> plugin_scripts;


void plugin_hooks::init(const wxString& defaultPluginsDir, wxConfig* config)
{
	config->SetPath("/");
	plugins_dir = config->Read("plugin-dir", defaultPluginsDir);
}

void plugin_hooks::exit()
{
	plugin_scripts.clear();
}


bool plugin_hooks::update_menu(wxMenu* plugins_menu, int first_id, int last_id)
{
	wxDir dir(plugins_dir);
	wxString filename;

	int next_id = first_id;
	first_plugin_id = first_id;

	if (dir.GetFirst(&filename, "*.lua", wxDIR_FILES))
	{
		do
		{
			wxFileName fullpath(dir.GetName(), filename);
			// Create a script descriptor with a fresh environment, and the name / filename of a script
			plugin_scripts.push_back(PluginScript{ fullpath.GetName(), fullpath.GetFullPath() });

			plugins_menu->Append(next_id++, plugin_scripts.back().Name);
		} while (dir.GetNext(&filename));
	}

	return next_id != first_id;
}

ITabPlugin* plugin_hooks::tab_opened(REHex::Tab* tab, REHex::SharedDocumentPointer& doc)
{
	return plugin_tab_factory(tab, doc, plugin_scripts);
}

IPlugin* plugin_hooks::activated_menu(ITabPlugin* tab, int command_id)
{
	if (tab)
	{
		assert(command_id >= first_plugin_id);
		if (command_id >= first_plugin_id)
		{
			command_id -= first_plugin_id;

			assert(command_id < plugin_scripts.size());
			if (command_id < plugin_scripts.size())
			{
				return tab->activated_menu(plugin_scripts[command_id].Name);
			}
		}
	}
	return nullptr;
}

