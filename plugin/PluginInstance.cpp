
#include "platform.hpp"

#include "hooks.hpp"

#include <wx/dir.h>
#include <wx/filename.h>

#include <sol/sol.hpp>
#include "luaenvironment.hpp"

#include "PluginInstance.hpp"
#include "PluginPanel.hpp"

std::list<class PluginInstance*> plugins;

struct PluginScript
{
	wxString Name;
	wxString Filename;

	sol::environment Env;
};

class PluginInstance: public IPlugin
{
	REHex::PluginPanel* panel;
	REHex::SharedDocumentPointer doc;

	std::list<std::unique_ptr<PluginScript>> plugin_scripts;
	sol::state lua;

public:
	PluginInstance(REHex::SharedDocumentPointer& docptr)
		:panel(nullptr)
		,doc(docptr)
	{
	}

	~PluginInstance()
	{
		// Ensure we can no longer be referenced
		plugins.remove(this);

		// Stop all scripts
		plugin_scripts.clear();

		// Cleanup the lua environment
		luaenvironment::exit(lua);
	}

	REHex::PluginPanel* create(wxWindow* parent, REHex::SharedDocumentPointer& document)
	{
		if (doc == document)
		{
			panel = new REHex::PluginPanel(parent);
			return panel;
		}
		return nullptr;
	}

	void load_scripts(const wxString& plugins_dir)
	{
		// Initialize a default lua environment
		luaenvironment::init(lua, this);

		wxDir dir(plugins_dir);
		wxString filename;

		if (dir.GetFirst(&filename, "*.lua", wxDIR_FILES))
		{
			do
			{
				wxFileName fullpath(dir.GetName(), filename);
				// Create a script descriptor with a fresh environment, and the name / filename of a script
				auto script = new PluginScript{ fullpath.GetName(), fullpath.GetFullPath(), sol::environment(lua, sol::create, lua.globals()) };
				plugin_scripts.push_back(std::unique_ptr<PluginScript>(script));
			} while (dir.GetNext(&filename));
		}
	}

	virtual void document_initialized() override
	{
		for (auto& script : plugin_scripts)
		{
			auto result = lua.safe_script_file(script->Filename, script->Env, sol::script_pass_on_error);
			if (!result.valid())
			{
				sol::error err = result;
				log(err.what());
				continue;
			}

			sol::protected_function test = script->Env["test"];
			if (test)
			{
				result = test("testarg");
				if (!result.valid())
				{
					sol::error err = result;
					log(err.what());
				}
			}
		}
	}

	virtual void log(const wxString& output) override
	{
		assert(panel);
		panel->log(output);
	}
};


IPlugin* plugin_factory(REHex::SharedDocumentPointer& doc, const wxString& plugins_dir)
{
	auto plugin = new PluginInstance(doc);
	plugins.push_back(plugin);

	plugin->load_scripts(plugins_dir);

	return plugin;
}



static REHex::ToolPanel* PluginPanel_factory(wxWindow* parent, REHex::SharedDocumentPointer& document, REHex::DocumentCtrl* document_ctrl)
{
	for (auto* plugin : plugins)
	{
		auto wnd = plugin->create(parent, document);
		if (wnd)
		{
			return wnd;
		}
	}
	__debugbreak();
	return nullptr;
}

static REHex::ToolPanelRegistration tpr("PluginPanel", "Plugins", REHex::ToolPanel::TPS_WIDE, &PluginPanel_factory);

