
#include "platform.hpp"

#include "hooks.hpp"

#include "../src/Tab.hpp"

#include "luaenvironment.hpp"

#include "PluginInstance.hpp"
#include "PluginPanel.hpp"


static class PluginInstance* creating_instance = nullptr;


class PluginInstance: public IPlugin
{
	REHex::Tab* tab;
	REHex::SharedDocumentPointer doc;
	REHex::PluginPanel* panel;
	wxString tab_name;

	PluginScript script;
	sol::environment Env;
	

public:
	PluginInstance(REHex::Tab* active_tab, REHex::SharedDocumentPointer& docptr, const PluginScript& source_script, const wxString& tabname)
		: tab(active_tab)
		, doc(docptr)
		, panel(nullptr)
		, tab_name(tabname)
		, script(source_script)
	{
	}

	~PluginInstance()
	{
		luaenvironment::exitenv(Env);
	}

	void initialize(sol::state& lua)
	{
		Env = sol::environment(lua, sol::create, lua.globals());

		luaenvironment::initenv(Env, this);

		auto result = lua.safe_script_file(script.Filename, Env, sol::script_pass_on_error);
		if (!result.valid())
		{
			sol::error err = result;
			log(err.what());
			return;
		}

		// Is there an init function defined?
		sol::protected_function init = Env["init"];
		if (init)
		{
			result = init(doc);
			if (!result.valid())
			{
				sol::error err = result;
				log(err.what());
			}
		}
	}

	void set_panel(REHex::PluginPanel* new_panel)
	{
		panel = new_panel;
		panel->set_name(tab_name);
	}

	virtual void log(const wxString& output) override
	{
		assert(panel);
		panel->log(output);
	}
};

struct PluginScriptInfo: public PluginScript
{
	int created;
};

class PluginTabInstance : public ITabPlugin
{
	REHex::Tab* tab;
	REHex::SharedDocumentPointer doc;
	std::list<PluginScriptInfo> scripts;

	sol::state lua;

public:
	PluginTabInstance(REHex::Tab* active_tab, REHex::SharedDocumentPointer& docptr)
		: tab(active_tab)
		, doc(docptr)
	{
		// Create a new lua vm
		luaenvironment::initvm(lua);
	}
	~PluginTabInstance()
	{
		luaenvironment::exitvm(lua);
	}

	void add_scripts(const std::vector<PluginScript>& plugin_scripts)
	{
		for (const auto& script : plugin_scripts)
		{
			scripts.push_back(PluginScriptInfo{ script.Name, script.Filename, 0 });
		}
	}

	virtual IPlugin* document_initialized() override
	{
		// We return no init plugin
		return nullptr;
	}

	virtual IPlugin* activated_menu(const wxString& name)
	{
		for (auto& info : scripts)
		{
			if (name == info.Name)
			{
				assert(creating_instance == nullptr);

				// Create a new tab
				std::string name = info.Name;

				if (info.created++ > 0)
				{
					name += "(" + std::to_string(info.created) + ")";
				}

				PluginInstance* result = new PluginInstance(tab, doc, info, name);

				creating_instance = result;
				tab->tool_create("script:" + name, true);
				assert(creating_instance == nullptr);

				// Personalize a new environment for this script
				result->initialize(lua);

				// The application assumes ownership of this plugin
				return result;
			}
		}
		return nullptr;
	}

};

ITabPlugin* plugin_tab_factory(REHex::Tab* tab, REHex::SharedDocumentPointer& doc, const std::vector<PluginScript>& plugin_scripts)
{
	auto plugin_tab = new PluginTabInstance(tab, doc);
	plugin_tab->add_scripts(plugin_scripts);
	return plugin_tab;
}



static REHex::ToolPanel* PluginPanel_factory(wxWindow* parent, REHex::SharedDocumentPointer& document, REHex::DocumentCtrl* document_ctrl)
{
	assert(creating_instance != nullptr);

	if (creating_instance)
	{
		auto wnd = new REHex::PluginPanel(parent);
		creating_instance->set_panel(wnd);
		creating_instance = nullptr;
		return wnd;
	}

	__debugbreak();
	return nullptr;
}

static REHex::ToolPanelRegistration tpr("script", "", REHex::ToolPanel::TPS_WIDE, &PluginPanel_factory);

