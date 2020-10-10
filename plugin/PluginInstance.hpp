/**
 * Application entry point towards extensions
 */


#ifndef REHEX_PLUGINMANAGER_HPP
#define REHEX_PLUGINMANAGER_HPP

#include <wx/string.h>
#include "PluginScript.hpp"



ITabPlugin* plugin_tab_factory(REHex::Tab* tab, REHex::SharedDocumentPointer& doc, const std::vector<PluginScript>& plugin_scripts);


#endif /* !REHEX_PLUGINMANAGER_HPP */
