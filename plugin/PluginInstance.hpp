/**
 * Application entry point towards extensions
 */


#ifndef REHEX_PLUGINMANAGER_HPP
#define REHEX_PLUGINMANAGER_HPP

#include <wx/string.h>

IPlugin* plugin_factory(REHex::SharedDocumentPointer& doc, const wxString& plugins_dir);


#endif /* !REHEX_PLUGINMANAGER_HPP */
