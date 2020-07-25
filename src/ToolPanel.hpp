/* Reverse Engineer's Hex Editor
 * Copyright (C) 2019 Daniel Collins <solemnwarning@solemnwarning.net>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#ifndef REHEX_TOOLPANEL_HPP
#define REHEX_TOOLPANEL_HPP

#include <map>
#include <string>
#include <wx/config.h>
#include <wx/panel.h>

#include "document.hpp"
#include "DocumentCtrl.hpp"
#include "SharedDocumentPointer.hpp"

/* Background on the classes here:
 *
 * Any "tool panels" added to the v_tools or h_tools notebooks in MainWindow must inherit from the
 * ToolPanel class, which is just a wxPanel with some extra virtual methods.
 *
 * The ToolPanelRegistry stores any tool panels which can be created directly (i.e. without any
 * extra input/configuration). Any tools defined in this registry will appear in the tools menu to
 * be instantiated by the user. ToolPanels do not HAVE to be instantiated this way, e.g. another
 * tool could create a panel with some results in it.
 *
 * Tools are added to ToolPanelRegistry by creating an instance of ToolPanelRegistration, usually
 * as a static global in the implementation of that tool.
*/

namespace REHex {
	class ToolPanel: public wxPanel
	{
		public:
			enum Shape {
				TPS_WIDE,
				TPS_TALL,
			};
			
			virtual ~ToolPanel();
			
			virtual std::string name() const = 0;
// 			virtual std::string label() const = 0;
// 			virtual Shape shape() const = 0;
			
			virtual void save_state(wxConfig *config) const = 0;
			virtual void load_state(wxConfig *config) = 0;
			virtual void update() = 0;
			void set_visible(bool visible);
			
		protected:
			ToolPanel(wxWindow *parent);
			bool is_visible;
	};
	
	class ToolPanelRegistration;
	class ToolPanelRegistry
	{
		friend class ToolPanelRegistration;
		
		public:
			static std::map<std::string, const ToolPanelRegistration*>::const_iterator begin();
			static std::map<std::string, const ToolPanelRegistration*>::const_iterator end();
			
			static const ToolPanelRegistration *by_name(const std::string &name);
			
		private:
			/* The registrations map is created by the first ToolPanelRegistration and
			 * destroyed when the last one in it removes itself. This is to avoid
			 * depending on global variable initialisation order.
			 *
			 * The no_registrations map is always empty and used to return iterators
			 * to an empty map when no registrations exist.
			*/
			
			static std::map<std::string, const ToolPanelRegistration*> *registrations;
			static const std::map<std::string, const ToolPanelRegistration*> no_registrations;
	};
	
	class ToolPanelRegistration
	{
		public:
			typedef ToolPanel* (*FactoryFunction)(wxWindow *parent, SharedDocumentPointer &document, DocumentCtrl *document_ctrl);
			
			std::string name;
			std::string label;
			ToolPanel::Shape shape;
			FactoryFunction factory;
			
			ToolPanelRegistration(const std::string &name, const std::string &label, ToolPanel::Shape shape, FactoryFunction factory);
			~ToolPanelRegistration();
	};
}

#endif /* !REHEX_TOOLPANEL_HPP */
