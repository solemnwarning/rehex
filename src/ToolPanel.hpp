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
	/**
	 * @brief Base class of all "tool panels".
	 *
	 * A "tool panel" is a wxPanel-derived class that can be displayed alongside an open
	 * document.
	 *
	 * Tool panels can currently be displayed under a tabbed control either alongside or
	 * beneath the main DocumentCtrl of an open file. In the future there will be more options
	 * including detatching them into a seperate window and perhaps placing multiple controls
	 * in arbitrary configurations around the main window.
	*/
	class ToolPanel: public wxPanel
	{
		public:
			/**
			 * @brief Preferred shape of the panel.
			*/
			enum Shape {
				TPS_WIDE,  /**< Panel is wide - place it under the document. */
				TPS_TALL,  /**< Panel is tall - place it next to the document. */
			};
			
			virtual ~ToolPanel();
			
			/**
			 * @brief Internal name of the tool.
			 *
			 * If implemented, returns the internal name of the tool which can be used
			 * to re-create the tool later via the ToolPanelRegistry.
			*/
			virtual std::string name() const = 0;
			virtual std::string label() const = 0;
			virtual Shape shape() const = 0;
			
			/**
			 * @brief Save the state of the ToolPanel.
			 *
			 * Saves the current configuration and/or state of the ToolPanel in a
			 * wxConfig so it can be restored later.
			*/
			virtual void save_state(wxConfig *config) const = 0;
			
			/**
			 * @brief Restore a state previously saved by save_state().
			*/
			virtual void load_state(wxConfig *config) = 0;
			
			/**
			 * @brief Called when the ToolPanel becomes visible.
			*/
			virtual void update() = 0;
			
			/**
			 * @brief Called when the ToolPanel becomes (in)visible.
			*/
			void set_visible(bool visible);
			
		protected:
			ToolPanel(wxWindow *parent);
			
			/**
			 * @brief True when the ToolPanel is visible.
			 *
			 * This can be checked to skip expensive UI update operations when the UI
			 * isn't visible. The update() method will be called to do any deferred
			 * updates when the ToolPanel becomes visible.
			*/
			bool is_visible;
	};
	
	class ToolPanelRegistration;
	
	/**
	 * @brief Registry of tool panels that the user can create directly.
	 * @see ToolPanelRegistration.
	*/
	class ToolPanelRegistry
	{
		friend class ToolPanelRegistration;
		
		public:
			/**
			 * @brief Get an iterator to the first registration.
			*/
			static std::map<std::string, const ToolPanelRegistration*>::const_iterator begin();
			
			/**
			 * @brief Get an iterator to the end of the registrations.
			*/
			static std::map<std::string, const ToolPanelRegistration*>::const_iterator end();
			
			/**
			 * @brief Search for a ToolPanelRegistration by its internal name.
			 *
			 * @return ToolPanelRegistration pointer, NULL if not found.
			*/
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
	
	/**
	 * @brief ToolPanelRegistry registration.
	 *
	 * This class is used to register a tool panel and associated factory function in the
	 * ToolPanelRegistry. This adds the panel to the "Tools" menu, allowing the user to show or
	 * hide it at will.
	 *
	 * This class is usually constructed during early program initialisation as a static global
	 * variable in the implementation of the tool.
	*/
	class ToolPanelRegistration
	{
		public:
			typedef ToolPanel* (*FactoryFunction)(wxWindow *parent, SharedDocumentPointer &document, DocumentCtrl *document_ctrl);
			
			std::string name;         /**< @brief Unique internal name of the tool. */
			std::string label;        /**< @brief Label to display in the "Tools" menu. */
			ToolPanel::Shape shape;   /**< @brief Preferred "shape" of the panel. */
			FactoryFunction factory;  /**< @brief Factory function that creates the ToolPanel object. */
			
			/**
			 * @brief Register the tool panel class.
			 *
			 * @param name     Unique internal name of the tool. Must match the one returned by the ToolPanel's name() method.
			 * @param label    Label to display in the "Tools" menu.
			 * @param shape    Preferred "shape" of the panel. TPS_WIDE panels will appear at the bottom of the window, TPS_TALL to the side.
			 * @param factory  Factory function that creates the ToolPanel object.
			*/
			ToolPanelRegistration(const std::string &name, const std::string &label, ToolPanel::Shape shape, FactoryFunction factory);
			~ToolPanelRegistration();
	};
}

#endif /* !REHEX_TOOLPANEL_HPP */
