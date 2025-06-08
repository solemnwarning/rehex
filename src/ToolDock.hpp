/* Reverse Engineer's Hex Editor
 * Copyright (C) 2025 Daniel Collins <solemnwarning@solemnwarning.net>
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

#ifndef REHEX_TOOLPANELDOCK_HPP
#define REHEX_TOOLPANELDOCK_HPP

#include <list>
#include <string>
#include <wx/bitmap.h>
#include <wx/config.h>
#include <wx/event.h>
#include <wx/graphics.h>
#include <wx/image.h>
#include <wx/notebook.h>
#include <wx/popupwin.h>
#include <wx/sizer.h>

#include "MultiSplitter.hpp"
#include "ToolPanel.hpp"

namespace REHex
{
	wxDECLARE_EVENT(TOOLPANEL_CLOSED, wxCommandEvent);
	
	/**
	 * @brief Splitter window for tiling and detaching/docking tool panels.
	*/
	class ToolDock: public MultiSplitter
	{
		public:
			ToolDock(wxWindow *parent);
			virtual ~ToolDock() override;
			
			void AddMainPanel(wxWindow *main_panel);
			
			void CreateTool(const std::string &name, SharedDocumentPointer &document, DocumentCtrl *document_ctrl);
			void DestroyTool(const std::string &name);
			bool ToolExists(const std::string &name) const;
			
			void SaveTools(wxConfig *config) const;
			void LoadTools(wxConfig *config, SharedDocumentPointer &document, DocumentCtrl *document_ctrl);
			
			/**
			 * @brief Hide any detached tools.
			*/
			void HideFrames();
			
			/**
			 * @brief Unhide any detached tools.
			*/
			void UnhideFrames();
			
		private:
			/**
			 * @brief wxNotebook specialisation for holding any tools docked to the main window.
			*/
			class ToolNotebook: public wxNotebook
			{
				public:
					ToolNotebook(wxWindow *parent, wxWindowID id, long style = 0);
					
					virtual bool AddPage(wxWindow *page, const wxString &text, bool select = false, int imageId = NO_IMAGE) override;
					virtual bool DeletePage(size_t page) override;
					virtual bool InsertPage(size_t index, wxWindow *page, const wxString &text, bool select = false, int imageId = NO_IMAGE) override;
					virtual bool RemovePage(size_t page) override;
					virtual int ChangeSelection(size_t page) override;
					
					virtual wxSize GetMinSize() const override;
					
				private:
					/**
					 * @brief Update the visible flag of each tool in this notebook.
					 *
					 * This is called internally after adding/removing any pages from the notebook
					 * because wxEVT_NOTEBOOK_PAGE_CHANGED events aren't generated consistently
					 * between platforms and versions of wxWidgets when the selected tab is changed
					 * due to adding/removing a page.
					*/
					void UpdateToolVisibility();
					
					void OnPageChanged(wxNotebookEvent &event);
					
				DECLARE_EVENT_TABLE()
			};
			
			class DockSite;
			
			/**
			 * @brief wxFrame specialisation for holding a detached/floating tool.
			*/
			class ToolFrame: public wxFrame
			{
				public:
					ToolFrame(wxWindow *parent, std::list<ToolFrame*> *frame_order, wxPoint position = wxDefaultPosition, wxSize size = wxDefaultSize, ToolPanel *tool = NULL);
					virtual ~ToolFrame() override;
					
					void AdoptTool(ToolPanel *tool, bool resize = true);
					
					/**
					 * @brief Remove the owned tool.
					 *
					 * This method must be called to detach the tool from the
					 * floating frame before it can be re-inserted elsewhere in
					 * the window heierarchy.
					*/
					void RemoveTool(ToolPanel *tool);
					
					ToolNotebook *GetNotebook() const;
					
					std::vector<ToolPanel*> GetTools() const;
					
					void SetupDockSite(const std::vector<wxRect> &mask_regions);
					void DestroyDockSite();
					
					void ShowShadow();
					void HideShadow();
					
					bool ScreenPointInDockImage(const wxPoint &screen_point) const;
					
				private:
					wxBoxSizer *m_sizer;
					ToolNotebook *m_notebook;
					
					std::list<ToolFrame*> *m_frames;
					
					DockSite *m_dock_site;
					
#ifdef _WIN32
					DockSite *m_shadow_site;
#endif
					
					void OnWindowActivate(wxActivateEvent &event);
					
				DECLARE_EVENT_TABLE()
			};
			
			enum class Anchor
			{
				LEFT,
				RIGHT,
				TOP,
				BOTTOM,
			};
			
			/**
			 * This is a wxPopupWindow-derived window which is used to draw the
			 * "dock sites" where the cursor must be positioned when dragging a tool
			 * window to dock it into one of the notebook controls.
			 *
			 * The on-screen image for the dock site is drawn over the parent window
			 * at a position based on the 'anchor' parameter to the constructor.
			*/
			class DockSite: public wxPopupWindow
			{
				public:
					DockSite(wxWindow *parent, const wxBitmap &image, Anchor anchor, const std::vector<wxRect> &mask_regions, const wxRect &shadow_rect = wxRect(-1, -1, -1, -1));
					
#ifndef _WIN32
					/**
					 * @brief Enable drawing the shadow.
					 *
					 * Calling this method will expand the window's position
					 * and size to encompass the provided on-screen rectangle
					 * and enable drawing an (ideally) semi-transparent shadow
					 * behind the drop site image but over the parent window.
					*/
					void ShowShadow(const wxRect &rect);
					
					/**
					 * @brief Disable drawing the shadow.
					*/
					void HideShadow();
#endif

					/**
					 * @brief Get the on-screen shadow rectangle.
					*/
					wxRect GetShadowRect() const;
					
					/**
					 * @brief Check if a screen point is over the drop site image.
					*/
					bool PointInImage(const wxPoint &screen_point) const;
					
				private:
					bool m_transparency; /**< Whether transparency is supported/enabled. */
					
					wxImage m_image;
					wxBitmap m_image_bitmap;
					Anchor m_anchor;
					
					std::vector<wxRect> m_mask_regions;
					bool m_mask_enabled;
					
					int m_image_x; /**< X offset of image within window. */
					int m_image_y; /**< Y offset of image within window. */
					
					wxRect m_shadow; /**< Screen rectangle of shadow. */
					
					/**
					 * @brief Update the window position and size.
					*/
					void Resize();
					
					void OnPaint(wxPaintEvent &event);
					
				DECLARE_EVENT_TABLE()
			};
			
			wxWindow *m_main_panel;
			
			ToolNotebook *m_left_notebook;
			ToolNotebook *m_right_notebook;
			ToolNotebook *m_top_notebook;
			ToolNotebook *m_bottom_notebook;
			
			bool m_initial_size_done;
			
			std::list<ToolFrame*> m_frames;
			
			bool m_drag_pending;
			wxPoint m_left_down_point;
			ToolPanel *m_left_down_tool;
			bool m_drag_active;
			ToolFrame *m_drag_frame;
			
			ToolNotebook *m_dock_notebook; /**< Notebook the cursor was last seen hovering to dock to. */
			DockSite *m_dock_site;         /**< DockSite of m_dock_notebook. */
			ToolFrame *m_dock_frame;       /**< Frame the cursor was last seen hovering to dock to. */
			
			DockSite *m_left_dock_site;
			DockSite *m_right_dock_site;
			DockSite *m_top_dock_site;
			DockSite *m_bottom_dock_site;

#ifdef _WIN32
			/**
			 * @brief DockSite instance for displaying shadow on Windows.
			 *
			 * Anything which updates a transparent wxPopupWindow on Windows doesn't work correctly
			 * (the draws overlay and blend together), so on Windows we instead use the main
			 * DockSite instances only for displaying the dock site image and construct another
			 * instance whenever we want to display the shadow.
			*/
			DockSite *m_shadow_site;
#endif
			
			ToolFrame *FindFrameByTool(ToolPanel *tool);
			ToolNotebook *FindNotebookByTool(ToolPanel *tool);
			ToolPanel *FindToolByName(const std::string &name) const;
			
			ToolNotebook *FindDockNotebook(const wxPoint &point, ToolNotebook *current);
			
			void DestroyTool(ToolPanel *tool);
			
			static void SaveToolsFromNotebook(wxConfig *config, ToolNotebook *notebook);
			void LoadToolsIntoNotebook(wxConfig *config, ToolNotebook *notebook, SharedDocumentPointer &document, DocumentCtrl *document_ctrl);
			
			void SaveToolFrames(wxConfig *config) const;
			void LoadToolFrames(wxConfig *config, SharedDocumentPointer &document, DocumentCtrl *document_ctrl);
			
			/**
			 * @brief Reset the size of a notebook to its default size.
			 *
			 * Resets the width/height (as applicable) of a Notebook in the splitter to
			 * its minimum/best size (whichever is larger).
			*/
			void ResetNotebookSize(ToolNotebook *notebook);
			
			void SetupDockSites();
			void DestroyDockSites();
			
			void ShowShadow(ToolNotebook *notebook, const wxRect &rect);
			void HideShadow();
			
			void OnNotebookLeftDown(wxMouseEvent &event);
			void OnLeftUp(wxMouseEvent &event);
			void OnMouseCaptureLost(wxMouseCaptureLostEvent &event);
			void OnMotion(wxMouseEvent &event);
			void OnNotebookPageChanged(wxNotebookEvent &event);
			void OnSize(wxSizeEvent &event);
			
		DECLARE_EVENT_TABLE()
	};
}

#endif /* !REHEX_TOOLPANELDOCK_HPP */
