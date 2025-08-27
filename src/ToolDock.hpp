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
#include <wx/dnd.h>
#include <wx/event.h>
#include <wx/generic/statbmpg.h>
#include <wx/graphics.h>
#include <wx/image.h>
#include <wx/notebook.h>
#include <wx/overlay.h>
#include <wx/popupwin.h>
#include <wx/sizer.h>

#include "MultiSplitter.hpp"
#include "ProxyDropTarget.hpp"
#include "ToolPanel.hpp"

#if defined(_WIN32)
#define REHEX_ENABLE_SCREENSHOT_OVERLAY
#elif defined(__APPLE__)
#define REHEX_ENABLE_POPUP_OVERLAY
#else
#define REHEX_ENABLE_POPUP_OVERLAY

#ifdef REHEX_ENABLE_WAYLAND_HACKS
#define REHEX_ENABLE_TOOL_DND
#define REHEX_ENABLE_WX_OVERLAY
#endif
#endif

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
			
			/**
			 * @brief Abstract per-ToolFrame data used by OverlayManager implementations.
			*/
			struct OverlayFrameData
			{
				virtual ~OverlayFrameData() = default;
			};
			
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
					
					bool ScreenPointInDockImage(const wxPoint &screen_point) const;
					
					std::unique_ptr<OverlayFrameData> m_overlay_data;
					
				private:
					wxBoxSizer *m_sizer;
					ToolNotebook *m_notebook;
					
					std::list<ToolFrame*> *m_frames;
					
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
			
#ifdef REHEX_ENABLE_POPUP_OVERLAY
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
#endif
			
			/**
			 * @brief Manager for the dock site and drop shadow overlays.
			 *
			 * This interface abstracts the implementation details of how we draw the dock points
			 * and drop shadows while dragging a tool on different platforms.
			*/
			class OverlayManager
			{
				public:
					virtual ~OverlayManager() = default;
					
					/**
					 * @brief Enables the overlays at the start of a drag operation.
					*/
					virtual void StartDrag() = 0;
					
					/**
					 * @brief Disables the overlays at the end of a drag operation.
					*/
					virtual void EndDrag() = 0;
					
					/**
					 * @brief Updates the shadow overlay based on mouse position within a window.
					 *
					 * @brief window        Window the mouse is over (ToolDock, ToolFrame or NULL).
					 * @brief window_point  Mouse position in window co-ordinates.
					 *
					 * This method informs the OverlayManager that the mouse pointer has moved.
					 *
					 * Passing a ToolDock or ToolFrame and a valid point within the window
					 * indicates the CURRENT position of the mouse within a drop window.
					 *
					 * Passing a ToolDock or ToolFrame and an invalid (wxDefaultPosition) point
					 * indicates the pointer has left a window, but MAY be over another valid
					 * drop window.
					 *
					 * Passing a NULL window pointer indicates the mouse pointer isn't over any
					 * valid drop window.
					*/
					virtual void UpdateDrag(wxWindow *window, const wxPoint &window_point) = 0;
			};
			
#ifdef REHEX_ENABLE_POPUP_OVERLAY
			/**
			 * @brief OverlayManager using popup windows.
			 *
			 * This implementation of OverlayManager works by creating a wxPopupWindow for each
			 * overlay we want to draw. It works on every platform where we can position windows in
			 * screen space (i.e. everywhere except Wayland), although transparent window support
			 * for best effect.
			*/
			class PopupOverlayManager: public OverlayManager
			{
				public:
					PopupOverlayManager(ToolDock *dock);
					virtual ~PopupOverlayManager() override = default;
					
					virtual void StartDrag() override;
					virtual void EndDrag() override;
					virtual void UpdateDrag(wxWindow *window, const wxPoint &window_point) override;
					
				private:
					struct FrameData: public OverlayFrameData
					{
						FrameData():
							m_dock_site(NULL)
#ifdef _WIN32
							, m_shadow_site(NULL)
#endif
							{}
							
						virtual ~FrameData() override = default;
						
						DockSite *m_dock_site;
						
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
					};
					
					ToolDock *m_dock;
					
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
			};
			
			friend PopupOverlayManager;
#endif
			
#ifdef REHEX_ENABLE_SCREENSHOT_OVERLAY
			/**
			 * @brief OverlayManager using screenshots and imposters.
			 *
			 * This implementation of OverlayManager works by taking a screenshot of each (child)
			 * window we want to display overlays over, hiding them and creating an imposter window
			 * in their place, over which we draw the screenshot and any overlays we want.
			 *
			 * The advantage of this over PopupOverlayManager is that we don't need transparent
			 * window support to draw transparent elements, or the ability to position windows in
			 * screen space, however, screenshot support is sketchy outside of Windows, so we only
			 * use it there.
			*/
			class ScreenshotOverlayManager: public OverlayManager
			{
				public:
					ScreenshotOverlayManager(ToolDock *dock);
					virtual ~ScreenshotOverlayManager() override = default;
					
					virtual void StartDrag() override;
					virtual void EndDrag() override;
					virtual void UpdateDrag(wxWindow *window, const wxPoint &window_point) override;
					
				private:
					struct FrameData: public OverlayFrameData
					{
						virtual ~FrameData() override = default;
						
						wxBitmap m_screenshot;
						wxGenericStaticBitmap *m_imposter;
					};
					
					ToolDock *m_dock;
					
					wxBitmap m_screenshot;
					wxGenericStaticBitmap *m_imposter;
					
					int m_saved_left_notebook_width;
					int m_saved_right_notebook_width;
					int m_saved_top_notebook_height;
					int m_saved_bottom_notebook_height;

					wxWindow *m_last_window;
					
					static wxBitmap CaptureScreenshot(wxWindow *window);
					wxBitmap RenderImposter(const wxBitmap &base, wxDirection dock_edges, const wxRect &shadow_rect);
			};
			
			friend ScreenshotOverlayManager;
#endif
			
#ifdef REHEX_ENABLE_WX_OVERLAY
			/**
			 * @brief OverlayManager using native wxWidgets overlay support.
			 *
			 * This implementation of OverlayManager works by setting up a wxOverlay on each window
			 * we want to display overlays over. In my testing it works fully under Wayland, only
			 * works for pre-existing (i.e. already-drawn) windows under X11 and doesn't work under
			 * Windows or macOS.
			*/
			class WxOverlayManager: public OverlayManager
			{
				public:
					WxOverlayManager(ToolDock *dock);
					virtual ~WxOverlayManager() override = default;
					
					virtual void StartDrag() override;
					virtual void EndDrag() override;
					virtual void UpdateDrag(wxWindow *window, const wxPoint &window_point) override;
					
				private:
					struct FrameData: public OverlayFrameData
					{
						virtual ~FrameData() override = default;
						
						wxOverlay m_overlay;
					};
					
					ToolDock *m_dock;
					wxOverlay m_overlay;
					
					wxWindow *m_last_window;
					
					void UpdateOverlay(wxWindow *window, wxOverlay &overlay, wxDirection dock_edges, const wxRect &shadow_rect);
			};
			
			friend WxOverlayManager;
#endif
			
			wxWindow *m_main_panel;
			
			ToolNotebook *m_left_notebook;
			ToolNotebook *m_right_notebook;
			ToolNotebook *m_top_notebook;
			ToolNotebook *m_bottom_notebook;
			
			bool m_initial_size_done;
			
			std::list<ToolFrame*> m_frames;
			
			bool m_drag_pending;          /**< Mouse button has been pressed over a tool tab, but not yet moved enough to start drag. */
			wxPoint m_left_down_point;    /**< Screen point where mouse button was pressed over tool tab. */
			ToolPanel *m_left_down_tool;  /**< ToolPanel whose tab was under the mouse when button was pressed. */
			bool m_drag_active;           /**< Non-DnD-based tab movement in progress. */
			ToolFrame *m_drag_frame;      /**< Frame currently being moved by non-DnD-based tab movement. */
			
#ifdef REHEX_ENABLE_TOOL_DND
			bool m_dnd_active;   /**< DnD-based tab movement in progress. */
			bool m_dnd_dropped;  /**< Tab was docked during DnD-based tab movement. */
#endif
			
			ToolNotebook *m_dock_notebook; /**< Notebook the cursor was last seen hovering to dock to. */
			ToolFrame *m_dock_frame;       /**< Frame the cursor was last seen hovering to dock to. */
			
			std::unique_ptr<OverlayManager> m_overlay_manager;
			
			wxBitmap m_dock_bitmap_left;
			wxBitmap m_dock_bitmap_right;
			wxBitmap m_dock_bitmap_top;
			wxBitmap m_dock_bitmap_bottom;
			
			/**
			 * @brief Create ToolFrame and set up event handlers.
			 *
			 * @param position  Screen position to create frame at.
			 * @param size      Initial size of frame.
			 * @param tool      Tool to adopt into new frame.
			 *
			 * @return New ToolFrame object.
			*/
			ToolFrame *CreateFrame(const wxPoint &position, const wxSize &size, ToolPanel *tool = NULL);
			
			ToolFrame *FindFrameByTool(ToolPanel *tool);
			
			/**
			 * @brief Find the topmost ToolFrame under the mouse pointer.
			 *
			 * @return ToolFrame object or NULL.
			*/
			ToolFrame *FindFrameByMousePosition(const wxPoint &screen_point);
			
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
			
			/**
			 * @brief Calculate area to display tool drop shadow.
			 *
			 * @param notebook  Notebook where the tool is to be docked.
			 * @param tool      Tool to be docked.
			 * @param screen    Return co-ordinates relative to screen (true) or Imposter (false).
			 *
			 * This function calculates the rect where a tinted shadow should be drawn when the
			 * mouse is hovering over a MAIN WINDOW tool docking site. The size will reflect the
			 * current size of the notebook (if visible) or the min/best size of the tool.
			*/
			wxRect CalculateShadowForNotebook(ToolNotebook *notebook, ToolPanel *tool, bool screen);
			
			/**
			 * @brief Calculate area to display drop zone indicator.
			 *
			 * @param size  Size of area to display drop zone within.
			 * @param edge  Which edge to display against.
			*/
			wxRect CalculateDropZone(const wxSize &size, wxDirection edge);
			
			void OnNotebookLeftDown(wxMouseEvent &event);
			void OnLeftUp(wxMouseEvent &event);
			void OnMouseCaptureLost(wxMouseCaptureLostEvent &event);
			void OnMotion(wxMouseEvent &event);
			void OnNotebookPageChanged(wxNotebookEvent &event);
			void OnSize(wxSizeEvent &event);
			
#ifdef REHEX_ENABLE_TOOL_DND
			/**
			 * @brief Perform a DnD movement of m_left_down_tool.
			*/
			void DragDropTool();
			
			/**
			 * @brief Callback for mouse movement over ToolDock during DnD tab movement.
			*/
			void OnDockDropMotion(DropEvent &event);
			
			/**
			 * @brief Callback for dropping tab over ToolDock during DnD tab movement.
			*/
			void OnDockDropDrop(DropEvent &event);
			
			/**
			 * @brief Callback for mouse leaving ToolDock during DnD tab movement.
			*/
			void OnDockDropLeave(DropEvent &event);
			
			/**
			 * @brief Callback for mouse movement over ToolFrame during DnD tab movement.
			*/
			void OnFrameDropMotion(ToolFrame *frame, DropEvent &event);
			
			/**
			 * @brief Callback for dropping tab over ToolFrame during DnD tab movement.
			*/
			void OnFrameDropDrop(ToolFrame *frame, DropEvent &event);
			
			/**
			 * @brief Callback for mouse leaving ToolFrame during DnD tab movement.
			*/
			void OnFrameDropLeave(ToolFrame *frame, DropEvent &event);
#endif
			
		DECLARE_EVENT_TABLE()
	};
}

#endif /* !REHEX_TOOLPANELDOCK_HPP */
