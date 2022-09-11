/* Reverse Engineer's Hex Editor
 * Copyright (C) 2017-2022 Daniel Collins <solemnwarning@solemnwarning.net>
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

#ifndef REHEX_APP_HPP
#define REHEX_APP_HPP

#include "AppSettings.hpp"
#include "ConsoleBuffer.hpp"
#include "mainwindow.hpp"

#include <functional>
#include <map>
#include <string>
#include <vector>
#include <wx/config.h>
#include <wx/filehistory.h>
#include <wx/help.h>
#include <wx/intl.h>
#include <wx/wx.h>

namespace REHex {
	#ifdef BUILD_HELP
	#ifdef _WIN32
	typedef wxCHMHelpController HelpController;
	#else
	typedef wxHtmlHelpController HelpController;
	#endif
	#endif
	
	class App: public wxApp
	{
		public:
			wxConfig *config;
			AppSettings *settings;
			
			wxFileHistory *recent_files;
			wxLocale *locale;
			
			ConsoleBuffer *console;
			
			/**
			 * @brief Get the last directory browsed to in a load/save dialog.
			*/
			const std::string &get_last_directory();
			
			/**
			 * @brief Set the last directory browsed to in a load/save dialog.
			*/
			void set_last_directory(const std::string &last_directory);
			
			/**
			 * @brief Get the current "font size adjustment" setting.
			 *
			 * The font size adjustment indicates how fonts in the application should
			 * be scaled - the default setting is zero, positive values should make any
			 * fonts increasingly larger and negative ones increasingly smaller.
			*/
			int get_font_size_adjustment() const;
			
			/**
			 * @brief Set the "font size adjustment" setting.
			 *
			 * Replaces the "font size adjustment" setting and raises a
			 * FontSizeAdjustmentEvent event.
			 *
			 * The font size adjustment indicates how fonts in the application should
			 * be scaled - the default setting is zero, positive values should make any
			 * fonts increasingly larger and negative ones increasingly smaller.
			*/
			void set_font_size_adjustment(int font_size_adjustment);
			
			/**
			 * @brief Get the selected font face name.
			*/
			std::string get_font_name() const;
			
			/**
			 * @brief Set the font face name.
			 *
			 * Updates the selected font face name and raises a FontSizeAdjustmentEvent
			 * event, but only if the font is monospace.
			*/
			void set_font_name(const std::string &font_name);
			
			/**
			 * @brief Get a list of directories to search for plugins.
			*/
			std::vector<std::string> get_plugin_directories();
			
			/**
			 * @brief Print a debug message to the application console.
			*/
			void print_debug(const std::string &text);
			
			/**
			 * @brief Print a printf format debug message to the application console.
			*/
			void printf_debug(const char *fmt, ...);
			
			/**
			 * @brief Print a message to the application console.
			*/
			void print_info(const std::string &text);
			
			/**
			 * @brief Print a printf format message to the application console.
			*/
			void printf_info(const char *fmt, ...);
			
			/**
			 * @brief Print an error message to the application console.
			*/
			void print_error(const std::string &text);
			
			/**
			 * @brief Print a printf format error message to the application console.
			*/
			void printf_error(const char *fmt, ...);
			
			/**
			 * @brief App setup phases, in order of execution.
			*/
			enum class SetupPhase
			{
				EARLY,  /**< About to begin App OnInit() method. */
				READY,  /**< Global state initialised - about to construct initial MainWindow. */
				DONE,   /**< About to return from OnInit() method. */
				
				SHUTDOWN,       /**< About to start App OnExit() method. */
				SHUTDOWN_LATE,  /**< Called near end of OnExit(), symmetric with EARLY. */
			};
			
			typedef std::function<void()> SetupHookFunction;
			
			/**
			 * @brief Register a hook function to be called during a setup phase.
			 *
			 * @param phase  Setup phase to call the hook during.
			 * @param func   Pointer to a std::function to invoke.
			 *
			 * You should probably use SetupHookRegistration rather than calling this
			 * function directly.
			 *
			 * NOTE: The std::function pointed to by func MUST remain valid until
			 * unregister_setup_hook() is used - it will be used to call the function
			 * and identifies the unique binding until is is unregistered.
			*/
			static void register_setup_hook(SetupPhase phase, const SetupHookFunction *func);
			
			/**
			 * @brief Unregister a setup hook.
			*/
			static void unregister_setup_hook(SetupPhase phase, const SetupHookFunction *func);
			
			/**
			 * @brief Performs RAII-style App setup hook registration.
			*/
			class SetupHookRegistration
			{
				public:
					SetupPhase phase;        /**< @brief App setup phase to call function during. */
					SetupHookFunction func;  /**< @brief Hook function to be called. */
					
					/**
					 * @brief Register the setup hook.
					 *
					 * @param phase  App setup phase to call function during.
					 * @param func   Hook function to be called.
					*/
					SetupHookRegistration(SetupPhase phase, const SetupHookFunction &func);
					
					/**
					 * @brief Unregister the setup hook.
					*/
					~SetupHookRegistration();
					
					SetupHookRegistration(const SetupHookRegistration &src) = delete;
					SetupHookRegistration &operator=(const SetupHookRegistration &rhs) = delete;
			};
			
			int get_caret_on_time_ms();
			int get_caret_off_time_ms();
			
			#ifdef BUILD_HELP
			HelpController *get_help_controller(wxWindow *error_parent);
			void show_help_contents(wxWindow *error_parent);
			#endif
			
			virtual bool OnInit() override;
			virtual int OnExit() override;
			
			#ifdef __APPLE__
			virtual void MacOpenFiles(const wxArrayString &fileNames) override;
			#endif
			
			int bulk_updates_freeze_count;
			
			void bulk_updates_freeze();
			void bulk_updates_thaw();
			bool bulk_updates_frozen();
			
		private:
			std::string last_directory;
			int font_size_adjustment;
			std::string font_name;
			
			MainWindow *window;
			
			#ifdef BUILD_HELP
			HelpController *help_controller;
			bool help_loaded;
			#endif
			
			static std::multimap<SetupPhase, const SetupHookFunction*> *setup_hooks;
			void call_setup_hooks(SetupPhase phase);
			
			void OnMainWindowShow(wxShowEvent &event);
			void OnDiffWindowClose(wxCloseEvent &event);
			
		public:
			void _test_setup_hooks(SetupPhase phase);
	};
}

DECLARE_APP(REHex::App);

#endif /* !REHEX_APP_HPP */
