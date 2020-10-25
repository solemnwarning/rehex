/* Reverse Engineer's Hex Editor
 * Copyright (C) 2017 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include <functional>
#include <map>
#include <string>
#include <wx/config.h>
#include <wx/filehistory.h>
#include <wx/wx.h>

namespace REHex {
	class App: public wxApp
	{
		public:
			wxConfig *config;
			wxFileHistory *recent_files;
			
			const std::string &get_last_directory();
			void set_last_directory(const std::string &last_directory);
			
			/**
			 * @brief App setup phases, in order of execution.
			*/
			enum class SetupPhase
			{
				EARLY,  /**< About to begin App OnInit() method. */
				READY,  /**< Global state initialised - about to construct initial MainWindow. */
				DONE,   /**< About to return from OnInit() method. */
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
					SetupPhase phase;        /**< App setup phase to call function during. */
					SetupHookFunction func;  /**< Hook function to be called. */
					
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
			
			virtual bool OnInit();
			virtual int OnExit();
			
		private:
			std::string last_directory;
			
			static std::multimap<SetupPhase, const SetupHookFunction*> *setup_hooks;
			void call_setup_hooks(SetupPhase phase);
	};
}

DECLARE_APP(REHex::App);

#endif /* !REHEX_APP_HPP */
