/* Reverse Engineer's Hex Editor
 * Copyright (C) 2020 Daniel Collins <solemnwarning@solemnwarning.net>
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

#include "../src/platform.hpp"
#include <gtest/gtest.h>
#include <memory>
#include <stdio.h>
#include <string>
#include <vector>
#include <wx/event.h>

#include "../src/SafeWindowPointer.hpp"

using namespace REHex;

class ClassX
{
	public:
		/* When compiling with MSVCs "Release" configuration, the optimiser flattens both
		 * of the below methods to the same address if they have the same code, preventing
		 * the Bind/Unbind methods from identifying which callback they were given.
		 *
		 * Despite the above, the compiler does some shennanigans to make comparing the
		 * method symbols work, so the following conditions are all simultaniously true!
		 *
		 * &ClassX::method_a   != &ClassX::method_b
		 * method_pointer_to_a == &ClassX::method_a
		 * method_pointer_to_a == &ClassX::method_b
		*/

		static volatile int fuck;

		void method_a(wxCommandEvent& event) { fuck = 1; }
		void method_b(wxCommandEvent& event) { fuck = 2; }
};

volatile int ClassX::fuck;

class TestWindow: public wxEvtHandler
{
	public:
		std::vector<std::string> calls;
		
		static std::string call_fmt(const char *my_method, int eventType, const char *method, void *handler)
		{
			const char *eventType_s;
			if(eventType == wxEVT_DESTROY)
			{
				eventType_s = "wxEVT_DESTROY";
			}
			else if(eventType == wxEVT_BUTTON)
			{
				eventType_s = "wxEVT_BUTTON";
			}
			else if(eventType == wxEVT_MENU)
			{
				eventType_s = "wxEVT_MENU";
			}
			else{
				eventType_s = "???";
			}
			
			char call_s[128];
			snprintf(call_s, sizeof(call_s), "%s(%s, %s, %p)", my_method, eventType_s, method, handler);
			
			return call_s;
		}
		
		template <typename EventTag, typename EventArg, typename EventHandler>
			void Bind(const EventTag &eventType, void (SafeWindowPointer<TestWindow>::*method)(EventArg &), EventHandler *handler)
		{
			wxEvtHandler::Bind(eventType, method, handler);
			
			calls.push_back(call_fmt("Bind", eventType, "&SafeWindowPointer<TestWindow>::???", handler));
		}
		
		template <typename EventTag, typename EventArg, typename EventHandler>
			void Bind(const EventTag &eventType, void (ClassX::*method)(EventArg &), EventHandler *handler)
		{
			wxEvtHandler::Bind(eventType, method, handler);

			if(method == &ClassX::method_a)
			{
				calls.push_back(call_fmt("Bind", eventType, "&ClassX::method_a", handler));
			}
			else if(method == &ClassX::method_b)
			{
				calls.push_back(call_fmt("Bind", eventType, "&ClassX::method_b", handler));
			}
			else{
				calls.push_back(call_fmt("Bind", eventType, "&ClassX::???", handler));
			}
		}
		
		template <typename EventTag, typename EventArg, typename EventHandler>
			void Unbind(const EventTag &eventType, void (SafeWindowPointer<TestWindow>::*method)(EventArg &), EventHandler *handler)
		{
			wxEvtHandler::Unbind(eventType, method, handler);
			
			calls.push_back(call_fmt("Unbind", eventType, "&SafeWindowPointer<TestWindow>::???", handler));
		}
		
		template <typename EventTag, typename EventArg, typename EventHandler>
			void Unbind(const EventTag &eventType, void (ClassX::*method)(EventArg &), EventHandler *handler)
		{
			wxEvtHandler::Unbind(eventType, method, handler);
			
			if(method == &ClassX::method_a)
			{
				calls.push_back(call_fmt("Unbind", eventType, "&ClassX::method_a", handler));
			}
			else if(method == &ClassX::method_b)
			{
				calls.push_back(call_fmt("Unbind", eventType, "&ClassX::method_b", handler));
			}
			else{
				calls.push_back(call_fmt("Unbind", eventType, "&ClassX::???", handler));
			}
		}
		
		void destroy()
		{
			wxWindowDestroyEvent destroy_event((wxWindow*)(this));
			ProcessEvent(destroy_event);
		}
};

TEST(SafeWindowPointer, CreateDestroyPointer)
{
	TestWindow window;
	
	std::unique_ptr< SafeWindowPointer<TestWindow> > ptr_up(new SafeWindowPointer<TestWindow>(&window));
	SafeWindowPointer<TestWindow> &ptr = *ptr_up;
	
	EXPECT_EQ((TestWindow*)(ptr), &window) << "SafeWindowPointer has window address";
	
	std::vector<std::string> expect_calls;
	expect_calls.push_back(TestWindow::call_fmt("Bind", wxEVT_DESTROY, "&SafeWindowPointer<TestWindow>::???", &ptr));
	
	EXPECT_EQ(window.calls, expect_calls) << "SafeWindowPointer c'tor binds wxEVT_DESTROY event";
	
	window.calls.clear();
	ptr_up.reset(); /* Destroy the SafeWindowPointer. */
	
	expect_calls.clear();
	expect_calls.push_back(TestWindow::call_fmt("Unbind", wxEVT_DESTROY, "&SafeWindowPointer<TestWindow>::???", &ptr));
	
	EXPECT_EQ(window.calls, expect_calls) << "SafeWindowPointer d'tor unbinds wxEVT_DESTROY event";
}

TEST(SafeWindowPointer, CreateDestroyWindow)
{
	TestWindow window;
	
	std::unique_ptr< SafeWindowPointer<TestWindow> > ptr_up(new SafeWindowPointer<TestWindow>(&window));
	SafeWindowPointer<TestWindow> &ptr = *ptr_up;
	
	EXPECT_EQ((TestWindow*)(ptr), &window) << "SafeWindowPointer has window address";
	
	std::vector<std::string> expect_calls;
	expect_calls.push_back(TestWindow::call_fmt("Bind", wxEVT_DESTROY, "&SafeWindowPointer<TestWindow>::???", &ptr));
	
	EXPECT_EQ(window.calls, expect_calls) << "SafeWindowPointer c'tor binds wxEVT_DESTROY event";
	
	window.calls.clear();
	window.destroy(); /* "Destroy" the TestWindow. */
	
	EXPECT_EQ((TestWindow*)(ptr), (TestWindow*)(NULL)) << "SafeWindowPointer has cleared window address";
	
	ptr_up.reset(); /* Destroy the SafeWindowPointer. */
	
	expect_calls.clear();
	EXPECT_EQ(window.calls, expect_calls) << "SafeWindowPointer d'tor unbinds no events after window destruction";
}

TEST(SafeWindowPointer, CreateBindDestroyPointer)
{
	TestWindow window;
	
	std::unique_ptr< SafeWindowPointer<TestWindow> > ptr_up(new SafeWindowPointer<TestWindow>(&window));
	SafeWindowPointer<TestWindow> &ptr = *ptr_up;
	
	EXPECT_EQ((TestWindow*)(ptr), &window) << "SafeWindowPointer has window address";
	
	std::vector<std::string> expect_calls;
	expect_calls.push_back(TestWindow::call_fmt("Bind", wxEVT_DESTROY, "&SafeWindowPointer<TestWindow>::???", &ptr));
	
	EXPECT_EQ(window.calls, expect_calls) << "SafeWindowPointer c'tor binds wxEVT_DESTROY event";
	
	window.calls.clear();
	ptr.auto_cleanup_bind(wxEVT_BUTTON, &ClassX::method_a, (ClassX*)(0xDEAD));
	ptr.auto_cleanup_bind(wxEVT_MENU,   &ClassX::method_b, (ClassX*)(0xBEEF));
	
	expect_calls.clear();
	expect_calls.push_back(TestWindow::call_fmt("Bind", wxEVT_BUTTON, "&ClassX::method_a", (ClassX*)(0xDEAD)));
	expect_calls.push_back(TestWindow::call_fmt("Bind", wxEVT_MENU,   "&ClassX::method_b", (ClassX*)(0xBEEF)));
	
	EXPECT_EQ(window.calls, expect_calls) << "SafeWindowPointer::auto_cleanup_bind() binds events";
	
	window.calls.clear();
	ptr_up.reset(); /* Destroy the SafeWindowPointer. */
	
	expect_calls.clear();
	expect_calls.push_back(TestWindow::call_fmt("Unbind", wxEVT_MENU,    "&ClassX::method_b", (ClassX*)(0xBEEF)));
	expect_calls.push_back(TestWindow::call_fmt("Unbind", wxEVT_BUTTON,  "&ClassX::method_a", (ClassX*)(0xDEAD)));
	expect_calls.push_back(TestWindow::call_fmt("Unbind", wxEVT_DESTROY, "&SafeWindowPointer<TestWindow>::???", &ptr));
	
	EXPECT_EQ(window.calls, expect_calls) << "SafeWindowPointer d'tor unbinds events";
}

TEST(SafeWindowPointer, CreateBindDestroyWindow)
{
	TestWindow window;
	
	std::unique_ptr< SafeWindowPointer<TestWindow> > ptr_up(new SafeWindowPointer<TestWindow>(&window));
	SafeWindowPointer<TestWindow> &ptr = *ptr_up;
	
	EXPECT_EQ((TestWindow*)(ptr), &window) << "SafeWindowPointer has window address";
	
	std::vector<std::string> expect_calls;
	expect_calls.push_back(TestWindow::call_fmt("Bind", wxEVT_DESTROY, "&SafeWindowPointer<TestWindow>::???", &ptr));
	
	EXPECT_EQ(window.calls, expect_calls) << "SafeWindowPointer c'tor binds wxEVT_DESTROY event";
	
	window.calls.clear();
	ptr.auto_cleanup_bind(wxEVT_BUTTON, &ClassX::method_a, (ClassX*)(0xDEAD));
	ptr.auto_cleanup_bind(wxEVT_MENU,   &ClassX::method_b, (ClassX*)(0xBEEF));
	
	expect_calls.clear();
	expect_calls.push_back(TestWindow::call_fmt("Bind", wxEVT_BUTTON, "&ClassX::method_a", (ClassX*)(0xDEAD)));
	expect_calls.push_back(TestWindow::call_fmt("Bind", wxEVT_MENU,   "&ClassX::method_b", (ClassX*)(0xBEEF)));
	
	EXPECT_EQ(window.calls, expect_calls) << "SafeWindowPointer::auto_cleanup_bind() binds events";
	
	window.calls.clear();
	window.destroy(); /* "Destroy" the TestWindow. */
	
	EXPECT_EQ((TestWindow*)(ptr), (TestWindow*)(NULL)) << "SafeWindowPointer has cleared window address";
	
	ptr_up.reset(); /* Destroy the SafeWindowPointer. */
	
	expect_calls.clear();
	EXPECT_EQ(window.calls, expect_calls) << "SafeWindowPointer d'tor unbinds no events after window destruction";
}

TEST(SafeWindowPointer, Copy)
{
	TestWindow window;
	
	std::unique_ptr< SafeWindowPointer<TestWindow> > ptr_up(new SafeWindowPointer<TestWindow>(&window));
	SafeWindowPointer<TestWindow> &ptr = *ptr_up;
	
	EXPECT_EQ((TestWindow*)(ptr), &window) << "SafeWindowPointer has window address";
	
	std::vector<std::string> expect_calls;
	expect_calls.push_back(TestWindow::call_fmt("Bind", wxEVT_DESTROY, "&SafeWindowPointer<TestWindow>::???", &ptr));
	
	EXPECT_EQ(window.calls, expect_calls) << "SafeWindowPointer c'tor binds wxEVT_DESTROY event";
	
	window.calls.clear();
	ptr.auto_cleanup_bind(wxEVT_BUTTON, &ClassX::method_a, (ClassX*)(0xDEAD));
	ptr.auto_cleanup_bind(wxEVT_MENU,   &ClassX::method_b, (ClassX*)(0xBEEF));
	
	expect_calls.clear();
	expect_calls.push_back(TestWindow::call_fmt("Bind", wxEVT_BUTTON, "&ClassX::method_a", (ClassX*)(0xDEAD)));
	expect_calls.push_back(TestWindow::call_fmt("Bind", wxEVT_MENU,   "&ClassX::method_b", (ClassX*)(0xBEEF)));
	
	EXPECT_EQ(window.calls, expect_calls) << "SafeWindowPointer::auto_cleanup_bind() binds events";
	
	window.calls.clear();
	
	/* Make a copy of the SafeWindowPointer. */
	std::unique_ptr< SafeWindowPointer<TestWindow> > ptr2_up(new SafeWindowPointer<TestWindow>(ptr));
	SafeWindowPointer<TestWindow> &ptr2 = *ptr2_up;
	
	EXPECT_EQ((TestWindow*)(ptr2), &window) << "SafeWindowPointer copy c'tor copies window address";
	
	expect_calls.clear();
	expect_calls.push_back(TestWindow::call_fmt("Bind", wxEVT_DESTROY, "&SafeWindowPointer<TestWindow>::???", &ptr2));
	
	EXPECT_EQ(window.calls, expect_calls) << "SafeWindowPointer copy c'tor binds wxEVT_DESTROY event";
	
	window.calls.clear();
	ptr2.auto_cleanup_bind(wxEVT_BUTTON, &ClassX::method_a, (ClassX*)(0xABCD));
	
	expect_calls.clear();
	expect_calls.push_back(TestWindow::call_fmt("Bind", wxEVT_BUTTON, "&ClassX::method_a", (ClassX*)(0xABCD)));
	
	EXPECT_EQ(window.calls, expect_calls) << "SafeWindowPointer::auto_cleanup_bind() binds events";
	
	window.calls.clear();
	ptr_up.reset(); /* Destroy the SafeWindowPointer. */
	
	expect_calls.clear();
	expect_calls.push_back(TestWindow::call_fmt("Unbind", wxEVT_MENU,    "&ClassX::method_b", (ClassX*)(0xBEEF)));
	expect_calls.push_back(TestWindow::call_fmt("Unbind", wxEVT_BUTTON,  "&ClassX::method_a", (ClassX*)(0xDEAD)));
	expect_calls.push_back(TestWindow::call_fmt("Unbind", wxEVT_DESTROY, "&SafeWindowPointer<TestWindow>::???", &ptr));
	
	EXPECT_EQ(window.calls, expect_calls) << "SafeWindowPointer d'tor unbinds events";
	
	window.calls.clear();
	ptr2_up.reset(); /* Destroy the SafeWindowPointer copy. */
	
	expect_calls.clear();
	expect_calls.push_back(TestWindow::call_fmt("Unbind", wxEVT_BUTTON,  "&ClassX::method_a", (ClassX*)(0xABCD)));
	expect_calls.push_back(TestWindow::call_fmt("Unbind", wxEVT_DESTROY, "&SafeWindowPointer<TestWindow>::???", &ptr2));
	
	EXPECT_EQ(window.calls, expect_calls) << "SafeWindowPointer copy d'tor unbinds events";
}

TEST(SafeWindowPointer, CopyThenDestroyWindow)
{
	TestWindow window;
	
	std::unique_ptr< SafeWindowPointer<TestWindow> > ptr_up(new SafeWindowPointer<TestWindow>(&window));
	SafeWindowPointer<TestWindow> &ptr = *ptr_up;
	
	EXPECT_EQ((TestWindow*)(ptr), &window) << "SafeWindowPointer has window address";
	
	window.calls.clear();
	
	/* Make a copy of the SafeWindowPointer. */
	std::unique_ptr< SafeWindowPointer<TestWindow> > ptr2_up(new SafeWindowPointer<TestWindow>(ptr));
	SafeWindowPointer<TestWindow> &ptr2 = *ptr2_up;
	
	EXPECT_EQ((TestWindow*)(ptr2), &window) << "SafeWindowPointer copy c'tor copies window address";
	
	std::vector<std::string> expect_calls;
	expect_calls.push_back(TestWindow::call_fmt("Bind", wxEVT_DESTROY, "&SafeWindowPointer<TestWindow>::???", &ptr2));
	
	EXPECT_EQ(window.calls, expect_calls) << "SafeWindowPointer copy c'tor binds wxEVT_DESTROY event";
	
	window.calls.clear();
	ptr2.auto_cleanup_bind(wxEVT_BUTTON, &ClassX::method_a, (ClassX*)(0xABCD));
	
	expect_calls.clear();
	expect_calls.push_back(TestWindow::call_fmt("Bind", wxEVT_BUTTON, "&ClassX::method_a", (ClassX*)(0xABCD)));
	
	EXPECT_EQ(window.calls, expect_calls) << "SafeWindowPointer::auto_cleanup_bind() binds events";
	
	window.calls.clear();
	window.destroy(); /* "Destroy" the TestWindow. */
	
	EXPECT_EQ((TestWindow*)(ptr),  (TestWindow*)(NULL)) << "SafeWindowPointer has cleared window address";
	EXPECT_EQ((TestWindow*)(ptr2), (TestWindow*)(NULL)) << "SafeWindowPointer copy has cleared window address";
	
	ptr_up.reset(); /* Destroy the SafeWindowPointer. */
	
	expect_calls.clear();
	EXPECT_EQ(window.calls, expect_calls) << "SafeWindowPointer d'tor unbinds no events after window destruction";
	
	ptr2_up.reset(); /* Destroy the SafeWindowPointer copy. */
	
	expect_calls.clear();
	EXPECT_EQ(window.calls, expect_calls) << "SafeWindowPointer copy d'tor unbinds no events after window destruction";
}

TEST(SafeWindowPointer, CopyAfterWindowDestroy)
{
	TestWindow window;
	
	std::unique_ptr< SafeWindowPointer<TestWindow> > ptr_up(new SafeWindowPointer<TestWindow>(&window));
	SafeWindowPointer<TestWindow> &ptr = *ptr_up;
	
	EXPECT_EQ((TestWindow*)(ptr), &window) << "SafeWindowPointer has window address";
	
	window.calls.clear();
	window.destroy(); /* "Destroy" the TestWindow. */
	
	EXPECT_EQ((TestWindow*)(ptr),  (TestWindow*)(NULL)) << "SafeWindowPointer has cleared window address";
	
	window.calls.clear();
	
	/* Make a copy of the SafeWindowPointer. */
	std::unique_ptr< SafeWindowPointer<TestWindow> > ptr2_up(new SafeWindowPointer<TestWindow>(ptr));
	SafeWindowPointer<TestWindow> &ptr2 = *ptr2_up;
	
	EXPECT_EQ((TestWindow*)(ptr2), (TestWindow*)(NULL)) << "SafeWindowPointer copy c'tor copies NULL window address";
	
	const std::vector<std::string> expect_calls;
	EXPECT_EQ(window.calls, expect_calls) << "SafeWindowPointer copy c'tor binds no events";
	
	window.calls.clear();
	ptr2.auto_cleanup_bind(wxEVT_BUTTON, &ClassX::method_a, (ClassX*)(0xABCD));
	
	EXPECT_EQ(window.calls, expect_calls) << "SafeWindowPointer::auto_cleanup_bind() binds no events";
	
	ptr2_up.reset(); /* Destroy the SafeWindowPointer copy. */
	
	EXPECT_EQ(window.calls, expect_calls) << "SafeWindowPointer copy d'tor unbinds no events";
}
