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
#include <stdexcept>
#include <stdio.h>
#include <string>
#include <vector>
#include <wx/event.h>

#include "../src/SharedDocumentPointer.hpp"

using namespace REHex;

class ClassY
{
	public:
		/* When compiling with MSVCs "Release" configuration, the optimiser flattens both
		 * of the below methods to the same address if they have the same code, preventing
		 * the Bind/Unbind methods from identifying which callback they were given.
		 *
		 * Despite the above, the compiler does some shennanigans to make comparing the
		 * method symbols work, so the following conditions are all simultaniously true!
		 *
		 * &ClassY::method_a   != &ClassY::method_b
		 * method_pointer_to_a == &ClassY::method_a
		 * method_pointer_to_a == &ClassY::method_b
		*/

		static volatile int fuck;

		void method_a(wxCommandEvent& event) { fuck = 1; }
		void method_b(wxCommandEvent& event) { fuck = 2; }
};

volatile int ClassY::fuck;

class TestDocument: public wxEvtHandler
{
	public:
		static TestDocument *instance;
		static std::vector<std::string> calls;
		
		TestDocument()
		{
			if(instance != NULL)
			{
				throw std::runtime_error("Constructed TestDocument, but instance isn't NULL!");
			}
			
			instance = this;
		}
		
		~TestDocument()
		{
			assert(instance == this);
			instance = NULL;
		}
		
		static std::string call_fmt(const char *my_method, int eventType, const char *method, void *handler)
		{
			const char *eventType_s;
			if(eventType == wxEVT_BUTTON)
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
			void Bind(const EventTag &eventType, void (ClassY::*method)(EventArg &), EventHandler *handler)
		{
			wxEvtHandler::Bind(eventType, method, handler);
			
			if(method == &ClassY::method_a)
			{
				calls.push_back(call_fmt("Bind", eventType, "&ClassY::method_a", handler));
			}
			else if(method == &ClassY::method_b)
			{
				calls.push_back(call_fmt("Bind", eventType, "&ClassY::method_b", handler));
			}
			else{
				calls.push_back(call_fmt("Bind", eventType, "&ClassY::???", handler));
			}
		}
		
		template <typename EventTag, typename EventArg, typename EventHandler>
			void Unbind(const EventTag &eventType, void (ClassY::*method)(EventArg &), EventHandler *handler)
		{
			wxEvtHandler::Unbind(eventType, method, handler);
			
			if(method == &ClassY::method_a)
			{
				calls.push_back(call_fmt("Unbind", eventType, "&ClassY::method_a", handler));
			}
			else if(method == &ClassY::method_b)
			{
				calls.push_back(call_fmt("Unbind", eventType, "&ClassY::method_b", handler));
			}
			else{
				calls.push_back(call_fmt("Unbind", eventType, "&ClassY::???", handler));
			}
		}
};

TestDocument *TestDocument::instance = NULL;
std::vector<std::string> TestDocument::calls;

#define EXPECT_CALLS(...) \
{ \
	std::vector<std::string> expected_calls({ __VA_ARGS__ }); \
	EXPECT_EQ(expected_calls, TestDocument::calls); \
}

TEST(SharedDocumentPointer, CreateDestroy)
{
	ASSERT_EQ(TestDocument::instance, (TestDocument*)(NULL)); /* Sanity check */
	TestDocument::calls.clear();
	
	/* --- Create ptr --- */
	
	std::unique_ptr< SharedDocumentPointerImpl<TestDocument> > ptr(new SharedDocumentPointerImpl<TestDocument>(SharedDocumentPointerImpl<TestDocument>::make()));
	
	ASSERT_NE(TestDocument::instance, (TestDocument*)(NULL)) << "TestDocument constructed";
	EXPECT_EQ((TestDocument*)(*ptr), TestDocument::instance) << "SharedDocumentPointer yields instance";
	
	EXPECT_CALLS();
	
	/* --- Destroy ptr --- */
	
	TestDocument::calls.clear();
	ptr.reset(); /* Destroy the SharedDocumentPointer */
	
	EXPECT_EQ(TestDocument::instance, (TestDocument*)(NULL)) << "TestDocument destroyed with last SharedDocumentPointer";
	EXPECT_CALLS();
}

TEST(SharedDocumentPointer, CreateBindDestroy)
{
	ASSERT_EQ(TestDocument::instance, (TestDocument*)(NULL)); /* Sanity check */
	TestDocument::calls.clear();
	
	/* --- Create ptr --- */
	
	std::unique_ptr< SharedDocumentPointerImpl<TestDocument> > ptr(new SharedDocumentPointerImpl<TestDocument>(SharedDocumentPointerImpl<TestDocument>::make()));
	
	ASSERT_NE(TestDocument::instance, (TestDocument*)(NULL)) << "TestDocument constructed";
	EXPECT_EQ((TestDocument*)(*ptr), TestDocument::instance) << "SharedDocumentPointer yields instance";
	
	EXPECT_CALLS();
	
	/* --- Bind events via ptr --- */
	
	TestDocument::calls.clear();
	ptr->auto_cleanup_bind(wxEVT_BUTTON, &ClassY::method_a, (ClassY*)(0xDEAD));
	ptr->auto_cleanup_bind(wxEVT_MENU,   &ClassY::method_b, (ClassY*)(0xBEEF));
	
	EXPECT_CALLS(
		TestDocument::call_fmt("Bind", wxEVT_BUTTON, "&ClassY::method_a", (ClassY*)(0xDEAD)),
		TestDocument::call_fmt("Bind", wxEVT_MENU,   "&ClassY::method_b", (ClassY*)(0xBEEF)),
	);
	
	/* --- Destroy ptr --- */
	
	TestDocument::calls.clear();
	ptr.reset(); /* Destroy the SharedDocumentPointer */
	
	EXPECT_EQ(TestDocument::instance, (TestDocument*)(NULL)) << "TestDocument destroyed with last SharedDocumentPointer";
	
	EXPECT_CALLS(
		TestDocument::call_fmt("Unbind", wxEVT_MENU,   "&ClassY::method_b", (ClassY*)(0xBEEF)),
		TestDocument::call_fmt("Unbind", wxEVT_BUTTON, "&ClassY::method_a", (ClassY*)(0xDEAD)),
	);
}

TEST(SharedDocumentPointer, CreateBindCopyBindDestroy)
{
	ASSERT_EQ(TestDocument::instance, (TestDocument*)(NULL)); /* Sanity check */
	TestDocument::calls.clear();
	
	/* --- Create ptr --- */
	
	std::unique_ptr< SharedDocumentPointerImpl<TestDocument> > ptr(new SharedDocumentPointerImpl<TestDocument>(SharedDocumentPointerImpl<TestDocument>::make()));
	
	ASSERT_NE(TestDocument::instance, (TestDocument*)(NULL)) << "TestDocument constructed";
	EXPECT_EQ((TestDocument*)(*ptr), TestDocument::instance) << "SharedDocumentPointer yields instance";
	
	EXPECT_CALLS();
	
	/* --- Bind events via ptr --- */
	
	TestDocument::calls.clear();
	ptr->auto_cleanup_bind(wxEVT_BUTTON, &ClassY::method_a, (ClassY*)(0xDEAD));
	ptr->auto_cleanup_bind(wxEVT_MENU,   &ClassY::method_b, (ClassY*)(0xBEEF));
	
	EXPECT_CALLS(
		TestDocument::call_fmt("Bind", wxEVT_BUTTON, "&ClassY::method_a", (ClassY*)(0xDEAD)),
		TestDocument::call_fmt("Bind", wxEVT_MENU,   "&ClassY::method_b", (ClassY*)(0xBEEF)),
	);
	
	/* --- Create copy of ptr --- */
	
	TestDocument::calls.clear();
	
	std::unique_ptr< SharedDocumentPointerImpl<TestDocument> > ptr2(new SharedDocumentPointerImpl<TestDocument>(*ptr));
	
	EXPECT_EQ((TestDocument*)(*ptr2), (TestDocument*)(*ptr)) << "SharedDocumentPointer copy yields same instance";
	
	EXPECT_CALLS();
	
	/* --- Bind events via ptr2 --- */
	
	TestDocument::calls.clear();
	ptr2->auto_cleanup_bind(wxEVT_BUTTON, &ClassY::method_a, (ClassY*)(0xF000));
	ptr2->auto_cleanup_bind(wxEVT_MENU,   &ClassY::method_b, (ClassY*)(0xBAAA));
	
	EXPECT_CALLS(
		TestDocument::call_fmt("Bind", wxEVT_BUTTON, "&ClassY::method_a", (ClassY*)(0xF000)),
		TestDocument::call_fmt("Bind", wxEVT_MENU,   "&ClassY::method_b", (ClassY*)(0xBAAA)),
	);
	
	/* --- Destroy ptr2 --- */
	
	TestDocument::calls.clear();
	ptr2.reset(); /* Destroy the SharedDocumentPointer */
	
	EXPECT_NE(TestDocument::instance, (TestDocument*)(NULL)) << "TestDocument not destroyed with non-final SharedDocumentPointer";
	
	EXPECT_CALLS(
		TestDocument::call_fmt("Unbind", wxEVT_MENU,   "&ClassY::method_b", (ClassY*)(0xBAAA)),
		TestDocument::call_fmt("Unbind", wxEVT_BUTTON, "&ClassY::method_a", (ClassY*)(0xF000)),
	);
	
	/* --- Destroy ptr --- */
	
	TestDocument::calls.clear();
	ptr.reset(); /* Destroy the SharedDocumentPointer */
	
	EXPECT_EQ(TestDocument::instance, (TestDocument*)(NULL)) << "TestDocument destroyed with last SharedDocumentPointer";
	
	EXPECT_CALLS(
		TestDocument::call_fmt("Unbind", wxEVT_MENU,   "&ClassY::method_b", (ClassY*)(0xBEEF)),
		TestDocument::call_fmt("Unbind", wxEVT_BUTTON, "&ClassY::method_a", (ClassY*)(0xDEAD)),
	);
}

TEST(SharedDocumentPointer, CreateBindCopyBindDestroyOutOfOrder)
{
	ASSERT_EQ(TestDocument::instance, (TestDocument*)(NULL)); /* Sanity check */
	TestDocument::calls.clear();
	
	/* --- Create ptr --- */
	
	std::unique_ptr< SharedDocumentPointerImpl<TestDocument> > ptr(new SharedDocumentPointerImpl<TestDocument>(SharedDocumentPointerImpl<TestDocument>::make()));
	
	ASSERT_NE(TestDocument::instance, (TestDocument*)(NULL)) << "TestDocument constructed";
	EXPECT_EQ((TestDocument*)(*ptr), TestDocument::instance) << "SharedDocumentPointer yields instance";
	
	EXPECT_CALLS();
	
	/* --- Bind events via ptr --- */
	
	TestDocument::calls.clear();
	ptr->auto_cleanup_bind(wxEVT_BUTTON, &ClassY::method_a, (ClassY*)(0xDEAD));
	ptr->auto_cleanup_bind(wxEVT_MENU,   &ClassY::method_b, (ClassY*)(0xBEEF));
	
	EXPECT_CALLS(
		TestDocument::call_fmt("Bind", wxEVT_BUTTON, "&ClassY::method_a", (ClassY*)(0xDEAD)),
		TestDocument::call_fmt("Bind", wxEVT_MENU,   "&ClassY::method_b", (ClassY*)(0xBEEF)),
	);
	
	/* -- Create copy of ptr --- */
	
	TestDocument::calls.clear();
	
	std::unique_ptr< SharedDocumentPointerImpl<TestDocument> > ptr2(new SharedDocumentPointerImpl<TestDocument>(*ptr));
	
	EXPECT_EQ((TestDocument*)(*ptr2), (TestDocument*)(*ptr)) << "SharedDocumentPointer copy yields same instance";
	
	EXPECT_CALLS();
	
	/* -- Bind events via ptr2 --- */
	
	TestDocument::calls.clear();
	ptr2->auto_cleanup_bind(wxEVT_BUTTON, &ClassY::method_a, (ClassY*)(0xF000));
	ptr2->auto_cleanup_bind(wxEVT_MENU,   &ClassY::method_b, (ClassY*)(0xBAAA));
	
	EXPECT_CALLS(
		TestDocument::call_fmt("Bind", wxEVT_BUTTON, "&ClassY::method_a", (ClassY*)(0xF000)),
		TestDocument::call_fmt("Bind", wxEVT_MENU,   "&ClassY::method_b", (ClassY*)(0xBAAA)),
	);
	
	/* -- Destroy ptr --- */
	
	TestDocument::calls.clear();
	ptr.reset(); /* Destroy the SharedDocumentPointer */
	
	EXPECT_NE(TestDocument::instance, (TestDocument*)(NULL)) << "TestDocument not destroyed with non-final SharedDocumentPointer";
	
	EXPECT_CALLS(
		TestDocument::call_fmt("Unbind", wxEVT_MENU,   "&ClassY::method_b", (ClassY*)(0xBEEF)),
		TestDocument::call_fmt("Unbind", wxEVT_BUTTON, "&ClassY::method_a", (ClassY*)(0xDEAD)),
	);
	
	/* --- Destroy ptr2 --- */
	
	TestDocument::calls.clear();
	ptr2.reset(); /* Destroy the SharedDocumentPointer */
	
	EXPECT_EQ(TestDocument::instance, (TestDocument*)(NULL)) << "TestDocument destroyed with last SharedDocumentPointer";
	
	EXPECT_CALLS(
		TestDocument::call_fmt("Unbind", wxEVT_MENU,   "&ClassY::method_b", (ClassY*)(0xBAAA)),
		TestDocument::call_fmt("Unbind", wxEVT_BUTTON, "&ClassY::method_a", (ClassY*)(0xF000)),
	);
}
