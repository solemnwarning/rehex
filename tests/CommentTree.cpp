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

#undef NDEBUG
#include "../src/platform.hpp"
#include <assert.h>

#include <functional>
#include <gtest/gtest.h>
#include <map>
#include <stdarg.h>
#include <stdlib.h>
#include <string>
#include <vector>
#include <wx/dataview.h>
#include <wx/init.h>
#include <wx/wx.h>

#include "../src/CommentTree.hpp"
#include "../src/document.hpp"

static const REHex::CommentTreeModel *build_model_values_cmp_model;
static int build_model_values_cmp(wxDataViewItem *a, wxDataViewItem *b)
{
	int asc = build_model_values_cmp_model->Compare(*a, *b, 0, true);
	int desc = build_model_values_cmp_model->Compare(*a, *b, 0, false);
	assert(asc == (-1 * desc));
	
	return asc;
}

static void build_model_values(std::vector<std::string> &values, const std::string &prefix, wxDataViewItem node, const REHex::CommentTreeModel *model)
{
	wxDataViewItemArray items;
	unsigned int n_items = model->GetChildren(node, items);
	
	EXPECT_EQ(n_items, items.GetCount()) << "CommentTreeModel::GetChildren(" << prefix << ") returns array size";
	
	build_model_values_cmp_model = model;
	items.Sort(&build_model_values_cmp);
	
	for(unsigned int i = 0; i < items.GetCount(); ++i)
	{
		wxDataViewItem item = items[i];
		
		wxVariant value;
		model->GetValue(value, item, 0);
		
		std::string item_string = prefix + value.GetString().ToStdString();
		
		values.push_back(item_string);
		
		wxDataViewItem parent = model->GetParent(item);
		EXPECT_EQ(node.GetID(), parent.GetID()) << "CommentTreeModel::GetParent(" << item_string << ") returns parent node";
		
		build_model_values(values, item_string + "/", item, model);
	}
}

static void check_values(const REHex::CommentTreeModel *model, ...)
{
	std::vector<std::string> expect_values;
	
	va_list argv;
	va_start(argv, model);
	for(const char *e; (e = va_arg(argv, const char*)) != NULL;)
	{
		expect_values.push_back(e);
	}
	va_end(argv);
	
	std::vector<std::string> got_values;
	build_model_values(got_values, "", wxDataViewItem(NULL), model);
	
	EXPECT_EQ(got_values, expect_values) << "CommentTreeModel returns correct values";
}

struct TestDataViewModelNotifier: public wxDataViewModelNotifier
{
	const REHex::CommentTreeModel *model;
	std::vector<std::string> events;
	std::map<void*,std::string> items;
	
	std::string item_string(const wxDataViewItem &item)
	{
		if(item.GetID() == NULL)
		{
			return "(null)";
		}
		
		wxVariant value;
		model->GetValue(value, item, 0);
		
		return value.GetString().ToStdString();
	}
	
	void populate_items(wxDataViewItem parent)
	{
		wxDataViewItemArray items;
		model->GetChildren(parent, items);
		
		for(unsigned int i = 0; i < items.GetCount(); ++i)
		{
			wxDataViewItem item = items[i];
			
			assert(item.IsOk());
			
			wxVariant value;
			model->GetValue(value, item, 0);
			
			assert(this->items.find(item.GetID()) == this->items.end());
			this->items.emplace(item.GetID(), value.GetString().ToStdString());
			
			populate_items(item);
		}
	}
	
	TestDataViewModelNotifier(REHex::CommentTreeModel *model):
		model(model)
	{
		populate_items(wxDataViewItem(NULL));
		
		model->AddNotifier(this);
	}
	
	virtual ~TestDataViewModelNotifier() {}
	
	virtual bool Cleared() override
	{
		events.push_back("Cleared()");
		return true;
	}
	
	virtual bool ItemAdded(const wxDataViewItem &parent, const wxDataViewItem &item) override
	{
		assert(item.IsOk());
		assert(items.find(item.GetID()) == items.end());
		
		items.emplace(item.GetID(), item_string(item));
		events.push_back(std::string("ItemAdded(\"") + item_string(parent) + "\", \"" + item_string(item) + "\")");
		return true;
	}
	
	virtual bool ItemChanged(const wxDataViewItem &item) override
	{
		assert(item.IsOk());
		assert(items.find(item.GetID()) != items.end());
		
		events.push_back(std::string("ItemChanged(\"") + items[item.GetID()] + "\")");
		items[item.GetID()] = item_string(item);
		return true;
	}
	
	virtual bool ItemDeleted(const wxDataViewItem &parent, const wxDataViewItem &item) override
	{
		if(parent.IsOk())
		{
			assert(items.find(parent.GetID()) != items.end());
		}
		
		assert(item.IsOk());
		assert(items.find(item.GetID()) != items.end());
		
		events.push_back(std::string("ItemDeleted(\"") + (parent.IsOk() ? items[parent.GetID()] : "(null)") + "\", \"" + items[item.GetID()] + "\")");
		items.erase(item.GetID());
		return true;
	}
	
	virtual bool ItemsAdded(const wxDataViewItem &parent, const wxDataViewItemArray &items) override
	{
		events.push_back("ItemsAdded(XXX)");
		return true;
	}
	
	virtual bool ItemsChanged(const wxDataViewItemArray &items) override
	{
		events.push_back("ItemsChanged(XXX)");
		return true;
	}
	
	virtual bool ItemsDeleted(const wxDataViewItem &parent, const wxDataViewItemArray &items) override
	{
		events.push_back("ItemsDeleted(XXX)");
		return true;
	}
	
	virtual void Resort() override
	{
		events.push_back("Resort()");
	}
	
	virtual bool ValueChanged(const wxDataViewItem &item, unsigned int col) override
	{
		events.push_back(std::string("ValueChanged(\"") + item_string(item) + "\")");
		return true;
	}
};

static void refresh_check_notifications(REHex::CommentTreeModel *model, const std::function<void()> &func, ...)
{
	std::vector<std::string> expect;
	
	va_list argv;
	va_start(argv, func);
	for(const char *e; (e = va_arg(argv, const char*)) != NULL;)
	{
		expect.push_back(e);
	}
	va_end(argv);
	
	TestDataViewModelNotifier *notifier = new TestDataViewModelNotifier(model);
	
	func();
	model->refresh_comments();
	
	EXPECT_EQ(notifier->events, expect) << "refresh_comments() generated expected notifications";
	
	model->RemoveNotifier(notifier);
}

TEST(CommentTree, NoComments)
{
	REHex::Document doc;
	
	unsigned char z1k[1024];
	memset(z1k, 0, 1024);
	
	doc.insert_data(0, z1k, 1024);
	
	REHex::CommentTreeModel *model = new REHex::CommentTreeModel(&doc);
	
	refresh_check_notifications(model, [](){}, NULL);
	
	check_values(model, NULL);
	
	model->DecRef();
}

TEST(CommentTree, SingleComment)
{
	REHex::Document doc;
	
	unsigned char z1k[1024];
	memset(z1k, 0, 1024);
	
	doc.insert_data(0, z1k, 1024);
	doc.set_comment(0, 0, REHex::Document::Comment("test"));
	
	REHex::CommentTreeModel *model = new REHex::CommentTreeModel(&doc);
	
	refresh_check_notifications(model, [](){},
		"ItemAdded(\"(null)\", \"test\")",
		NULL
	);
	
	check_values(model,
		"test",
		NULL
	);
	
	model->DecRef();
}

TEST(CommentTree, MultipleComments)
{
	REHex::Document doc;
	
	unsigned char z1k[1024];
	memset(z1k, 0, 1024);
	
	doc.insert_data(0, z1k, 1024);
	doc.set_comment(0, 0,   REHex::Document::Comment("foo"));
	doc.set_comment(10, 10, REHex::Document::Comment("bar"));
	doc.set_comment(20, 0,  REHex::Document::Comment("baz"));
	
	REHex::CommentTreeModel *model = new REHex::CommentTreeModel(&doc);
	
		refresh_check_notifications(model, [](){},
		"ItemAdded(\"(null)\", \"foo\")",
		"ItemAdded(\"(null)\", \"bar\")",
		"ItemAdded(\"(null)\", \"baz\")",
		NULL
	);
	
	check_values(model,
		"foo",
		"bar",
		"baz",
		NULL
	);
	
	model->DecRef();
}

TEST(CommentTree, Heirarchy)
{
	REHex::Document doc;
	
	unsigned char z1k[1024];
	memset(z1k, 0, 1024);
	
	doc.insert_data(0, z1k, 1024);
	doc.set_comment(10, 10, REHex::Document::Comment("10,10"));
	doc.set_comment(10, 4,  REHex::Document::Comment("10,4"));
	doc.set_comment(10, 0,  REHex::Document::Comment("10,0"));
	doc.set_comment(13, 0,  REHex::Document::Comment("13,0"));
	doc.set_comment(16, 4,  REHex::Document::Comment("16,4"));
	doc.set_comment(19, 0,  REHex::Document::Comment("19,0"));
	
	REHex::CommentTreeModel *model = new REHex::CommentTreeModel(&doc);
	
	refresh_check_notifications(model, [](){},
		"ItemAdded(\"(null)\", \"10,10\")",
		"ItemAdded(\"10,10\", \"10,4\")",
		"ItemAdded(\"10,4\", \"10,0\")",
		"ItemAdded(\"10,4\", \"13,0\")",
		"ItemAdded(\"10,10\", \"16,4\")",
		"ItemAdded(\"16,4\", \"19,0\")",
		NULL
	);
	
	check_values(model,
		"10,10",
		"10,10/10,4",
		"10,10/10,4/10,0",
		"10,10/10,4/13,0",
		"10,10/16,4",
		"10,10/16,4/19,0",
		NULL
	);
	
	model->DecRef();
}

TEST(CommentTree, EraseRootCommentNoChildren)
{
	REHex::Document doc;
	
	unsigned char z1k[1024];
	memset(z1k, 0, 1024);
	
	doc.insert_data(0, z1k, 1024);
	doc.set_comment(10, 10, REHex::Document::Comment("10,10"));
	doc.set_comment(20, 10, REHex::Document::Comment("20,10"));
	
	REHex::CommentTreeModel *model = new REHex::CommentTreeModel(&doc);
	model->refresh_comments();
	
	refresh_check_notifications(model,
		[&]()
		{
			doc.erase_comment(10, 10);
		},
		
		"ItemDeleted(\"(null)\", \"10,10\")",
		NULL
	);
	
	check_values(model,
		"20,10",
		NULL
	);
	
	model->DecRef();
}

TEST(CommentTree, EraseRootCommentWithChildren)
{
	REHex::Document doc;
	
	unsigned char z1k[1024];
	memset(z1k, 0, 1024);
	
	doc.insert_data(0, z1k, 1024);
	doc.set_comment(10, 10, REHex::Document::Comment("10,10"));
	doc.set_comment(12, 6,  REHex::Document::Comment("12,6"));
	doc.set_comment(14, 0,  REHex::Document::Comment("14,0"));
	doc.set_comment(20, 10, REHex::Document::Comment("20,10"));
	
	REHex::CommentTreeModel *model = new REHex::CommentTreeModel(&doc);
	model->refresh_comments();
	
	refresh_check_notifications(model,
		[&]()
		{
			doc.erase_comment(10, 10);
		},
		
		"ItemDeleted(\"12,6\", \"14,0\")",
		"ItemDeleted(\"10,10\", \"12,6\")",
		"ItemDeleted(\"(null)\", \"10,10\")",
		"ItemAdded(\"(null)\", \"12,6\")",
		"ItemAdded(\"12,6\", \"14,0\")",
		NULL
	);
	
	check_values(model,
		"12,6",
		"12,6/14,0",
		"20,10",
		NULL
	);
	
	model->DecRef();
}

TEST(CommentTree, EraseNestedCommentNoChildren)
{
	REHex::Document doc;
	
	unsigned char z1k[1024];
	memset(z1k, 0, 1024);
	
	doc.insert_data(0, z1k, 1024);
	doc.set_comment(10, 10, REHex::Document::Comment("10,10"));
	doc.set_comment(12, 0,  REHex::Document::Comment("12,0"));
	doc.set_comment(20, 10, REHex::Document::Comment("20,10"));
	
	REHex::CommentTreeModel *model = new REHex::CommentTreeModel(&doc);
	model->refresh_comments();
	
	doc.erase_comment(12, 0);
	
	model->refresh_comments();
	
	check_values(model,
		"10,10",
		"20,10",
		NULL
	);
	
	model->DecRef();
}

TEST(CommentTree, EraseNestedCommentWithChildren)
{
	REHex::Document doc;
	
	unsigned char z1k[1024];
	memset(z1k, 0, 1024);
	
	doc.insert_data(0, z1k, 1024);
	doc.set_comment(10, 10, REHex::Document::Comment("10,10"));
	doc.set_comment(12, 8,  REHex::Document::Comment("12,8"));
	doc.set_comment(14, 6,  REHex::Document::Comment("14,6"));
	doc.set_comment(16, 0,  REHex::Document::Comment("16,0"));
	doc.set_comment(20, 10, REHex::Document::Comment("20,10"));
	
	REHex::CommentTreeModel *model = new REHex::CommentTreeModel(&doc);
	model->refresh_comments();
	
	doc.erase_comment(12, 8);
	
	model->refresh_comments();
	
	check_values(model,
		"10,10",
		"10,10/14,6",
		"10,10/14,6/16,0",
		"20,10",
		NULL
	);
	
	model->DecRef();
}

TEST(CommentTree, AddCommentRoot)
{
	REHex::Document doc;
	
	unsigned char z1k[1024];
	memset(z1k, 0, 1024);
	
	doc.insert_data(0, z1k, 1024);
	doc.set_comment(10, 10, REHex::Document::Comment("10,10"));
	doc.set_comment(20, 10, REHex::Document::Comment("20,10"));
	
	REHex::CommentTreeModel *model = new REHex::CommentTreeModel(&doc);
	model->refresh_comments();
	
	refresh_check_notifications(model,
		[&]()
		{
			doc.set_comment(30, 10, REHex::Document::Comment("30,10"));
		},
		
		"ItemAdded(\"(null)\", \"30,10\")",
		NULL
	);
	
	check_values(model,
		"10,10",
		"20,10",
		"30,10",
		NULL
	);
	
	model->DecRef();
}

TEST(CommentTree, AddNestedComment)
{
	REHex::Document doc;
	
	unsigned char z1k[1024];
	memset(z1k, 0, 1024);
	
	doc.insert_data(0, z1k, 1024);
	doc.set_comment(10, 10, REHex::Document::Comment("10,10"));
	doc.set_comment(20, 10, REHex::Document::Comment("20,10"));
	
	REHex::CommentTreeModel *model = new REHex::CommentTreeModel(&doc);
	model->refresh_comments();
	
	refresh_check_notifications(model,
		[&]()
		{
			doc.set_comment(22, 6, REHex::Document::Comment("22,6"));
		},
		
		"ItemAdded(\"20,10\", \"22,6\")",
		NULL
	);
	
	check_values(model,
		"10,10",
		"20,10",
		"20,10/22,6",
		NULL
	);
	
	model->DecRef();
}

TEST(CommentTree, AddContainingComment)
{
	REHex::Document doc;
	
	unsigned char z1k[1024];
	memset(z1k, 0, 1024);
	
	doc.insert_data(0, z1k, 1024);
	doc.set_comment(10, 10, REHex::Document::Comment("10,10"));
	doc.set_comment(12,  2, REHex::Document::Comment("12,2"));
	doc.set_comment(14,  6, REHex::Document::Comment("14,6"));
	doc.set_comment(15,  2, REHex::Document::Comment("15,2"));
	doc.set_comment(20, 10, REHex::Document::Comment("20,10"));
	
	REHex::CommentTreeModel *model = new REHex::CommentTreeModel(&doc);
	model->refresh_comments();
	
	refresh_check_notifications(model,
		[&]()
		{
			doc.set_comment(5, 25, REHex::Document::Comment("5,25"));
		},
		
		"ItemAdded(\"(null)\", \"5,25\")",
		"ItemDeleted(\"10,10\", \"12,2\")",
		"ItemDeleted(\"14,6\", \"15,2\")",
		"ItemDeleted(\"10,10\", \"14,6\")",
		"ItemDeleted(\"(null)\", \"10,10\")",
		"ItemAdded(\"5,25\", \"10,10\")",
		"ItemAdded(\"10,10\", \"12,2\")",
		"ItemAdded(\"10,10\", \"14,6\")",
		"ItemAdded(\"14,6\", \"15,2\")",
		"ItemDeleted(\"(null)\", \"20,10\")",
		"ItemAdded(\"5,25\", \"20,10\")",
		NULL
	);
	
	check_values(model,
		"5,25",
		"5,25/10,10",
		"5,25/10,10/12,2",
		"5,25/10,10/14,6",
		"5,25/10,10/14,6/15,2",
		"5,25/20,10",
		NULL
	);
	
	model->DecRef();
}

TEST(CommentTree, ModifyComment)
{
	REHex::Document doc;
	
	unsigned char z1k[1024];
	memset(z1k, 0, 1024);
	
	doc.insert_data(0, z1k, 1024);
	doc.set_comment(10, 10, REHex::Document::Comment("10,10"));
	doc.set_comment(20, 10, REHex::Document::Comment("20,10"));
	
	REHex::CommentTreeModel *model = new REHex::CommentTreeModel(&doc);
	model->refresh_comments();
	
	refresh_check_notifications(model,
		[&]()
		{
			doc.set_comment(10, 10, REHex::Document::Comment("hello"));
		},
		
		"ItemChanged(\"10,10\")",
		NULL
	);
	
	check_values(model,
		"hello",
		"20,10",
		NULL
	);
	
	model->DecRef();
}
