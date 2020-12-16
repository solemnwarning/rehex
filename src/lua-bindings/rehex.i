#include "../app.hpp"
#include "../document.hpp"
#include "../mainwindow.hpp"

// TODO: Make this a proper enum class?
enum REHex::App::SetupPhase
{};

#define App_SetupPhase_EARLY (double)(REHex::App::SetupPhase::EARLY)
#define App_SetupPhase_READY (double)(REHex::App::SetupPhase::READY)
#define App_SetupPhase_DONE  (double)(REHex::App::SetupPhase::DONE)

// TODO: Less obnoxious name in Lua environment.
class %delete REHex::App::SetupHookRegistration
{
	REHex::App::SetupHookRegistration(REHex::App::SetupPhase phase, const LuaFunction func);
};

// TODO: Make this a proper enum class?
enum REHex::MainWindow::SetupPhase
{};

#define MainWindow_SetupPhase_FILE_MENU_PRE      (double)(REHex::MainWindow::SetupPhase::FILE_MENU_PRE)
#define MainWindow_SetupPhase_FILE_MENU_TOP      (double)(REHex::MainWindow::SetupPhase::FILE_MENU_TOP)
#define MainWindow_SetupPhase_FILE_MENU_BOTTOM   (double)(REHex::MainWindow::SetupPhase::FILE_MENU_BOTTOM)
#define MainWindow_SetupPhase_FILE_MENU_POST     (double)(REHex::MainWindow::SetupPhase::FILE_MENU_POST)
#define MainWindow_SetupPhase_EDIT_MENU_PRE      (double)(REHex::MainWindow::SetupPhase::EDIT_MENU_PRE)
#define MainWindow_SetupPhase_EDIT_MENU_TOP      (double)(REHex::MainWindow::SetupPhase::EDIT_MENU_TOP)
#define MainWindow_SetupPhase_EDIT_MENU_BOTTOM   (double)(REHex::MainWindow::SetupPhase::EDIT_MENU_BOTTOM)
#define MainWindow_SetupPhase_EDIT_MENU_POST     (double)(REHex::MainWindow::SetupPhase::EDIT_MENU_POST)
#define MainWindow_SetupPhase_VIEW_MENU_PRE      (double)(REHex::MainWindow::SetupPhase::VIEW_MENU_PRE)
#define MainWindow_SetupPhase_VIEW_MENU_TOP      (double)(REHex::MainWindow::SetupPhase::VIEW_MENU_TOP)
#define MainWindow_SetupPhase_VIEW_MENU_BOTTOM   (double)(REHex::MainWindow::SetupPhase::VIEW_MENU_BOTTOM)
#define MainWindow_SetupPhase_VIEW_MENU_POST     (double)(REHex::MainWindow::SetupPhase::VIEW_MENU_POST)
#define MainWindow_SetupPhase_TOOLS_MENU_PRE     (double)(REHex::MainWindow::SetupPhase::TOOLS_MENU_PRE)
#define MainWindow_SetupPhase_TOOLS_MENU_TOP     (double)(REHex::MainWindow::SetupPhase::TOOLS_MENU_TOP)
#define MainWindow_SetupPhase_TOOLS_MENU_BOTTOM  (double)(REHex::MainWindow::SetupPhase::TOOLS_MENU_BOTTOM)
#define MainWindow_SetupPhase_TOOLS_MENU_POST    (double)(REHex::MainWindow::SetupPhase::TOOLS_MENU_POST)
#define MainWindow_SetupPhase_HELP_MENU_PRE      (double)(REHex::MainWindow::SetupPhase::HELP_MENU_PRE)
#define MainWindow_SetupPhase_HELP_MENU_TOP      (double)(REHex::MainWindow::SetupPhase::HELP_MENU_TOP)
#define MainWindow_SetupPhase_HELP_MENU_BOTTOM   (double)(REHex::MainWindow::SetupPhase::HELP_MENU_BOTTOM)
#define MainWindow_SetupPhase_HELP_MENU_POST     (double)(REHex::MainWindow::SetupPhase::HELP_MENU_POST)

// TODO: Less obnoxious name in Lua environment.
class %delete REHex::MainWindow::SetupHookRegistration
{
	REHex::MainWindow::SetupHookRegistration(REHex::MainWindow::SetupPhase phase, const LuaFunction func);
};

class REHex::MainWindow: public wxFrame
{
	wxMenuBar *get_menu_bar() const;
	wxMenu *get_file_menu() const;
	wxMenu *get_edit_menu() const;
	wxMenu *get_view_menu() const;
	wxMenu *get_tools_menu() const;
	wxMenu *get_help_menu() const;
	
	REHex::Document *active_document();
};

class REHex::Document: public wxEvtHandler
{
	wxString read_data(off_t offset, off_t max_length) const;
	off_t buffer_length();
};
