#include "../App.hpp"
#include "../BitOffset.hpp"
#include "../CharacterEncoder.hpp"
#include "../document.hpp"
#include "../mainwindow.hpp"

void print_debug(const wxString &text);
void print_info(const wxString &text);
void print_error(const wxString &text);

void bulk_updates_freeze();
void bulk_updates_thaw();

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
#define MainWindow_SetupPhase_DONE               (double)(REHex::MainWindow::SetupPhase::DONE)

// TODO: Less obnoxious name in Lua environment.
class %delete REHex::MainWindow::SetupHookRegistration
{
	REHex::MainWindow::SetupHookRegistration(REHex::MainWindow::SetupPhase phase, const LuaFunction func);
};

class %delete REHex::BitOffset
{
	REHex::BitOffset();
	REHex::BitOffset(off_t byte, int bit);
	
	off_t byte() const;
	int bit() const;
	off_t total_bits();
	bool byte_aligned() const;
	off_t byte_round_up() const;
	
	bool operator<(const REHex::BitOffset &rhs) const;
	bool operator<=(const REHex::BitOffset &rhs) const;
	bool operator==(const REHex::BitOffset &rhs) const;
	
	REHex::BitOffset operator+(const REHex::BitOffset &rhs) const;
	REHex::BitOffset operator-(const REHex::BitOffset &rhs) const;
	
	// BitOffset operator%(const BitOffset &rhs) const;
	
	REHex::BitOffset operator-() const;
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
	REHex::Tab *active_tab();
};

struct %delete REHex::Document::Comment
{
	REHex::Document::Comment(const wxString &text);
};

class REHex::Document: public wxEvtHandler
{
	wxString get_title();
	wxString get_filename();
	
	wxString read_data(REHex::BitOffset offset, off_t max_length) const;
	wxString read_data(off_t offset, off_t max_length) const;
	off_t buffer_length();
	
	LuaTable get_comments() const;
	bool set_comment(REHex::BitOffset offset, REHex::BitOffset length, const REHex::Document::Comment &comment);
	bool set_comment(off_t offset, off_t length, const REHex::Document::Comment &comment);
	bool set_data_type(REHex::BitOffset offset, REHex::BitOffset length, const wxString &type);
	bool set_data_type(off_t offset, off_t length, const wxString &type);
	
	bool set_virt_mapping(off_t real_offset, off_t virt_offset, off_t length);
	void clear_virt_mapping_r(off_t real_offset, off_t length);
	void clear_virt_mapping_v(off_t virt_offset, off_t length);
	
	// TODO const ByteRangeMap<off_t> &get_real_to_virt_segs() const;
	// TODO const ByteRangeMap<off_t> &get_virt_to_real_segs() const;
	
	off_t real_to_virt_offset(off_t real_offset) const;
	off_t virt_to_real_offset(off_t virt_offset) const;
	
	REHex::BitOffset get_cursor_position() const;
	
	void transact_begin(const wxString &desc);
	void transact_commit();
	void transact_rollback();
};

class REHex::Tab: public wxPanel
{
	const REHex::Document *doc;
	
	void get_selection_linear();
};

class REHex::TabCreatedEvent: public wxEvent
{
	%wxEventType REHex::TAB_CREATED
	
	REHex::Tab *tab;
	
	// Filthy hack to get the MainWindow handle into Lua land rather than an opaque userdata.
	REHex::MainWindow *GetEventObject();
};

class REHex::CharacterEncoding
{
	const wxString key;
	const wxString label;
	
	static const REHex::CharacterEncoding *encoding_by_key(const wxString &key);
	static LuaTable all_encodings();
};
