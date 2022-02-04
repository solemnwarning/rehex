// ===========================================================================
// Purpose:     Various wxBase classes
// Author:      Ray Gilbert, John Labenski
// Created:     July 2004
// Copyright:   (c) Ray Gilbert
// Licence:     wxWidgets licence
// wxWidgets:   Updated to 2.8.4
// ===========================================================================

// ---------------------------------------------------------------------------
// wxWidgets version defines

#define wxMAJOR_VERSION
#define wxMINOR_VERSION
#define wxRELEASE_NUMBER
#define wxSUBRELEASE_NUMBER
#define_wxstring wxVERSION_STRING

bool wxCHECK_VERSION(int major, int minor, int release); // actually a define
bool wxCHECK_VERSION_FULL(int major, int minor, int release, int subrel); // actually a define

#define wxABI_VERSION

// ---------------------------------------------------------------------------
// wxWidgets platform defines

%__WINDOWS__       #define __WINDOWS__       1
%__WIN16__         #define __WIN16__         1
%__WIN32__         #define __WIN32__         1
%__WIN95__         #define __WIN95__         1
%__WXBASE__        #define __WXBASE__        1
%__WXCOCOA__       #define __WXCOCOA__       1
%__WXWINCE__       #define __WXWINCE__       1
%__WXGTK__         #define __WXGTK__         1
%__WXGTK12__       #define __WXGTK12__       1
%__WXGTK20__       #define __WXGTK20__       1
%__WXMOTIF__       #define __WXMOTIF__       1
%__WXMOTIF20__     #define __WXMOTIF20__     1
%__WXMAC__         #define __WXMAC__         1
%__WXMAC_CLASSIC__ #define __WXMAC_CLASSIC__ 1
%__WXMAC_CARBON__  #define __WXMAC_CARBON__  1
%__WXMAC_OSX__     #define __WXMAC_OSX__     1
%__WXMGL__         #define __WXMGL__         1
%__WXMSW__         #define __WXMSW__         1
%__WXOS2__         #define __WXOS2__         1
%__WXOSX__         #define __WXOSX__         1
%__WXPALMOS__      #define __WXPALMOS__      1
%__WXPM__          #define __WXPM__          1
%__WXSTUBS__       #define __WXSTUBS__       1
%__WXXT__          #define __WXXT__          1
%__WXX11__         #define __WXX11__         1
%__WXWINE__        #define __WXWINE__        1
%__WXUNIVERSAL__   #define __WXUNIVERSAL__   1
%__X__             #define __X__             1

// ---------------------------------------------------------------------------

#if wxUSE_ON_FATAL_EXCEPTION
    bool wxHandleFatalExceptions(bool doIt = true);
#endif // wxUSE_ON_FATAL_EXCEPTION

// ---------------------------------------------------------------------------
// Network, user, and OS functions

#if !%wxchkver_2_8
enum
{
    wxUNKNOWN_PLATFORM,
    wxCURSES,
    wxXVIEW_X,
    wxMOTIF_X,
    wxCOSE_X,
    wxNEXTSTEP,
    wxMAC,
    wxMAC_DARWIN,
    wxBEOS,
    wxGTK,
    wxGTK_WIN32,
    wxGTK_OS2,
    wxGTK_BEOS,
    wxGEOS,
    wxOS2_PM,
    wxWINDOWS,
    wxMICROWINDOWS,
    wxPENWINDOWS,
    wxWINDOWS_NT,
    wxWIN32S,
    wxWIN95,
    wxWIN386,
    wxWINDOWS_CE,
    wxWINDOWS_POCKETPC,
    wxWINDOWS_SMARTPHONE,
    wxMGL_UNIX,
    wxMGL_X,
    wxMGL_WIN32,
    wxMGL_OS2,
    wxMGL_DOS,
    wxWINDOWS_OS2,
    wxUNIX,
    wxX11,
    wxPALMOS,
    wxDOS
};
#endif // !%wxchkver_2_8

// ---------------------------------------------------------------------------

#define wxNOT_FOUND        //      (-1)

// ---------------------------------------------------------------------------

wxString wxGetEmailAddress();
wxLongLong wxGetFreeMemory();
wxString wxGetFullHostName();
wxString wxGetHomeDir();
wxString wxGetHostName();
wxString wxGetOsDescription();
// %override [int version, int major, int minor] wxGetOsVersion();
// int wxGetOsVersion(int *major = NULL, int *minor = NULL);
int wxGetOsVersion();

wxString wxGetUserHome(const wxString& user = "");
wxString wxGetUserId();
wxString wxGetUserName();

// ---------------------------------------------------------------------------
// Environmental access functions

// %override [bool lua_string] wxGetEnv(const wxString& var);
// Returns success and the string environment variable.
// C++ Func: bool wxGetEnv(const wxString& var, wxString *value);
bool wxGetEnv(const wxString& var);
bool wxSetEnv(const wxString& var, const wxString& value);
bool wxUnsetEnv(const wxString& var);


// ---------------------------------------------------------------------------
// wxSystemOptions

#if wxLUA_USE_wxSystemOptions

#include "wx/sysopt.h"

class wxSystemOptions : public wxObject
{
    //wxSystemOptions(); // No constructor, all member functions static

    static wxString GetOption(const wxString& name) const;
    static int GetOptionInt(const wxString& name) const;
    static bool HasOption(const wxString& name) const;
    static bool IsFalse(const wxString& name) const;

    #if wxUSE_SYSTEM_OPTIONS
        static void SetOption(const wxString& name, const wxString& value);
        static void SetOption(const wxString& name, int value);
    #endif //wxUSE_SYSTEM_OPTIONS
};

#endif //wxLUA_USE_wxSystemOptions


// ---------------------------------------------------------------------------
// wxPlatformInfo

enum wxOperatingSystemId
{
    wxOS_UNKNOWN,                     // returned on error

    wxOS_MAC_OS,                      // Apple Mac OS 8/9/X with Mac paths
    wxOS_MAC_OSX_DARWIN,              // Apple Mac OS X with Unix paths
    wxOS_MAC,                         // wxOS_MAC_OS|wxOS_MAC_OSX_DARWIN,

    wxOS_WINDOWS_9X,                   // Windows 9x family (95/98/ME);
    wxOS_WINDOWS_NT,                   // Windows NT family (NT/2000/XP);
    wxOS_WINDOWS_MICRO,                // MicroWindows
    wxOS_WINDOWS_CE,                   // Windows CE (Window Mobile);
    wxOS_WINDOWS,                      //  wxOS_WINDOWS_9X|wxOS_WINDOWS_NT|wxOS_WINDOWS_MICRO|wxOS_WINDOWS_CE,

    wxOS_UNIX_LINUX,                    // Linux
    wxOS_UNIX_FREEBSD,                  // FreeBSD
    wxOS_UNIX_OPENBSD,                  // OpenBSD
    wxOS_UNIX_NETBSD,                   // NetBSD
    wxOS_UNIX_SOLARIS,                  // SunOS
    wxOS_UNIX_AIX,                      // AIX
    wxOS_UNIX_HPUX,                     // HP/UX
    wxOS_UNIX,                          // wxOS_UNIX_LINUX|wxOS_UNIX_FREEBSD|wxOS_UNIX_OPENBSD|wxOS_UNIX_NETBSD|wxOS_UNIX_SOLARIS|wxOS_UNIX_AIX|wxOS_UNIX_HPUX,

    wxOS_DOS,                           // Microsoft DOS
    wxOS_OS2                            // OS/2
};

enum wxPortId
{
    wxPORT_UNKNOWN,      // returned on error

    wxPORT_BASE,         // wxBase, no native toolkit used

    wxPORT_MSW,          // wxMSW, native toolkit is Windows API
    wxPORT_MOTIF,        // wxMotif, using [Open]Motif or Lesstif
    wxPORT_GTK,          // wxGTK, using GTK+ 1.x, 2.x, GPE or Maemo
    !%wxchkver_2_9 wxPORT_MGL,          // wxMGL, using wxUniversal
    wxPORT_X11,          // wxX11, using wxUniversal
    wxPORT_PM,           // wxOS2, using OS/2 Presentation Manager
    wxPORT_OS2,          // wxOS2, using OS/2 Presentation Manager
    wxPORT_MAC,          // wxMac, using Carbon or Classic Mac API
    wxPORT_COCOA,        // wxCocoa, using Cocoa NextStep/Mac API
    wxPORT_WINCE,        // wxWinCE, toolkit is WinCE SDK API
    !%wxchkver_2_9 wxPORT_PALMOS,       // wxPalmOS, toolkit is PalmOS API
    wxPORT_DFB           // wxDFB, using wxUniversal
};

#if %wxchkver_3_1_5
enum wxBitness
{
    wxBITNESS_INVALID,             //!< returned on error

    wxBITNESS_32,                  //!< 32 bit
    wxBITNESS_64,                  //!< 64 bit

    wxBITNESS_MAX
};
#endif // !%wxchkver_3_1_5

enum wxArchitecture
{
    wxARCH_INVALID,         // returned on error

    wxARCH_32,              // 32 bit
    wxARCH_64,

    wxARCH_MAX
};

enum wxEndianness
{
    wxENDIAN_INVALID,           // returned on error

    wxENDIAN_BIG,               // 4321
    wxENDIAN_LITTLE,            // 1234
    wxENDIAN_PDP,               // 3412

    wxENDIAN_MAX
};

class wxPlatformInfo
{
    // No constructor, use static Get() function
    //wxPlatformInfo();
    //wxPlatformInfo(wxPortId pid, int tkMajor = -1, int tkMinor = -1, wxOperatingSystemId id = wxOS_UNKNOWN, int osMajor = -1, int osMinor = -1, wxArchitecture arch = wxARCH_INVALID, wxEndianness endian = wxENDIAN_INVALID, bool usingUniversal = false);

    // Gets a wxPlatformInfo already initialized with the values for
    // the currently running platform.
    //static const wxPlatformInfo& Get();
    static const wxPlatformInfo& Get();

    static wxOperatingSystemId GetOperatingSystemId(const wxString &name);
    static wxPortId GetPortId(const wxString &portname);

    static wxArchitecture GetArch(const wxString &arch);
    static wxEndianness GetEndianness(const wxString &end);

    static wxString GetOperatingSystemFamilyName(wxOperatingSystemId os);
    static wxString GetOperatingSystemIdName(wxOperatingSystemId os);
    static wxString GetPortIdName(wxPortId port, bool usingUniversal);
    static wxString GetPortIdShortName(wxPortId port, bool usingUniversal);

    !%wxchkver_3_1_5 static wxString GetArchName(wxArchitecture arch);
    %wxchkver_3_1_5 static wxString GetBitnessName(wxBitness bitness);
    static wxString GetEndiannessName(wxEndianness end);

    int GetOSMajorVersion() const;
    int GetOSMinorVersion() const;

    bool CheckOSVersion(int major, int minor) const;

    int GetToolkitMajorVersion() const;
    int GetToolkitMinorVersion() const;

    bool CheckToolkitVersion(int major, int minor) const;
    bool IsUsingUniversalWidgets() const;

    wxOperatingSystemId GetOperatingSystemId() const;
    wxPortId GetPortId() const;
    wxArchitecture GetArchitecture() const;
    wxEndianness GetEndianness() const;

    wxString GetOperatingSystemFamilyName() const;
    wxString GetOperatingSystemIdName() const;
    wxString GetPortIdName() const;
    wxString GetPortIdShortName() const;
    !%wxchkver_3_1_5 wxString GetArchName() const;
    %wxchkver_3_1_5 wxString GetBitnessName() const;
    wxString GetEndiannessName() const;

    void SetOSVersion(int major, int minor);
    void SetToolkitVersion(int major, int minor);
    void SetOperatingSystemId(wxOperatingSystemId n);
    void SetPortId(wxPortId n);
    void SetArchitecture(wxArchitecture n);
    void SetEndianness(wxEndianness n);

    bool IsOk() const;

    //bool operator==(const wxPlatformInfo &t) const; // we only use the wxWidget's wxPlatformInfo
    //bool operator!=(const wxPlatformInfo &t) const;
};


// ---------------------------------------------------------------------------
// wxSingleInstanceChecker

#if wxUSE_SNGLINST_CHECKER

#include "wx/snglinst.h"

class %delete wxSingleInstanceChecker
{
    wxSingleInstanceChecker(); // default ctor, use Create() after it
    // like Create() but no error checking (dangerous!);
    //wxSingleInstanceChecker(const wxString& name, const wxString& path = "");

    // name must be given and be as unique as possible, it is used as the mutex
    // name under Win32 and the lock file name under Unix -
    // wxTheApp->GetAppName() may be a good value for this parameter
    //
    // path is optional and is ignored under Win32 and used as the directory to
    // create the lock file in under Unix (default is wxGetHomeDir());
    //
    // returns false if initialization failed, it doesn't mean that another
    // instance is running - use IsAnotherRunning() to check it
    bool Create(const wxString& name, const wxString& path = "");

    bool IsAnotherRunning() const; // is another copy of this program already running?
};

#endif // wxUSE_SNGLINST_CHECKER


// ---------------------------------------------------------------------------
// wxLog - See GUI log bindings in wxcore_core.i

#if wxLUA_USE_wxLog && wxUSE_LOG

#include "wx/log.h"

// These functions are in log.h
unsigned long wxSysErrorCode();
wxString wxSysErrorMsg(unsigned long nErrCode = 0);

void wxSafeShowMessage(const wxString& title, const wxString& text);

// All of the wxLogXXX functions take only a single string,
// use string.format(...) to format the string in Lua.

// C++ Func: void wxLogError(const char *formatString, ...);
void wxLogError(const wxString& message);
// C++ Func: void wxLogFatalError(const char *formatString, ...);
void wxLogFatalError(const wxString& message);
// C++ Func: void wxLogWarning(const char *formatString, ...);
void wxLogWarning(const wxString& message);
// C++ Func: void wxLogMessage(const char *formatString, ...);
void wxLogMessage(const wxString& message);
// C++ Func: void wxLogVerbose(const char *formatString, ...);
void wxLogVerbose(const wxString& message);
// C++ Func: void wxLogStatus(wxFrame *frame, const char *formatString, ...);
// void wxLogStatus(const char *formatString, ...); // this just uses the toplevel frame, use wx.NULL for the frame
// IN wxCore void wxLogStatus(wxFrame *frame, const wxString& message);

// C++ Func: void wxLogSysError(const char *formatString, ...);
void wxLogSysError(const wxString& message);
// C++ Func: void wxLogDebug(const char *formatString, ...);
void wxLogDebug(const wxString& message);
// C++ Func: void wxLogTrace(const char *mask, const char *formatString, ...);
void wxLogTrace(const wxString& mask, const wxString& message);
// void wxLogTrace(const char *formatString, ...);
// void wxLogTrace(wxTraceMask mask, const char *formatString, ...) - deprecated

typedef unsigned long wxTraceMask
typedef unsigned long wxLogLevel

enum // wxLogLevel - uses these enums
{
    wxLOG_FatalError, // program can't continue, abort immediately
    wxLOG_Error,      // a serious error, user must be informed about it
    wxLOG_Warning,    // user is normally informed about it but may be ignored
    wxLOG_Message,    // normal message (i.e. normal output of a non GUI app);
    wxLOG_Status,     // informational: might go to the status line of GUI app
    wxLOG_Info,       // informational message (a.k.a. 'Verbose');
    wxLOG_Debug,      // never shown to the user, disabled in release mode
    wxLOG_Trace,      // trace messages are also only enabled in debug mode
    wxLOG_Progress,   // used for progress indicator (not yet);

    wxLOG_User,       // user defined levels start here
    wxLOG_Max
};

// symbolic trace masks - wxLogTrace("foo", "some trace message...") will be
// discarded unless the string "foo" has been added to the list of allowed
// ones with AddTraceMask();
#define_wxstring wxTRACE_MemAlloc //wxT("memalloc"); // trace memory allocation (new/delete);
#define_wxstring wxTRACE_Messages //wxT("messages"); // trace window messages/X callbacks
#define_wxstring wxTRACE_ResAlloc //wxT("resalloc"); // trace GDI resource allocation
#define_wxstring wxTRACE_RefCount //wxT("refcount"); // trace various ref counting operations
%msw #define_wxstring wxTRACE_OleCalls //wxT("ole"); // OLE interface calls

class %delete wxLog
{
    //wxLog() - No constructor, a base class, use one of the derived classes.

    static bool IsEnabled();
    static bool EnableLogging(bool doIt = true);
    virtual void Flush();
    static void FlushActive();
    // Don't delete the active target until you set a new one or set it to wx.NULL
    // Note, a new wxLog is created unless DontCreateOnDemand() is called.
    static wxLog *GetActiveTarget();
    // When you create a new wxLog and call "oldLog = SetActiveTarget(MyLog)"
    // the returned oldLog will be garbage collected or you can delete() the
    // oldLog unless you want to reuse it by calling "myLog = SetActiveTarget(oldLog)"
    // which releases myLog to be garbage collected or delete()ed by you.
    // Basicly, wxWidgets 'owns' the log you pass to SetActiveTarget() and
    // wxLua 'owns' the returned log.
    static %gc wxLog *SetActiveTarget(%ungc wxLog *pLogger);
    static void Suspend();
    static void Resume();
    static void SetVerbose(bool bVerbose = true);
    static void SetLogLevel(wxLogLevel logLevel);
    static void DontCreateOnDemand();
    %wxchkver_2_8 static void SetRepetitionCounting(bool bRepetCounting = true);
    %wxchkver_2_8 static bool GetRepetitionCounting();
    !%wxchkver_2_9 || %wxcompat_2_8 static void SetTraceMask(wxTraceMask ulMask);
    static void AddTraceMask(const wxString& str);
    static void RemoveTraceMask(const wxString& str);
    static void ClearTraceMasks();
    static wxArrayString GetTraceMasks(); // not const wxArrayString since we copy it anyway

    // %override static void wxLog::SetTimestamp(const wxString& ts);
    // Allows an input of "nil" or no value to disable time stamping.
    // C++ Func: static void wxLog::SetTimestamp(const wxChar* ts);
    static void SetTimestamp(const wxString& ts);

    static bool GetVerbose();
    !%wxchkver_2_9 || %wxcompat_2_8 static wxTraceMask GetTraceMask();
    static bool IsAllowedTraceMask(const wxString& mask);
    static wxLogLevel GetLogLevel();
    static wxString GetTimestamp();
};

// ---------------------------------------------------------------------------
// wxLogBuffer

class %delete wxLogBuffer : public wxLog
{
    wxLogBuffer();

    const wxString& GetBuffer() const; // get the string contents with all messages logged
};

// ---------------------------------------------------------------------------
// wxLogChain

class %delete wxLogChain : public wxLog
{
    wxLogChain(wxLog *logger);

    void SetLog(wxLog *logger); // change the new log target
    // this can be used to temporarily disable (and then reenable) passing
    // messages to the old logger (by default we do pass them);
    void PassMessages(bool bDoPass);
    // are we passing the messages to the previous log target?
    bool IsPassingMessages() const;
    // return the previous log target (may be NULL);
    wxLog *GetOldLog() const;
};

// ---------------------------------------------------------------------------
// wxLogNull

class %delete wxLogNull // NOTE: this is not derived from wxLog
{
    // NOTE: ALWAYS delete() this when done since Lua's gc may not delete it soon enough
    wxLogNull();
};

// ---------------------------------------------------------------------------
// wxLogPassThrough - a chain log target which uses itself as the new logger

class %delete wxLogPassThrough : public wxLogChain
{
    wxLogPassThrough();
};

// ---------------------------------------------------------------------------
// wxLogStderr - FIXME need to implement FILE*

/*
class %delete wxLogStderr : public wxLog
{
    wxLogStderr(FILE *fp = (FILE *) NULL); // redirect log output to a FILE
};
*/

// ---------------------------------------------------------------------------
// wxLogStream - FIXME need to implement wxSTD ostream* (just use wxLogBuffer);

/*
#if wxUSE_STD_IOSTREAM

class %delete wxLogStream : public wxLog
{
    wxLogStream(wxSTD ostream *ostr = NULL); // redirect log output to an ostream
};

#endif // wxUSE_STD_IOSTREAM
*/

#endif // wxLUA_USE_wxLog && wxUSE_LOG

// ---------------------------------------------------------------------------
// wxDynamicLibrary - No a lot you can do with this, but it might make
//                    testing or debugging a C++ program easier to test thing
//                    out in wxLua first.

#if // wxLUA_USE_wxDynamicLibrary && wxUSE_DYNLIB_CLASS

#include "wx/dynlib.h"

enum wxDLFlags
{
    wxDL_LAZY,       // resolve undefined symbols at first use
                    // (only works on some Unix versions);
    wxDL_NOW,        // resolve undefined symbols on load
                    // (default, always the case under Win32);
    wxDL_GLOBAL,     // export extern symbols to subsequently
                    // loaded libs.
    wxDL_VERBATIM,   // attempt to load the supplied library
                    // name without appending the usual dll
                    // filename extension.
    wxDL_NOSHARE,    // load new DLL, don't reuse already loaded
                    // (only for wxPluginManager);

    wxDL_DEFAULT,    // = wxDL_NOW // default flags correspond to Win32
};

enum wxDynamicLibraryCategory
{
    wxDL_LIBRARY,       // standard library
    wxDL_MODULE         // loadable module/plugin
};

enum wxPluginCategory
{
    wxDL_PLUGIN_GUI,    // plugin that uses GUI classes
    wxDL_PLUGIN_BASE    // wxBase-only plugin
};


class %delete wxDynamicLibraryDetails
{
    // ctor, normally never used as these objects are only created by wxDynamicLibrary
    // wxDynamicLibrary::ListLoaded();
    //wxDynamicLibraryDetails() { m_address = NULL; m_length = 0; }

    wxString GetName() const; // get the (base) name
    wxString GetPath() const; // get the full path of this object

    // get the load address and the extent, return true if this information is available
    //bool GetAddress(void **addr, size_t *len) const;

    wxString GetVersion() const; // return the version of the DLL (may be empty if no version info);
};

class %delete wxDynamicLibraryDetailsArray
{
    //wxDynamicLibraryDetailsArray(); // Get this from wxDynamicLibrary::ListLoaded

    int  GetCount() const;
    wxDynamicLibraryDetails Item(int n);
};


class %delete wxDynamicLibrary
{
    wxDynamicLibrary();
    wxDynamicLibrary(const wxString& libname, int flags = wxDL_DEFAULT);

    // return a valid handle for the main program itself or NULL if back
    // linking is not supported by the current platform (e.g. Win32);
    //static wxDllType GetProgramHandle();

    // return the platform standard DLL extension (with leading dot);
    //static const wxChar *GetDllExt();
    static wxString GetDllExt();

    // return true if the library was loaded successfully
    bool IsLoaded() const;

    // load the library with the given name (full or not), return true if ok
    bool Load(const wxString& libname, int flags = wxDL_DEFAULT);

    // raw function for loading dynamic libs: always behaves as if
    // wxDL_VERBATIM were specified and doesn't log error message if the
    // library couldn't be loaded but simply returns NULL
    //static wxDllType RawLoad(const wxString& libname, int flags = wxDL_DEFAULT);

    // detach the library object from its handle, i.e. prevent the object from
    // unloading the library in its dtor -- the caller is now responsible for doing this
    //wxDllType Detach();

    // unload the given library handle (presumably returned by Detach() before);
    //static void Unload(wxDllType handle);

    // unload the library, also done automatically in dtor
    void Unload();

    // Return the raw handle from dlopen and friends.
    //wxDllType GetLibHandle() const; // { return m_handle; }

    // check if the given symbol is present in the library, useful to verify if
    // a loadable module is our plugin, for example, without provoking error
    // messages from GetSymbol();
    bool HasSymbol(const wxString& name) const;

    // resolve a symbol in a loaded DLL, such as a variable or function name.
    // 'name' is the (possibly mangled) name of the symbol. (use extern "C" to
    // export unmangled names);
    // Since it is perfectly valid for the returned symbol to actually be NULL,
    // that is not always indication of an error.  Pass and test the parameter
    // 'success' for a true indication of success or failure to load the symbol.
    // Returns a pointer to the symbol on success, or NULL if an error occurred
    // or the symbol wasn't found.
    //void *GetSymbol(const wxString& name, bool *success = NULL) const;

    // low-level version of GetSymbol();
    //static void *RawGetSymbol(wxDllType handle, const wxString& name);
    //void *RawGetSymbol(const wxString& name) const;

//#ifdef __WXMSW__
    // this function is useful for loading functions from the standard Windows
    // DLLs: such functions have an 'A' (in ANSI build) or 'W' (in Unicode, or
    // wide character build) suffix if they take string parameters
    //static void *RawGetSymbolAorW(wxDllType handle, const wxString& name);
    //void *GetSymbolAorW(const wxString& name) const;
//#endif // __WXMSW__

    // return all modules/shared libraries in the address space of this process
    // returns an empty array if not implemented or an error occurred
    static wxDynamicLibraryDetailsArray ListLoaded();

    // return platform-specific name of dynamic library with proper extension
    // and prefix (e.g. "foo.dll" on Windows or "libfoo.so" on Linux);
    static wxString CanonicalizeName(const wxString& name, wxDynamicLibraryCategory cat = wxDL_LIBRARY);

    // return name of wxWidgets plugin (adds compiler and version info
    // to the filename):
    static wxString CanonicalizePluginName(const wxString& name, wxPluginCategory cat = wxDL_PLUGIN_GUI);

    // return plugin directory on platforms where it makes sense and empty string on others:
    static wxString GetPluginsDirectory();
};

// ---------------------------------------------------------------------------
// wxPluginLibrary - You cannot use this within wxLua

// ---------------------------------------------------------------------------
// wxPluginManager - You cannot use this within wxLua

#endif // wxLUA_USE_wxDynamicLibrary && wxUSE_DYNLIB_CLASS


// ---------------------------------------------------------------------------
// wxCriticalSection

#if wxLUA_USE_wxCriticalSection && wxUSE_THREADS

#include "wx/thread.h"

class %delete wxCriticalSection
{
    wxCriticalSection();
    void Enter();
    void Leave();
};

#endif // wxLUA_USE_wxCriticalSection


// ---------------------------------------------------------------------------
// wxCriticalSectionLocker

#if wxLUA_USE_wxCriticalSectionLocker

#include "wx/thread.h"

class %delete wxCriticalSectionLocker
{
    wxCriticalSectionLocker(wxCriticalSection& cs);
};

#endif // wxLUA_USE_wxCriticalSectionLocker && wxUSE_THREADS


// ---------------------------------------------------------------------------
//  wxRegEx - Regular expression support

#if wxLUA_USE_wxRegEx && wxUSE_REGEX

#include "wx/regex.h"

enum
{
    wxRE_EXTENDED,
    wxRE_BASIC,
    wxRE_ICASE,
    wxRE_NOSUB,
    wxRE_NEWLINE,
    wxRE_DEFAULT
};

enum
{
    wxRE_NOTBOL,
    wxRE_NOTEOL
};

class %delete wxRegEx
{
    wxRegEx();
    wxRegEx(const wxString& expr, int flags = wxRE_DEFAULT);

    bool Compile(const wxString& pattern, int flags = wxRE_DEFAULT);
    bool IsValid() const;
    wxString GetMatch(const wxString& text, size_t index = 0) const;

    // %override [bool, size_t start, size_t len] wxRegEx::GetMatch(size_t index = 0) const;
    // C++ Func: bool GetMatch(size_t* start, size_t* len, size_t index = 0) const;
    %override_name wxLua_wxRegEx_GetMatchIndexes bool GetMatch(size_t index = 0) const;

    size_t GetMatchCount() const;
    // Note: only need this form of Matches
    bool Matches(const wxString &text, int flags = 0) const;

    // %override [int, string text] wxRegEx::Replace(const wxString& text, const wxString& replacement, size_t maxMatches = 0) const;
    // C++ Func: int Replace(wxString* text, const wxString& replacement, size_t maxMatches = 0) const;
    int Replace(const wxString& text, const wxString& replacement, size_t maxMatches = 0) const;

    // %override [int, string text] wxRegEx::ReplaceAll(const wxString& text, const wxString& replacement) const;
    // C++ Func: int ReplaceAll(wxString* text, const wxString& replacement) const;
    int ReplaceAll(const wxString& text, const wxString& replacement) const;

    // %override [int, string text] wxRegEx::ReplaceFirst(const wxString& text, const wxString& replacement) const;
    // C++ Func: int ReplaceFirst(wxString* text, const wxString& replacement) const;
    int ReplaceFirst(const wxString& text, const wxString& replacement) const;
};

#endif //wxLUA_USE_wxRegEx && wxUSE_REGEX

// ---------------------------------------------------------------------------
// wxEvtHandler

#include "wx/event.h"

class %delete wxEventLoopBase
{
    %wxchkver_3_0_0 static wxEventLoopBase *GetActive();
    %wxchkver_3_0_0 static void SetActive(wxEventLoopBase* loop);
    %wxchkver_3_0_0 bool IsMain() const;
    %wxchkver_3_0_0 int Run();
    %wxchkver_3_0_0 bool IsRunning() const;
    %wxchkver_3_0_0 bool IsOk() const;
    %wxchkver_3_0_0 void Exit(int rc = 0);
    %wxchkver_3_0_0 void ScheduleExit(int rc = 0);
    %wxchkver_3_0_0 bool Pending() const;
    %wxchkver_3_0_0 bool Dispatch();
    %wxchkver_3_0_0 int DispatchTimeout(unsigned long timeout);
    %wxchkver_3_0_0 void WakeUp();
    %wxchkver_3_0_0 void WakeUpIdle();
    %wxchkver_3_0_0 bool ProcessIdle();
    %wxchkver_3_0_0 bool IsYielding() const;
    %wxchkver_3_0_0 bool Yield(bool onlyIfNeeded = false);
    %wxchkver_3_0_0 bool YieldFor(long eventsToProcess);
    %wxchkver_3_0_0 bool IsEventAllowedInsideYield(wxEventCategory cat) const;
};

class wxEventFilter
{
    // wxEventFilter(); // no constructor as it's an abstract class
    %wxchkver_3_0_0 int FilterEvent(wxEvent& event);
};

class %delete wxEvtHandler : public wxObject
{
    wxEvtHandler();
    %wxchkver_2_9 virtual void QueueEvent(%ungc wxEvent *event);
    %wxchkver_3_0_0 void AddPendingEvent(const wxEvent& event);
    virtual bool ProcessEvent(wxEvent& event);
    %wxchkver_3_0_0 bool ProcessEventLocally(wxEvent& event);
    %wxchkver_3_0_0 bool SafelyProcessEvent(wxEvent& event);
    %wxchkver_3_0_0 void ProcessPendingEvents();
    %wxchkver_3_0_0 void DeletePendingEvents();
    // void Connect(int id, int lastId, wxEventType eventType, wxObjectEventFunction function, wxObject* userData = NULL, wxEvtHandler* eventSink = NULL);
    // void Connect(int id, wxEventType eventType, wxObjectEventFunction function, wxObject* userData = NULL, wxEvtHandler* eventSink = NULL);
    // void Connect(wxEventType eventType, wxObjectEventFunction function, wxObject* userData = NULL, wxEvtHandler* eventSink = NULL);
    // void Bind(const EventTag& eventType, Functor functor, int id = wxID_ANY, int lastId = wxID_ANY, wxObject *userData = NULL);
    // bool Unbind(const EventTag& eventType, Functor functor, int id = wxID_ANY, int lastId = wxID_ANY, wxObject *userData = NULL);
    voidptr_long GetClientData(); // %override C++ returns (void *) You get a number here
    wxClientData* GetClientObject() const;
    void SetClientObject(wxClientData* data);
    bool GetEvtHandlerEnabled();
    wxEvtHandler* GetNextHandler();
    wxEvtHandler* GetPreviousHandler();
    void SetEvtHandlerEnabled(bool enabled);
    void SetNextHandler(wxEvtHandler* handler);
    void SetPreviousHandler(wxEvtHandler* handler);
    %wxchkver_3_0_0 void Unlink();
    %wxchkver_3_0_0 bool IsUnlinked() const;
    %wxchkver_3_0_0 static void AddFilter(wxEventFilter* filter);
    %wxchkver_3_0_0 static void RemoveFilter(wxEventFilter* filter);
    !%wxchkver_3_0_0 void AddPendingEvent(wxEvent& event);
    %wxchkver_2_9_5 void CallAfter(); // %override to pass a function
    // bool SearchEventTable(wxEventTable& table, wxEvent& event); // no wxEventTable
    bool Disconnect(int id, int lastId, wxEventType eventType); // %override parameters
    void Connect(int id, int lastId, wxEventType eventType, LuaFunction func); // %add parameters
    void SetClientData(voidptr_long number); // %override C++ is (void *clientData) You can put a number here
};

// ---------------------------------------------------------------------------
// wxEvent

enum Propagation_state
{
    wxEVENT_PROPAGATE_NONE, // don't propagate it at all
    wxEVENT_PROPAGATE_MAX  // propagate it until it is processed
};

#if %wxchkver_3_0_0
enum wxEventCategory
{
    /**
        This is the category for those events which are generated to update
        the appearance of the GUI but which (usually) do not comport data
        processing, i.e. which do not provide input or output data
        (e.g. size events, scroll events, etc).
        They are events NOT directly generated by the user's input devices.
    */
    wxEVT_CATEGORY_UI = 1,

    /**
        This category groups those events which are generated directly from the
        user through input devices like mouse and keyboard and usually result in
        data to be processed from the application
        (e.g. mouse clicks, key presses, etc).
    */
    wxEVT_CATEGORY_USER_INPUT = 2,

    /// This category is for wxSocketEvent
    wxEVT_CATEGORY_SOCKET = 4,

    /// This category is for wxTimerEvent
    wxEVT_CATEGORY_TIMER = 8,

    /**
        This category is for any event used to send notifications from the
        secondary threads to the main one or in general for notifications among
        different threads (which may or may not be user-generated).
        See e.g. wxThreadEvent.
    */
    wxEVT_CATEGORY_THREAD = 16,

    /**
        This mask is used in wxEventLoopBase::YieldFor to specify that all event
        categories should be processed.
    */
    wxEVT_CATEGORY_ALL =
        wxEVT_CATEGORY_UI|wxEVT_CATEGORY_USER_INPUT|wxEVT_CATEGORY_SOCKET| \
        wxEVT_CATEGORY_TIMER|wxEVT_CATEGORY_THREAD
};
#endif

class %delete wxEvent : public wxObject
{
    // wxEvent(int id = 0, wxEventType eventType = wxEVT_NULL); // no constructor as it's an abstract class
    // wxEvent* Clone() const; // no constructor as it's an abstract class
    wxObject* GetEventObject();
    wxEventType GetEventType();
    %wxchkver_3_0_0 wxEventCategory GetEventCategory() const;
    int GetId();
    %wxchkver_3_0_0 wxObject *GetEventUserData() const;
    bool GetSkipped();
    long GetTimestamp();
    bool IsCommandEvent() const;
    void ResumePropagation(int propagationLevel);
    void SetEventObject(wxObject* object);
    void SetEventType(wxEventType type);
    void SetId(int id);
    void SetTimestamp(long timeStamp);
    bool ShouldPropagate() const;
    void Skip(bool skip = true);
    int StopPropagation();
};

#if %wxchkver_2_9_2
class wxVersionInfo
{
public:
    wxVersionInfo(const wxString& name = "",
                  int major = 0,
                  int minor = 0,
                  int micro = 0,
                  const wxString& description = "",
                  const wxString& copyright = "");
    const wxString& GetName() const;
    int GetMajor() const;
    int GetMinor() const;
    int GetMicro() const;
    wxString ToString() const;
    wxString GetVersionString() const;
    bool HasDescription() const;
    const wxString& GetDescription();
    bool HasCopyright() const;
    const wxString& GetCopyright() const;
};
#endif

#if wxUSE_INTL

#if %wxchkver_2_9_1 && wxLUA_USE_wxTranslations

// ----------------------------------------------------------------------------
// wxMsgCatalog corresponds to one loaded message catalog.
// ----------------------------------------------------------------------------

class %delete wxMsgCatalog
{
public:
    // load the catalog from disk or from data; caller is responsible for
    // deleting them if not NULL
    static wxMsgCatalog *CreateFromFile(const wxString& filename,
                                        const wxString& domain);

    // get name of the catalog
    wxString GetDomain() const;

    // get the translated string: returns NULL if not found
    !%wxchkver_3_1_1 const wxString *GetString(const wxString& sz, unsigned int n = UINT_MAX) const;
    %wxchkver_3_1_1 const wxString *GetString(const wxString& sz, unsigned int n = UINT_MAX, const wxString& ct = "") const;
};


// abstraction of translations discovery and loading
class %delete wxTranslationsLoader
{
public:
    wxTranslationsLoader();

    virtual wxMsgCatalog *LoadCatalog(const wxString& domain,
                                      const wxString& lang) = 0;

    virtual wxArrayString GetAvailableTranslations(const wxString& domain) const = 0;
};


// standard wxTranslationsLoader implementation, using filesystem
class %delete wxFileTranslationsLoader : public wxTranslationsLoader
{
public:
    static void AddCatalogLookupPathPrefix(const wxString& prefix);
    virtual wxMsgCatalog *LoadCatalog(const wxString& domain, const wxString& lang);
    virtual wxArrayString GetAvailableTranslations(const wxString& domain) const;
};


#if defined(__WINDOWS__)
// loads translations from win32 resources
class %delete wxResourceTranslationsLoader : public wxTranslationsLoader
{
public:
    virtual wxMsgCatalog *LoadCatalog(const wxString& domain, const wxString& lang);
	virtual wxArrayString GetAvailableTranslations(const wxString& domain) const;

};
#endif // __WINDOWS__

// ----------------------------------------------------------------------------
// wxTranslations: message catalogs
// ----------------------------------------------------------------------------

// this class allows to get translations for strings
class %delete wxTranslations
{
public:
    wxTranslations();

    // returns current translations object, may return NULL
    static wxTranslations *Get();
    // sets current translations object (takes ownership; may be NULL)
    static void Set(wxTranslations *t);

    // changes loader to non-default one; takes ownership of 'loader'
    void SetLoader(wxTranslationsLoader *loader);

    void SetLanguage(wxLanguage lang);
    void SetLanguage(const wxString& lang);

    // get languages available for this app
    wxArrayString GetAvailableTranslations(const wxString& domain) const;

    // find best translation language for given domain
    wxString GetBestTranslation(const wxString& domain, wxLanguage msgIdLanguage);
    wxString GetBestTranslation(const wxString& domain,
                                const wxString& msgIdLanguage = "en");

    // add standard wxWidgets catalog ("wxstd")
    bool AddStdCatalog();

    // add catalog with given domain name and language, looking it up via
    // wxTranslationsLoader
    bool AddCatalog(const wxString& domain,
                    wxLanguage msgIdLanguage = wxLANGUAGE_ENGLISH_US);
#if !wxUSE_UNICODE
    bool AddCatalog(const wxString& domain,
                    wxLanguage msgIdLanguage,
                    const wxString& msgIdCharset);
#endif

    // check if the given catalog is loaded
    bool IsLoaded(const wxString& domain) const;

    // access to translations
    !%wxchkver_3_1_1 const wxString *GetTranslatedString(const wxString& origString,
                                        const wxString& domain = wxEmptyString) const;
    !%wxchkver_3_1_1 const wxString *GetTranslatedString(const wxString& origString,
                                        unsigned int n,
                                        const wxString& domain = wxEmptyString) const;

    %wxchkver_3_1_1 const wxString *GetTranslatedString(const wxString& origString,
                                        const wxString& domain = "",
                                        const wxString& context = "") const;
    %wxchkver_3_1_1 const wxString *GetTranslatedString(const wxString& origString,
                                        unsigned int n,
                                        const wxString& domain = "",
                                        const wxString& context = "") const;

    wxString GetHeaderValue(const wxString& header,
                            const wxString& domain = "") const;

    // this is hack to work around a problem with wxGetTranslation() which
    // returns const wxString& and not wxString, so when it returns untranslated
    // string, it needs to have a copy of it somewhere
    static const wxString& GetUntranslatedString(const wxString& str);
};

#endif //%wxchkver_2_9_1 && wxLUA_USE_wxTranslations

// ---------------------------------------------------------------------------
// wxLocale

#include "wx/intl.h"

enum wxLanguage
{
    // user's default/preffered language as got from OS:
    wxLANGUAGE_DEFAULT,
    // unknown language, if wxLocale::GetSystemLanguage fails:
    wxLANGUAGE_UNKNOWN,

    wxLANGUAGE_ABKHAZIAN,
    wxLANGUAGE_AFAR,
    wxLANGUAGE_AFRIKAANS,
    wxLANGUAGE_ALBANIAN,
    wxLANGUAGE_AMHARIC,
    wxLANGUAGE_ARABIC,
    wxLANGUAGE_ARABIC_ALGERIA,
    wxLANGUAGE_ARABIC_BAHRAIN,
    wxLANGUAGE_ARABIC_EGYPT,
    wxLANGUAGE_ARABIC_IRAQ,
    wxLANGUAGE_ARABIC_JORDAN,
    wxLANGUAGE_ARABIC_KUWAIT,
    wxLANGUAGE_ARABIC_LEBANON,
    wxLANGUAGE_ARABIC_LIBYA,
    wxLANGUAGE_ARABIC_MOROCCO,
    wxLANGUAGE_ARABIC_OMAN,
    wxLANGUAGE_ARABIC_QATAR,
    wxLANGUAGE_ARABIC_SAUDI_ARABIA,
    wxLANGUAGE_ARABIC_SUDAN,
    wxLANGUAGE_ARABIC_SYRIA,
    wxLANGUAGE_ARABIC_TUNISIA,
    wxLANGUAGE_ARABIC_UAE,
    wxLANGUAGE_ARABIC_YEMEN,
    wxLANGUAGE_ARMENIAN,
    wxLANGUAGE_ASSAMESE,
    wxLANGUAGE_AYMARA,
    wxLANGUAGE_AZERI,
    wxLANGUAGE_AZERI_CYRILLIC,
    wxLANGUAGE_AZERI_LATIN,
    wxLANGUAGE_BASHKIR,
    wxLANGUAGE_BASQUE,
    wxLANGUAGE_BELARUSIAN,
    wxLANGUAGE_BENGALI,
    wxLANGUAGE_BHUTANI,
    wxLANGUAGE_BIHARI,
    wxLANGUAGE_BISLAMA,
    wxLANGUAGE_BRETON,
    wxLANGUAGE_BULGARIAN,
    wxLANGUAGE_BURMESE,
    wxLANGUAGE_CAMBODIAN,
    wxLANGUAGE_CATALAN,
    wxLANGUAGE_CHINESE,
    wxLANGUAGE_CHINESE_SIMPLIFIED,
    wxLANGUAGE_CHINESE_TRADITIONAL,
    wxLANGUAGE_CHINESE_HONGKONG,
    wxLANGUAGE_CHINESE_MACAU,
    wxLANGUAGE_CHINESE_SINGAPORE,
    wxLANGUAGE_CHINESE_TAIWAN,
    wxLANGUAGE_CORSICAN,
    wxLANGUAGE_CROATIAN,
    wxLANGUAGE_CZECH,
    wxLANGUAGE_DANISH,
    wxLANGUAGE_DUTCH,
    wxLANGUAGE_DUTCH_BELGIAN,
    wxLANGUAGE_ENGLISH,
    wxLANGUAGE_ENGLISH_UK,
    wxLANGUAGE_ENGLISH_US,
    wxLANGUAGE_ENGLISH_AUSTRALIA,
    wxLANGUAGE_ENGLISH_BELIZE,
    wxLANGUAGE_ENGLISH_BOTSWANA,
    wxLANGUAGE_ENGLISH_CANADA,
    wxLANGUAGE_ENGLISH_CARIBBEAN,
    wxLANGUAGE_ENGLISH_DENMARK,
    wxLANGUAGE_ENGLISH_EIRE,
    wxLANGUAGE_ENGLISH_JAMAICA,
    wxLANGUAGE_ENGLISH_NEW_ZEALAND,
    wxLANGUAGE_ENGLISH_PHILIPPINES,
    wxLANGUAGE_ENGLISH_SOUTH_AFRICA,
    wxLANGUAGE_ENGLISH_TRINIDAD,
    wxLANGUAGE_ENGLISH_ZIMBABWE,
    wxLANGUAGE_ESPERANTO,
    wxLANGUAGE_ESTONIAN,
    wxLANGUAGE_FAEROESE,
    wxLANGUAGE_FARSI,
    wxLANGUAGE_FIJI,
    wxLANGUAGE_FINNISH,
    wxLANGUAGE_FRENCH,
    wxLANGUAGE_FRENCH_BELGIAN,
    wxLANGUAGE_FRENCH_CANADIAN,
    wxLANGUAGE_FRENCH_LUXEMBOURG,
    wxLANGUAGE_FRENCH_MONACO,
    wxLANGUAGE_FRENCH_SWISS,
    wxLANGUAGE_FRISIAN,
    wxLANGUAGE_GALICIAN,
    wxLANGUAGE_GEORGIAN,
    wxLANGUAGE_GERMAN,
    wxLANGUAGE_GERMAN_AUSTRIAN,
    wxLANGUAGE_GERMAN_BELGIUM,
    wxLANGUAGE_GERMAN_LIECHTENSTEIN,
    wxLANGUAGE_GERMAN_LUXEMBOURG,
    wxLANGUAGE_GERMAN_SWISS,
    wxLANGUAGE_GREEK,
    wxLANGUAGE_GREENLANDIC,
    wxLANGUAGE_GUARANI,
    wxLANGUAGE_GUJARATI,
    wxLANGUAGE_HAUSA,
    wxLANGUAGE_HEBREW,
    wxLANGUAGE_HINDI,
    wxLANGUAGE_HUNGARIAN,
    wxLANGUAGE_ICELANDIC,
    wxLANGUAGE_INDONESIAN,
    wxLANGUAGE_INTERLINGUA,
    wxLANGUAGE_INTERLINGUE,
    wxLANGUAGE_INUKTITUT,
    wxLANGUAGE_INUPIAK,
    wxLANGUAGE_IRISH,
    wxLANGUAGE_ITALIAN,
    wxLANGUAGE_ITALIAN_SWISS,
    wxLANGUAGE_JAPANESE,
    wxLANGUAGE_JAVANESE,
    wxLANGUAGE_KANNADA,
    wxLANGUAGE_KASHMIRI,
    wxLANGUAGE_KASHMIRI_INDIA,
    wxLANGUAGE_KAZAKH,
    wxLANGUAGE_KERNEWEK,
    wxLANGUAGE_KINYARWANDA,
    wxLANGUAGE_KIRGHIZ,
    wxLANGUAGE_KIRUNDI,
    wxLANGUAGE_KONKANI,
    wxLANGUAGE_KOREAN,
    wxLANGUAGE_KURDISH,
    wxLANGUAGE_LAOTHIAN,
    wxLANGUAGE_LATIN,
    wxLANGUAGE_LATVIAN,
    wxLANGUAGE_LINGALA,
    wxLANGUAGE_LITHUANIAN,
    wxLANGUAGE_MACEDONIAN,
    wxLANGUAGE_MALAGASY,
    wxLANGUAGE_MALAY,
    wxLANGUAGE_MALAYALAM,
    wxLANGUAGE_MALAY_BRUNEI_DARUSSALAM,
    wxLANGUAGE_MALAY_MALAYSIA,
    wxLANGUAGE_MALTESE,
    wxLANGUAGE_MANIPURI,
    wxLANGUAGE_MAORI,
    wxLANGUAGE_MARATHI,
    wxLANGUAGE_MOLDAVIAN,
    wxLANGUAGE_MONGOLIAN,
    wxLANGUAGE_NAURU,
    wxLANGUAGE_NEPALI,
    wxLANGUAGE_NEPALI_INDIA,
    wxLANGUAGE_NORWEGIAN_BOKMAL,
    wxLANGUAGE_NORWEGIAN_NYNORSK,
    wxLANGUAGE_OCCITAN,
    wxLANGUAGE_ORIYA,
    wxLANGUAGE_OROMO,
    wxLANGUAGE_PASHTO,
    wxLANGUAGE_POLISH,
    wxLANGUAGE_PORTUGUESE,
    wxLANGUAGE_PORTUGUESE_BRAZILIAN,
    wxLANGUAGE_PUNJABI,
    wxLANGUAGE_QUECHUA,
    wxLANGUAGE_RHAETO_ROMANCE,
    wxLANGUAGE_ROMANIAN,
    wxLANGUAGE_RUSSIAN,
    wxLANGUAGE_RUSSIAN_UKRAINE,
    wxLANGUAGE_SAMOAN,
    wxLANGUAGE_SANGHO,
    wxLANGUAGE_SANSKRIT,
    wxLANGUAGE_SCOTS_GAELIC,
    wxLANGUAGE_SERBIAN,
    wxLANGUAGE_SERBIAN_CYRILLIC,
    wxLANGUAGE_SERBIAN_LATIN,
    wxLANGUAGE_SERBO_CROATIAN,
    wxLANGUAGE_SESOTHO,
    wxLANGUAGE_SETSWANA,
    wxLANGUAGE_SHONA,
    wxLANGUAGE_SINDHI,
    wxLANGUAGE_SINHALESE,
    wxLANGUAGE_SISWATI,
    wxLANGUAGE_SLOVAK,
    wxLANGUAGE_SLOVENIAN,
    wxLANGUAGE_SOMALI,
    wxLANGUAGE_SPANISH,
    wxLANGUAGE_SPANISH_ARGENTINA,
    wxLANGUAGE_SPANISH_BOLIVIA,
    wxLANGUAGE_SPANISH_CHILE,
    wxLANGUAGE_SPANISH_COLOMBIA,
    wxLANGUAGE_SPANISH_COSTA_RICA,
    wxLANGUAGE_SPANISH_DOMINICAN_REPUBLIC,
    wxLANGUAGE_SPANISH_ECUADOR,
    wxLANGUAGE_SPANISH_EL_SALVADOR,
    wxLANGUAGE_SPANISH_GUATEMALA,
    wxLANGUAGE_SPANISH_HONDURAS,
    wxLANGUAGE_SPANISH_MEXICAN,
    wxLANGUAGE_SPANISH_MODERN,
    wxLANGUAGE_SPANISH_NICARAGUA,
    wxLANGUAGE_SPANISH_PANAMA,
    wxLANGUAGE_SPANISH_PARAGUAY,
    wxLANGUAGE_SPANISH_PERU,
    wxLANGUAGE_SPANISH_PUERTO_RICO,
    wxLANGUAGE_SPANISH_URUGUAY,
    wxLANGUAGE_SPANISH_US,
    wxLANGUAGE_SPANISH_VENEZUELA,
    wxLANGUAGE_SUNDANESE,
    wxLANGUAGE_SWAHILI,
    wxLANGUAGE_SWEDISH,
    wxLANGUAGE_SWEDISH_FINLAND,
    wxLANGUAGE_TAGALOG,
    wxLANGUAGE_TAJIK,
    wxLANGUAGE_TAMIL,
    wxLANGUAGE_TATAR,
    wxLANGUAGE_TELUGU,
    wxLANGUAGE_THAI,
    wxLANGUAGE_TIBETAN,
    wxLANGUAGE_TIGRINYA,
    wxLANGUAGE_TONGA,
    wxLANGUAGE_TSONGA,
    wxLANGUAGE_TURKISH,
    wxLANGUAGE_TURKMEN,
    wxLANGUAGE_TWI,
    wxLANGUAGE_UIGHUR,
    wxLANGUAGE_UKRAINIAN,
    wxLANGUAGE_URDU,
    wxLANGUAGE_URDU_INDIA,
    wxLANGUAGE_URDU_PAKISTAN,
    wxLANGUAGE_UZBEK,
    wxLANGUAGE_UZBEK_CYRILLIC,
    wxLANGUAGE_UZBEK_LATIN,
    wxLANGUAGE_VIETNAMESE,
    wxLANGUAGE_VOLAPUK,
    wxLANGUAGE_WELSH,
    wxLANGUAGE_WOLOF,
    wxLANGUAGE_XHOSA,
    wxLANGUAGE_YIDDISH,
    wxLANGUAGE_YORUBA,
    wxLANGUAGE_ZHUANG,
    wxLANGUAGE_ZULU,

    // for custom, user-defined languages:
    wxLANGUAGE_USER_DEFINED
};

enum wxFontEncoding
{
    wxFONTENCODING_SYSTEM,           // system default
    wxFONTENCODING_DEFAULT,         // current default encoding

    // ISO8859 standard defines a number of single-byte charsets
    wxFONTENCODING_ISO8859_1,       // West European (Latin1);
    wxFONTENCODING_ISO8859_2,       // Central and East European (Latin2);
    wxFONTENCODING_ISO8859_3,       // Esperanto (Latin3);
    wxFONTENCODING_ISO8859_4,       // Baltic (old) (Latin4);
    wxFONTENCODING_ISO8859_5,       // Cyrillic
    wxFONTENCODING_ISO8859_6,       // Arabic
    wxFONTENCODING_ISO8859_7,       // Greek
    wxFONTENCODING_ISO8859_8,       // Hebrew
    wxFONTENCODING_ISO8859_9,       // Turkish (Latin5);
    wxFONTENCODING_ISO8859_10,      // Variation of Latin4 (Latin6);
    wxFONTENCODING_ISO8859_11,      // Thai
    wxFONTENCODING_ISO8859_12,      // doesn't exist currently, but put it
                                    // here anyhow to make all ISO8859
                                    // consecutive numbers
    wxFONTENCODING_ISO8859_13,      // Baltic (Latin7);
    wxFONTENCODING_ISO8859_14,      // Latin8
    wxFONTENCODING_ISO8859_15,      // Latin9 (a.k.a. Latin0, includes euro);
    wxFONTENCODING_ISO8859_MAX,

    // Cyrillic charset soup (see http://czyborra.com/charsets/cyrillic.html);
    wxFONTENCODING_KOI8,            // KOI8 Russian
    wxFONTENCODING_KOI8_U,          // KOI8 Ukrainian
    wxFONTENCODING_ALTERNATIVE,     // same as MS-DOS CP866
    wxFONTENCODING_BULGARIAN,       // used under Linux in Bulgaria

    // what would we do without Microsoft? They have their own encodings
        // for DOS
    wxFONTENCODING_CP437,           // original MS-DOS codepage
    wxFONTENCODING_CP850,           // CP437 merged with Latin1
    wxFONTENCODING_CP852,           // CP437 merged with Latin2
    wxFONTENCODING_CP855,           // another cyrillic encoding
    wxFONTENCODING_CP866,           // and another one
        // and for Windows
    wxFONTENCODING_CP874,           // WinThai
    wxFONTENCODING_CP932,           // Japanese (shift-JIS);
    wxFONTENCODING_CP936,           // Chinese simplified (GB);
    wxFONTENCODING_CP949,           // Korean (Hangul charset);
    wxFONTENCODING_CP950,           // Chinese (traditional - Big5);
    wxFONTENCODING_CP1250,          // WinLatin2
    wxFONTENCODING_CP1251,          // WinCyrillic
    wxFONTENCODING_CP1252,          // WinLatin1
    wxFONTENCODING_CP1253,          // WinGreek (8859-7);
    wxFONTENCODING_CP1254,          // WinTurkish
    wxFONTENCODING_CP1255,          // WinHebrew
    wxFONTENCODING_CP1256,          // WinArabic
    wxFONTENCODING_CP1257,          // WinBaltic (same as Latin 7);
    wxFONTENCODING_CP12_MAX,

    wxFONTENCODING_UTF7,            // UTF-7 Unicode encoding
    wxFONTENCODING_UTF8,            // UTF-8 Unicode encoding
    wxFONTENCODING_EUC_JP,          // Extended Unix Codepage for Japanese
    wxFONTENCODING_UTF16BE,         // UTF-16 Big Endian Unicode encoding
    wxFONTENCODING_UTF16LE,         // UTF-16 Little Endian Unicode encoding
    wxFONTENCODING_UTF32BE,         // UTF-32 Big Endian Unicode encoding
    wxFONTENCODING_UTF32LE,         // UTF-32 Little Endian Unicode encoding

    wxFONTENCODING_MACROMAN,        // the standard mac encodings
    wxFONTENCODING_MACJAPANESE,
    wxFONTENCODING_MACCHINESETRAD,
    wxFONTENCODING_MACKOREAN,
    wxFONTENCODING_MACARABIC,
    wxFONTENCODING_MACHEBREW,
    wxFONTENCODING_MACGREEK,
    wxFONTENCODING_MACCYRILLIC,
    wxFONTENCODING_MACDEVANAGARI,
    wxFONTENCODING_MACGURMUKHI,
    wxFONTENCODING_MACGUJARATI,
    wxFONTENCODING_MACORIYA,
    wxFONTENCODING_MACBENGALI,
    wxFONTENCODING_MACTAMIL,
    wxFONTENCODING_MACTELUGU,
    wxFONTENCODING_MACKANNADA,
    wxFONTENCODING_MACMALAJALAM,
    wxFONTENCODING_MACSINHALESE,
    wxFONTENCODING_MACBURMESE,
    wxFONTENCODING_MACKHMER,
    wxFONTENCODING_MACTHAI,
    wxFONTENCODING_MACLAOTIAN,
    wxFONTENCODING_MACGEORGIAN,
    wxFONTENCODING_MACARMENIAN,
    wxFONTENCODING_MACCHINESESIMP,
    wxFONTENCODING_MACTIBETAN,
    wxFONTENCODING_MACMONGOLIAN,
    wxFONTENCODING_MACETHIOPIC,
    wxFONTENCODING_MACCENTRALEUR,
    wxFONTENCODING_MACVIATNAMESE,
    wxFONTENCODING_MACARABICEXT,
    wxFONTENCODING_MACSYMBOL,
    wxFONTENCODING_MACDINGBATS,
    wxFONTENCODING_MACTURKISH,
    wxFONTENCODING_MACCROATIAN,
    wxFONTENCODING_MACICELANDIC,
    wxFONTENCODING_MACROMANIAN,
    wxFONTENCODING_MACCELTIC,
    wxFONTENCODING_MACGAELIC,
    wxFONTENCODING_MACKEYBOARD,

    wxFONTENCODING_MAX,             // highest enumerated encoding value

    wxFONTENCODING_MACMIN, //= wxFONTENCODING_MACROMAN ,
    wxFONTENCODING_MACMAX, //= wxFONTENCODING_MACKEYBOARD ,

    // aliases for endian-dependent UTF encodings
    wxFONTENCODING_UTF16,   // native UTF-16
    wxFONTENCODING_UTF32,   // native UTF-32

    // alias for the native Unicode encoding on this platform
    // (this is used by wxEncodingConverter and wxUTFFile only for now);
    wxFONTENCODING_UNICODE,

    // alternative names for Far Eastern encodings
        // Chinese
    wxFONTENCODING_GB2312,  // Simplified Chinese
    wxFONTENCODING_BIG5,    // Traditional Chinese

        // Japanese (see http://zsigri.tripod.com/fontboard/cjk/jis.html);
    wxFONTENCODING_SHIFT_JIS, // Shift JIS
};

enum wxLocaleCategory
{
    wxLOCALE_CAT_NUMBER,    // (any) numbers
    wxLOCALE_CAT_DATE,      // date/time
    wxLOCALE_CAT_MONEY,     // monetary value
    wxLOCALE_CAT_MAX
};

enum wxLocaleInfo
{
    wxLOCALE_THOUSANDS_SEP, // the thounsands separator
    wxLOCALE_DECIMAL_POINT  // the character used as decimal point
};

enum wxLocaleInitFlags
{
    wxLOCALE_DONT_LOAD_DEFAULT,
    wxLOCALE_LOAD_DEFAULT,
    !%wxchkver_2_9 || %wxcompat_2_8 wxLOCALE_CONV_ENCODING
};

#if %wxchkver_2_8
enum wxLayoutDirection
{
    wxLayout_Default,
    wxLayout_LeftToRight,
    wxLayout_RightToLeft
};
#endif //%wxchkver_2_8

struct %delete wxLanguageInfo
{
    wxLanguageInfo(); // you must set all the values by hand

    int Language;                   // wxLanguage id
    wxString CanonicalName;         // Canonical name, e.g. fr_FR
    wxString Description;           // human-readable name of the language
    %wxchkver_2_8 wxLayoutDirection LayoutDirection;
};


class %delete wxLocale
{
    // call Init() if you use this ctor
    wxLocale();

    // the ctor has a side effect of changing current locale
    // name (for messages),  dir prefix (for msg files), locale (for setlocale), preload wxstd.mo?, convert Win<->Unix if necessary?
    !%wxchkver_2_9 || %wxcompat_2_8 wxLocale(const wxString& szName, const wxString& szShort = "", const wxString& szLocale = "", bool bLoadDefault = true, bool bConvertEncoding = false);
    %wxchkver_2_8 wxLocale(const wxString& szName, const wxString& szShort = "", const wxString& szLocale = "", bool bLoadDefault = true);

    // wxLanguage id or custom language
    wxLocale(int language, int flags = wxLOCALE_LOAD_DEFAULT);

    // the same as a function (returns true on success);
    //bool Init(const wxChar *szName, const wxChar *szShort = (const wxChar *) NULL, const wxChar *szLocale = (const wxChar *) NULL, bool bLoadDefault = true, bool bConvertEncoding = false);
    !%wxchkver_2_9 || %wxcompat_2_8 bool Init(const wxString &szName, const wxString &szShort = "", const wxString &szLocale = "", bool bLoadDefault = true, bool bConvertEncoding = false);
    %wxchkver_2_8 bool Init(const wxString &szName, const wxString &szShort = "", const wxString &szLocale = "", bool bLoadDefault = true);

    // same as second ctor (returns true on success);
    bool Init(int language = wxLANGUAGE_DEFAULT, int flags = wxLOCALE_LOAD_DEFAULT);

    // Try to get user's (or OS's) preferred language setting.
    // Return wxLANGUAGE_UNKNOWN if language-guessing algorithm failed
    static int GetSystemLanguage();

    // get the encoding used by default for text on this system, returns
    // wxFONTENCODING_SYSTEM if it couldn't be determined
    static wxFontEncoding GetSystemEncoding();

    // get the string describing the system encoding, return empty string if
    // couldn't be determined
    static wxString GetSystemEncodingName();

    // get the values of the given locale-dependent datum: the current locale
    // is used, the US default value is returned if everything else fails
    static wxString GetInfo(wxLocaleInfo index, wxLocaleCategory cat);

    // return true if the locale was set successfully
    bool IsOk() const;

    // returns locale name
    wxString GetLocale() const;

    // return current locale wxLanguage value
    int GetLanguage() const;

    // return locale name to be passed to setlocale();
    wxString GetSysName() const;

    // return 'canonical' name, i.e. in the form of xx[_YY], where xx is
    // language code according to ISO 639 and YY is country name
    // as specified by ISO 3166.
    wxString GetCanonicalName() const;

    // add a prefix to the catalog lookup path: the message catalog files will be
    // looked up under prefix/<lang>/LC_MESSAGES, prefix/LC_MESSAGES and prefix
    // (in this order).
    //
    // This only applies to subsequent invocations of AddCatalog()!
    static void AddCatalogLookupPathPrefix(const wxString& prefix);

    // add a catalog: it's searched for in standard places (current directory
    // first, system one after), but the you may prepend additional directories to
    // the search path with AddCatalogLookupPathPrefix().
    //
    // The loaded catalog will be used for message lookup by GetString().
    //
    // Returns 'true' if it was successfully loaded
    bool AddCatalog(const wxString& szDomain);
    bool AddCatalog(const wxString& szDomain, wxLanguage msgIdLanguage, const wxString& msgIdCharset);

    // check if the given locale is provided by OS and C run time
    %wxchkver_2_8 static bool IsAvailable(int lang);

    // check if the given catalog is loaded
    bool IsLoaded(const wxString& szDomain) const;

    // Retrieve the language info struct for the given language
    //
    // Returns NULL if no info found, pointer must *not* be deleted by caller
    static const wxLanguageInfo *GetLanguageInfo(int lang);

    // Returns language name in English or empty string if the language
    // is not in database
    static wxString GetLanguageName(int lang);

    // Find the language for the given locale string which may be either a
    // canonical ISO 2 letter language code ("xx"), a language code followed by
    // the country code ("xx_XX") or a Windows full language name ("Xxxxx...");
    //
    // Returns NULL if no info found, pointer must *not* be deleted by caller
    static const wxLanguageInfo *FindLanguageInfo(const wxString& locale);

    // Add custom language to the list of known languages.
    // Notes: 1) wxLanguageInfo contains platform-specific data
    //        2) must be called before Init to have effect
    static void AddLanguage(const wxLanguageInfo& info);

    // retrieve the translation for a string in all loaded domains unless
    // the szDomain parameter is specified (and then only this domain is
    // searched);
    // n - additional parameter for PluralFormsParser
    //
    // return original string if translation is not available
    // (in this case an error message is generated the first time
    //  a string is not found; use wxLogNull to suppress it);
    //
    // domains are searched in the last to first order, i.e. catalogs
    // added later override those added before.
    %wxchkver_2_9  virtual wxString GetString(const wxString& szOrigString, const wxString& szDomain = "") const;
    !%wxchkver_2_9 virtual wxString GetString(const wxString& szOrigString, const wxChar* szDomain = NULL) const;
    // plural form version of the same:
    %wxchkver_2_9  virtual wxString GetString(const wxString& szOrigString, const wxString& szOrigString2, size_t n, const wxString& szDomain = "") const;
    !%wxchkver_2_9 virtual wxString GetString(const wxString& szOrigString, const wxString& szOrigString2, size_t n, const wxChar* szDomain = NULL) const;

    // Returns the current short name for the locale
    const wxString& GetName() const;

    // return the contents of .po file header
    wxString GetHeaderValue(const wxString& szHeader, const wxString& szDomain = "") const;
};

wxLocale* wxGetLocale();

%wxchkver_2_9  wxString wxGetTranslation(const wxString& sz, const wxString& domain = "");
!%wxchkver_2_9 && %wxchkver_2_8  wxString wxGetTranslation(const wxString& sz, const wxChar* domain=NULL);
!%wxchkver_2_8 wxString wxGetTranslation(const wxString& sz);

%wxchkver_2_9  %rename wxGetTranslationPlural wxString wxGetTranslation(const wxString& sz1, const wxString& sz2, size_t n, const wxString& domain = "");
!%wxchkver_2_9 && %wxchkver_2_8  %rename wxGetTranslationPlural wxString wxGetTranslation(const wxString& sz1, const wxString& sz2, size_t n, const wxChar* domain=NULL);
!%wxchkver_2_8 %rename wxGetTranslationPlural wxString wxGetTranslation(const wxString& sz1, const wxString& sz2, size_t n);

#endif //wxUSE_INTL
