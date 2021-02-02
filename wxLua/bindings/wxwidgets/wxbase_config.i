// ===========================================================================
// Purpose:     wxConfig and wxConfigBase classes
// Author:      J Winwood, John Labenski
// Created:     14/11/2001
// Copyright:   (c) 2001-2002 Lomtick Software. All rights reserved.
// Licence:     wxWidgets licence
// wxWidgets:   Updated to 2.8.4
// ===========================================================================

// TODO - add wxConfigFile and Reg

// ---------------------------------------------------------------------------
// wxConfigBase

#if wxLUA_USE_wxConfig && wxUSE_CONFIG

#include "wx/confbase.h"
#include "wx/config.h"
#include "wx/fileconf.h"

enum
{
    wxCONFIG_USE_LOCAL_FILE,
    wxCONFIG_USE_GLOBAL_FILE,
    wxCONFIG_USE_RELATIVE_PATH,
    wxCONFIG_USE_NO_ESCAPE_CHARACTERS,
    %wxchkver_2_8_1 wxCONFIG_USE_SUBDIR
};

enum wxConfigBase::EntryType
{
    Type_Unknown,
    Type_String,
    Type_Boolean,
    Type_Integer,
    Type_Float
};

class %delete wxConfigBase : public wxObject
{
    // No constructor since this is a base class

    // %override wxConfigBase::delete() - this is a wxLua provided function to
    //  delete the config (or derived class). Created wxConfigs are NOT tracked
    //  in memory since you MUST call wxConfigBase::Set(NULL) before
    //  deleting them. This is because the wxConfig you install using
    //  wxConfigBase::Set may need to exist outside of the scope it was created
    //  in and we don't want Lua to garbage collect it.
    //void delete();

    // Note: the return wxConfig cannot be deleted.
    // You must call "config = Set(wx.NULL); config:delete()"
    static wxConfigBase* Create();
    static void DontCreateOnDemand();

    bool DeleteAll();
    bool DeleteEntry(const wxString& key, bool bDeleteGroupIfEmpty = true);
    bool DeleteGroup(const wxString& key);
    bool Exists(wxString& strName) const;
    bool Flush(bool bCurrentOnly = false);
    static wxConfigBase* Get(bool CreateOnDemand = true);
    wxString GetAppName() const;
    wxConfigBase::EntryType GetEntryType(const wxString& name) const;

    // %override [bool, string, index] wxConfigBase::GetFirstGroup();
    // C++ Func: bool GetFirstGroup(wxString& str, long& index) const;
    bool GetFirstGroup() const;

    // %override [bool, string, index] wxConfigBase::GetFirstEntry();
    // C++ Func: bool GetFirstEntry(wxString& str, long& index) const;
    bool GetFirstEntry() const;

    // %override [bool, string, index] wxConfigBase::GetNextGroup(index);
    // C++ Func: bool GetNextGroup(wxString& str, long& index) const;
    bool GetNextGroup() const;

    // %override [bool, string, index] wxConfigBase::GetNextEntry(index);
    // C++ Func: bool GetNextEntry(wxString& str, long& index) const;
    bool GetNextEntry(long index) const;

    unsigned int GetNumberOfEntries(bool bRecursive = false) const;
    unsigned int GetNumberOfGroups(bool bRecursive = false) const;
    const wxString& GetPath() const;
    wxString GetVendorName() const;
    bool HasEntry(wxString& strName) const;
    bool HasGroup(const wxString& strName) const;
    bool IsExpandingEnvVars() const;
    bool IsRecordingDefaults() const;

    // %override [bool, string] wxConfigBase::Read(const wxString& key, const wxString& defaultVal = "");
    // C++ Func: bool Read(const wxString& key, wxString* str, const wxString& defaultVal) const;
    bool Read(const wxString& key, const wxString& defaultVal = "") const;

    // Since Lua uses double as it's number type, we only read/write doubles

    // %override [bool, double] wxConfigBase::Read(const wxString& key, double defaultVal = 0);
    // C++ Func: bool Read(const wxString&  key, double* d, double defaultVal = 0) const;
    %override_name wxLua_wxConfigBase_ReadFloat bool Read(const wxString&  key, double defaultVal) const;

    // // %override [bool, int] wxConfigBase::ReadInt(const wxString& key, long defaultVal = 0);
    // // C++ Func: bool Read(const wxString&  key, long* l, long defaultVal = 0) const;
    // %rename ReadInt bool Read(const wxString&  key, long defaultVal = 0) const;
    // // %override [bool, double] wxConfigBase::ReadFloat(const wxString& key, double defaultVal = 0);
    // // C++ Func: bool Read(const wxString&  key, double* d, double defaultVal = 0) const;
    // %rename ReadFloat bool Read(const wxString&  key, double defaultVal = 0) const;

    bool RenameEntry(const wxString& oldName, const wxString& newName);
    bool RenameGroup(const wxString& oldName, const wxString& newName);
    static %gc wxConfigBase* Set(%ungc wxConfigBase *pConfig = NULL);
    void SetExpandEnvVars(bool bDoIt = true);
    void SetPath(const wxString& strPath);
    void SetRecordDefaults(bool bDoIt = true);


    bool Write(const wxString& key, wxString &value);
    // Since Lua uses double as it's number type, we only read/write doubles
    bool Write(const wxString &key, double value);

    // %rename WriteInt bool Write(const wxString &key, long value);
    // %rename WriteFloat bool Write(const wxString &key, double value);
};

// ---------------------------------------------------------------------------
// wxConfig

class %delete wxConfig : public wxConfigBase
{
    wxConfig(const wxString& appName = "", const wxString& vendorName = "", const wxString& localFilename = "", const wxString& globalFilename = "", long style = 0);
};

// ---------------------------------------------------------------------------
// wxFileConfig

class %delete wxFileConfig : public wxConfigBase
{
    wxFileConfig(const wxString& appName = "", const wxString& vendorName = "", const wxString& localFilename = "", const wxString& globalFilename = "", long style = wxCONFIG_USE_LOCAL_FILE | wxCONFIG_USE_GLOBAL_FILE); //, wxMBConv& conv = wxConvUTF8);
    wxFileConfig(wxInputStream& is); //, const wxMBConv& conv = wxConvAuto());

    static wxFileName GetGlobalFile(const wxString& basename);
    static wxFileName GetLocalFile(const wxString& basename, int style = 0);

    static wxString GetGlobalFileName(const wxString& szFile);
    static wxString GetLocalFileName(const wxString& szFile, int style = 0);

    virtual bool Save(wxOutputStream& os); //, const wxMBConv& conv = wxConvAuto());

    %wxchkver_3_1_3 void EnableAutoSave();
    %wxchkver_3_1_3 void DisableAutoSave();

    void SetUmask(int mode);
};

// ---------------------------------------------------------------------------
// wxMemoryConfig

#include "wx/memconf.h"

class %delete wxMemoryConfig : public wxFileConfig
{
    wxMemoryConfig();
};

// ---------------------------------------------------------------------------
// wxConfigPathChanger

// a handy little class which changes current path to the path of given entry
// and restores it in dtor: so if you declare a local variable of this type,
// you work in the entry directory and the path is automatically restored
// when the function returns

class %delete wxConfigPathChanger
{
    // NOTE: ALWAYS delete() this when done since Lua's gc may not delete it soon enough
    wxConfigPathChanger(const wxConfigBase *pContainer, const wxString& strEntry);

    wxString Name() const;
    %wxchkver_2_8 void UpdateIfDeleted();
};

#endif //wxLUA_USE_wxConfig && wxUSE_CONFIG
