// ===========================================================================
// Purpose:     wxNet library
// Author:      J Winwood, John Labenski
// Created:     14/11/2001
// Copyright:   (c) 2001-2002 Lomtick Software. All rights reserved.
// Licence:     wxWidgets licence
// wxWidgets:   Updated to 2.8.4
// ===========================================================================

#if wxLUA_USE_wxSocket && wxUSE_SOCKETS

// ---------------------------------------------------------------------------
// wxSocketBase

#include "wx/socket.h"

enum wxSocketError
{
    wxSOCKET_NOERROR,
    wxSOCKET_INVOP,
    wxSOCKET_IOERR,
    wxSOCKET_INVADDR,
    wxSOCKET_INVSOCK,
    wxSOCKET_NOHOST,
    wxSOCKET_INVPORT,
    wxSOCKET_WOULDBLOCK,
    wxSOCKET_TIMEDOUT,
    wxSOCKET_MEMERR
};

enum wxSocketFlags // actually typedef int wxSocketFlags
{
    wxSOCKET_NONE,
    wxSOCKET_NOWAIT,
    wxSOCKET_WAITALL,
    wxSOCKET_BLOCK,
    wxSOCKET_REUSEADDR
};

enum wxSocketNotify
{
    wxSOCKET_INPUT,
    wxSOCKET_OUTPUT,
    wxSOCKET_CONNECTION,
    wxSOCKET_LOST
};

enum wxSocketEventFlags
{
    wxSOCKET_INPUT_FLAG,
    wxSOCKET_OUTPUT_FLAG,
    wxSOCKET_CONNECTION_FLAG,
    wxSOCKET_LOST_FLAG
};

enum wxSocketType
{
    wxSOCKET_UNINIT,
    wxSOCKET_CLIENT,
    wxSOCKET_SERVER,
    wxSOCKET_BASE,
    wxSOCKET_DATAGRAM
};

class wxSocketBase : public wxObject
{
    // wxSocketBase() - No constructor, base class

    void Close();
    bool Destroy();
    void Discard();
    bool Error() const;
    voidptr_long GetClientData() const; // C++ returns (void *) You get a number here
    bool GetLocal(wxSockAddress& addr) const;
    wxSocketFlags GetFlags() const;
    bool GetPeer(wxSockAddress& addr) const;
    void InterruptWait();
    bool IsConnected() const;
    bool IsData() const;
    bool IsDisconnected() const;
    unsigned long LastCount() const;
    wxSocketError LastError() const; // %gtk|%mac causes link error with Borland C++ w/DLL not exported?
    void Notify(bool notify);
    bool Ok() const;
    void RestoreState();
    void SaveState();
    void SetClientData(voidptr_long number); // C++ is (void *clientData) You can put a number here
    void SetEventHandler(wxEvtHandler& handler, int id = -1);
    void SetFlags(wxSocketFlags flags);
    void SetNotify(wxSocketEventFlags flags);
    void SetTimeout(int seconds);

    // %override [Lua string] wxSocketBase::Peek(unsigned long nbytes);
    // C++ Func: void Peek(void * buffer, unsigned long nbytes);
    void Peek(unsigned long nbytes);

    // %override [Lua string] wxSocketBase::Read(unsigned long nbytes);
    // C++ Func: void Read(unsigned long nbytes);
    void Read(void * buffer, unsigned long nbytes);

    // %override [Lua string] wxSocketBase::ReadMsg(unsigned long nbytes);
    // C++ Func: void ReadMsg(void * buffer, unsigned long nbytes);
    void ReadMsg(unsigned long nbytes);

    // %override void wxSocketBase::Unread(Lua string, [optional unsigned long nbytes]);
    // C++ Func: void Unread(const void * buffer, unsigned long nbytes);
    void Unread(const char* buffer, unsigned long nbytes);

    bool Wait(long seconds = -1, long millisecond = 0);
    bool WaitForLost(long seconds = -1, long millisecond = 0);
    bool WaitForRead(long seconds = -1, long millisecond = 0);
    bool WaitForWrite(long seconds = -1, long millisecond = 0);

    // %override void wxSocketBase::Write(Lua string, [optional unsigned long nbytes]);
    // C++ Func: void Write(const void * buffer, unsigned long nbytes);
    void Write(const char* buffer, unsigned long nbytes);

    // %override void wxSocketBase::WriteMsg(Lua string, [optional unsigned long nbytes]);
    // C++ Func: void WriteMsg(const void * buffer, wxUint32 nbytes);
    void WriteMsg(const char* buffer, wxUint32 nbytes);
};

// ---------------------------------------------------------------------------
// wxSocketClient

class %delete wxSocketClient : public wxSocketBase
{
    wxSocketClient(wxSocketFlags flags = wxSOCKET_NONE);

    bool Connect(wxSockAddress& address, bool wait = true);
    bool WaitOnConnect(long seconds = -1, long milliseconds = 0);
};

// ---------------------------------------------------------------------------
// wxSocketServer

class %delete wxSocketServer : public wxSocketBase
{
    wxSocketServer(wxSockAddress& address, wxSocketFlags flags = wxSOCKET_NONE);

    wxSocketBase* Accept(bool wait = true);
    bool AcceptWith(wxSocketBase& socket, bool wait = true);
    bool WaitForAccept(long seconds = -1, long millisecond = 0);
};

// ---------------------------------------------------------------------------
// wxSocketEvent

class %delete wxSocketEvent : public wxEvent
{
    %wxEventType wxEVT_SOCKET // EVT_SOCKET(id, func);

    wxSocketEvent(int id = 0);

    voidptr_long GetClientData(); // C++ returns (void *) You get a number here
    wxSocketBase * GetSocket() const;
    wxSocketNotify GetSocketEvent() const;
};

// ---------------------------------------------------------------------------
// wxSockAddress

class wxSockAddress : public wxObject
{
    // wxSockAddress() virtual base class

    void Clear();
    //int  SockAddrLen(); // Does not exist
};

// ---------------------------------------------------------------------------
// wxIPAddress

class %delete wxIPaddress : public wxSockAddress
{
    //wxIPaddress() virtual base class

    bool Hostname(const wxString& hostname);
    //bool Hostname(unsigned long addr); // pure virtual, fun in derived classes
    wxString Hostname();
    wxString  IPAddress();
    bool Service(const wxString& service);
    bool Service(unsigned short service);
    unsigned short Service();
    bool AnyAddress();
    bool LocalHost();
    virtual bool IsLocalHost();
};

// ---------------------------------------------------------------------------
// wxIPV4address

class %delete wxIPV4address : public wxIPaddress
{
    wxIPV4address();
    wxIPV4address(const wxIPV4address& other);

    //bool Hostname(const wxString& hostname);
    bool Hostname(unsigned long addr);
    //wxString Hostname();
    //wxString  IPAddress();
    //bool Service(const wxString& service);
    //bool Service(unsigned short service);
    //unsigned short Service();
    //bool AnyAddress();
    //bool LocalHost();
};

// ---------------------------------------------------------------------------
//  wxProtocol

#if wxUSE_PROTOCOL

#include "wx/protocol/protocol.h"

enum wxProtocolError
{
    wxPROTO_NOERR,
    wxPROTO_NETERR,
    wxPROTO_PROTERR,
    wxPROTO_CONNERR,
    wxPROTO_INVVAL,
    wxPROTO_NOHNDLR,
    wxPROTO_NOFILE,
    wxPROTO_ABRT,
    wxPROTO_RCNCT,
    wxPROTO_STREAMING
};

class %delete wxProtocol : public wxSocketClient
{
    //wxProtocol() virtual base class

    bool Reconnect();
    wxInputStream *GetInputStream(const wxString& path);
    bool Abort();
    wxProtocolError GetError();
    wxString GetContentType();
    void SetUser(const wxString& user);
    void SetPassword(const wxString& user);
};

#endif //wxUSE_PROTOCOL

// ---------------------------------------------------------------------------
//  wxHTTP

#if wxUSE_PROTOCOL_HTTP

#include "wx/protocol/http.h"

class %delete wxHTTP : public wxProtocol
{
    wxHTTP();

    int GetResponse() const;
    // wxInputStream *GetInputStream(const wxString& path) - see wxProtocol
    void SetHeader(const wxString& header, const wxString& h_data);
    wxString GetHeader(const wxString& header);
};

#endif //wxUSE_PROTOCOL_HTTP

// ---------------------------------------------------------------------------
//  wxFTP

#if wxUSE_PROTOCOL_FTP

#include "wx/protocol/ftp.h"

enum wxFTP::TransferMode
{
    NONE,
    ASCII,
    BINARY
};

class %delete wxFTP : public wxProtocol
{
    wxFTP();

    //bool Abort();
    bool CheckCommand(const wxString& command, char ret);
    char SendCommand(const wxString& command);
    wxString GetLastResult();
    bool ChDir(const wxString& dir);
    bool MkDir(const wxString& dir);
    bool RmDir(const wxString& dir);
    wxString Pwd();
    bool Rename(const wxString& src, const wxString& dst);
    bool RmFile(const wxString& path);
    bool SetAscii();
    bool SetBinary();
    void SetPassive(bool pasv);
    bool SetTransferMode(wxFTP::TransferMode mode);
    // void SetUser(const wxString& user) - see wxProtocol
    // void SetPassword(const wxString& passwd) - see wxProtocol
    bool FileExists(const wxString& filename);
    int GetFileSize(const wxString& filename);
    bool GetDirList(wxArrayString& files, const wxString& wildcard = "");
    bool GetFilesList(wxArrayString& files, const wxString& wildcard = "");
    wxOutputStream * GetOutputStream(const wxString& file);
    // wxInputStream * GetInputStream(const wxString& path) - see wxProtocol
};

#endif //wxUSE_PROTOCOL_FTP

// ---------------------------------------------------------------------------
//  wxURI

#include "wx/uri.h"

enum wxURIHostType
{
    wxURI_REGNAME,
    wxURI_IPV4ADDRESS,
    wxURI_IPV6ADDRESS,
    wxURI_IPVFUTURE
};

enum wxURIFieldType
{
    wxURI_SCHEME,
    wxURI_USERINFO,
    wxURI_SERVER,
    wxURI_PORT,
    wxURI_PATH,
    wxURI_QUERY,
    wxURI_FRAGMENT
};

enum wxURIFlags
{
    wxURI_STRICT
};

class %delete wxURI : public wxObject
{
    wxURI();
    wxURI(const wxString& uri);
    wxURI(const wxURI& uri);

    %wxchkver_2_9_2 bool Create(const wxString& uri);
    !%wxchkver_2_9_2 wxString Create(const wxString& uri);

    bool HasScheme() const;
    bool HasUserInfo() const;
    bool HasServer() const;
    bool HasPort() const;
    bool HasPath() const;
    bool HasQuery() const;
    bool HasFragment() const;
    wxString GetScheme() const;
    wxString GetPath() const;
    wxString GetQuery() const;
    wxString GetFragment() const;
    wxString GetPort() const;
    wxString GetUserInfo() const;
    wxString GetServer() const;
    wxURIHostType GetHostType() const;
    wxString GetUser() const;
    wxString GetPassword() const;
    wxString BuildURI() const;
    wxString BuildUnescapedURI() const;
    void Resolve(const wxURI& base, int flags = wxURI_STRICT);
    bool IsReference() const;
    static wxString Unescape (const wxString& szEscapedURI);

    wxURI& operator = (const wxURI& uri);
    //wxURI& operator = (const wxString& string);
    bool operator == (const wxURI& uri) const;
};

// ---------------------------------------------------------------------------
//  wxURL

#if wxUSE_URL

#include "wx/url.h"

enum wxURLError
{
    wxURL_NOERR,
    wxURL_SNTXERR,
    wxURL_NOPROTO,
    wxURL_NOHOST,
    wxURL_NOPATH,
    wxURL_CONNERR,
    wxURL_PROTOERR
};

class %delete wxURL : public wxURI
{
    wxURL(const wxString& sUrl);
    wxURL(const wxURI& url);

    wxProtocol& GetProtocol();
    wxURLError GetError() const;
    wxString GetURL() const;

    wxInputStream *GetInputStream();

#if wxUSE_PROTOCOL_HTTP
    static void SetDefaultProxy(const wxString& url_proxy);
    void SetProxy(const wxString& url_proxy);
#endif // wxUSE_PROTOCOL_HTTP

    //wxURL& operator = (const wxString& url);
    //wxURL& operator = (const wxURI& url);
};

#endif //wxUSE_URL

// ---------------------------------------------------------------------------
////  wxConnectionBase
//
//%include "wx/ipcbase.h"
//
//enum wxIPCFormat
//{
//    wxIPC_INVALID,
//    wxIPC_TEXT,
//    wxIPC_BITMAP,
//    wxIPC_METAFILE,
//    wxIPC_SYLK,
//    wxIPC_DIF,
//    wxIPC_TIFF,
//    wxIPC_OEMTEXT,
//    wxIPC_DIB,
//    wxIPC_PALETTE,
//    wxIPC_PENDATA,
//    wxIPC_RIFF,
//    wxIPC_WAVE,
//    wxIPC_UNICODETEXT,
//    wxIPC_ENHMETAFILE,
//    wxIPC_FILENAME,
//    wxIPC_LOCALE,
//    wxIPC_PRIVATE
//};
//
//class wxConnectionBase : public wxObject
//{
//    // no constructor virtual base class
//
//    bool Advise(const wxString& item, char* data, int size = -1, wxIPCFormat format = wxCF_TEXT);
//};
//
// ---------------------------------------------------------------------------
////  wxConnection
//
//class wxConnection : public wxConnectionBase
//{
//    wxConnection();
//};
//
// ---------------------------------------------------------------------------
////  wxClient
//
//class wxClient : public wxObject
//{
//     wxClient();
//     wxConnectionBase * MakeConnection(const wxString& host, const wxString& service, const wxString& topic);
//
//     //virtual wxConnectionBase * OnMakeConnection();
//     bool ValidHost(const wxString& host);
//};
//

#endif //wxLUA_USE_wxSocket && wxUSE_SOCKETS
