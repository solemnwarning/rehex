/////////////////////////////////////////////////////////////////////////////
// Name:        wxlsock.cpp
// Purpose:     Socket class for wxLua.
// Author:      J. Winwood, John Labenski, Ray Gilbert
// Created:     February 2002
// Copyright:   (c) 2012 John Labenski, 2002 Lomtick Software. All rights reserved.
// Licence:     wxWidgets licence
/////////////////////////////////////////////////////////////////////////////

#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#ifndef WX_PRECOMP
    #include "wx/wx.h"
#endif

#include "wxlua/debugger/wxlsock.h"
#include "wxlua/debugger/wxldserv.h"
#include "wxlua/wxlstate.h"
#include "wxlua/debug/wxldebug.h"

#ifdef _MSC_VER
    #pragma warning(push, 4)
#endif

// A simple way to debug the sockets to see if things are right
// prints to the console for unix and to a file (see below) for MSW the socket
// cmd/event and the socket read/write
//#define DEBUG_WXLUASOCKET
#ifdef DEBUG_WXLUASOCKET

    char* s_wxlsocket_event[] = {
        "wxLUA_DEBUGGEE_EVENT_NONE",
        "wxLUA_DEBUGGEE_EVENT_BREAK",
        "wxLUA_DEBUGGEE_EVENT_PRINT",
        "wxLUA_DEBUGGEE_EVENT_ERROR",
        "wxLUA_DEBUGGEE_EVENT_EXIT",
        "wxLUA_DEBUGGEE_EVENT_STACK_ENUM",
        "wxLUA_DEBUGGEE_EVENT_STACK_ENTRY_ENUM",
        "wxLUA_DEBUGGEE_EVENT_TABLE_ENUM",
        "wxLUA_DEBUGGEE_EVENT_EVALUATE_EXPR",
    };

    char* s_wxlsocket_cmd[] = {
        "wxLUA_DEBUGGER_CMD_NONE",
        "wxLUA_DEBUGGER_CMD_ADD_BREAKPOINT",
        "wxLUA_DEBUGGER_CMD_REMOVE_BREAKPOINT",
        "wxLUA_DEBUGGER_CMD_DISABLE_BREAKPOINT",
        "wxLUA_DEBUGGER_CMD_ENABLE_BREAKPOINT",
        "wxLUA_DEBUGGER_CMD_CLEAR_ALL_BREAKPOINTS",
        "wxLUA_DEBUGGER_CMD_RUN_BUFFER",
        "wxLUA_DEBUGGER_CMD_DEBUG_STEP",
        "wxLUA_DEBUGGER_CMD_DEBUG_STEPOVER",
        "wxLUA_DEBUGGER_CMD_DEBUG_STEPOUT",
        "wxLUA_DEBUGGER_CMD_DEBUG_CONTINUE",
        "wxLUA_DEBUGGER_CMD_DEBUG_BREAK",
        "wxLUA_DEBUGGER_CMD_RESET",
        "wxLUA_DEBUGGER_CMD_ENUMERATE_STACK",
        "wxLUA_DEBUGGER_CMD_ENUMERATE_STACK_ENTRY",
        "wxLUA_DEBUGGER_CMD_ENUMERATE_TABLE_REF",
        "wxLUA_DEBUGGER_CMD_CLEAR_DEBUG_REFERENCES",
        "wxLUA_DEBUGGER_CMD_EVALUATE_EXPR",
    };

    wxString wxLuaSocketCmdEventMsg(int val)
    {
        if (val <= 0) return wxString::Format(wxT("INVALID SOCKET CMD/EVENT (%d), SOCKET ERROR?"), val);

        if ((val >= wxLUA_DEBUGGEE_EVENT_BREAK) && (val <= wxLUA_DEBUGGEE_EVENT__COUNT))
            return lua2wx(s_wxlsocket_event[val]);

        if ((val >= wxLUA_DEBUGGER_CMD_ADD_BREAKPOINT) && (val <= wxLUA_DEBUGGER_CMD_ENABLE_BREAKPOINT))
            return lua2wx(s_wxlsocket_cmd[val - wxLUA_DEBUGGER_CMD_ADD_BREAKPOINT + 1]);

        return wxString::Format(wxT("INVALID SOCKET CMD/EVENT (%d), SOCKET ERROR?"), val);
    }


    void wxLuaSocketDebugMsg(const wxString& title, const wxString& msg)
    {
#ifdef __WXMSW__ // no console in MSW
        wxLuaCharBuffer buf(wxString::Format(wxT("%s PID %ld TIME %s %s\n"), title.c_str(), (long)wxGetProcessId(), wxT(__TIME__), msg.c_str()));
        FILE* h = fopen("wxLua_socketdebug.log", "a");
        fprintf(h, buf.GetData());
        fclose(h);
#else  // !__WXMSW__
        wxSafeShowMessage(title, wxString::Format(wxT("PID %ld TIME %s\n\t%s"), (long)wxGetProcessId(), wxT(__TIME__), msg.c_str()));
#endif // __WXMSW__
    }

#else // !DEBUG_WXLUASOCKET

    #define wxLuaSocketDebugMsg(title, msg) // do nothing

#endif //DEBUG_WXLUASOCKET

// ----------------------------------------------------------------------------
// wxLuaSocketBase
// ----------------------------------------------------------------------------
IMPLEMENT_ABSTRACT_CLASS(wxLuaSocketBase, wxObject);

bool wxLuaSocketBase::ReadCmd(unsigned char& value_)
{
    unsigned char value = 0;
    bool ok = Read((char *) &value, sizeof(unsigned char)) == sizeof(unsigned char);
    wxLuaSocketDebugMsg(m_name + wxT(" wxLuaSocketBase::ReadCmd"), wxString::Format(wxT("ok %d val %d "), (int)ok, (int)value) + wxLuaSocketCmdEventMsg(value));
    if (ok) value_ = value;
    return ok;
}
bool wxLuaSocketBase::ReadInt32(wxInt32& value_)
{
    wxInt32 value = 0;
    bool ok = Read((char *) &value, sizeof(wxInt32)) == sizeof(wxInt32);
    wxLuaSocketDebugMsg(m_name + wxT(" wxLuaSocketBase::ReadInt32"), wxString::Format(wxT("ok %d val %d"), (int)ok, value));
    if (ok) value_ = value;
    return ok;
}
bool wxLuaSocketBase::ReadLong(long& value_)
{
    long value = 0;
    // make sure that long really works for 32 and 64 bit platforms, use a string
    char buf[65] = { 0 }; memset(buf, 0, 65);
    bool ok = Read(buf, 64) == 64;
    if (ok) ok = lua2wx(buf).ToLong(&value);
    wxLuaSocketDebugMsg(m_name + wxT(" wxLuaSocketBase::ReadLong"), wxString::Format(wxT("ok %d val %ld '%s'"), (int)ok, value, lua2wx(buf).c_str()));
    if (ok) value_ = value;
    return ok;
}
bool wxLuaSocketBase::ReadString(wxString& value_)
{
    wxString value;
    wxUint32 length = 0;
    bool ok = Read((char *) &length, sizeof(wxUint32)) == sizeof(wxUint32);

    if (ok && (length > 0))
    {
        char *buffer = new char[length + 1];
        memset(buffer, 0, length+1);
        ok = Read(buffer, length) == (int)length;
        buffer[length] = 0;
        if (ok) value = lua2wx(buffer);
        delete[] buffer;
    }

    wxLuaSocketDebugMsg(m_name + wxT(" wxLuaSocketBase::ReadString"), wxString::Format(wxT("ok %d len %u val '%s'"), (int)ok, length, value.c_str()));

    if (ok) value_ = value;
    return ok;
}
bool wxLuaSocketBase::ReadDebugData(wxLuaDebugData& value)
{
    wxLuaDebugData debugData(true);

    wxInt32 idx, idxMax = 0;
    bool ok = ReadInt32(idxMax);

    wxLuaSocketDebugMsg(m_name + wxT(" wxLuaSocketBase::ReadDebugData"), wxString::Format(wxT("items %d"), idxMax));

    for (idx = 0; ok && (idx < idxMax); ++idx)
    {
        wxInt32 bufferLength = 0;
        ok = Read((char*)&bufferLength, sizeof(wxInt32)) == sizeof(wxInt32);

        if (ok && (bufferLength > 0))
        {
            char *pBuffer = new char[bufferLength];
            char *pMemory = pBuffer;
            ok = Read(pMemory, bufferLength) == bufferLength;
            if (!ok) break;

            wxInt32 nReference = *(wxInt32 *) pMemory;
            pMemory += sizeof(wxInt32);

            wxInt32 nIndex = *(wxInt32 *) pMemory;
            pMemory += sizeof(wxInt32);

            wxInt32 flag = *(wxInt32 *) pMemory;
            pMemory += sizeof(wxInt32);

            wxInt32 keyType = *(wxInt32 *) pMemory;
            pMemory += sizeof(wxInt32);

            wxInt32 valueType = *(wxInt32 *) pMemory;
            pMemory += sizeof(wxInt32);

            const char *pKeyPtr = pMemory;
            pMemory += strlen(pKeyPtr) + 1;
            const char *pValuePtr = pMemory;
            pMemory += strlen(pValuePtr) + 1;
            const char *pSourcePtr = pMemory;

            wxLuaDebugItem *pItem = new wxLuaDebugItem(lua2wx(pKeyPtr), keyType,
                                                       lua2wx(pValuePtr), valueType,
                                                       lua2wx(pSourcePtr),
                                                       nReference,
                                                       nIndex,
                                                       flag);
            debugData.Add(pItem);

            delete[] pBuffer;
        }
    }

    if (ok) value = debugData;
    return ok;
}

bool wxLuaSocketBase::WriteCmd(char value)
{
    wxLuaSocketDebugMsg(m_name + wxT(" wxLuaSocketBase::WriteCmd"), wxString::Format(wxT("val %d "), (int)value) + wxLuaSocketCmdEventMsg(value));
    return Write((const char*)&value, sizeof(char)) == sizeof(char);
}
bool wxLuaSocketBase::WriteInt32(wxInt32 value)
{
    wxLuaSocketDebugMsg(m_name + wxT(" wxLuaSocketBase::WriteInt32"), wxString::Format(wxT("val %d"), value));
    return Write((const char*)&value, sizeof(wxInt32)) == sizeof(wxInt32);
}
bool wxLuaSocketBase::WriteLong(long value)
{
    wxLuaSocketDebugMsg(m_name + wxT(" wxLuaSocketBase::WriteLong"), wxString::Format(wxT("val %ld"), value));
    // make sure that long really works for 32 and 64 bit platforms, use a string
    char buf[65] = { 0 }; memset(buf, 0, 65);
    sprintf(buf, "%ld", value);
    return Write(buf, 64) == 64;
}
bool wxLuaSocketBase::WriteString(const wxString &value)
{
    wxLuaCharBuffer buf(value);
    wxUint32 buflen = (wxUint32)buf.Length();

    wxLuaSocketDebugMsg(m_name + wxT(" wxLuaSocketBase::WriteString"), wxString::Format(wxT("len %u val '%s'"), buflen, value.c_str()));

    bool ok = Write((const char*)&buflen, sizeof(wxUint32)) == sizeof(wxUint32);
    if (ok && (buflen > 0))
        ok = Write(buf.GetData(), buflen) == (int)buflen;

    return ok;
}
bool wxLuaSocketBase::WriteDebugData(const wxLuaDebugData& debugData)
{
    // Debug data is written as
    // [wxInt32 debug data item count] then for each item
    //   [wxInt32 item data length]
    //   [{wxInt32 GetReference}{wxInt32 GetIndex}{wxInt32 GetFlag}
    //    {char GetName \0}{char GetType \0}{char GetValue \0}{char GetSource \0}]

    wxInt32 idx, idxMax = debugData.GetCount();

    wxLuaSocketDebugMsg(m_name + wxT(" wxLuaSocketBase::WriteDebugData"), wxString::Format(wxT("items %d"), idxMax));

    bool ok = Write((const char*)&idxMax, sizeof(wxInt32)) == sizeof(wxInt32);

    for (idx = 0; ok && (idx < idxMax); ++idx)
    {
        const wxLuaDebugItem *item = debugData.Item(idx);

        wxLuaCharBuffer keyBuffer(item->GetKey());
        wxLuaCharBuffer valueBuffer(item->GetValue());
        wxLuaCharBuffer sourceBuffer(item->GetSource());

        int keyLength    = keyBuffer.Length() + 1; // add 1 for terminating \0
        int valueLength  = valueBuffer.Length() + 1;
        int sourceLength = sourceBuffer.Length() + 1;

        wxInt32 bufferLength = (5 * sizeof(wxInt32)) +
                                keyLength + valueLength + sourceLength;

        unsigned char *pBuffer = new unsigned char[bufferLength];
        unsigned char *pMemory = pBuffer;

        ok = Write((const char*)&bufferLength, sizeof(wxInt32)) == sizeof(wxInt32);
        if (!ok) break;

        *(wxInt32 *) pMemory = (wxInt32)item->GetRef();
        pMemory += sizeof(wxInt32);

        *(wxInt32 *) pMemory = (wxInt32)item->GetIndex();
        pMemory += sizeof(wxInt32);

        *(wxInt32 *) pMemory = (wxInt32)item->GetFlag();
        pMemory += sizeof(wxInt32);

        *(wxInt32 *) pMemory = (wxInt32)item->GetKeyType();
        pMemory += sizeof(wxInt32);

        *(wxInt32 *) pMemory = (wxInt32)item->GetValueType();
        pMemory += sizeof(wxInt32);

        memcpy(pMemory, keyBuffer.GetData(), keyLength);
        pMemory += keyLength;

        memcpy(pMemory, valueBuffer.GetData(), valueLength);
        pMemory += valueLength;

        memcpy(pMemory, sourceBuffer.GetData(), sourceLength);

        ok = Write((const char *) pBuffer, bufferLength) == bufferLength;

        delete[] pBuffer;
    }

    return ok;
}

wxString wxLuaSocketBase::GetErrorMsg(bool clear_msg)
{
    wxString s(m_errorMsg);
    if (clear_msg)
        m_errorMsg.Clear();

    return s;
}

void wxLuaSocketBase::AddErrorMessage(const wxString& msg)
{
    wxString s(msg); // wxT(__TIME__)

    if (m_address.Length() != 0)
        s += wxString::Format(wxT(" Address '%s'."), m_address.c_str());
    if (m_port_number > 0)
        s += wxString::Format(wxT(" Port %d."), m_port_number);

    wxString lastErrorMsg = GetLastErrorMsg();
    if (lastErrorMsg.Length() > 0)
        s += wxT("\n") + s;

    if (m_errorMsg.Length() > 0)
        m_errorMsg += wxT("\n\n");

    m_errorMsg += s;
}

// ----------------------------------------------------------------------------
// wxLuaCSocket
// ----------------------------------------------------------------------------
IMPLEMENT_ABSTRACT_CLASS(wxLuaCSocket, wxLuaSocketBase);

wxLuaCSocket::wxLuaCSocket() : m_sock(0), m_sockstate(SOCKET_CLOSED)
{
    memset(&m_sockaddress, 0, sizeof(m_sockaddress));
}

wxLuaCSocket::wxLuaCSocket(socket_type socket, sockaddr_in address)
             :m_sock(socket), m_sockaddress(address), m_sockstate(SOCKET_ACCEPTED)
{
    m_address = lua2wx(inet_ntoa(m_sockaddress.sin_addr));
    m_port_number = ntohs(m_sockaddress.sin_port);
}

wxLuaCSocket::~wxLuaCSocket()
{
    // close the socket if not already closed, don't bother with errors
    //  since we should have shut down nicely unless the program is terminating
    if (m_sockstate != SOCKET_CLOSED)
    {
#ifdef WIN32
        ::closesocket(m_sock);
#else
        ::close(m_sock);
#endif //WIN32
    }
}

bool wxLuaCSocket::Listen(u_short port_number, int backLog)
{
    m_port_number = port_number;

    if (m_sockstate != SOCKET_CLOSED)
    {
        AddErrorMessage(wxT("Failed to create a listening socket, socket already open."));
        return false;
    }

    m_sock = ::socket(AF_INET, SOCK_STREAM, 0);

    if (m_sock == INVALID_SOCKET)
    {
        AddErrorMessage(wxT("Unable to create a listening socket."));
        return false;
    }

    sockaddr_in localAddr = { 0 };

    localAddr.sin_family      = AF_INET;
    localAddr.sin_port        = htons(port_number);
    localAddr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (::bind(m_sock, (sockaddr *) &localAddr, sizeof(localAddr)) == SOCKET_ERROR)
    {
        AddErrorMessage(wxT("Unable to bind to socket to listen for clients."));
        return false;
    }

    if (::listen(m_sock, backLog) == SOCKET_ERROR)
    {
        AddErrorMessage(wxT("Unable to listen to bound socket."));
        return false;
    }

    memset(&m_sockaddress, 0, sizeof(m_sockaddress));
    m_sockstate = SOCKET_LISTENING;

    return true;
}

wxLuaCSocket* wxLuaCSocket::Accept()
{
    if (m_sockstate != SOCKET_LISTENING)
    {
        AddErrorMessage(wxT("Unable to accept from a socket that's not listening."));
        return NULL;
    }

    sockaddr_in fromAddr = { 0 };
    socklen_t length = sizeof(fromAddr);

    socket_type acceptedSocket = ::accept(m_sock, (sockaddr *)&fromAddr, &length);
    if (acceptedSocket == INVALID_SOCKET)
    {
        AddErrorMessage(wxT("Unable to accept socket connection."));
        return NULL;
    }

    return new wxLuaCSocket(acceptedSocket, fromAddr);
}

bool wxLuaCSocket::Connect(const wxString &addr, u_short port_number)
{
    m_port_number = port_number;
    hostent *pHost = NULL;

    if (m_sockstate != SOCKET_CLOSED)
    {
        AddErrorMessage(wxString::Format(wxT("Unable to connect to addr '%s' socket already open."), addr.c_str()));
        return false;
    }

    m_sock = ::socket(AF_INET, SOCK_STREAM, 0);
    if (m_sock == INVALID_SOCKET)
    {
        AddErrorMessage(wxString::Format(wxT("Unable to create client socket for addr '%s'."), addr.c_str()));
        return false;
    }

    unsigned long  address = ::inet_addr(wx2lua(addr));
    if (address != INADDR_NONE)
        pHost = ::gethostbyaddr((const char*) &address, 4, AF_INET);
    else
        pHost = ::gethostbyname(wx2lua(addr));

    if (pHost == NULL)
    {
        AddErrorMessage(wxString::Format(wxT("Unable to get hostbyaddr or gethostbyname for addr '%s'."), addr.c_str()));
        return false;
    }

    if (pHost->h_addrtype != AF_INET)
    {
        AddErrorMessage(wxString::Format(wxT("Socket for addr '%s' is wrong type, isn't AF_INET."), addr.c_str()));
        return false;
    }

    memset(&m_sockaddress, 0, sizeof(m_sockaddress));
    memcpy(&(m_sockaddress.sin_addr), pHost->h_addr_list[0], pHost->h_length);

    m_sockaddress.sin_family = AF_INET;
    m_sockaddress.sin_port   = htons(port_number);

    m_address = lua2wx(inet_ntoa(m_sockaddress.sin_addr));
    m_port_number = ntohs(m_sockaddress.sin_port);

    if (::connect(m_sock, (sockaddr *) &m_sockaddress, sizeof(m_sockaddress)) == SOCKET_ERROR)
    {
        AddErrorMessage(wxString::Format(wxT("Unable to connect socket to addr '%s'."), addr.c_str()));
        return false;
    }

    m_sockstate = SOCKET_CONNECTED;
    return true;
}

// Write data to an open socket, repeat until all data has been sent.
int wxLuaCSocket::Write(const char *buffer_, wxUint32 length_)
{
    if ((m_sockstate != SOCKET_CONNECTED) && (m_sockstate != SOCKET_ACCEPTED))
    {
        AddErrorMessage(wxT("Unable to write to unconnected or unaccepted socket. "));
        return 0;
    }

    int length = length_;
    const char *buffer = buffer_;
    int num_written = 0;

    while (num_written < length)
    {
        int s = ::send(m_sock, buffer, length - num_written, 0);
        if (s == SOCKET_ERROR)
        {
            AddErrorMessage(wxT("Got a socket error trying to write to socket."));
            return num_written;
        }

        num_written += s;
        buffer += s;
    }

    return num_written;
}

// Read data from an open socket, repeat reading until all data has been read
int wxLuaCSocket::Read(char *buffer_, wxUint32 length_)
{
    if ((m_sockstate != SOCKET_CONNECTED) && (m_sockstate != SOCKET_ACCEPTED))
    {
        AddErrorMessage(wxT("Unable to read from an unconnected or unaccepted socket. "));
        return 0;
    }

    int length = length_;
    char *buffer = buffer_;
    int num_read = 0;

    while (num_read < length)
    {
        int r = ::recv(m_sock, buffer, length - num_read, 0);
        if (r == 0)
            return num_read;

        if (r == SOCKET_ERROR)
        {
            AddErrorMessage(wxT("Got a socket error trying to read."));
            return num_read;
        }

        num_read += r;
        buffer += r;
    }

    return num_read;
}

bool wxLuaCSocket::Shutdown(int how)
{
    if (m_sockstate != SOCKET_CLOSED)
    {
        return ::shutdown(m_sock, how) == 0;
    }

    return false;
}

bool wxLuaCSocket::Close()
{
    if (m_sockstate != SOCKET_CLOSED)
    {
#ifdef WIN32
        if (::closesocket(m_sock) == SOCKET_ERROR)
        {
            AddErrorMessage(wxT("Unable to close socket."));
            return false;
        }
#else
        if (::close(m_sock))
        {
            AddErrorMessage(wxT("Unable to close socket."));
            return false;
        }
#endif // WIN32
        else
        {
            m_sockstate = SOCKET_CLOSED;
            return true;
        }
    }

    return false;
}

wxString wxLuaCSocket::GetLastErrorMsg() const
{
    wxString str;
    int errnum = 0;

#ifdef WIN32
    errnum = ::WSAGetLastError();
    switch(errnum)
    {
        case WSANOTINITIALISED:
            str = _("A successful WSAStartup must occur before using this function.");
            break;
        case WSAENETDOWN:
            str = _("The network subsystem or the associated service provider has failed.");
            break;
        case WSAEAFNOSUPPORT:
            str = _("The specified address family is not supported.");
            break;
        case WSAEINPROGRESS:
            str = _("A blocking Windows Sockets 1.1 call is in progress, or the service provider is still processing a callback function.");
            break;
        case WSAEMFILE:
            str = _("No more socket descriptors are available.");
            break;
        case WSAENOBUFS:
            str = _("No buffer space is available. The socket cannot be created.");
            break;
        case WSAEPROTONOSUPPORT:
            str = _("The specified protocol is not supported.");
            break;
        case WSAEPROTOTYPE:
            str = _("The specified protocol is the wrong type for this socket.");
            break;
        case WSAESOCKTNOSUPPORT:
            str = _("The specified socket type is not supported in this address family.");
            break;
    }

#else // a unix type system

    str = lua2wx(strerror(errno));
    errnum = errno;
    //wxPrintf(wxT("ERRNO %d '%s' code: %d msg: '%s'\n"), errno, m_description.c_str(), code, m_msg.c_str());

#endif //WIN32

    if (str.IsEmpty())
        str = _("Unknown Socket Error.");

    str = wxString::Format(wxT("Socket Error %d : '%s'"), errnum, str.c_str());

    return str;
}

// ----------------------------------------------------------------------------
// wxLuawxSocket - Handles Debugger/Debuggee IO
// ----------------------------------------------------------------------------

bool wxLuawxSocket::Destroy()
{
    if (m_socket)
    {
        wxSocketBase* sock = m_socket;
        m_socket = NULL;
        return sock->Destroy(); // this deletes the socket
    }

    return true;
}

int wxLuawxSocket::Read(char *buffer, wxUint32 length)
{
    wxCHECK_MSG(m_socket, 0, wxT("Invalid wxLuawxSocket"));

    if (!IsConnected())
    {
        AddErrorMessage(wxT("Unable to read from an unconnected or unaccepted socket. "));
        return 0;
    }

    long num_read = 0;

    if (m_socket->WaitForRead(20, 0))
        num_read = (long)m_socket->Read(buffer, length).LastCount();

    if ((num_read < (long)length) || m_socket->Error())
    {
        wxString s(wxT("Got a socket error trying to read. "));
        if (m_socket->Error())
            s += GetLastErrorMsg();

        AddErrorMessage(s);
    }

    return num_read;
}

int wxLuawxSocket::Write(const char *buffer, wxUint32 length)
{
    wxCHECK_MSG(m_socket, 0, wxT("Invalid wxLuawxSocket"));

    if (!IsConnected())
    {
        AddErrorMessage(wxT("Unable to write to an unconnected or unaccepted socket. "));
        return 0;
    }

    long num_written = 0;

    if (m_socket->WaitForWrite(20, 0))
        num_written = m_socket->Write(buffer, length).LastCount();

    if ((num_written < (long)length) || m_socket->Error())
    {
        wxString s(wxT("Got a socket error trying to read. "));
        if (m_socket->Error())
            s += GetLastErrorMsg();

        AddErrorMessage(s);
    }

    return num_written;
}

wxString wxLuawxSocket::GetLastErrorMsg() const
{
    wxString s;
    if ((m_socket == NULL) || !m_socket->Error())
        return s;

    switch (m_socket->LastError())
    {
        case wxSOCKET_NOERROR    : s = wxT("No error happened."); break;
        case wxSOCKET_INVOP      : s = wxT("Invalid operation."); break;
        case wxSOCKET_IOERR      : s = wxT("Input/Output error."); break;
        case wxSOCKET_INVADDR    : s = wxT("Invalid address passed to wxSocket."); break;
        case wxSOCKET_INVSOCK    : s = wxT("Invalid socket (uninitialized)."); break;
        case wxSOCKET_NOHOST     : s = wxT("No corresponding host."); break;
        case wxSOCKET_INVPORT    : s = wxT("Invalid port."); break;
        case wxSOCKET_WOULDBLOCK : s = wxT("The socket is non-blocking and the operation would block."); break;
        case wxSOCKET_TIMEDOUT   : s = wxT("The timeout for this operation expired."); break;
        case wxSOCKET_MEMERR     : s = wxT("Memory exhausted."); break;
        default                  : break;
    }

    return s;
}
