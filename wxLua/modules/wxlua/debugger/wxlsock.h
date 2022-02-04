/////////////////////////////////////////////////////////////////////////////
// Name:            wxlsock.h
// Purpose:         wxLua Socket interfaces
// Author:          J. Winwood, John Labenski, Ray Gilbert
// Created:         March 2002
// Copyright:       (c) 2012 John Labenski, 2002 Lomtick Software. All rights reserved.
// Licence:         wxWidgets licence.
/////////////////////////////////////////////////////////////////////////////

#ifndef WX_LUA_SOCKET_H_
#define WX_LUA_SOCKET_H_

#include "wxlua/debugger/wxluadebuggerdefs.h"

class WXDLLIMPEXP_FWD_WXLUADEBUG wxLuaDebugData;

#ifdef WIN32
    typedef int socklen_t;
    #include <winsock.h>
#else
    #include <unistd.h>
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <cerrno>
    #include <netdb.h>
    #include <arpa/inet.h>
    #define INVALID_SOCKET -1
    #define SOCKET_ERROR   -1
#endif // !WIN32

// This is the MSW version of SHUT_RDWR for ::shutdown(sock, how=SHUT_RDWR)
// Note that these are defined in winsock2.h, but if you try to include it
// you get errors about redefinitions since it includes winsock.h anyway
#if !defined(SD_RECEIVE) && defined(SHUT_RD)
    #define SD_RECEIVE      SHUT_RD
    #define SD_SEND         SHUT_WR
    #define SD_BOTH         SHUT_RDWR
#elif !defined(SD_RECEIVE)
    #define SD_RECEIVE      0
    #define SD_SEND         1
    #define SD_BOTH         2
#endif // SD_RECEIVE


// ----------------------------------------------------------------------------
// wxLuaSocketBase - a base class for different socket implementations
//
// The derived socket class must override
//   virtual int Read(...) all ReadXXX functions use this
//   virtual int Write(...) all WriteXXX functions use this
//   virtual bool IsConnected()
// ----------------------------------------------------------------------------

class WXDLLIMPEXP_WXLUADEBUGGER wxLuaSocketBase : public wxObject
{
public:
    wxLuaSocketBase() : m_port_number(-1) {}
    virtual ~wxLuaSocketBase() {}

    // Get the port used for the socket, -1 if not initialized
    int GetPortNumber() const { return m_port_number; }
    // Get the address of the socket, empty string if not initialized
    wxString GetAddress() const { return m_address; }

    // Is the socket currently connected
    virtual bool IsConnected() = 0;

    // Read the number of bytes length into buffer from the socket
    //  the buffer must be large enough to hold the data.
    virtual int Read(char *buffer, wxUint32 length) = 0;
    // Write the whole buffer of number of bytes length to the socket
    virtual int Write(const char *buffer, wxUint32 length) = 0;

    // Note: Read/WriteCmd reads/writes a byte and if debugging prints the cmd/event type

    // Read data from the socket, calls virtual int Read(...)
    //  false is returned on failure and the input var is not modified
    bool ReadCmd(unsigned char& value);
    bool ReadInt32(wxInt32& value);
    bool ReadLong(long& value); // reads platform independent long using a string
    bool ReadString(wxString& value);
    bool ReadDebugData(wxLuaDebugData& data);

    // Write data to the socket, calls virtual void Write(...)
    //   returns success
    bool WriteCmd(char value);
    bool WriteInt32(wxInt32 value);
    bool WriteLong(long value); // write platform independent long using a string
    bool WriteString(const wxString &value);
    bool WriteDebugData(const wxLuaDebugData& debugData);

    // Concat the error message array together and optionally clear the message
    virtual wxString GetErrorMsg(bool clear_msg);
    // Add a message to the internal error message and then append any
    //   additional from GetLastErrorMsg() to it.
    void AddErrorMessage(const wxString& msg);
    // Get the last/current error message as a string
    virtual wxString GetLastErrorMsg() const = 0;

    // implementation

    wxString m_name;        // human readable name of socket, for debugging
    wxString m_errorMsg;    // human readable error message
    wxString m_address;     // The address for the socket to use
    int      m_port_number; // The port that's used, else -1

private:
    DECLARE_ABSTRACT_CLASS(wxLuaSocketBase);
};

// ----------------------------------------------------------------------------
// wxLuaCSocket - a C socket implementation for both client and server
// ----------------------------------------------------------------------------

#ifdef WIN32
    typedef SOCKET socket_type;
#else
    typedef int socket_type;
#endif

class WXDLLIMPEXP_WXLUADEBUGGER wxLuaCSocket : public wxLuaSocketBase
{
public:

    enum SocketState
    {
        SOCKET_CLOSED,
        SOCKET_LISTENING,
        SOCKET_ACCEPTED,
        SOCKET_CONNECTED
    };

    wxLuaCSocket();
    // Socket constructor from an accepted socket
    wxLuaCSocket(socket_type socket, sockaddr_in address);

    virtual ~wxLuaCSocket();

    // Create a listening socket, using the specified port number
    //   server: bind and listen for client connections
    bool Listen(u_short port, int backLog = 100);
    // Accept a connection, returning an accepted socket.
    //   server: block until accepting a connection from a client
    wxLuaCSocket* Accept();
    // Connect to a given host and port number
    //   client: connect a client to a server
    bool Connect(const wxString &address, u_short port);
    // Get the socket state
    SocketState GetState() const { return m_sockstate; }
    // Get the socket handle
    int GetSocket() const { return m_sock; }

    // Get the address of the opened socket
    wxString GetAddress();
    // Get the port number of the opened socket
    int GetPort();
    // Shutdown the socket in an orderly fashion, ::shutdown(sock, how)
    //  returns true on success
    bool Shutdown(int how = SD_BOTH);
    // Close the open socket, returns true on success
    bool Close();

    // Is the socket connected?
    //   Overridden from wxLuaSocketBase
    virtual bool IsConnected()
    {
        return ((m_sockstate == SOCKET_CONNECTED) ||
                (m_sockstate == SOCKET_ACCEPTED));
    }

    // Read the whole buffer of byte size length into buffer from the socket
    //   Overridden from wxLuaSocketBase
    virtual int Read(char *buffer, wxUint32 length);
    // Write the whole buffer of byte size length to the socket
    //   Overridden from wxLuaSocketBase
    virtual int Write(const char *buffer, wxUint32 length);

    // Get the last/current error message using the system error
    //   either errno in Unix or WSAGetLastError in MSW, doesn't clear error
    virtual wxString GetLastErrorMsg() const;

protected:
    // Prevent copying and assignment of this class
    wxLuaCSocket(const wxLuaCSocket&);
    wxLuaCSocket& operator=(const wxLuaCSocket&);

    socket_type  m_sock;
    sockaddr_in  m_sockaddress;
    SocketState  m_sockstate;

private:
    DECLARE_ABSTRACT_CLASS(wxLuaCSocket);
};

// ----------------------------------------------------------------------------
// wxLuawxSocket - Handles Debugger/Debuggee IO
// ----------------------------------------------------------------------------
#include <wx/socket.h>

class WXDLLIMPEXP_WXLUADEBUGGER wxLuawxSocket : public wxLuaSocketBase
{
public:
    wxLuawxSocket() : m_socket(NULL) {}
    wxLuawxSocket(wxSocketBase* sock) : m_socket(sock) {}

    virtual ~wxLuawxSocket() { Destroy(); }

    // Safely close and destroy the socket
    bool Destroy();

    // Get/Set the socket, if you set a new socket you must delete the
    //  previous one first
    wxSocketBase* GetSocket() const { return m_socket; }
    void SetSocket(wxSocketBase* sock) { m_socket = sock; }
    // Socket Error from wxSocketBase
    bool Error() { return !m_socket || m_socket->Error(); }
    // Is Socket Connected, from wxSocketBase
    bool WaitForRead(long seconds = 0, long milliseconds = 300) { return m_socket && m_socket->WaitForRead(seconds, milliseconds); }

    // Is Socket Connected, from wxSocketBase
    virtual bool IsConnected() { return m_socket && m_socket->IsConnected(); }

    // Read the whole buffer of size length into buffer buffer from the socket
    virtual int Read(char *buffer, wxUint32 length);
    // Write the whole buffer of size length to the socket
    virtual int Write(const char *buffer, wxUint32 length);

    virtual wxString GetLastErrorMsg() const;

protected:
    wxSocketBase* m_socket;
};

// ----------------------------------------------------------------------------
// wxLuaSocket - Choose the socket we want to use
// ----------------------------------------------------------------------------

typedef wxLuaCSocket wxLuaSocket;

#endif // WX_LUA_SOCKET_H_
