// ===========================================================================
// Purpose:     wxWebRequest library
// Author:      Daniel Collins
// Created:     19/09/2025
// Copyright:   (c) 2025 Daniel Collins. All rights reserved.
// Licence:     wxWidgets licence
// ===========================================================================

#if wxLUA_USE_wxWebRequest && wxUSE_WEBREQUEST

#include "wx/webrequest.h"

class %delete wxWebResponse
{
	wxWebResponse();
	
	bool IsOk() const;
	wxString GetURL() const;
	wxString GetHeader(const wxString &name) const;
	wxFileOffset GetContentLength() const;
	wxString GetMimeType() const;
	int GetStatus() const;
	wxString GetStatusText() const;
	wxInputStream *GetStream();
	wxString GetSuggestedFileName() const;
	wxString GetDataFile() const;
	wxString AsString() const;
};

enum wxWebRequest::State
{
	State_Idle,
	State_Unauthorized,
	State_Active,
	State_Completed,
	State_Failed,
	State_Cancelled,
};

enum wxWebRequest::Storage
{
	Storage_Memory,
	Storage_File,
	Storage_None,
};

class %delete wxWebRequest
{
	wxWebRequest();
	
	bool IsOk() const;
	void Start();
	void Cancel();
	wxWebResponse GetResponse() const;
	// wxWebAuthChallenge 	GetAuthChallenge () const
	int GetId() const;
	
	void SetHeader(const wxString &name, const wxString &value);
	void SetMethod(const wxString &method);
	void SetData(const wxString &text, const wxString &contentType); // , const wxMBConv &conv = wxConvUTF8);
	bool SetData(wxInputStream *dataStream, const wxString &contentType, wxFileOffset dataSize = wxInvalidOffset);
	void SetStorage(wxWebRequest::Storage storage);
	void DisablePeerVerify(bool disable=true);
	bool IsPeerVerifyDisabled() const;
	
	wxWebRequest::State GetState() const;
	wxFileOffset GetBytesSent() const;
	wxFileOffset GetBytesExpectedToSend() const;
	wxFileOffset GetBytesReceived() const;
	wxFileOffset GetBytesExpectedToReceive() const;
};

class %delete wxWebRequestEvent: public wxEvent
{
	wxWebRequest::State GetState() const;
	const wxWebRequest &GetRequest() const;
	const wxWebResponse &GetResponse() const;
	const wxString &GetErrorDescription() const;
	const wxString &GetDataFile() const;
	wxString GetData() const;

	%wxEventType wxEVT_WEBREQUEST_DATA
	%wxEventType wxEVT_WEBREQUEST_STATE
};

class wxWebSession
{
	static wxWebSession &GetDefault();
	
	wxWebRequest CreateRequest(wxEvtHandler *handler, const wxString &url, int id = wxID_ANY);
	void AddCommonHeader(const wxString &name, const wxString &value);
	void SetTempDir (const wxString &dir);
	wxString GetTempDir() const;
	bool IsOpened() const;
};

#endif // wxLUA_USE_wxWebRequest && wxUSE_WEBREQUEST
