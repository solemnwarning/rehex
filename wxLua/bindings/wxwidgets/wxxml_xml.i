// ===========================================================================
// Purpose:     wxXML library
// Author:      J Winwood, John Labenski
// Created:     14/11/2001
// Copyright:   (c) 2001-2002 Lomtick Software. All rights reserved.
// Licence:     wxWidgets licence
// wxWidgets:   Updated to 2.8.4
// ===========================================================================

#if wxLUA_USE_wxXML && wxUSE_XML

%wxchkver_2_6 #include "wx/xml/xml.h"

enum wxXmlNodeType
{
    wxXML_ELEMENT_NODE,
    wxXML_ATTRIBUTE_NODE,
    wxXML_TEXT_NODE,
    wxXML_CDATA_SECTION_NODE,
    wxXML_ENTITY_REF_NODE,
    wxXML_ENTITY_NODE,
    wxXML_PI_NODE,
    wxXML_COMMENT_NODE,
    wxXML_DOCUMENT_NODE,
    wxXML_DOCUMENT_TYPE_NODE,
    wxXML_DOCUMENT_FRAG_NODE,
    wxXML_NOTATION_NODE,
    wxXML_HTML_DOCUMENT_NODE
};

#if %wxchkver_3_1_1
enum wxTextFileType
{
    wxTextFileType_None,  //!< incomplete (the last line of the file only)
    wxTextFileType_Unix,  //!< line is terminated with 'LF' = 0xA = 10 = '\\n'
    wxTextFileType_Dos,   //!< line is terminated with 'CR' 'LF'
    wxTextFileType_Mac,   //!< line is terminated with 'CR' = 0xD = 13 = '\\r'
    wxTextFileType_Os2    //!< line is terminated with 'CR' 'LF'
};
#endif //%wxchkver_3_1_0

// ---------------------------------------------------------------------------
// wxXmlNode

class %delete wxXmlNode
{
    %wxchkver_2_9_0 wxXmlNode(wxXmlNode* parent, wxXmlNodeType type, const wxString& name, const wxString& content = wxEmptyString, wxXmlAttribute* attrs = NULL, wxXmlNode* next = NULL, int lineNo = -1);
    %wxchkver_2_9_0 wxXmlNode(wxXmlNodeType type, const wxString& name, const wxString& content = wxEmptyString, int lineNo = -1);
    %wxchkver_2_9_0 wxXmlNode(const wxXmlNode& node);
    %wxchkver_2_9_0 void AddAttribute(const wxString& name, const wxString& value);
    %wxchkver_2_9_0 void AddAttribute(wxXmlAttribute* attr);
    void AddChild(%ungc wxXmlNode *child);
    %wxchkver_2_9_0 bool DeleteAttribute(const wxString& name);
    %wxchkver_2_9_0 bool GetAttribute(const wxString& attrName, wxString* value) const;
    %wxchkver_2_9_0 wxString GetAttribute(const wxString& attrName, const wxString& defaultVal = wxEmptyString) const;
    %wxchkver_2_9_0 wxXmlAttribute* GetAttributes() const;
    wxXmlNode *GetChildren() const;
    wxString GetContent() const;
    %wxchkver_2_9_0 int GetDepth(wxXmlNode* grandparent = NULL) const;
    %wxchkver_3_0_0 bool GetNoConversion() const;
    %wxchkver_2_9_0 int GetLineNumber() const;
    wxString GetName() const;
    wxXmlNode *GetNext() const;
    %wxchkver_2_9_0 wxString GetNodeContent() const;
    wxXmlNode *GetParent() const;
    wxXmlNodeType GetType() const;
    %wxchkver_2_9_0 bool HasAttribute(const wxString& attrName) const;
    void InsertChild(%ungc wxXmlNode *child, wxXmlNode *before_node);
    %wxchkver_2_9_0 bool InsertChildAfter(%ungc wxXmlNode* child, wxXmlNode* precedingNode);
    %wxchkver_2_9_0 bool IsWhitespaceOnly() const;
    bool RemoveChild(%gc wxXmlNode *child);
    %wxchkver_2_9_0 void SetAttributes(wxXmlAttribute* attr);
    void SetChildren(%ungc wxXmlNode *child);
    void SetContent(const wxString& con);
    void SetName(const wxString& name);
    void SetNext(wxXmlNode *next);
    %wxchkver_3_0_0 void SetNoConversion(bool noconversion);
    void SetParent(wxXmlNode *parent);
    void SetType(wxXmlNodeType type);
    !%wxchkver_2_9 %override_name wxLua_wxXmlNode_GetPropValPtr bool GetPropVal(const wxString& propName) const;
    !%wxchkver_2_9 bool DeleteProperty(const wxString& name);
    !%wxchkver_2_9 bool HasProp(const wxString& propName) const;
    !%wxchkver_2_9 void AddProperty(%ungc wxXmlProperty *prop);
    !%wxchkver_2_9 void AddProperty(const wxString& name, const wxString& value);
    !%wxchkver_2_9 void SetProperties(%ungc wxXmlProperty *prop);
    !%wxchkver_2_9 wxString GetPropVal(const wxString& propName, const wxString& defaultVal) const;
    !%wxchkver_2_9 wxXmlNode(wxXmlNode *parent, wxXmlNodeType type, const wxString& name, const wxString& content, wxXmlProperty *props, wxXmlNode *next);
    !%wxchkver_2_9 wxXmlProperty *GetProperties() const;
    !%wxchkver_2_9_0 wxXmlNode();
    !%wxchkver_2_9_0 wxXmlNode(wxXmlNodeType type, const wxString& name, const wxString& content = "");
};

// ---------------------------------------------------------------------------
// wxXmlProperty

#if !%wxchkver_2_9
class %delete wxXmlProperty
{
    wxXmlProperty();
    wxXmlProperty(const wxString& name, const wxString& value, wxXmlProperty *next);

    wxString GetName();
    wxString GetValue();
    wxXmlProperty *GetNext();
    void SetName(const wxString& name);
    void SetValue(const wxString& value);
    void SetNext(wxXmlProperty *next);
};
#endif //!%wxchkver_2_9

// ---------------------------------------------------------------------------
// wxXmlAttribute

class %delete wxXmlAttribute
{
    wxXmlAttribute();
    %wxchkver_2_9_0 wxXmlAttribute(const wxString& name, const wxString& value, wxXmlAttribute* next = NULL);
    wxString GetName() const;
    wxXmlAttribute* GetNext() const;
    wxString GetValue() const;
    void SetName(const wxString& name);
    void SetNext(wxXmlAttribute* next);
    void SetValue(const wxString& value);
};

// ---------------------------------------------------------------------------
// wxXmlDoctype

#if %wxchkver_3_1_0
class wxXmlDoctype
{
    wxXmlDoctype(const wxString& rootName = "",
                 const wxString& systemId = "",
                 const wxString& publicId = "");

    void Clear();
    const wxString& GetRootName() const;
    const wxString& GetSystemId() const;
    const wxString& GetPublicId() const;
    wxString GetFullString() const;
    bool IsValid() const;
};
#endif //%wxchkver_3_1_0

// ---------------------------------------------------------------------------
// wxXmlDocument

class %delete wxXmlDocument : public wxObject
{
    wxXmlDocument();
    %wxchkver_2_9_0 wxXmlDocument(const wxXmlDocument& doc);
    %wxchkver_2_9_0 wxXmlDocument(const wxString& filename, const wxString& encoding = "UTF-8");
    //wxXmlDocument(wxInputStream& stream, const wxString& encoding = "UTF-8");
    %wxchkver_3_0_0 void AppendToProlog(wxXmlNode* node);
    %wxchkver_3_0_0 wxXmlNode* DetachDocumentNode();
    %wxchkver_2_9_0 wxXmlNode* DetachRoot();
    !wxUSE_UNICODE && %wxchkver_2_9_0 wxString GetEncoding() const;
    wxString GetFileEncoding() const;
    %wxchkver_3_1_0 const wxXmlDoctype& GetDoctype() const;
    %wxchkver_3_1_1 wxTextFileType GetFileType() const;
    %wxchkver_3_1_1 wxString GetEOL() const;
    %wxchkver_3_0_0 wxXmlNode* GetDocumentNode() const;
    wxXmlNode *GetRoot() const;
    wxString GetVersion() const;
    bool IsOk() const;
    %wxchkver_2_9_0 bool Load(const wxString& filename, const wxString& encoding = "UTF-8", int flags = wxXMLDOC_NONE);
    %wxchkver_2_9_0 bool Load(wxInputStream& stream, const wxString& encoding = "UTF-8", int flags = wxXMLDOC_NONE);
    %wxchkver_2_9_0 bool Save(const wxString& filename, int indentstep = 1) const;
    %wxchkver_2_9_0 bool Save(wxOutputStream& stream, int indentstep = 1) const;
    %wxchkver_3_0_0 void SetDocumentNode(wxXmlNode* node);
    !wxUSE_UNICODE && %wxchkver_2_9_0 void SetEncoding(const wxString& enc);
    void SetFileEncoding(const wxString& encoding);
    %wxchkver_3_1_0 void SetDoctype(const wxXmlDoctype& doctype);
    %wxchkver_3_1_1 void SetFileType(wxTextFileType fileType);
    void SetRoot(%ungc wxXmlNode *node);
    void SetVersion(const wxString& version);
    %wxchkver_2_9_0 wxXmlDocument& operator=(const wxXmlDocument& doc);
    %wxchkver_3_0_0 static wxVersionInfo GetLibraryVersionInfo();
    !%wxchkver_2_9_0 bool Load(const wxString& filename, const wxString& encoding = "UTF-8");
    !%wxchkver_2_9_0 bool Save(const wxString& filename) const;
    !%wxchkver_2_9_0 wxXmlDocument(const wxString& filename, const wxString& encoding = "UTF-8");
    //bool Load(wxInputStream& stream, const wxString& encoding = "UTF-8");
    //bool Save(wxOutputStream& stream) const;
};

#endif //wxLUA_USE_wxXML && wxUSE_XML
