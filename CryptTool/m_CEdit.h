#pragma once


#include "FIlestruct.h"
#include <memory>
// m_CEdit

class m_CEdit : public CEdit
{
	DECLARE_DYNAMIC(m_CEdit)

public:
    #define   WM_USER_CHANGE_LIST  (WM_USER + 0x100);
	m_CEdit();
	virtual ~m_CEdit();
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持
	afx_msg VOID OnDropFiles(HDROP hDropInfo);
	void m_CEdit::SetText(LPCTSTR str);
	char   cFilePathName[250] = { 0 };
protected:

	DECLARE_MESSAGE_MAP()
};


