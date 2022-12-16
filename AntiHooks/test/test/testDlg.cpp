
// testDlg.cpp: 实现文件
//

#include "pch.h"
#include "framework.h"
#include "test.h"
#include "testDlg.h"
#include "afxdialogex.h"




#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CtestDlg 对话框



CtestDlg::CtestDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_TEST_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CtestDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CtestDlg, CDialogEx)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON1, &CtestDlg::OnBnClickedButton1)
END_MESSAGE_MAP()


// CtestDlg 消息处理程序

BOOL CtestDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CtestDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CtestDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING* PUNICODE_STRING;
typedef const UNICODE_STRING* PCUNICODE_STRING;


typedef struct _SYSTEM_PROCESS_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	BYTE Reserved1[48];
	UNICODE_STRING ImageName;
	LONG BasePriority;
	HANDLE UniqueProcessId;
	PVOID Reserved2;
	ULONG HandleCount;
	ULONG SessionId;
	PVOID Reserved3;
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG Reserved4;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	PVOID Reserved5;
	SIZE_T QuotaPagedPoolUsage;
	PVOID Reserved6;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER Reserved7[6];
} SYSTEM_PROCESS_INFORMATION,* LPSYSTEM_PROCESS_INFORMATION;


typedef LONG( *fn_NtQuerySystemInformation)(
LONG                     SystemInformationClass,
PVOID                    SystemInformation,
ULONG                    SystemInformationLength,
PULONG                   ReturnLength);

typedef LONG( *fn_NtQueryInformationProcess)(
HANDLE           ProcessHandle,
LONG ProcessInformationClass,
PVOID            ProcessInformation,
ULONG            ProcessInformationLength,
PULONG           ReturnLength);


//NtQuerySystemInformation
DWORD GetPidByName(wchar_t* processName)
{
	HMODULE hModule = GetModuleHandleW(L"ntdll.dll");
	if (hModule == NULL)
	{
		return 0;
	}

	fn_NtQuerySystemInformation NtQuerySystemInformation = (fn_NtQuerySystemInformation)
		GetProcAddress(hModule, "NtQuerySystemInformation");

	ULONG size = 0;
	NtQuerySystemInformation(5, NULL, NULL, &size);//拿到合适的缓冲区大小.如果缓冲区大小不够，通常会返回0xC0000004


	void* buffer = malloc(size);
	if (buffer == NULL)
	{
		return 0;
	}

	NtQuerySystemInformation(5, buffer, size - 1, NULL);  



	LPSYSTEM_PROCESS_INFORMATION pro = (LPSYSTEM_PROCESS_INFORMATION)buffer;

	ULONG pid = 0;

	do
	{
		pro = (LPSYSTEM_PROCESS_INFORMATION)((ULONG64)pro + pro->NextEntryOffset);
		if (pro->UniqueProcessId == 0)
		{
			continue;
		}	
		if (pro->ImageName.Buffer)
		{
			if (wcscmp(pro->ImageName.Buffer, processName) == 0)
			{
				pid = HandleToULong(pro->UniqueProcessId);
				break;
			}

		}
	} while (pro->NextEntryOffset != 0);

	free(buffer);
	return pid;
}


bool GetProcessFullName(ULONG pid,wchar_t * processName)
{
	HMODULE hModule = GetModuleHandleW(L"ntdll.dll");
	if (hModule == NULL)
	{
		return false;
	}
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
	if (hProcess == NULL)
	{
		return false;
	}

	fn_NtQueryInformationProcess NtQueryInformationProcess = (fn_NtQueryInformationProcess)
		GetProcAddress(hModule, "NtQueryInformationProcess");


	ULONG size = 0;
	NtQueryInformationProcess(hProcess, 43, NULL, NULL, &size);//拿到合适的缓冲区大小.如果缓冲区大小不够，通常会返回0xC0000004

	void* buffer = malloc(size);
	if (buffer == NULL)
	{
		CloseHandle(hProcess);
		return false;
	}
	if (NtQueryInformationProcess(hProcess, 43, buffer, size, NULL) == 0)
	{
		PUNICODE_STRING path = (PUNICODE_STRING)buffer;
		memcpy(processName, path->Buffer, path->Length);
		free(buffer);
		CloseHandle(hProcess);
		return true;
	}

	free(buffer);
	CloseHandle(hProcess);
	return false;
}

ULONG GetDebugerPID()
{
	HMODULE hModule = GetModuleHandleW(L"ntdll.dll");
	if (hModule == NULL)
	{
		return 0;
	}

	fn_NtQuerySystemInformation NtQuerySystemInformation = (fn_NtQuerySystemInformation)
		GetProcAddress(hModule, "NtQuerySystemInformation");

	ULONG size = 0;
	NtQuerySystemInformation(5, NULL, NULL, &size);//拿到合适的缓冲区大小.如果缓冲区大小不够，通常会返回0xC0000004


	void* buffer = malloc(size);
	if (buffer == NULL)
	{
		return 0;
	}

	NtQuerySystemInformation(5, buffer, size - 1, NULL);

	LPSYSTEM_PROCESS_INFORMATION pro = (LPSYSTEM_PROCESS_INFORMATION)buffer;

	ULONG retPid = 0;

	do
	{
		pro = (LPSYSTEM_PROCESS_INFORMATION)((ULONG64)pro + pro->NextEntryOffset);
		if (pro->UniqueProcessId == 0)
		{
			continue;
		}

		wchar_t fileName[MAX_PATH] = { 0 };
		if (GetProcessFullName(HandleToULong(pro->UniqueProcessId), fileName))
		{
			wchar_t* temp = wcsrchr(fileName, L'\\');
			int len = (int)(wcslen(fileName) - wcslen(temp));

			memcpy(fileName + len, L"\\TitanEngine.dll", sizeof(L"\\TitanEngine.dll"));

			HANDLE hFile = CreateFileW(fileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
				FILE_ATTRIBUTE_NORMAL, NULL);
			if (hFile != INVALID_HANDLE_VALUE)
			{
				CloseHandle(hFile);
				retPid = HandleToULong(pro->UniqueProcessId);
				break;
			}
		}

	} while (pro->NextEntryOffset != 0);

	free(buffer);
	return retPid;
}


void CtestDlg::OnBnClickedButton1()
{
	ULONG pid = GetDebugerPID();
	if (pid >0)
	{
		CString  str;
		str.Format(L"发现调试器，PID:%d", pid);
		MessageBoxW(str);

	}
	else
	{
		MessageBoxW(L"未发现调试器");
	}

	

	
}
