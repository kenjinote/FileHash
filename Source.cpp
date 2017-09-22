#pragma comment(linker,"\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

#pragma comment(lib, "shlwapi")

#include <windows.h>
#include <shlwapi.h>

#define ID_DELETE 100
#define ID_SELECTALL 101
#define ID_COPYTOCLIPBOARD 102

BOOL CalcFileHash(LPCTSTR lpszFilePath, ALG_ID Algid, LPTSTR lpszHashValue)
{
	if (PathFileExists(lpszFilePath) == FALSE) return FALSE;
	if (lpszHashValue == NULL) return FALSE;
	if ((Algid & ALG_CLASS_HASH) == 0) return FALSE;
	HANDLE hFile = CreateFile(lpszFilePath, GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}
	HCRYPTPROV hProv = 0;
	if (!CryptAcquireContext(&hProv, 0, 0, PROV_RSA_AES, CRYPT_VERIFYCONTEXT | CRYPT_MACHINE_KEYSET))
	{
		CloseHandle(hFile);
		return FALSE;
	}
	HCRYPTHASH hHash = 0;
	if (!CryptCreateHash(hProv, Algid, 0, 0, &hHash))
	{
		CloseHandle(hFile);
		CryptReleaseContext(hProv, 0);
		return FALSE;
	}
	BOOL bRet = FALSE;
	for (;;)
	{
		BYTE Buffer[64 * 1024];
		DWORD wReadSize;
		if (ReadFile(hFile, Buffer, sizeof(Buffer), &wReadSize, 0) == FALSE)
			break;
		if (!wReadSize)
			break;
		bRet = CryptHashData(hHash, Buffer, wReadSize, 0) ? TRUE : FALSE;
		if (!bRet)
			break;
	}
	CloseHandle(hFile);
	if (!bRet)
	{
		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, 0);
		return FALSE;
	}
	DWORD dwHashLen = 0;
	if (!CryptGetHashParam(hHash, HP_HASHVAL, 0, &dwHashLen, 0) || !dwHashLen)
	{
		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, 0);
		return FALSE;
	}
	LPBYTE lpHash = (LPBYTE)GlobalAlloc(GMEM_FIXED, dwHashLen);
	if (!lpHash)
	{
		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, 0);
		return FALSE;
	}
	if (!CryptGetHashParam(hHash, HP_HASHVAL, lpHash, &dwHashLen, 0))
	{
		GlobalFree(lpHash);
		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, 0);
		return FALSE;
	}
	CryptDestroyHash(hHash);
	CryptReleaseContext(hProv, 0);
	lpszHashValue[0] = 0;
	for (DWORD i = 0; i < dwHashLen; ++i)
	{
		TCHAR tmp[3] = { 0 };
		wsprintf(tmp, TEXT("%02X"), lpHash[i]);
		lstrcat(lpszHashValue, tmp);
	}
	GlobalFree(lpHash);
	return TRUE;
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	static HWND hCombo;
	static HWND hList;
	switch (msg)
	{
	case WM_CREATE:
		hCombo = CreateWindow(TEXT("COMBOBOX"), 0, WS_VISIBLE | WS_CHILD | CBS_DROPDOWNLIST, 10, 10, 256, 1024, hWnd, 0, ((LPCREATESTRUCT)lParam)->hInstance, 0);
		SendMessage(hCombo, CB_SETITEMDATA, SendMessage(hCombo, CB_ADDSTRING, 0, (LPARAM)TEXT("SHA-1")), (LPARAM)CALG_SHA1);
		SendMessage(hCombo, CB_SETITEMDATA, SendMessage(hCombo, CB_ADDSTRING, 0, (LPARAM)TEXT("SHA-256")), (LPARAM)CALG_SHA_256);
		SendMessage(hCombo, CB_SETITEMDATA, SendMessage(hCombo, CB_ADDSTRING, 0, (LPARAM)TEXT("SHA-384")), (LPARAM)CALG_SHA_384);
		SendMessage(hCombo, CB_SETITEMDATA, SendMessage(hCombo, CB_ADDSTRING, 0, (LPARAM)TEXT("SHA-512")), (LPARAM)CALG_SHA_512);
		SendMessage(hCombo, CB_SETITEMDATA, SendMessage(hCombo, CB_ADDSTRING, 0, (LPARAM)TEXT("MD5")), (LPARAM)CALG_MD5);
		SendMessage(hCombo, CB_SETCURSEL, 0, 0);
		hList = CreateWindowEx(WS_EX_CLIENTEDGE, TEXT("LISTBOX"), 0, WS_VISIBLE | WS_CHILD | WS_VSCROLL | LBS_NOINTEGRALHEIGHT | LBS_EXTENDEDSEL, 0, 0, 0, 0, hWnd, 0, ((LPCREATESTRUCT)lParam)->hInstance, 0);
		DragAcceptFiles(hWnd, TRUE);
		break;
	case WM_SIZE:
		MoveWindow(hList, 10, 50, LOWORD(lParam) - 20, HIWORD(lParam) - 60, TRUE);
		break;
	case WM_DROPFILES:
		{
			SendMessage(hList, LB_SETSEL, 0, -1);
			const ALG_ID Algid = (ALG_ID)SendMessage(hCombo, CB_GETITEMDATA, SendMessage(hCombo, CB_GETCURSEL, 0, 0), 0);
			if (Algid)
			{
				const UINT nFileCount = DragQueryFile((HDROP)wParam, 0xFFFFFFFF, NULL, 0);
				for (UINT i = 0; i < nFileCount; ++i)
				{
					TCHAR szFilePath[MAX_PATH];
					DragQueryFile((HDROP)wParam, i, szFilePath, _countof(szFilePath));
					TCHAR szHash[256];
					if (CalcFileHash(szFilePath, Algid, szHash))
					{
						TCHAR szText[1024];
						wsprintf(szText, TEXT("%s(%s)"), szHash, szFilePath);
						SendMessage(hList, LB_SETSEL, 1, SendMessage(hList, LB_ADDSTRING, 0, (LPARAM)szText));
					}
				}
			}
			DragFinish((HDROP)wParam);
		}
		break;
	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case ID_COPYTOCLIPBOARD:
			{
				const int nSelItems = (int)SendMessage(hList, LB_GETSELCOUNT, 0, 0);
				if (nSelItems > 0)
				{
					int* pBuffer = (int*)GlobalAlloc(0, sizeof(int) * nSelItems);
					SendMessage(hList, LB_GETSELITEMS, nSelItems, (LPARAM)pBuffer);
					INT nLen = 1; // NULL 終端文字分
					for (int i = 0; i < nSelItems; ++i)
					{
						nLen += (INT)SendMessage(hList, LB_GETTEXTLEN, pBuffer[i], 0);
						nLen += 2; // 改行文字 \r\n 分
					}
					HGLOBAL hMem = GlobalAlloc(GMEM_DDESHARE | GMEM_MOVEABLE, sizeof(TCHAR)*(nLen + 1));
					LPTSTR lpszBuflpszBuf = (LPTSTR)GlobalLock(hMem);
					lpszBuflpszBuf[0] = 0;
					for (int i = 0; i < nSelItems; ++i)
					{
						SendMessage(hList, LB_GETTEXT, pBuffer[i], (LPARAM)(lpszBuflpszBuf + lstrlen(lpszBuflpszBuf)));
						lstrcat(lpszBuflpszBuf, TEXT("\r\n"));
					}
					GlobalFree(pBuffer);
					GlobalUnlock(hMem);
					OpenClipboard(NULL);
					EmptyClipboard();
					SetClipboardData(CF_UNICODETEXT, hMem);
					CloseClipboard();
				}
			}
			break;
		case ID_SELECTALL:
			SendMessage(hList, LB_SETSEL, 1, -1);
			break;
		case ID_DELETE:
			{
				const INT nSelItems = (INT)SendMessage(hList, LB_GETSELCOUNT, 0, 0);
				if (nSelItems > 0)
				{
					LPINT pBuffer = (LPINT)GlobalAlloc(0, sizeof(INT) * nSelItems);
					SendMessage(hList, LB_GETSELITEMS, nSelItems, (LPARAM)pBuffer);
					for (INT i = nSelItems - 1; i >= 0; --i)
					{
						SendMessage(hList, LB_DELETESTRING, pBuffer[i], 0);
					}
					GlobalFree(pBuffer);
				}
			}
			break;
		}
		break;
	case WM_DESTROY:
		PostQuitMessage(0);
		break;
	default:
		return DefWindowProc(hWnd, msg, wParam, lParam);
	}
	return 0;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPreInst, LPSTR pCmdLine, int nCmdShow)
{
	TCHAR szClassName[] = TEXT("FileHash");
	MSG msg;
	WNDCLASS wndclass = {
		CS_HREDRAW | CS_VREDRAW,
		WndProc,
		0,
		0,
		hInstance,
		0,
		LoadCursor(0,IDC_ARROW),
		(HBRUSH)(COLOR_WINDOW + 1),
		0,
		szClassName
	};
	RegisterClass(&wndclass);
	HWND hWnd = CreateWindow(
		szClassName,
		TEXT("ドロップされたファイルのハッシュ値を求める"),
		WS_OVERLAPPEDWINDOW,
		CW_USEDEFAULT,
		0,
		CW_USEDEFAULT,
		0,
		0,
		0,
		hInstance,
		0
	);
	ShowWindow(hWnd, SW_SHOWDEFAULT);
	UpdateWindow(hWnd);
	ACCEL Accel[] = { { FVIRTKEY, VK_DELETE, ID_DELETE }, { FVIRTKEY | FCONTROL, 'A', ID_SELECTALL }, { FVIRTKEY | FCONTROL, 'C', ID_COPYTOCLIPBOARD } };
	HACCEL hAccel = CreateAcceleratorTable(Accel, sizeof(Accel) / sizeof(ACCEL));
	while (GetMessage(&msg, 0, 0, 0))
	{
		if (!TranslateAccelerator(hWnd, hAccel, &msg))
		{
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
	}
	DestroyAcceleratorTable(hAccel);
	return (int)msg.wParam;
}
