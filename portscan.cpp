#include <iostream>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <thread> 
#include <vector>
#include <fstream>
#include <string>
#include <wininet.h>
#include <map>
#include <unordered_map>
#include <mutex>
#include <string>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "ws2_32.lib")

using namespace std;
std::map<int, std::string> portServiceMap;
std::mutex mtx;

string GetServiceFromPort(int port);

string GetOperatingSystemFromSNMPResponse(const std::string& snmp_response) {
    if (snmp_response.find("Windows") != std::string::npos) {
        return "Windows";
    }
    else if (snmp_response.find("Linux") != std::string::npos) {
        return "Linux";
    }
    else if (snmp_response.find("Cisco IOS") != std::string::npos) {
        return "Cisco IOS";
    }
    return "Unknown";
}

string GetOperatingSystemFromSMBResponse(const std::string& smb_response) {
    if (smb_response.find("Windows") != std::string::npos) {
        return "Windows";
    }
    else if (smb_response.find("Linux") != std::string::npos) {
        return "Linux";
    }
    return "Unknown";
}

string GetOperatingSystemFromSSH(std::string banner) {
    if (banner.find("OpenSSH") != std::string::npos) {
        return "Linux or Unix-like";
    }
    else if (banner.find("Microsoft") != std::string::npos) {
        return "Windows";
    }
    else {
        return "Unknown";
    }
}

string GetOperatingSystemFromTTL(int ttl) {
    if (ttl >= 64 && ttl <= 128) {
        return "Linux or Unix-like";
    }
    else if (ttl >= 128 && ttl <= 255) {
        return "Windows";
    }
    else {
        return "Unknown";
    }
}

string GetOperatingSystemFromBanner(const std::string& banner) {
    if (banner.find("Windows") != std::string::npos) {
        return "Windows";
    }
    else if (banner.find("Linux") != std::string::npos) {
        return "Linux";
    }
    else if (banner.find("Cisco IOS") != std::string::npos) {
        return "Cisco IOS";
    }
    return "Unknown";
}

string GetOperatingSystemFromHTTPResponse(const std::string& http_response) {
    if (http_response.find("Server: Microsoft-IIS") != std::string::npos) {
        return "Windows";
    }
    else if (http_response.find("Server: Apache") != std::string::npos) {
        return "Linux";
    }
    return "Unknown";
}

string GetOperatingSystemFromHTTPHeader(const std::string& http_response) {
    size_t pos = http_response.find("Server: ");
    if (pos != std::string::npos) {
        std::string server_info = http_response.substr(pos + 8);
        size_t end_pos = server_info.find("\r\n");
        if (end_pos != std::string::npos) {
            server_info = server_info.substr(0, end_pos);
            if (server_info.find("Windows") != std::string::npos) {
                return "Windows";
            }
            else if (server_info.find("Linux") != std::string::npos) {
                return "Linux";
            }
        }
    }
    return "Unknown";
}

string GetOperatingSystemFingerprint(const std::string& destination_ip, unsigned short port)
{
    // Ваш код для отправки запроса и анализа ответа
    // Возвращайте строку, представляющую отпечаток операционной системы

    // Пример:
    if (port == 22) {
        // Пример: если порт 22, то это может быть Linux
        return "Linux";
    }
    else if (port == 3389) {
        // Пример: если порт 3389, то это может быть Windows
        return "Windows";
    }
    else {
        // Если не удалось определить по порту, можно вернуть "Unknown" или провести дополнительные анализы
        return "Unknown";
    }
}

string GetServiceAndOperatingSystem(int port, const std::string& destination_ip)
{
    std::string service = GetServiceFromPort(port);
    std::string os_fingerprint = GetOperatingSystemFingerprint(destination_ip, port);

    return "Service: " + service + ", OS Fingerprint: " + os_fingerprint;
}

string GetOperatingSystemFromFTPBanner(const std::string& ftp_banner) {
    if (ftp_banner.find("Microsoft FTP Service") != std::string::npos) {
        return "Windows";
    }
    else if (ftp_banner.find("vsftpd") != std::string::npos) {
        return "Linux";
    }
    return "Unknown";
}

void PrintNSALogo() {
    cout << "\033[1;31m"; // Устанавливаем красный цвет
    cout <<
        "      A      N   N  GGG  EEEEE  L        DDDD   EEEEE  TTTTT EEEEE CCCC TTTTT OOO  RRRR \n"
        "     A A     NN  N G     E      L        D   D  E        T   E     C       T  O   O R   R\n"
        "    A   A    N N N G  GG EEEEE  L        D   D  EEEE     T   EEEE  C       T  O   O RRRR \n"
        "   AAAAAAA   N  NN G   G E      L        D   D  E        T   E     C       T  O   O R  R \n"
        "  A       A  N   N  GGGG EEEEE  LLLLL    DDDD   EEEEE    T   EEEEE  CCCC    T   OOO  R   RR\n\t\n";
    cout << "\033[0m"; // Возвращаем обычный цвет
}
// Функция для загрузки данных из nmap-service-probes
void LoadServiceProbes() {
    std::ifstream file("C:\\Users\\Wrzesien\\source\\repos\\portscan\\nmap-service-probes");
    std::string line;

    while (std::getline(file, line)) {
        if (line.find("match ") == 0) {
            size_t pos1 = line.find(" ", 6);
            size_t pos2 = line.find(" ", pos1 + 1);
            int port = std::stoi(line.substr(pos1, pos2 - pos1));
            std::string service = line.substr(pos2 + 1);
            portServiceMap[port] = service;
        }
    }
}

void LoadServicesThread() {
    mtx.lock();
    LoadServiceProbes();
    mtx.unlock();
}

void ScanPortsUDP() {
   
}

void ScanPortsTCP() {
    
}

void ScanPortsFTP() {
   
}
//функция для сопоставления портов и служб
std::string GetServiceFromPort(int port) {
    auto it = portServiceMap.find(port);
    if (it != portServiceMap.end()) {
        return it->second;
    }
    return "Unknown";
}

void CheckService(std::string destination_ip, unsigned short port, std::ostream& output)
{
    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0)
    {
        cout << "\033[1;31m";
        output << "Error initializing Winsock" << endl;
        return;
    }

    SOCKET socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket_fd == INVALID_SOCKET)
    {
        cout << "\033[1;31m";
        output << "Error creating socket: " << WSAGetLastError() << endl;
        WSACleanup();
        return;
    }

    sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(port);

    wchar_t dest_ip_wide[16];
    MultiByteToWideChar(CP_UTF8, 0, destination_ip.c_str(), -1, dest_ip_wide, 16);
    InetPton(AF_INET, dest_ip_wide, &(dest_addr.sin_addr));

    if (connect(socket_fd, (struct sockaddr*)&dest_addr, sizeof(dest_addr)) == SOCKET_ERROR)
    {
        cout << "\033[1;31m";
        output << "Error connecting to " << destination_ip << ":" << port << " - Error code: " << WSAGetLastError() << endl;
        closesocket(socket_fd);
        WSACleanup();
        return;
    }

    output << destination_ip << ":" << port << " is open." << endl;

    // Далее, в зависимости от порта и типа соединения (TCP/UDP/FTP), 
    // вам потребуется отправить запрос и анализировать ответ.

    closesocket(socket_fd);
    WSACleanup();
    return;
}

void CheckForWebServer(const std::string& destination_ip, std::ostream& output)
{
    HINTERNET hInternet = InternetOpen(L"Service Checker", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet)
    {
        cout << "\033[1;31m";
        output << "Error initializing WinINet" << endl;
        return;
    }

    wstring wideString = wstring(destination_ip.begin(), destination_ip.end());

    HINTERNET hConnect = InternetOpenUrl(hInternet, (L"http://" + wideString).c_str(), NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (hConnect)
    {
        DWORD responseCode;
        DWORD responseCodeSize = sizeof(responseCode);
        if (HttpQueryInfo(hConnect, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &responseCode, &responseCodeSize, NULL) && responseCode == 200)
        {
            output << destination_ip << " is running a web server (HTTP) on port 80." << endl;
        }
        InternetCloseHandle(hConnect);
    }
    else
    {
        output << destination_ip << " does not have a web server (HTTP) running on port 80." << endl;
    }

    InternetCloseHandle(hInternet);
}

void HandleTCPConnection(std::string destination_ip, unsigned short start_port, unsigned short end_port, int max_attempts, std::ostream& output)
{
   
    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0)
    {
        cout << "\033[1;31m";
        output << "Error initializing Winsock" << endl;
        return;
    }

    int total_ports = end_port - start_port + 1;
    int scanned_ports = 0;

    for (unsigned short port = start_port; port <= end_port; port++)
    {

        scanned_ports++;

        // Обновляем состояние сканирования в процентах
        float progress = (float)scanned_ports / total_ports * 100;
        cout << "\rScanning progress:" << progress << "%";
        cout.flush();

        std::string serviceName = GetServiceFromPort(port);
        cout << "\033[1;34m";
        output << "  Port " << port << " is associated with service: " << serviceName << std::endl;

        int attempts = 0;
        SOCKET socket_fd;
        cout << "\033[1;34m";
        cout << "Scanning port " << port << "..." << endl;

        while (attempts < max_attempts)
        {
            socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (socket_fd == INVALID_SOCKET)
            {
                output << "Error creating socket: " << WSAGetLastError() << endl;
                WSACleanup();
                return;
            }

            sockaddr_in dest_addr;
            memset(&dest_addr, 0, sizeof(dest_addr));
            dest_addr.sin_family = AF_INET;
            dest_addr.sin_port = htons(port);

            wchar_t dest_ip_wide[16];
            MultiByteToWideChar(CP_UTF8, 0, destination_ip.c_str(), -1, dest_ip_wide, 16);
            InetPton(AF_INET, dest_ip_wide, &(dest_addr.sin_addr));

            if (connect(socket_fd, (struct sockaddr*)&dest_addr, sizeof(dest_addr)) == SOCKET_ERROR)
            {
                cout << "\033[1;31m";
                output << "Error connecting to " << destination_ip << ":" << port << " - Error code: " << WSAGetLastError() << endl;
                closesocket(socket_fd);
                attempts++;
            }
            else
            {
                output << destination_ip << ":" << port << " is open." << endl;
                closesocket(socket_fd);
                WSACleanup();
                return;
            }
        }

        cout << "\033[1;31m";
        output << "Failed to connect to " << destination_ip << ":" << port << " after " << max_attempts << " attempts." << endl;
    }
    CheckForWebServer(destination_ip, output);
    WSACleanup();
    return;
}

void HandleUDPConnection(std::string destination_ip, unsigned short start_port, unsigned short end_port, int max_attempts, std::ostream& output)
{
   
    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0)
    {
        output << "Error initializing Winsock" << endl;
        return;
    }

    int total_ports = end_port - start_port + 1;
    int scanned_ports = 0;

    for (unsigned short port = start_port; port <= end_port; port++)
    {
        scanned_ports++;

        // Обновляем состояние сканирования в процентах
        float progress = (float)scanned_ports / total_ports * 100;
        cout << "\rScanning progress:" << progress << "%";
        cout.flush();

        int attempts = 0;
        SOCKET socket_fd;
        cout << "\033[1;34m";
        cout << "Scanning port " << port << " (UDP)..." << endl;

        while (attempts < max_attempts)
        {
            socket_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
            if (socket_fd == INVALID_SOCKET)
            {
                cout << "\033[1;31m";
                output << "Error creating socket: " << WSAGetLastError() << endl;
                WSACleanup();
                return;
            }

            sockaddr_in dest_addr;
            memset(&dest_addr, 0, sizeof(dest_addr));
            dest_addr.sin_family = AF_INET;
            dest_addr.sin_port = htons(port);

            wchar_t dest_ip_wide[16];
            MultiByteToWideChar(CP_UTF8, 0, destination_ip.c_str(), -1, dest_ip_wide, 16);
            InetPton(AF_INET, dest_ip_wide, &(dest_addr.sin_addr));

            int send_result = sendto(socket_fd, "", 1, 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr));

            if (send_result == SOCKET_ERROR) {
                cout << "\033[1;31m";
                output << "Error sending to " << destination_ip << ":" << port << " (UDP) - Error code: " << WSAGetLastError() << endl;
            }
            else {
                output << destination_ip << ":" << port << " is open (UDP)." << endl;
            }

            closesocket(socket_fd);
            WSACleanup();
            return;
        }

        cout << "\033[1;31m";
        output << "Failed to connect to " << destination_ip << ":" << port << " after " << max_attempts << " attempts." << endl;
    }
    CheckForWebServer(destination_ip, output);
    WSACleanup();
    return;
}

void HandleFTPConnection(std::string destination_ip, int max_attempts, std::ostream& output)
{
    int total_attempts = max_attempts;
    int attempted_connections = 0;

    while (attempted_connections < total_attempts)
    {
        // ...

        attempted_connections++;

        // Обновляем состояние сканирования в процентах
        float progress = (float)attempted_connections / total_attempts * 100;
        cout << "\rScanning progress: " << progress << "%";
        cout.flush();
    }

    HINTERNET hInternet = InternetOpen(L"FTP Checker", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet)
    {
        cout << "\033[1;31m";
        output << "Error initializing WinINet" << endl;
        return;
    }

    wstring wideString = wstring(destination_ip.begin(), destination_ip.end());
    LPCWSTR wideChar = wideString.c_str();

    HINTERNET hFtpSession = InternetConnect(hInternet, wideChar, INTERNET_DEFAULT_FTP_PORT, L"", L"", INTERNET_SERVICE_FTP, 0, 0);
    if (!hFtpSession)
    {
        cout << "\033[1;31m";
        output << "Error connecting to FTP server - Error code: " << GetLastError() << endl;
        InternetCloseHandle(hInternet);
        return;
    }

    output << destination_ip << " FTP port is open." << endl;

    InternetCloseHandle(hFtpSession);
    InternetCloseHandle(hInternet);
}

int main()
{
    PrintNSALogo();

    int max_attempts = 1;
    unsigned short start_port, end_port;
    int scan_type;
    int device_count;

    cout << "Enter the number of devices to scan: ";
    cin >> device_count;

    cout << "Enter scan type (1 for TCP, 2 for UDP, 3 for FTP): ";
    cin >> scan_type;

  
    switch (scan_type)
    {
    case 1:
        cout << "Enter the starting port: ";
        cin >> start_port;
        cout << "Enter the ending port: ";
        cin >> end_port;

        while (device_count > 0) // Используем диапазон для определения количества устройств
        {
            // ...
            device_count--;
        }

        while (true)
        {
            string destination_ip;
            cout << "Enter the destination IP address (or 'exit' to quit): ";
            cin >> destination_ip;

            if (destination_ip == "exit")
                break;

            thread t1(HandleTCPConnection, destination_ip, start_port, end_port, max_attempts, ref(cout));
            t1.join();
        }
        break;

    case 2:

        while (device_count > 0) // Используем диапазон для определения количества устройств
        {
            // ...
            device_count--;
        }

        while (true)
        {
            cout << "Enter the starting port: ";
            cin >> start_port;
            cout << "Enter the ending port: ";
            cin >> end_port;

            string destination_ip;
            cout << "Enter the destination IP address (or 'exit' to quit): ";
            cin >> destination_ip;

            if (destination_ip == "exit")
                break;

            thread t1(HandleUDPConnection, destination_ip, start_port, end_port, max_attempts, ref(cout));
            t1.join();
        }
        break;

    case 3:

        while (device_count > 0) // Используем диапазон для определения количества устройств
        {
            // ...
            device_count--;
        }
        while (true)
        {
            cout << "Enter the starting port: ";
            cin >> start_port;
            cout << "Enter the ending port: ";
            cin >> end_port;

            string destination_ip;
            cout << "Enter the destination IP address (or 'exit' to quit): ";
            cin >> destination_ip;

            if (destination_ip == "exit")
                break;

            thread t1(HandleFTPConnection, destination_ip, max_attempts, ref(cout));
            t1.join();
        }
        break;

    default:
        cout << "Invalid scan type. Please enter 1 for TCP, 2 for UDP, 3 for FTP." << endl;
    }

    thread t1(LoadServicesThread);
    t1.join(); // Дождитесь завершения загрузки служб

    thread t2(ScanPortsUDP);
    thread t3(ScanPortsTCP);
    thread t4(ScanPortsFTP);

    t2.join();
    t3.join();
    t4.join();

    std::string snmp_response = "Windows SNMP response";
    std::string smb_response = "Linux SMB response";
    std::string ssh_banner = "OpenSSH banner";
    int ttl = 64;
    std::string banner = "Web server banner";
    std::string http_response = "HTTP Response";
    std::string ftp_banner = "FTP Banner";

    std::cout << GetOperatingSystemFromSNMPResponse(snmp_response) << std::endl;
    std::cout << GetOperatingSystemFromSMBResponse(smb_response) << std::endl;
    std::cout << GetOperatingSystemFromSSH(ssh_banner) << std::endl;
    std::cout << GetOperatingSystemFromTTL(ttl) << std::endl;
    std::cout << GetOperatingSystemFromBanner(banner) << std::endl;
    std::cout << GetOperatingSystemFromHTTPResponse(http_response) << std::endl;
    std::cout << GetOperatingSystemFromHTTPHeader(http_response) << std::endl;
    std::cout << GetOperatingSystemFromFTPBanner(ftp_banner) << std::endl;

    return 0;
}