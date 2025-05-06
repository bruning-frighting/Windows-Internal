#include <windows.h>
#include <stdio.h>
#include <string.h>

DWORD hash_api(const char* name, const char* key) {
    size_t key_len = strlen(key);  // key là chuỗi null-terminated
    DWORD hash = 0x1337BEEF; // Có thể dùng một seed cố định hoặc biến thể khác
    size_t i = 0;

    while (*name) {
        hash ^= *name;
        hash = _rotl(hash, 7);  // Xoay bit trái
        hash += key[i % key_len]; // Dùng tuần hoàn từng byte của key
        name++;
        i++;
    }

    return hash;
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("Usage: %s <API name> <key>\n", argv[0]);
        return 1;
    }

    char* name = argv[1];  // Tên API
    const char* key = "H0wD0y0u937By73s";  // Khóa là chuỗi
    DWORD h = hash_api(name, key);  // Tính toán hash với khóa
    printf("Hash of %s: %08X\n", name, h);  // In ra hash ở dạng hex
    return 0;
}
