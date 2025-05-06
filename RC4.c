#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>

#pragma comment(lib, "advapi32.lib")

BYTE* base64_decode(const char* base64_data, DWORD* out_len) {
    DWORD base64_len = strlen(base64_data);
    DWORD decoded_len = 0;

    // First, get required size
    if (!CryptStringToBinaryA(base64_data, base64_len, CRYPT_STRING_BASE64, NULL, &decoded_len, NULL, NULL)) {
        printf("[-] CryptStringToBinaryA size query failed\n");
        return NULL;
    }

    BYTE* decoded = (BYTE*)malloc(decoded_len);
    if (!decoded) return NULL;

    if (!CryptStringToBinaryA(base64_data, base64_len, CRYPT_STRING_BASE64, decoded, &decoded_len, NULL, NULL)) {
        printf("[-] CryptStringToBinaryA decode failed\n");
        free(decoded);
        return NULL;
    }

    *out_len = decoded_len;
    return decoded;
}

BOOL rc4_decrypt(const BYTE* key, DWORD key_len, const BYTE* data_in, BYTE* data_out, DWORD* data_len) {
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;
    HCRYPTHASH hHash = 0;
    BOOL result = FALSE;

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        printf("[-] CryptAcquireContext failed\n");
        return FALSE;
    }

    if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
        printf("[-] CryptCreateHash failed\n");
        goto cleanup;
    }

    if (!CryptHashData(hHash, key, key_len, 0)) {
        printf("[-] CryptHashData failed\n");
        goto cleanup;
    }

    if (!CryptDeriveKey(hProv, CALG_RC4, hHash, 0, &hKey)) {
        printf("[-] CryptDeriveKey failed\n");
        goto cleanup;
    }

    // Copy input to output buffer (RC4 decrypts in-place)
    memcpy(data_out, data_in, *data_len);

    if (!CryptDecrypt(hKey, 0, TRUE, 0, data_out, data_len)) {
        printf("[-] CryptDecrypt failed\n");
        goto cleanup;
    }

    result = TRUE;

cleanup:
    if (hHash) CryptDestroyHash(hHash);
    if (hKey) CryptDestroyKey(hKey);
    if (hProv) CryptReleaseContext(hProv, 0);

    return result;
}

int main() {
    const char* base64_str = "POQh+MW8W1sBFzm5w37OyYY=";  // ví dụ base64 RC4 mã hóa chuỗi "hello"
    const BYTE key[] = "H0wD0y0u937By73s";             // RC4 key
    DWORD key_len = sizeof(key) - 1;

    DWORD decoded_len = 0;
    BYTE* decoded_data = base64_decode(base64_str, &decoded_len);
    if (!decoded_data) {
        return 1;
    }

    BYTE* decrypted = (BYTE*)malloc(decoded_len);
    if (!decrypted) {
        free(decoded_data);
        return 1;
    }

    DWORD decrypted_len = decoded_len;
    if (!rc4_decrypt(key, key_len, decoded_data, decrypted, &decrypted_len)) {
        printf("[-] Decryption failed\n");
        free(decoded_data);
        free(decrypted);
        return 1;
    }

    printf("[+] Decrypted (%lu bytes): ", decrypted_len);
    for (DWORD i = 0; i < decrypted_len; i++) {
        putchar(decrypted[i]);
    }
    printf("\n");

    free(decoded_data);
    free(decrypted);
    return 0;
}
