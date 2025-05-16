#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>
#include <openssl/evp.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

#define PORT 8080
#define BUFFER_SIZE 1024

char shared_buffer[BUFFER_SIZE];
HANDLE mutex;

// AES key và IV (ph?i gi?ng client)
unsigned char key[32] = "01234567890123456789012345678901";
unsigned char iv[16]  = "0123456789012345";

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, plaintext_len;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    plaintext_len = len;
    EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

DWORD WINAPI receive_thread(LPVOID lpParam) {
    SOCKET client = *(SOCKET*)lpParam;
    unsigned char temp[BUFFER_SIZE];
    unsigned char decrypted[BUFFER_SIZE];

    while (1) {
        int recv_size = recv(client, (char*)temp, BUFFER_SIZE, 0);
        if (recv_size > 0) {
            int decrypted_len = decrypt(temp, recv_size, key, iv, decrypted);
            decrypted[decrypted_len] = '\0';

            WaitForSingleObject(mutex, INFINITE);
            strcpy(shared_buffer, (char*)decrypted);
            ReleaseMutex(mutex);
        }
        Sleep(100);
    }
    return 0;
}

DWORD WINAPI display_thread(LPVOID lpParam) {
    char temp[BUFFER_SIZE];
    while (1) {
        WaitForSingleObject(mutex, INFINITE);
        strcpy(temp, shared_buffer);
        shared_buffer[0] = '\0';
        ReleaseMutex(mutex);

        if (strlen(temp) > 0) {
            printf("Nhan duoc: %s\n", temp);
        }
        Sleep(100);
    }
    return 0;
}

int main() {
    WSADATA wsa;
    SOCKET server, client;
    struct sockaddr_in server_addr, client_addr;
    int addr_len = sizeof(client_addr);

    WSAStartup(MAKEWORD(2,2), &wsa);

    server = socket(AF_INET, SOCK_STREAM, 0);
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    bind(server, (struct sockaddr*)&server_addr, sizeof(server_addr));
    listen(server, 1);

    printf("Dang cho ket noi...\n");
    client = accept(server, (struct sockaddr*)&client_addr, &addr_len);
    printf("Client da ket noi!\n");

    mutex = CreateMutex(NULL, FALSE, NULL);

    CreateThread(NULL, 0, receive_thread, &client, 0, NULL);
    CreateThread(NULL, 0, display_thread, NULL, 0, NULL);

    while (1);

    closesocket(client);
    closesocket(server);
    WSACleanup();
    return 0;
}

