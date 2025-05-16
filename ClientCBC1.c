#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <openssl/evp.h>

#define PORT 8080
#define BUFFER_SIZE 1024

pthread_mutex_t mutex;
char buffer[BUFFER_SIZE];

unsigned char key[32] = "01234567890123456789012345678901";
unsigned char iv[16]  = "0123456789012345";

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ciphertext_len;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

void* read_input(void* arg) {
    while (1) {
        printf("Nhap tin nhan: ");
        fgets(buffer, BUFFER_SIZE, stdin);

        pthread_mutex_lock(&mutex);
        buffer[strcspn(buffer, "\n")] = 0;
        pthread_mutex_unlock(&mutex);
    }
}

void* send_data(void* arg) {
    int sock = *(int*)arg;
    unsigned char encrypted[BUFFER_SIZE];

    while (1) {
        pthread_mutex_lock(&mutex);
        if (strlen(buffer) > 0) {
            int encrypted_len = encrypt((unsigned char*)buffer, strlen(buffer), key, iv, encrypted);
            send(sock, encrypted, encrypted_len, 0);
            memset(buffer, 0, BUFFER_SIZE);
        }
        pthread_mutex_unlock(&mutex);
        usleep(100000);
    }
}

int main() {
    int sock;
    struct sockaddr_in server_addr;
    pthread_t input_thread, send_thread;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Tao socket that bai");
        return 1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Ket noi that bai");
        return 1;
    }

    pthread_mutex_init(&mutex, NULL);
    pthread_create(&input_thread, NULL, read_input, NULL);
    pthread_create(&send_thread, NULL, send_data, (void*)&sock);

    pthread_join(input_thread, NULL);
    pthread_join(send_thread, NULL);

    pthread_mutex_destroy(&mutex);
    close(sock);
    return 0;
}
