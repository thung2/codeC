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
char shared_buffer[BUFFER_SIZE];

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

void* receive_data(void* arg) {
    int client_sock = *(int*)arg;
    unsigned char buffer[BUFFER_SIZE];
    unsigned char decrypted[BUFFER_SIZE];

    while (1) {
        int len = recv(client_sock, buffer, BUFFER_SIZE, 0);
        if (len <= 0) break;

        int decrypted_len = decrypt(buffer, len, key, iv, decrypted);
        decrypted[decrypted_len] = '\0';

        pthread_mutex_lock(&mutex);
        strncpy(shared_buffer, (char*)decrypted, BUFFER_SIZE);
        pthread_mutex_unlock(&mutex);
    }
    return NULL;
}

void* display_data(void* arg) {
    char temp[BUFFER_SIZE];

    while (1) {
        pthread_mutex_lock(&mutex);
        if (strlen(shared_buffer) > 0) {
            strncpy(temp, shared_buffer, BUFFER_SIZE);
            shared_buffer[0] = '\0';
            pthread_mutex_unlock(&mutex);

            printf("Nhan duoc: %s\n", temp);
        } else {
            pthread_mutex_unlock(&mutex);
        }
        usleep(100000);
    }
}

int main() {
    int server_sock, client_sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_size = sizeof(client_addr);
    pthread_t recv_thread, disp_thread;

    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr));
    listen(server_sock, 1);

    printf("Dang cho ket noi...");
    client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &addr_size);
    printf("\nClient da ket noi!\n");

    pthread_mutex_init(&mutex, NULL);
    pthread_create(&recv_thread, NULL, receive_data, (void*)&client_sock);
    pthread_create(&disp_thread, NULL, display_data, NULL);

    pthread_join(recv_thread, NULL);
    pthread_join(disp_thread, NULL);

    pthread_mutex_destroy(&mutex);
    close(client_sock);
    close(server_sock);
    return 0;
}
