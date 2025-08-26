#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/dh.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rsa.h>

int generate_nonce(unsigned char* buffer, int buffer_size, unsigned long *err); 
void print_hex(unsigned char *data, size_t len);
int hex_to_byte(const char *hex, unsigned char *byte);
int bytes_to_hex(const unsigned char *bytes, int len, char *hex_out, int hex_out_len);
int decode_hex_string_to_bytes(const char *hex_string, unsigned char *output, int output_len);

int main(){
    unsigned long err;
    unsigned char nonce[16];

    unsigned char nonce2[32];
    unsigned char nonce3[32];
    unsigned char nonce2tohex[65];

    generate_nonce(nonce2,32,&err);
    bytes_to_hex(nonce2, 32, nonce2tohex, 65);
    printf("Salt: %s\n", nonce2tohex);
    decode_hex_string_to_bytes(nonce2tohex,nonce3,sizeof(nonce3));
    //printf("Nonce changed: ");
    //print_hex(nonce3, 32);
    //bytes_to_hex(nonce2,32,nonce2tohex,65);
    char computed_hash[SHA256_DIGEST_LENGTH * 2 + 1];
    char concat[512];
    char password[] = "password123"; // Example password, replace with actual input
    memcpy(concat, password, strlen(password));
    memcpy(concat + strlen(password), nonce3, sizeof(nonce3));
    //printf("\nValue to hash: ");
    //print_hex(concat, strlen(password) + sizeof(nonce3));
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)concat, strlen(password) + sizeof(nonce3), hash);

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        snprintf(computed_hash + (i * 2), 3, "%02x", hash[i]);
    computed_hash[SHA256_DIGEST_LENGTH * 2] = '\0';
    printf("Hash: %s", computed_hash);
    //printf("\nHex: ");
    //print_hex(hash, SHA256_DIGEST_LENGTH);
    

}


int generate_nonce(unsigned char* buffer, int buffer_size, unsigned long *err) {
    /* Generate a random nonce */
    int rc = RAND_bytes(buffer, buffer_size);
    *err = ERR_get_error();

    if (rc != 1) {
        /* RAND_bytes failed */
        /* `err` is valid    */
        return -1;
    }

    return 1; // Success
}

void print_hex(unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        printf("%02x", data[i]);  // 2-digit hex
    }
    printf("\n");
}

int bytes_to_hex(const unsigned char *bytes, int len, char *hex_out, int hex_out_len) {
    if(hex_out_len < 2*len){
        return -1;
    }
    for (size_t i = 0; i < len; i++) {
        snprintf(&hex_out[i * 2], 3, "%02x", bytes[i]);
    }
    hex_out[len * 2] = '\0';
    return 1;
}

int hex_to_byte(const char *hex, unsigned char *byte) {
    if (!isxdigit(hex[0]) || !isxdigit(hex[1])) return 0;

    char temp[3] = { hex[0], hex[1], '\0' };
    *byte = (unsigned char)strtol(temp, NULL, 16);
    return 1;
}

int decode_hex_string_to_bytes(const char *hex_string, unsigned char *output, int output_len) {
    int hex_len = strlen(hex_string);
    if (hex_len != output_len * 2) return 0;

    for (int i = 0; i < output_len; i++) {
        if (!hex_to_byte(&hex_string[i * 2], &output[i])) {
            return 0;
        }
    }
    return 1;
}