#ifndef SERVER_AUTHENTICATION_PROTOCOL_H
#define SERVER_AUTHENTICATION_PROTOCOL_H

int get_user_hello(int socket, char * username);
int send_NACK(int socket);
int send_ACK(int socket);
int generate_nonce(unsigned char* buffer, int buffer_size, unsigned long *err);
int getPasskey(char * passkey, int passkey_len);
int send_signed_dh_params(int socket_fd, unsigned char * key_container, unsigned char* user_nonce, int nonce_len);
int sign(unsigned char **signature, unsigned char *message, int message_len);
int get_user_pubkey(int socket);
int gcm_encrypt(unsigned char *plaintext, int plaintext_len,
                unsigned char *aad, int aad_len,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *ciphertext,
                unsigned char *tag);
int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *aad, int aad_len,
                unsigned char *tag,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *plaintext);
int send_encrypted_message(int socket_fd, unsigned char *plaintext, int plaintext_len, unsigned char *key_container);
int get_encrypted_message(int socket_fd, unsigned char *key_container, unsigned char **plaintext, int *plaintext_len);
int is_username_valid(char *username);
int is_password_valid(const char *username, const char *password, int *change_password_flag);
int check_user_password(int socket, unsigned char *key_container, unsigned char *username, int* change_password_flag);
int change_user_password(int socket, unsigned char* key_container, unsigned char* username);
void handleErrors();

#endif
