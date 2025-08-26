#ifndef CLIENT_AUTHENTICATION_PROTOCOL_H
#define CLIENT_AUTHENTICATION_PROTOCOL_H

int get_username(char *buffer, int sizeof_buffer);
int get_password(char *buffer, int sizeof_buffer);
int get_new_password(char *buffer, int sizeof_buffer);
int send_username_to_server(int socket);
int generate_nonce(unsigned char* buffer, int buffer_size, unsigned long *err);
int send_nonce(int socket, unsigned char *nonce, int nonce_len);
int verify_signature(unsigned char *signature, int signature_len, unsigned char *message, int message_len);
int get_signed_dh_params(int socket, unsigned char * key_container, unsigned char* nonce, int nonce_len);
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
int send_password_to_server(int socket, unsigned char *key_container, int* change_pwd);
int send_new_password_to_server(int socket, unsigned char *key_container);
void handleErrors();

#endif