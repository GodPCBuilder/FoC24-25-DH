#ifndef SERVER_SOCKET_MANAGEMENT_H
#define SERVER_SOCKET_MANAGEMENT_H

int server_init(int * server_fd, struct sockaddr_in * address);
int sclose(int socket);
int user_sign(unsigned char **signature, unsigned char *message, int message_len, const char *currentUser);
int signDoc(const char *userID, int socket, void *key_container);
int deleteKeys(const char *userID, int socket, void *key_container);
int getKeys(int socket, void *key_container);
int GenerateKeys(const char *username, int socket, void *key_container);
int handle_user_choice(int socket, unsigned char* key_container, const char *username);
int error_handler(int error_code, int socket);

// Utility functions
void print_hex(unsigned char *data, size_t len);
int bytes_to_hex(const unsigned char *bytes, int len, char *hex_out, int hex_out_len);
int hex_to_byte(const char *hex, unsigned char *byte);
int decode_hex_string_to_bytes(const char *hex_string, unsigned char *output, int output_len);

#endif
