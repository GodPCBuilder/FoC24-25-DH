#ifndef CLIENT_SOCKET_MANAGEMENT_H
#define CLIENT_SOCKET_MANAGEMENT_H

int client_init(const char *ip_address, int port);
int receive_public_key(int socket, void *key_container);
int request_document_signature(int socket,unsigned char* key_container);

void print_menu();
int run_interface(int socket, unsigned char* key_container);
int sclose(int socket);
int error_handler(int error_code, int socket);

// Utility functions
void print_hex(unsigned char *data, size_t len);

#endif
