#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>

#include <openssl/rand.h>
#include <openssl/err.h>

#include "params.h"
#include "server_application_protocol.h"
#include "server_authentication_protocol.h"
#include <openssl/sha.h>

int main() {

    // Initialize parameters
    int error_code = OK;
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);

    // Initialize the server
    error_code = server_init(&server_fd, &address);
    if (error_code < 0) {
        error_handler(error_code, -1);
        exit(EXIT_FAILURE);
    }

    printf("Server initialized and listening on port %d\n", PORT);

    // Main loop to accept connections
    while(1){

        printf("\nWaiting for a connection...\n");

        // Accept a new connection
        new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen);

        // Check if accept was successful
        if (new_socket < 0) {
            fprintf(stderr, "[Server]: Failed to accept a connection.");
            continue; // Continue to the next iteration to accept new connections
        }

        char username[MAX_USERNAME_LENGTH + 1];
        // Read the username from the client
        if((error_code = get_user_hello(new_socket, username)) != OK){
            switch (error_code)
            {
            case BAD_USERNAME:
                // If the username is invalid, we send a NACK and close the socket
                if(error_handler(send_NACK(new_socket), new_socket) == OK)
                    sclose(new_socket);
                fprintf(stderr, "[Server]: Invalid username.\n");
                fprintf(stderr, "[Server]: The connection has been terminated.\n");
                break;
            default:
                // Handle other errors
                error_handler(error_code, new_socket);
            }
            continue;
        }
        // We have a valid username, but we need to check wether that username exists
        else if((error_code = is_username_valid(username)) != OK){
            switch(error_code){
                case BAD_USERNAME:
                    // If the username is not registered, we send a NACK and close the socket
                    if(error_handler(send_NACK(new_socket), new_socket) == OK)
                        sclose(new_socket);
                    fprintf(stderr, "[Server]: Username not registered.\n");
                    fprintf(stderr, "[Server]: The connection has been terminated.\n");
                    break;
                default:
                    // Handle other errors
                    error_handler(error_code, new_socket);
            }
            continue;
        }
        printf("[Server]: Username received: %s\n", username);

        // Send ACK
        if(error_handler(send_ACK(new_socket), new_socket) != OK){
            continue;
        }

        unsigned char nonce[16];

        // Get the client's nonce
        if(read(new_socket, nonce, sizeof(nonce)), new_socket < OK) {
            error_handler(SOCKET_READ_ERROR, new_socket);
            continue; // Continue to the next iteration to accept new connections
        }

        unsigned char key_container[SHA256_DIGEST_LENGTH];

        // Evaluate the shared secret for a session
        if(error_handler(send_signed_dh_params(new_socket, key_container, nonce, sizeof(nonce)), new_socket) != OK) {
            continue; // Continue to the next iteration to accept new connections
        }

        int change_password_flag = -1; // Flag to indicate if the user needs to change password

        // Check the user's password
        if(error_handler(check_user_password(new_socket, key_container, username, &change_password_flag), new_socket) != OK) {
            continue; // Continue to the next iteration to accept new connections
        }
        
        // If the user needs to change password, we handle that case
        if(change_password_flag == 1) {
            printf("[Server]: User %s needs to change password.\n", username);
            // Send a request to change password
            if(error_handler(change_user_password(new_socket, key_container, username), new_socket) != OK) {
                continue; // Handle error and continue to the next iteration
            printf("[Server]: Password changed successfully for user %s.\n", username);
            }
        }

        // The server listens for requests from the client and executes them
        if(error_handler(handle_user_choice(new_socket, key_container, username), new_socket) != OK) {
            continue; // Continue to the next iteration to accept new connections
        }

    }
    
    close(new_socket);
    close(server_fd);
    return 0;
}


