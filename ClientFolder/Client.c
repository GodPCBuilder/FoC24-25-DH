#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "params.h"
#include "client_authentication_protocol.h"
#include "client_application_protocol.h"
#include <openssl/sha.h>

int main() {
    // Initialize parameters
    int error_message = OK;

    const char *server_ip = "127.0.0.1";
    int port = PORT;

    // Initialize the client socket
    int sock = client_init(server_ip, port);
    if (sock < 0) {
        error_handler(SOCKET_INIT_ERROR, sock);
        return SOCKET_INIT_ERROR;
    }
    
    printf("-------------------------------------------------------------------\n");
    printf("------------------SUCCESFULLY CONNECTED TO SERVER------------------\n");
    printf("-------------------------------------------------------------------\n\n");

    if ((error_message = error_handler(send_username_to_server(sock), sock)) != OK) {
        return error_message;
    }

    unsigned char nonce[16];

    if ((error_message = error_handler(send_nonce(sock, nonce, sizeof(nonce)), sock)) != OK) {
        return error_message;
    }

    unsigned char key_container[SHA256_DIGEST_LENGTH];
    if((error_message = get_signed_dh_params(sock, key_container, nonce, sizeof(nonce))) != OK) {
        return error_message;
    }

    // From here you have a session that is valid
    printf("\n\nSecure session succesfully established with the server.\n\n");
    // Client needs to send password through encrypted channel
    int change_pwd = 0; // Flag to indicate if password change is requested by server
    if((error_message = error_handler(send_password_to_server(sock, key_container, &change_pwd), sock)) != OK) {
        //printf("Error sending password\n");
        return error_message;
    }

    if(change_pwd) {
        // Here you can implement the logic to change the password
        // For example, you can prompt the user to enter a new password
        printf("----------------------------------------------------------------------------\n");
        printf("Welcome. This is your first login. Please change your password.\n");
        printf("----------------------------------------------------------------------------\n");

        // Retrieve new password
        if((error_message = error_handler(send_new_password_to_server(sock, key_container), sock)) != OK) {
            return error_message;
        }
        printf("Password changed succesfully.\n");

    }
    // At this point the client has sent the password and received an ACK from the server
    // We can initialize the session
    printf("Login completed. Welcome.\n");
    if((error_message = error_handler(run_interface(sock, key_container), sock)) != OK) {
        return error_message;
    }

    return sclose(sock); // Close the socket and return the status

}
