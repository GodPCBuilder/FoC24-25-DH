#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/sha.h>
#include <unistd.h>

#include "params.h"
#include "client_application_protocol.h"
#include "client_authentication_protocol.h"

// Initializes a TCP client socket and connects to the specified server IP and port
// Returns the socket file descriptor on success, or a negative error code on failure
int client_init(const char *ip_address, int port) {
    int sock = 0; // Socket file descriptor
    struct sockaddr_in serv_addr; // Struct that holds server address information

    // Create the socket: IPv4 (AF_INET), TCP (SOCK_STREAM), default protocol (0)
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return SOCKET_INIT_ERROR; // Socket creation failed
    }

    // Set address family to IPv4
    serv_addr.sin_family = AF_INET;

    // Convert the port number from host byte order to network byte order
    serv_addr.sin_port = htons(port);

    // Convert the server's IP address (as string) into binary form and store it in serv_addr
    // Returns 1 on success, 0 if invalid format, -1 on error
    if (inet_pton(AF_INET, ip_address, &serv_addr.sin_addr) <= 0) {
        sclose(sock);
        return INVALID_ADDRESS_ERROR; // Invalid address format
    }

    // Attempt to connect to the server using the socket and server address info
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        sclose(sock);
        return CONNECTION_ERROR; // Connection to the server failed
    }

    // Successfully connected to the server, return the socket descriptor
    return sock;
}

int get_pubkey_username(char *buffer, int sizeof_buffer) {

    printf("-------------------------------------------------------------------\n");
    printf("Please enter the username of interest (max %d characters): ", MAX_USERNAME_LENGTH);
    
    // Read user input from stdin into the buffer
    if (fgets(buffer, sizeof_buffer, stdin)) { 

        size_t len = strlen(buffer); // Get the length of the input string (including '\n' if present)

        // If only a newline was entered (i.e., input is just '\n')
        if (len == 1) { 
            printf("[Error]: Username cannot be empty.\n");
            return BAD_USERNAME;
        }

        // If input ends with a newline (user hit Enter within buffer size)
        if (len > 0 && buffer[len - 1] == '\n') {
            buffer[len - 1] = '\0'; // Replace newline with null terminator

        } else {

            // If the input didn't fit entirely in the buffer (no '\n'), we need to flush the rest
            int ch, i = 0;
            while ((ch = getchar()) != '\n' && ch != EOF){i++;}; // Count how many characters we discard

            if(i > 0){
                // User typed more characters than allowed, input was truncated
                printf("[Error]: Username too long. Please try again.\n");
                return BAD_USERNAME;
            }
        }
    } else {
        // fgets() failed (EOF or error on stdin)
        return BAD_USERNAME;
    }

    // All checks passed, username is valid
    return OK;
}


// Prints the menu of operations available to the user
void print_menu() {
    printf("\n--- Select an operation ---\n");
    printf("1. Create Keys\n");
    printf("2. Sign Document\n");
    printf("3. Get Public Key\n");
    printf("4. Delete Keys\n");
    printf("q. Quit\n");
    printf("Choice: ");
}

// Runs the main client-side interface loop communicating with the server over the given socket
// Uses the key_container for encryption/decryption of messages
// Returns OK on clean exit or appropriate error code on failure
int run_interface(int socket, unsigned char* key_container) {
    char choice;                            // Stores the user's menu choice
    int error_code = OK;                    // Tracks error codes during communication
    int server_response_len = 0;            // Length of the response message from the server
    unsigned char *server_response = NULL;  // Pointer to hold dynamically allocated server response

    while (1) {

        // Show user the available options
        print_menu();   

        // Read user choice from input
        choice = getchar();
        // Flush the rest of the input buffer to avoid leftover chars
        while (getchar() != '\n');

        printf("\n");

        switch (choice) {
            // Create keys operation
            case '1':
                // TODO: Replace with CreateKeys logic
                printf("[+] Creating keys...\n");
                // Send "OP1" command encrypted to server (to create keys)
                if((error_code = send_encrypted_message(socket, "OP1", strlen("OP1"), key_container)) != OK) {
                    return error_code; // Fail early if sending fails
                }
                // Wait for server's encrypted response
                if((error_code = get_encrypted_message(socket, key_container, &server_response, &server_response_len)) != OK || server_response == NULL || server_response_len <= 0) {
                    return error_code; // Fail if reading response fails or response invalid
                }

                // Handle server response codes
                if (strncmp(server_response, "KAE", 3) == 0){
                    // KAE = Keys Already Exist
                    printf("[-] Keys already exist for this user.\n");
                }
                else if( strncmp(server_response, "ACK", 3) == 0) {
                    // ACK = Acknowledgment / success
                    printf("[+] Keys created successfully.\n");
                }
                free(server_response); // Free allocated buffer after processing
                break;

            // Sign document operation
            case '2':
                // TODO: Replace with SignDoc logic
                printf("[+] Signing document...\n");
                if((error_code = send_encrypted_message(socket, "OP2", strlen("OP2"), key_container)) != OK) {
                    return error_code; // Fail early if sending fails
                }
                // Wait for server's response to the signing request
                if((error_code = get_encrypted_message(socket, key_container, &server_response, &server_response_len)) != OK || server_response == NULL || server_response_len <= 0) {
                    return error_code; // Error during reading server's response
                }
                // Check if the server's response is an ACK or a KDE (Key Doesn't Exist)
                if (strncmp(server_response, "KDE", 3) == 0) {
                    // KDE = Key Doesn't Exist, private key missing
                    free(server_response);
                    printf("[-] Private key does not exist. Please create keys first.\n");
                    continue; // Continue to the next iteration of the loop
                } else if (strncmp(server_response, "ACK", 3) != 0) {
                    // If response is not ACK, treat as error
                    free(server_response);
                    return SIGNATURE_GEN_ERROR; // Signature generation error
                }
                // Call function to handle signing the document on client and server side
                if((error_code = request_document_signature(socket, key_container)) != OK){
                    if(error_code == PRIVATE_KEY_READ_ERROR) {
                        // If private key missing, inform user and continue interface loop
                        printf("[-] Private key does not exist. Please create keys first.\n");
                        continue;
                    }
                    else return error_code; // Other errors abort the interface
                }
                break;

            // Get public key operation
            case '3':
                // TODO: Replace with GetPublicKey logic
                printf("[+] Getting public key...\n");
                if((error_code = send_encrypted_message(socket, "OP3", strlen("OP3"), key_container)) != OK) {
                    return error_code; // Fail early if sending fails
                }
                // Receive the public key from server
                if((error_code = receive_public_key(socket, key_container)) != OK) {
                    if(error_code == PUBKEY_RECEIVAL_ERROR) {
                        // Inform user if no public key is available
                        printf("[-] Error receiving public key. User doesn't have public keys.\n");
                        continue;
                    }
                    return error_code; // Error during receiving public key
                }
                break;

            // Delete keys operation
            case '4':
                // TODO: Replace with DeleteKeys logic
                printf("[+] Deleting keys...\n");
                if((error_code = send_encrypted_message(socket, "OP4", strlen("OP4"), key_container)) != OK) {
                    return error_code; // Fail early if sending fails
                }
                // Await server response confirming deletion
                if((error_code = get_encrypted_message(socket, key_container, &server_response, &server_response_len)) != OK || server_response == NULL || server_response_len <= 0) {
                    return error_code; // Error during reading server's response
                }
                if (strncmp(server_response, "ACK", 3) == 0){
                    // Server confirmed keys deleted, also delete local public key file if exists
                    if (remove("UserPubKey/pubkey.pem") == 0) {
                        printf("[+] Public key file deleted locally.\n");
                    }
                    printf("[+] Keys succesfully deleted on server. Please ask for new credentials.\n");
                    return OK; // Exit the interface after deletion
                }
                else{
                    printf("[-] Error deleting keys.\n");
                }
                free(server_response); // Free after use
                break;

            // Quit option
            case 'q':
            case 'Q':
                // Send BYE command to notify server of disconnection
                if((error_code = send_encrypted_message(socket, "BYE", strlen("BYE"), key_container)) != OK) {
                    return error_code; // Fail early if sending fails
                }
                printf("[Info]: Closing connection with the server...\n");

                // Wait for server acknowledgement before closing
                if((error_code = get_encrypted_message(socket, key_container, &server_response, &server_response_len)) != OK) {
                    return error_code; // Error during reading server's response
                }
                if (strncmp(server_response, "ACK", 3) == 0){
                    printf("[Info]: Connection closed successfully.\n");
                } else {
                    printf("[-] Error closing connection with the server.\n");
                    free(server_response); 
                    return SOCKET_CLOSE_ERROR; // Error during closing connection
                }
                free(server_response); // Free the server response buffer after checking
                return OK; // Exit interface cleanly

            default:
                printf("Invalid choice. Please select 1, 2, 3, 4 or q.\n");
                break;
        }
    }
}

// Receives the public key from the server, verifies it, and saves it to a file
int receive_public_key(int socket, void *key_container) {
    // Allocate buffer for server response
    unsigned char *server_response = NULL;
    int server_response_len = 0;
    int error_code = OK;

    // Buffer for username
    char username[MAX_USERNAME_LENGTH + 1];
    int username_size = sizeof(username);

    // Retrieve username
    do{
        error_code = get_pubkey_username(username, username_size);
    }while(error_code != OK);

    if((error_code = send_encrypted_message(socket, (unsigned char *)username, strlen(username) + 1, key_container)) != OK) {
        return error_code; // Error during sending username
    }

    // Receive server's response to the public key request
    if ((error_code = get_encrypted_message(socket, key_container, &server_response, &server_response_len)) != OK) {
        return error_code;
    }

    // Check if the server's response is an ACK
    if (server_response_len != 3 || strncmp((char *)server_response, "ACK", 3) != 0) {
        free(server_response);
        return PUBKEY_RECEIVAL_ERROR; // Not an ACK
    }
    // Free the response buffer
    free(server_response);
    server_response = NULL;
    server_response_len = 0;

    // Receive public key
    if ((error_code = get_encrypted_message(socket, key_container, &server_response, &server_response_len)) != OK) {
        return error_code;
    }

    // Print to stdout
    printf("\nUser's public key: \n%.*s", server_response_len, server_response);
    
    char publicKeyFile[256]; // Buffer to hold the public key file path
    snprintf(publicKeyFile, sizeof(publicKeyFile), "PubKeys/%s_public_key.pem", username);

    // Save to pubkey.pem
    FILE *f = fopen(publicKeyFile, "wb");
    if (!f) {
        free(server_response);
        return FILE_OPEN_ERROR; // Failed to open file
    }

    // Write the public key to the file
    size_t written = fwrite(server_response, 1, server_response_len, f);
    fclose(f);
    free(server_response);

    // Check if the write operation was successful
    if (written != (size_t)server_response_len) {
        return FILE_WRITE_ERROR; // Write failed
    }

    // Successfully saved the public key
    printf("\nUser's public key written in file \"UserPubKey/pubkey.pem\"\n");

    return OK; // Success
}

// Requests a digital signature for a document file from the server
// - Reads the filename from user input
// - Reads the file content and hashes it with SHA256
// - Sends the hash encrypted to the server for signing
// - Receives the signature and saves it locally
// Returns OK on success or appropriate error codes on failure
int request_document_signature(int socket, unsigned char *key_container) {
    char filename[256]; // Buffer to hold user input filename
    int error_code = 0;

    // Read filename string (up to 255 chars) from stdin
    printf("Enter the name of the file to sign: ");
    if (scanf("%255s", filename) != 1) {
        return FILE_OPEN_ERROR; // Error if no valid input
    }

    // Flush leftover chars from stdin to avoid input issues
    int ch;
    while ((ch = getchar()) != '\n' && ch != EOF); 


    // Open the specified file in binary read mode
    FILE *f = fopen(filename, "rb");
    if (!f) {
        return FILE_OPEN_ERROR; // File could not be opened
    }

    // Get file stats to determine size
    struct stat st;
    if (stat(filename, &st) != 0) {
        fclose(f);
        return FILE_OPEN_ERROR; // Error getting file metadata
    }

    // Enforce a maximum file size limit to avoid excessive memory use
    if (st.st_size > MAX_FILE_SIZE) {
        fclose(f);
        //fprintf(stderr, "File too large (>1GB).\n");
        return FILE_TOO_BIG;
    }

    size_t filesize = st.st_size;                   // Store file size
    unsigned char *file_data = malloc(filesize);    // Allocate buffer to hold entire file
    if (!file_data) {
        fclose(f);
        return MALLOC_ERROR; // Memory allocation failed
    }

    // Read entire file content into buffer
    if (fread(file_data, 1, filesize, f) != filesize) {
        fclose(f);
        free(file_data);
        return FILE_READ_ERROR; // Failed to read the entire file
    }

    // Close the file after reading
    fclose(f);

    // Compute SHA256 hash of file data
    unsigned char hash[SHA256_DIGEST_LENGTH];
    if (!SHA256(file_data, filesize, hash)) {
        free(file_data);
        return HASH_ERROR; // Hash computation failed
    }

    // Free file buffer, no longer needed
    free(file_data);

    // Send the computed hash to the server encrypted for signing
    if((error_code = send_encrypted_message(socket, hash, SHA256_DIGEST_LENGTH, key_container)) != OK){
        return error_code;
    }

    // Wait for the server’s encrypted response with signature or error
    unsigned char *signature_buffer = NULL;
    int signature_len = 0;
    if((error_code = get_encrypted_message(socket, key_container, &signature_buffer, &signature_len)) != OK || signature_buffer == NULL || signature_len <= 0){
        return error_code;
    }

    // Server response check for "KDE" = Key Doesn't Exist (private key missing)
    if( strncmp(signature_buffer, "KDE", 3) == 0){
        free(signature_buffer);
        return PRIVATE_KEY_READ_ERROR;
    }
    // If response is not acknowledgment, treat as signature generation error
    else if (strncmp(signature_buffer, "ACK", 3) != 0){
        return SIGNATURE_GEN_ERROR;
    }

    // Save the file hash locally for verification reference
    char hash_filename[512];
    snprintf(hash_filename, sizeof(hash_filename), "UserSignatures/%s_hash.bin", filename);

    FILE *hash_file = fopen(hash_filename, "wb");
    if (!hash_file) {
        free(file_data);
        return SIGNATURE_FILE_SAVE_ERROR;
    }

    if (fwrite(hash, 1, SHA256_DIGEST_LENGTH, hash_file) != (size_t)SHA256_DIGEST_LENGTH) {
        fclose(hash_file);
        return SIGNATURE_FILE_SAVE_ERROR;
    }

    fclose(hash_file);
    free(signature_buffer);  // Free previous buffer (which contained ACK or KDE)
    signature_buffer = NULL;
    signature_len = 0;

    // Receive the actual signature from server
    if((error_code = get_encrypted_message(socket, key_container, &signature_buffer, &signature_len)) != OK || signature_buffer == NULL || signature_len <= 0){
        return error_code;
    }
    
    // Print the signature in hex format on console for user's info
    printf("\nSignature received:");
    printf("\n----------------------------------------------------------------------------------------------------\n");
    print_hex(signature_buffer, signature_len);
    printf("\n----------------------------------------------------------------------------------------------------\n");

    // Construct filename to save signature
    char signature_filename[512];
    snprintf(signature_filename, sizeof(signature_filename), "UserSignatures/%s_signature.bin", filename);

    FILE *sig_file = fopen(signature_filename, "wb");
    if (!sig_file) {
        free(signature_buffer);
        return SIGNATURE_FILE_SAVE_ERROR;
    }

    // Write the signature binary data to the file
    if (fwrite(signature_buffer, 1, signature_len, sig_file) != (size_t)signature_len) {
        fclose(sig_file);
        free(signature_buffer);
        return SIGNATURE_FILE_SAVE_ERROR;
    }

    fclose(sig_file);
    free(signature_buffer);

    printf("Signature saved to '%s'\n", signature_filename);


    return OK; // Success
}



// Safely closes a socket and returns OK on success, or SOCKET_CLOSE_ERROR on failure
int sclose(int socket){
    if(close(socket) == -1){
        perror("Error closing socket");
        return SOCKET_CLOSE_ERROR;
    }
    return OK;
}

// Handles errors by printing appropriate messages based on the error code
int error_handler(int error_code, int socket){
    int close_ret = OK;
    switch(error_code){
        case OK:
            break;
        case SOCKET_READ_ERROR:
            fprintf(stderr, "[Error]: Failed to read data from the socket. The server might have closed the connection or sent invalid data.\n");
            break;
        case SOCKET_WRITE_ERROR:
            fprintf(stderr, "[Error]: Failed to send data to the server. Connection might be broken or unreachable.\n");
            break;
        case SOCKET_INIT_ERROR:
            fprintf(stderr, "[Error]: Failed to create the server socket. Check system resources or permissions.\n");
            break;
        case INVALID_ADDRESS_ERROR:
            fprintf(stderr, "[Error]: Invalid address. Please provide a valid IPv4 address.\n");
            break;
        case CONNECTION_ERROR:
            fprintf(stderr, "[Error]: Failed to connect to the server. Please check the server address and port.\n");
            break;
        case BIO_INIT_ERROR:
            fprintf(stderr, "[Error]: Failed to initialize memory buffer or open file.\n");
            break;
        case PRIVATE_KEY_READ_ERROR:
            fprintf(stderr, "[Error]: Private key not found on the server. Please generate keys before signing.\n");
            break;
        case PUBLIC_KEY_READ_ERROR:
            fprintf(stderr, "[Error]: Server's public key not found. The file might be missing or inaccessible.\n");
            break;
        case PUBLIC_KEY_EXTRACTION_ERROR:
            fprintf(stderr, "[Error]: Failed to extract the server's public key. The key file may be corrupted or in the wrong format.\n");
            break;
        // Keep the errors generic to avoid leaking sensitive information
        case EVP_VERIFY_INIT_ERROR:
            fprintf(stderr, "[Error]: Failed to execute the key verification process.\n");
            break;
        case EVP_VERIFY_UPDATE_ERROR:
            fprintf(stderr, "[Error]: Failed to execute the key verification process.\n");
            break;
        case EVP_VERIFY_FINALIZATION_ERROR:
            fprintf(stderr, "[Error]: Failed to execute the key verification process.\n");
            break;
        case DH_PARAM_READ_ERROR:
            fprintf(stderr, "[Error]: Failed to read DH parameters or server's public key from PEM file.\n");
            break;
        // Keep the errors generic to avoid leaking sensitive information
        case DH_CTX_INIT_ERROR:
            fprintf(stderr, "[Error]: Failed to execute the key exchange process.\n");
            break;
        case EVP_PKEY_KEYGEN_INIT_ERROR:
            fprintf(stderr, "[Error]: Failed to execute the key exchange process.\n");
            break;
        case EVP_PKEY_KEYGEN_ERROR:
            fprintf(stderr, "[Error]: Failed to execute the key exchange process.\n");
            break;
        case DH_PUBKEY_SEND_ERROR:
            fprintf(stderr, "[Error]: Failed to execute the key exchange process.\n");
            break;
        case EVP_PKEY_CTX_CREATION_ERROR:
            fprintf(stderr, "[Error]: Failed to execute the key exchange process.\n");
            break;
        case EVP_PKEY_DERIVATION_ERROR:
            fprintf(stderr, "[Error]: Failed to execute the key exchange process.\n");
            break;
        case EVP_PKEY_SECRET_DERIVATION_ERROR:
            fprintf(stderr, "[Error]: Failed to execute the key exchange process.\n");
            break;
        case SIGNATURE_VERIFICATION_ERROR:
            fprintf(stderr, "[Error]: Failed to execute the key exchange process.\n");
            break;
        case EVP_CIPHER_CTX_CREATION_ERROR:
            fprintf(stderr, "[Error]: Encryption/Decryption Failure.\n");
            break;
        case EVP_CIPHER_CTX_INIT_ERROR:
            fprintf(stderr, "[Error]: Encryption/Decryption Failure.\n");
            break;
        case EVP_CIPHER_CTX_IV_SET_ERROR:
            fprintf(stderr, "[Error]: Encryption/Decryption Failure.\n");
            break;
        case EVP_CIPHER_CTX_UPDATE_ERROR:
            fprintf(stderr, "[Error]: Encryption/Decryption Failure.\n");
            break;
        case EVP_CIPHER_CTX_FINALIZATION_ERROR:
            fprintf(stderr, "[Error]: Encryption/Decryption Failure.\n");
            break;
        case EVP_CIPHER_CTX_TAG_RETRIEVAL_ERROR:
            fprintf(stderr, "[Error]: Encryption/Decryption Failure.\n");
            break;
        case EVP_PKEY_CTX_DECRYPTION_ERROR:
            fprintf(stderr, "[Error]: Decryption failure.\n");
            break;
        case ENCRYPTION_ERROR:
            fprintf(stderr, "[Error]: Encryption failed. Ciphertext could not be produced.\n");
            break;
        case DECRYPTION_ERROR:
            fprintf(stderr, "[Error]: Decryption failed. The message received was invalid.\n");
            break;
        case BAD_USERNAME:
            fprintf(stderr, "[Error]: Username not recognized by the server.\n");
            break;
        case BAD_PASSWORD:
            fprintf(stderr, "[Error]: The password is incorrect.\n");
            break;
        case BAD_PW_UPDATE:
            fprintf(stderr, "[Error]: The server couldn't update the password.\n");
            break;
        case MALLOC_ERROR:
            fprintf(stderr, "[Error]: Memory allocation failed. Not enough space to proceed.\n");
            break;
        case PUBKEY_RECEIVAL_ERROR:
            fprintf(stderr, "[Error]: Failed to receive the public key from the server. The server might not have your public keys.\n");
            break;
        case FILE_OPEN_ERROR:
            fprintf(stderr, "[Error]: Could not open file for reading or writing. Please check file permissions and paths.\n");
            break;
        case FILE_WRITE_ERROR:
            fprintf(stderr, "[Error]: Could not write public key to the file. Check if you have write permissions in this directory.\n");
            break;
        case FILE_READ_ERROR:
            fprintf(stderr, "[Error]: Could not read the entire file content. File may be corrupted or unreadable.\n");
            break;
        case NONCE_GENERATION_ERROR:
            fprintf(stderr, "[Error]: Failed to generate a secure random nonce.\n");
            break;
        case FILE_TOO_BIG:
            fprintf(stderr, "[Error]: The file is too large to be processed for signature. Maximum size is 1GB.\n");
            break;
        case HASH_ERROR:
            fprintf(stderr, "[Error]: Failed to compute SHA-256 hash of the file.\n");
            break;
        case SIGNATURE_GEN_ERROR:
            fprintf(stderr, "[Error]: Unexpected server response. Failed to generate or receive the signature.\n");
            break;
        case SIGNATURE_FILE_SAVE_ERROR:
            fprintf(stderr, "[Error]: Failed to save hash or signature to file. Check write permissions in this directory.\n");
            break;
        case SOCKET_CLOSE_ERROR:
            fprintf(stderr, "[Error]: Failed to close the socket properly. The connection may be in an inconsistent state.\n");
            break;
        default:
            fprintf(stderr, "[Error]: Unknown error code: %d\n", error_code);
            break;
    }
    if(error_code != OK && socket > 0){
        close_ret = sclose(socket);
        fprintf(stderr, "[Error]: The connection with the server has been terminated.\n");
    }
    if(close_ret != OK){
        return SOCKET_CLOSE_ERROR;
    }
    return error_code;

}

// Utility functions:
void print_hex(unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        printf("%02x", data[i]);  // 2-digit hex
    }
}
