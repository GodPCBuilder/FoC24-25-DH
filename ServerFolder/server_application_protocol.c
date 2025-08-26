#include <stdio.h>
#include <unistd.h>
#include <ctype.h>
#include <netinet/in.h>
#include <openssl/pem.h>
#include "params.h"

#include "server_application_protocol.h"
#include "server_authentication_protocol.h"

int server_init(int *server_fd, struct sockaddr_in *address) {
    int addrlen = sizeof(*address);  // Length of the address structure

    // Create a TCP socket (AF_INET = IPv4, SOCK_STREAM = TCP)
    *server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (*server_fd == 0) {
        return SOCKET_INIT_ERROR; // Failed to create socket
    }

    // Allow reuse of the address/port to avoid "address already in use" errors
    int opt = 1;
    if (setsockopt(*server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        return SOCKET_INIT_ERROR; // You can define this error code too
    }

    // Configure the server's address structure
    address->sin_family = AF_INET;             // IPv4 address family
    address->sin_addr.s_addr = INADDR_ANY;     // Bind to all available interfaces (e.g., 0.0.0.0)
    address->sin_port = htons(PORT);           // Convert port to network byte order

    // Bind the socket to the specified IP and port
    if (bind(*server_fd, (struct sockaddr *)address, addrlen) < 0) {
        return SOCKET_BIND_ERROR; // Failed to bind the socket to the address
    }

    // Mark the socket as passive; it will be used to accept incoming connections
    if (listen(*server_fd, 3) < 0) {
        return SOCKET_LISTEN_ERROR; // Failed to listen on socket
    }

    return OK; // Server socket successfully created, bound, and listening
}

int handle_user_choice(int socket, unsigned char* key_container, const char *username) {
    while (1) {
        unsigned char *user_choice = NULL;
        int choice_len = 0;
        int error_code = OK;

        // --- Receive encrypted user choice from client ---
        if ((error_code = get_encrypted_message(socket, key_container, &user_choice, &choice_len)) != OK) {
            return error_code; // If failed, return the error
        }

        // --- Handle client exit request ---
        if (strncmp((char *)user_choice, "BYE", 3) == 0) {
            printf("[Server] Client sent BYE. Closing session.\n");
            // Send confirmation of closure (ACK)
            if((error_code = send_encrypted_message(socket, "ACK", strlen("ACK"), key_container)) != OK) {
                free(user_choice);
                return error_code; // Return error if sending fails
            }
            free(user_choice);
            return OK; // Clean shutdown
        }

        // --- Handle key generation request ---
        if (strncmp((char *)user_choice, "OP1", 3) == 0) {
            printf("[Server] Received OP1 - Creating keys...\n");
            if((error_code = GenerateKeys(username, socket, key_container)) != OK) {
                free(user_choice);
                return error_code; // Key generation failed
            }

        // --- Handle document signature request ---
        } else if (strncmp((char *)user_choice, "OP2", 3) == 0) {
            printf("[Server] Received OP2 - Signing document...\n");
            if((error_code = signDoc(username, socket, key_container)) != OK) {
                if(error_code == PRIVATE_KEY_READ_ERROR) {
                    // No private key file found
                    printf("[Server] Keys don't exist for username %s\n", username);
                    continue; // Let client decide what to do
                }
                else if(error_code == BAD_HASH){
                    fprintf(stderr, "[Server] Bad hash received from client. The document hash is not of standardized length.\n");
                    continue; // Hash format invalid, wait for another request
                }
                free(user_choice);
                return error_code; // Other error while signing
            }

        // --- Handle public key request ---
        } else if (strncmp((char *)user_choice, "OP3", 3) == 0) {
            printf("[Server] Received OP3 - Sending public key...\n");
            if((error_code = getKeys(socket, key_container)) != OK) {
                free(user_choice);
                if(error_code == USER_PUBKEY_READ_ERROR) {
                    continue; // Informative log, let client decide next
                }
                return error_code; // Error while reading key
            }

        // --- Handle key deletion request ---
        } else if (strncmp((char *)user_choice, "OP4", 3) == 0) {
            printf("[Server] Received OP4 - Deleting keys...\n");
            if((error_code = deleteKeys(username, socket, key_container)) != OK) {
                free(user_choice);
                if(error_code == KEY_DELETE_ERROR) {
                    printf("[Server] Keys don't exist for username %s\n", username);
                    continue; // Inform user and keep session open
                }
                return error_code; // Other error
            }
            return OK; // After deletion, we exit handler to avoid future operations

        // --- Handle unknown or malformed operation codes ---
        } else {
            return UNKNOWN_OPERATION_ERROR;
        }

        // Clean up after each operation
        free(user_choice);
    }

    return OK; // Should never be reached normally
}

int user_sign(unsigned char **signature, unsigned char *message, int message_len, const char *currentUser){
    // Ensure the input message length matches the expected SHA256 hash length
    if(message_len != SHA256_DIGEST_LENGTH) {
        return NOT_HASHED_INPUT_ERROR; // The input should be a SHA256 hash, reject otherwise
    }
    int signature_len;
    
    // Prepare the filename for the user's private key based on a format string
    char privateKeyFile[256], msg[512];
    snprintf(privateKeyFile, sizeof(privateKeyFile), PRIVATE_KEY_FILE_FORMAT, currentUser);

    EVP_PKEY* privkey;
    // Open the private key file for the current user
    FILE* file = fopen(privateKeyFile,"r");
    if(!file) {
        // Could not open private key file
        return PRIVATE_KEY_READ_ERROR;
    }

    // Buffer to hold the passphrase for decrypting the private key file
    char passkey[65] = {0}; // Passphrase length + null terminator
    if(getPasskey(passkey, sizeof(passkey)) != OK) {
        fclose(file);
        // Failed to read passphrase
        return PASSKEY_READ_ERROR;
    }

    // Read and decrypt the private key using the passphrase
    privkey = PEM_read_PrivateKey(file,NULL,NULL,passkey);
    if(!privkey) {
        // Failed to extract private key, print OpenSSL error stack for debugging
        printf("OPENSSL DUMP:\n");
        printf("---------------------------------------------------------------\n");
        handleErrors();
        printf("---------------------------------------------------------------\n");
        return PRIVATE_KEY_EXTRACTION_ERROR;
    }
    fclose(file); // Close the key file, no longer needed

    // Allocate memory for the signature buffer (initial allocation, but will be reallocated)
    *signature = malloc(EVP_PKEY_size(privkey));
    if (*signature == NULL) {
        EVP_PKEY_free(privkey);
        return MALLOC_ERROR; // Allocation failure
    }

    // Create a new signing context for the private key
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(privkey, NULL);
    if (!ctx) {
        EVP_PKEY_free(privkey);
        // Print error details
        printf("OPENSSL DUMP:\n");
        printf("---------------------------------------------------------------\n");
        handleErrors();
        printf("---------------------------------------------------------------\n");
        return SIGNING_CONTEXT_INIT_ERROR;
    }

    // Initialize the signing operation on the context
    if (EVP_PKEY_sign_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(privkey);
        printf("OPENSSL DUMP:\n");
        printf("---------------------------------------------------------------\n");
        handleErrors();
        printf("---------------------------------------------------------------\n");
        return SIGNING_CONTEXT_INIT_ERROR;
    }

    // If the key is RSA, set padding scheme to PKCS#1 v1.5 (typical for RSA signatures)
    if (EVP_PKEY_base_id(privkey) == EVP_PKEY_RSA) {
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(privkey);
            printf("OPENSSL DUMP:\n");
            printf("---------------------------------------------------------------\n");
            handleErrors();
            printf("---------------------------------------------------------------\n");
            return SIGNING_CONTEXT_INIT_ERROR;
        }
    }

    // First call to EVP_PKEY_sign with NULL output buffer to get required signature length
    size_t siglen = 0;
    if (EVP_PKEY_sign(ctx, NULL, &siglen, message, message_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(privkey);
        printf("OPENSSL DUMP:\n");
        printf("---------------------------------------------------------------\n");
        handleErrors();
        printf("---------------------------------------------------------------\n");
        return SIGNATURE_FINALIZATION_ERROR;
    }

    // Allocate the exact size needed for the signature buffer
    *signature = malloc(siglen);
    if (!*signature) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(privkey);
        return MALLOC_ERROR;
    }

    // Perform the actual signing operation, writing signature to the buffer
    if (EVP_PKEY_sign(ctx, *signature, &siglen, message, message_len) <= 0) {
        free(*signature);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(privkey);
        printf("OPENSSL DUMP:\n");
        printf("---------------------------------------------------------------\n");
        handleErrors();
        printf("---------------------------------------------------------------\n");
        return SIGNATURE_FINALIZATION_ERROR;
    }

    // Clean up the signing context and private key structure
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(privkey);

    // Return the length of the generated signature on success
    return siglen;
}

// Sends an ACK to the client followed by the signature of the document hash, otherwise sends a NCK
int signDoc(const char *userID, int socket, void *key_container) {
    // Prepare the file path for the user's private key based on their userID
    char privateKeyFile[256], msg[512];

    int error_code = OK;

    snprintf(privateKeyFile, sizeof(privateKeyFile), PRIVATE_KEY_FILE_FORMAT, userID);

    EVP_PKEY* privkey;
    // Open the private key file for the current user
    FILE* file = fopen(privateKeyFile,"r");
    if(!file) {
        // Could not open private key file
        send_encrypted_message(socket, "KDE", strlen("KDE"), key_container);
        return PRIVATE_KEY_READ_ERROR;
    }
    else{
        fclose(file);
        if((error_code = send_encrypted_message(socket, "ACK", strlen("ACK"), key_container)) != OK) {
            return error_code; // If sending ACK fails, return the error code
        }
    }

    unsigned char *hashed_doc = NULL;
    int hashed_doc_len = 0;
    
    // Receive the encrypted message containing the document hash from the client
    error_code = get_encrypted_message(socket, key_container, &hashed_doc, &hashed_doc_len);
    if (error_code != OK) {
        return error_code; // If reading fails, return the error code immediately
    }

    // Verify the length of the received hash is exactly SHA256_DIGEST_LENGTH (32 bytes)
    if (hashed_doc_len != SHA256_DIGEST_LENGTH) {
        // Defensive: if hashed_doc was allocated, free it (though likely not NULL here)
        if (hashed_doc == NULL)
            free(hashed_doc);
        // Inform client that the hash is invalid with a NCK (Negative Acknowledgment)
        send_encrypted_message(socket, "NCK", strlen("NCK"), key_container);
        return BAD_HASH; // Indicate the hash length was invalid
    }

    unsigned char *signature = NULL;

    // Call user_sign to create a digital signature of the document hash using the user's private key
    int signature_len = user_sign(&signature, hashed_doc, hashed_doc_len, userID);
    
    // If signing failed (negative length returned)
    if (signature_len < 0) {
        if (signature != NULL) {
            free(signature); // Free signature buffer if allocated
        }
        free(hashed_doc); // Free the received hash buffer

        if (signature_len == PRIVATE_KEY_READ_ERROR) {
            // Special case: private key not found, notify client with "KDE" (Key Doesn't Exist)
            send_encrypted_message(socket, "KDE", strlen("KDE"), key_container);
        }
        else {
            // For other errors, notify client with "NCK"
            send_encrypted_message(socket, "NCK", strlen("NCK"), key_container);
        }
        return signature_len; // Return the specific signing error
    }

    // Clean up the hashed document buffer after successful signing
    free(hashed_doc);

    // Notify client with ACK that the signing process succeeded
    if ((error_code = send_encrypted_message(socket, "ACK", strlen("ACK"), key_container)) != OK) {
        free(signature); // Free allocated signature on error
        return error_code; // Return sending error
    }

    // Send the digital signature itself, encrypted with the session key
    if ((error_code = send_encrypted_message(socket, signature, signature_len, key_container)) != OK) {
        free(signature);
        return error_code; // Return sending error if it fails
    }

    // Clean up allocated signature memory after sending
    free(signature);

    return OK; // Success
}


// Sends an ACK to the client if the keys were successfully deleted, otherwise sends a NCK
int deleteKeys(const char *userID, int socket, void *key_container) {
    // Prepare file paths for the user's private and public key files
    char privateKeyFile[256], publicKeyFile[256];
    int error_code = OK;
    snprintf(privateKeyFile, sizeof(privateKeyFile), PRIVATE_KEY_FILE_FORMAT, userID);
    snprintf(publicKeyFile, sizeof(publicKeyFile), PUBLIC_KEY_FILE_FORMAT, userID);

    // Flags indicating deletion success: 1 means success or not needed, 0 means failure
    int privateKeyDeleted = 1, publicKeyDeleted = 1;

    // Check if private and public key files exist
    int privateKeyExisted = access(privateKeyFile, F_OK) == 0;
    int publicKeyExisted = access(publicKeyFile, F_OK) == 0;

    // Attempt to remove the private key file if it exists
    if (privateKeyExisted) {
        privateKeyDeleted = remove(privateKeyFile);
    }
    // Attempt to remove the public key file if it exists
    if (publicKeyExisted) {
        publicKeyDeleted = remove(publicKeyFile);
    }

    // Verify deletion success for the cases:
    //  - private key existed and deleted successfully, public key did not exist
    //  - public key existed and deleted successfully, private key did not exist
    //  - both keys existed and were deleted successfully
    if ((privateKeyExisted && privateKeyDeleted == 0 && !publicKeyExisted) ||
        (publicKeyExisted && publicKeyDeleted == 0 && !privateKeyExisted) ||
        (privateKeyExisted && privateKeyDeleted == 0 &&
        publicKeyExisted && publicKeyDeleted == 0)) {
        
        // Open the passwords file to update the user's flag to '2', indicating keys deleted
        FILE *fp = fopen("UsersData/passwords.txt", "r+");
        if (!fp) return PWD_FILE_OPEN_ERROR;

        char line[512];
        int found = 0;

        // Read through the file line by line
        while (fgets(line, sizeof(line), fp)) {
            // Calculate the position at the start of the current line for seeking later
            long line_start_pos = ftell(fp) - strlen(line);
            // Remove trailing newline character from the line
            line[strcspn(line, "\n")] = '\0';

            // Find the first ':' separator to isolate username in the line
            char *sep1 = strchr(line, ':');
            if (!sep1) continue;  // Malformed line; skip
            *sep1 = '\0'; // Temporarily terminate string to isolate username part
            const char *file_user = line;

            // Check if this line corresponds to the userID
            if (strcmp(file_user, userID) == 0) {
                found = 1;

                // Find the last semicolon to locate the flag position at the end of the line
                char *last_semicolon = strrchr(sep1 + 1, ';');
                // Validate format: flag should be a digit following last semicolon
                if (!last_semicolon || !isdigit(*(last_semicolon + 1))) {
                    fclose(fp);
                    return BAD_FILE_FORMAT;
                }

                // Calculate exact file position of the flag character
                long flag_offset = line_start_pos + (last_semicolon + 1 - line);
                fseek(fp, flag_offset, SEEK_SET);

                // Overwrite the flag character with '2' to mark keys deleted
                fputc('2', fp);
                fflush(fp); // Ensure changes are written to disk
            }
        }

        fclose(fp);

        // Notify client that keys were successfully deleted with "ACK"
        if ((error_code = send_encrypted_message(socket, "ACK", strlen("ACK"), key_container)) != OK) {
            return error_code;
        }
        return OK;
    } else {
        // If keys were not deleted properly, notify client with "KDE" (Key Doesn't Exist)
        send_encrypted_message(socket, "KDE", strlen("KDE"), key_container);
        return KEY_DELETE_ERROR;
    }
}



// Sends an ACK followed by the public key of the user if successful
int getKeys(int socket, void *key_container) {
    // Prepare the path to the user's public key file based on userID
    char publicKeyFile[256], msg[512];
    int error_code = OK;

    char* username = NULL; // Pointer to hold the username buffer
    int username_size = 0;

    // Retrieve the username from the client
    if((error_code = get_encrypted_message(socket, key_container, (unsigned char **)&username, &username_size)) != OK) {
        return error_code; // If reading username fails, return the error code
    }

    snprintf(publicKeyFile, sizeof(publicKeyFile), PUBLIC_KEY_FILE_FORMAT, username);

    // Attempt to open the user's public key file in binary read mode
    FILE *publicKeyFilePtr = fopen(publicKeyFile, "rb");
    if (!publicKeyFilePtr) {
        // If the public key file doesn't exist, notify client with "KDE" (Key Doesn't Exist)
        send_encrypted_message(socket, "KDE", strlen("KDE"), key_container);
        printf("[Server] Public key file does not exist or is corrupted for the specified user\n");
        return USER_PUBKEY_READ_ERROR;
    }

    // Read the public key from the PEM file into an EVP_PKEY structure
    EVP_PKEY *pkey = PEM_read_PUBKEY(publicKeyFilePtr, NULL, NULL, NULL);
    fclose(publicKeyFilePtr);
    if (!pkey) {
        // If reading the public key fails, return an error
        printf("[Server] Public key file does not exist or is corrupted for the specified user\n");
        return USER_PUBKEY_READ_ERROR;
    }

    // Create a new memory BIO to write the public key in PEM format
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio || !PEM_write_bio_PUBKEY(bio, pkey)) {
        // If BIO creation or writing the public key to BIO fails, free resources and return error
        EVP_PKEY_free(pkey);
        printf("[Server] Public key file does not exist or is corrupted for the specified user\n");
        return USER_PUBKEY_READ_ERROR;
    }

    // Determine how many bytes are pending to be read from the BIO (the public key length)
    size_t keyLen = BIO_pending(bio);
    // Allocate memory to hold the public key data plus a null terminator (not strictly needed here)
    unsigned char *publicKey = malloc(keyLen + 1);
    if (!publicKey) {
        // On memory allocation failure, free BIO and EVP_PKEY and return error
        BIO_free(bio);
        EVP_PKEY_free(pkey);
        return MALLOC_ERROR;
    }
    // Read the public key bytes from the BIO into our allocated buffer
    if(BIO_read(bio, publicKey, keyLen) <= 0) {
        // If reading from BIO fails, clean up and return error
        BIO_free(bio);
        EVP_PKEY_free(pkey);
        free(publicKey);
        return USER_PUBKEY_READ_ERROR;
    }
    // Note: No need to null terminate publicKey buffer because we send exact length bytes

    // Send an encrypted ACK message to the client indicating success
    if((error_code = send_encrypted_message(socket, "ACK", strlen("ACK"), key_container)) != OK) {
        return error_code; // Error during sending ACK
    }
    // Send the actual public key data encrypted to the client
    if((error_code = send_encrypted_message(socket, publicKey, keyLen, key_container)) != OK) {
        // On error, free resources and return the error code
        BIO_free(bio);
        EVP_PKEY_free(pkey);
        free(publicKey);
        return error_code;
    }

    // Free allocated resources before returning success
    BIO_free(bio);
    EVP_PKEY_free(pkey);
    free(publicKey);
    return OK;
}


// --- Generazione chiavi RSA ---
int GenerateKeys(const char *userID, int socket, void *key_container) {
    // Prepare filenames for the user's private and public RSA key files
    char privateKeyFile[256], publicKeyFile[256];
    int error_code = OK;
    snprintf(privateKeyFile, sizeof(privateKeyFile), PRIVATE_KEY_FILE_FORMAT, userID);
    snprintf(publicKeyFile, sizeof(publicKeyFile), PUBLIC_KEY_FILE_FORMAT, userID);

    // Check if keys already exist by verifying file existence
    if (access(privateKeyFile, F_OK) == 0 || access(publicKeyFile, F_OK) == 0) {
        // If keys exist, notify the client with "KAE" (Key Already Exists)
        if((error_code = send_encrypted_message(socket, "KAE", strlen("KAE"), key_container)) != OK) {
            return error_code; // Return if sending fails
        }
        return OK; // Keys already exist, no further action needed
    }

    // Create a new context for RSA key generation
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    // Initialize the context and set RSA key size, handle failure cases
    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, KEY_SIZE) <= 0) {
        if (ctx) {
            EVP_PKEY_CTX_free(ctx); // Clean up context if allocated
        }
        // Send "NCK" (negative acknowledgment) if initialization fails
        send_encrypted_message(socket, "NCK", strlen("NCK"), key_container);
        return USER_KEYGEN_ERROR;
    }

    EVP_PKEY *pkey = NULL;
    // Generate the RSA key pair, handle failure with cleanup and notification
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        send_encrypted_message(socket, "NCK", strlen("NCK"), key_container);
        return USER_KEYGEN_ERROR;
    }

    // Open the private key file for writing in binary mode
    FILE *privateKeyFilePtr = fopen(privateKeyFile, "wb");
    if (!privateKeyFilePtr) {
        // Clean up and notify client if file can't be opened
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        send_encrypted_message(socket, "NCK", strlen("NCK"), key_container);
        return USER_KEYGEN_ERROR;
    }

    // Retrieve passkey to encrypt the private key file
    char passkey[65] = {0}; // Buffer large enough for passkey + null terminator
    if(getPasskey(passkey, sizeof(passkey)) != OK) {
        return PASSKEY_READ_ERROR; // Return on passkey read failure
    }

    // Write the private key to file, encrypted with AES-256-CBC using the passkey
    if (!PEM_write_PrivateKey(privateKeyFilePtr, pkey, EVP_aes_256_cbc(), NULL, 0, NULL, passkey)) {
        // Clean up and notify if writing fails
        fclose(privateKeyFilePtr);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        send_encrypted_message(socket, "NCK", strlen("NCK"), key_container);
        return USER_KEYGEN_ERROR;
    }
    fclose(privateKeyFilePtr);

    // Open the public key file for writing in binary mode
    FILE *publicKeyFilePtr = fopen(publicKeyFile, "wb");
    if (!publicKeyFilePtr) {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        send_encrypted_message(socket, "NCK", strlen("NCK"), key_container);
        return USER_KEYGEN_ERROR;
    }

    // Write the public key to file in PEM format
    if (!PEM_write_PUBKEY(publicKeyFilePtr, pkey)) {
        fclose(publicKeyFilePtr);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        send_encrypted_message(socket, "NCK", strlen("NCK"), key_container);
        return USER_KEYGEN_ERROR;
    }
    fclose(publicKeyFilePtr);

    // Clean up OpenSSL structures
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);

    // Send an "ACK" to the client indicating successful key generation
    if((error_code = send_encrypted_message(socket, "ACK", strlen("ACK"), key_container)) != OK) {
        return error_code; // Return if sending ACK fails
    }
    return OK;
}


// Closes the socket and handles any errors that may occur during closure
int sclose(int socket){
    if(close(socket) != 0){
        perror("Error closing socket");
        return SOCKET_CLOSE_ERROR;
    }
    return OK;
}

// Handles errors by printing appropriate messages and closing the socket if necessary
int error_handler(int error_code, int socket){
    int close_ret = OK;
    switch(error_code){
        case OK:
            break;
        case SOCKET_READ_ERROR:
            fprintf(stderr, "[Error]: Failed to read data from the socket. The client might have terminated the session.\n");
            break;
        case SOCKET_WRITE_ERROR:
            fprintf(stderr, "[Error]: Failed to send data to the client. Connection might be broken or unreachable.\n");
            break;
        case SOCKET_INIT_ERROR:
            fprintf(stderr, "[Error]: Failed to create the server socket. Check system resources or permissions.\n");
            break;
        case SOCKET_BIND_ERROR:
            fprintf(stderr, "[Error]: Failed to bind the server socket to the address. The port might already be in use or requires elevated permissions.\n");
            break;
        case SOCKET_LISTEN_ERROR:
            fprintf(stderr, "[Error]: Failed to listen on the server socket. The socket could not enter listening state.\n");
            break;
        case BIO_INIT_ERROR:
            fprintf(stderr, "[Error]: Failed to create a BIO object. Could not initialize memory buffer or open file.\n");
            break;
        case PRIVATE_KEY_READ_ERROR:
            fprintf(stderr, "[Error]: Private key not found. The client might still need to generate them.\n");
            break;
        case PRIVATE_KEY_EXTRACTION_ERROR:
            fprintf(stderr, "[Error]: Failed to extract the private key. The key file may be corrupted or in the wrong format.\n");
            break;
        case SIGNING_CONTEXT_INIT_ERROR:
            fprintf(stderr, "[Error]: Could not initialize the signing context. OpenSSL setup failed.\n");
            break;
        case SIGNING_CONTEXT_UPDATE_ERROR:
            fprintf(stderr, "[Error]: Failed to update the signing context with the message. Hashing may have failed.\n");
            break;
        case SIGNATURE_FINALIZATION_ERROR:
            fprintf(stderr, "[Error]: Could not finalize the signature.\n");
            break;
        case NOT_HASHED_INPUT_ERROR:
            fprintf(stderr, "[Error]: The input message was not hashed before signing.\n");
            break;
        case PASSKEY_READ_ERROR:
            fprintf(stderr, "[Error]: Failed to read the passkey for private key decryption. The server might not be able to proceed with signing.\n");
            break;
        case DH_PARAM_READ_ERROR:
            fprintf(stderr, "[Error]: Failed to read DH parameters or public key from PEM file.\n");
            break;
        case DH_CTX_INIT_ERROR:
            fprintf(stderr, "[Error]: Could not initialize DH context. EVP_PKEY_CTX creation failed.\n");
            break;
        case EVP_PKEY_KEYGEN_INIT_ERROR:
            fprintf(stderr, "[Error]: Failed to initialize key generation for DH parameters.\n");
            break;
        case EVP_PKEY_KEYGEN_ERROR:
            fprintf(stderr, "[Error]: Failed to generate DH private key.\n");
            break;
        case DH_PUBKEY_SEND_ERROR:
            fprintf(stderr, "[Error]: Failed to prepare or format public key for transmission to the client.\n");
            break;
        case EVP_PKEY_CTX_CREATION_ERROR:
            fprintf(stderr, "[Error]: Failed to create a context for shared secret derivation.\n");
            break;
        case EVP_PKEY_DERIVATION_ERROR:
            fprintf(stderr, "[Error]: Could not set the peer key or initialize DH key agreement phase.\n");
            break;
        case EVP_PKEY_SECRET_DERIVATION_ERROR:
            fprintf(stderr, "[Error]: Failed during shared secret derivation or hashing. Could not compute session key.\n");
            break;
        case EVP_CIPHER_CTX_CREATION_ERROR:
            fprintf(stderr, "[Error]: Failed to create the decryption context.\n");
            break;
        case EVP_CIPHER_CTX_INIT_ERROR:
            fprintf(stderr, "[Error]: Failed to initialize the cipher context. Check the provided cipher or key.\n");
            break;
        case EVP_CIPHER_CTX_IV_SET_ERROR:
            fprintf(stderr, "[Error]: Failed to set the IV length for GCM. The IV might be malformed or unsupported.\n");
            break;
        case EVP_CIPHER_CTX_UPDATE_ERROR:  
            fprintf(stderr, "[Error]: Decryption failed during update phase. The ciphertext or AAD may be corrupted.\n");
            break;
        case EVP_CIPHER_CTX_FINALIZATION_ERROR:
            fprintf(stderr, "[Error]: Final encryption step failed. Possible internal error in OpenSSL or corrupted data.\n");
            break;
        case EVP_CIPHER_CTX_TAG_RETRIEVAL_ERROR:
            fprintf(stderr, "[Error]: Failed to set or retrieve the expected authentication tag. Decryption cannot proceed.\n");
            break;
        case EVP_PKEY_CTX_DECRYPTION_ERROR:
            fprintf(stderr, "[Error]: Decryption failed during final verification. The data may have been tampered with or the tag is invalid.\n");
            break;
        case ENCRYPTION_ERROR:
            fprintf(stderr, "[Error]: GCM encryption failed. Ciphertext could not be produced.\n");
            break;
        case DECRYPTION_ERROR:
            fprintf(stderr, "[Error]: Decryption failed. The message received was invalid.\n");
            break;
        case BAD_HASH:
            fprintf(stderr, "[Error]: The hash of the client's document is not of standardized length.\n");
            break;
        case KEY_DELETE_ERROR:
            fprintf(stderr, "[Error]: Failed to delete the key files. The server might not be able to clean up properly.\n");
            break;
        case USER_PUBKEY_READ_ERROR:
            fprintf(stderr, "[Error]: Failed to read the user's public key.\n");
            break;
        case BAD_USERNAME:
            fprintf(stderr, "[Error]: Username not recognized.\n");
            break;
        case BAD_PASSWORD:
            fprintf(stderr, "[Error]: The password sent by the client is incorrect.\n");
            break;
        case MALLOC_ERROR:
            fprintf(stderr, "[Error]: Memory allocation failed. Not enough space to proceed.\n");
            break;
        case PWD_FILE_OPEN_ERROR:
            fprintf(stderr, "[Error]: Failed to open the password file. The server might not be able to authenticate users.\n");
            break;
        case MALFORMED_USERNAME_LINE_ERROR:
            fprintf(stderr, "[Error]: Malformed line in the password file. The server might not be able to authenticate users.\n");
            break;
        case BAD_FILE_FORMAT:
            fprintf(stderr, "[Error]: The username information is not of standardized format.\n");
            break;
        case UNKNOWN_OPERATION_ERROR:
            fprintf(stderr, "[Error]: The server received an unknown operation request from the client.\n");
            break;
        case USER_KEYGEN_ERROR:
            fprintf(stderr, "[Error]: Failed to generate the RSA keys for the user. The server might not be able to proceed with authentication.\n");
            break;
        case NONCE_GENERATION_ERROR:
            fprintf(stderr, "[Error]: Failed to generate a secure random nonce.\n");
            break;
        default:
            fprintf(stderr, "Unknown error code: %d\n", error_code);
            break;   
    }
    if(error_code != OK && socket > 0){
        close_ret = sclose(socket);
        fprintf(stderr, "[Error]: The connection with the client has been terminated.\n");
    }
    if(close_ret != OK){
        return SOCKET_CLOSE_ERROR;
    }
    return error_code;

}


// Utility functions

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
    return OK;
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

