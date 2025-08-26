#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/evp.h>

#include "params.h"
#include "client_authentication_protocol.h"
#include "client_application_protocol.h"


// Prompts the user to enter a username and stores it into the provided buffer
// Returns OK on success, or BAD_USERNAME if the input is invalid (too long or empty)
int get_username(char *buffer, int sizeof_buffer) {

    printf("-------------------------------------------------------------------\n");
    printf("Please enter your username (max %d characters): ", MAX_USERNAME_LENGTH);
    
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

// Prompts the user to enter a password and stores it into the provided buffer
// Enforces minimum and maximum length constraints
// Returns OK on valid input, or BAD_PASSWORD if the input is invalid
int get_password(char *buffer, int sizeof_buffer) {

    printf("----------------------------------------------------------------------------\n");
    printf("Enter your password (max %d characters, min %d characters): ", MAX_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH);
    
    // Read the password input from stdin
    if (fgets(buffer, sizeof_buffer, stdin)) {

        // Get the length of the input (includes '\n' if present)
        size_t len = strlen(buffer);

        // Case 1: User just pressed Enter (input is only a newline)
        if (len == 1 && buffer[0] == '\n') {
            printf("[Error]: Password cannot be empty.\n");
            return BAD_PASSWORD;
        }

        // Case 2: If input ends with newline, it means it's within buffer size
        if (buffer[len - 1] == '\n') {
            buffer[len - 1] = '\0'; // Remove newline
            len--;                  // Adjust actual length

        } else {
            // Case 3: Input is too long (didn’t include a newline) — flush remaining characters
            int ch, i = 0;
            while ((ch = getchar()) != '\n' && ch != EOF){i++;};
            
            if(i > 0){
                // Input exceeded max allowed characters — reject it
                printf("[Error]: Password length must be between %d and %d.\n", MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH);
                return BAD_PASSWORD;
            }
        }

        // Final check: ensure password meets minimum length requirement
        if (len < MIN_PASSWORD_LENGTH) {
            printf("[Error]: Password length must be between %d and %d.\n", MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH);
            return BAD_PASSWORD;
        }

    } else {
        // fgets() failed due to EOF or error on stdin
        return BAD_PASSWORD;
    }

    // If all checks passed, return success
    return OK;
}


// Prompts the user to enter a new password, then confirms it by asking twice
// Checks length requirements and ensures both entries match
// Returns OK if all validations pass, or BAD_PASSWORD if any check fails
int get_new_password(char *buffer, int sizeof_buffer) {

    // Temporary buffer for confirmation password input (+2 for newline and null terminator)
    char confirm_buffer[MAX_PASSWORD_LENGTH + 2];

    printf("----------------------------------------------------------------------------\n");
    printf("Enter new password (max %d characters, min %d characters): ", MAX_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH);
    
    // Read the first password input
    if (!fgets(buffer, sizeof_buffer, stdin)) {
        return BAD_PASSWORD; // Input failure (EOF or error)
    }

    size_t len = strlen(buffer); // Get length including newline if present

    // Check if user just pressed Enter without typing a password
    if (len == 1 && buffer[0] == '\n') {
        printf("[Error]: Password cannot be empty.\n");
        return BAD_PASSWORD;
    }

    // If input ends with newline, remove it and adjust length
    if (buffer[len - 1] == '\n') {
        buffer[len - 1] = '\0';
        len--;
    } else {
        // Input was too long; flush remaining characters from stdin
        int ch, i = 0;
        while ((ch = getchar()) != '\n' && ch != EOF) { i++; }
        if (i > 0) {
            printf("[Error]: Password length must be between %d and %d.\n", MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH);
            return BAD_PASSWORD;
        }
    }

    // Check length constraints: must be within min and max bounds
    if (len < MIN_PASSWORD_LENGTH || len > MAX_PASSWORD_LENGTH) {
        printf("[Error]: Password length must be between %d and %d.\n", MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH);
        return BAD_PASSWORD;
    }

    // Prompt for password confirmation input
    printf("Confirm new password: ");
    if (!fgets(confirm_buffer, sizeof(confirm_buffer), stdin)) {
        return BAD_PASSWORD;
    }

    size_t confirm_len = strlen(confirm_buffer);
    // Remove newline from confirmation input if present
    if (confirm_len > 0 && confirm_buffer[confirm_len - 1] == '\n') {
        confirm_buffer[confirm_len - 1] = '\0';
    }

    // Compare original password and confirmation for exact match
    if (strcmp(buffer, confirm_buffer) != 0) {
        printf("[Error]: Passwords do not match.\n");
        return BAD_PASSWORD;
    }

    // All checks passed — password accepted
    return OK;
}

int send_username_to_server(int socket) {

    // Set up error code
    int error_code = OK;

    // Local array for server response
    char server_response[3];

    // Buffer for username
    char username[MAX_USERNAME_LENGTH + 1];
    int username_size = sizeof(username);

    // Retrieve username
    do{
        error_code = get_username(username, username_size);
    }while(error_code != OK);

    // Send username to server
    if(send(socket, username, strlen(username) + 1, 0) == -1){
        return SOCKET_WRITE_ERROR; // Error during sending
    }

    // Read server's ACK/NACK
    if(read(socket, server_response, sizeof(server_response)) == -1) {
        return SOCKET_READ_ERROR; // Error during reading
    }

    // Check if server responded with "NCK"
    if (strncmp(server_response, "ACK", 3) != 0) {
        return BAD_USERNAME; // Server did not acknowledge the username
    }

    return OK; // Success
}

int send_password_to_server(int socket, unsigned char *key_container, int* change_pwd) {
    
    // Set up error code
    int error_code = OK;

    // Buffer for password
    unsigned char password[MAX_PASSWORD_LENGTH + 1]; 

    // Retrieve password
    do{
        error_code = get_password(password, MAX_PASSWORD_LENGTH + 1);
    }while(error_code != OK);

    // Send encrypted password to server
    if((error_code = send_encrypted_message(socket, (unsigned char *)password, strlen(password) + 1, key_container)) != OK) {
        return error_code; // Error during sending encrypted password
    }

    // Allocate buffer for server's response
    unsigned char *server_response = NULL;
    int server_response_len = 0;

    // Read server's response
    if((error_code = get_encrypted_message(socket, key_container, &server_response, &server_response_len)) != OK) {
        return error_code; // Error during reading server's response
    }

    // Check if server's response is a NCK
    if (server_response_len < 3 || strncmp((char *)server_response, "NCK", 3) == 0) {
        free(server_response);
        return BAD_PASSWORD; // Server did not acknowledge the password
    }
    // Check if server's response is a request for password change
    if(strncmp((char *)server_response, "CPW", 3) == 0){
        *change_pwd = 1; // Indicate that the server requested a password change
        free(server_response);
        return OK;
    // If the server's response is not a NCK or CPW, it should be an ACK
    } else if (strncmp((char *)server_response, "ACK", 3) != 0) {
        free(server_response);
        return BAD_PASSWORD; // Server did not acknowledge the password
    }

    // Free the server response buffer after checking
    free(server_response); 

    return OK; // Success
}

int send_new_password_to_server(int socket, unsigned char *key_container) {
    
    // Set up error code
    int error_code = OK;

    // Buffer for password
    unsigned char password[MAX_PASSWORD_LENGTH + 1];

    // Retrieve password
    do{
        error_code = get_new_password(password, MAX_PASSWORD_LENGTH + 1);
    }while(error_code != OK);


    // Send encrypted password to server
    if((error_code = send_encrypted_message(socket, (unsigned char *)password, strlen(password) + 1, key_container)) != OK) {
        return error_code; // Error during sending encrypted password
    }

    // Allocate buffer for server's response
    unsigned char *server_response = NULL;
    int server_response_len = 0;

    // Read server's response
    if((error_code = get_encrypted_message(socket, key_container, &server_response, &server_response_len)) != OK) {
        return error_code; // Error during reading server's response
    }

    // Check if server's response is an ACK or NCK
    if (server_response_len < 3 || strncmp((char *)server_response, "ACK", 3) != 0) {
        free(server_response);
        return BAD_PW_UPDATE; // Server did not acknowledge the password
    }

    // Free the server response buffer after checking
    free(server_response);

    return OK; // Success
}


int generate_nonce(unsigned char* buffer, int buffer_size, unsigned long *err) {
    /* Generate a random nonce */
    int rc = RAND_bytes(buffer, buffer_size);
    *err = ERR_get_error();

    if (rc != 1) {
        /* RAND_bytes failed */
        /* `err` is valid    */
        return NONCE_GENERATION_ERROR;
    }

    return OK; // Success
}

int send_nonce(int socket, unsigned char *nonce, int nonce_len) {
    
    // Set up error code and error value
    int error_message = OK;
    unsigned long err;

    // Generate a nonce
    if((error_message = error_handler(generate_nonce(nonce, nonce_len, &err), socket)) != OK) {
        printf("[Error]: %lu\n", err);
        return error_message;
    }

    // Send the nonce to the server
    if((error_message = send(socket, nonce, nonce_len, 0)) < 0) {
        return SOCKET_WRITE_ERROR;
    }

    return OK; // Success
}

int verify_signature(unsigned char *signature, int signature_len, unsigned char *message, int message_len){
    
    // Set up public key file
    const char *pubkey_file = "ServerParams/rsa_pubkey.pem";

    // Load the public key from the PEM file
    EVP_PKEY* pubkey;
    FILE* file = fopen(pubkey_file,"r");
    if(!file) {
        return PUBLIC_KEY_READ_ERROR;
    }

    // Read the public key from the file
    pubkey = PEM_read_PUBKEY(file,NULL,NULL,NULL);
    if(!pubkey) {
        return PUBLIC_KEY_EXTRACTION_ERROR;
    }
    fclose(file);


    // Create a new EVP_MD_CTX for signature verification
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    // Check if the context was created successfully
    if(EVP_VerifyInit(ctx, EVP_sha256()) != 1){
        EVP_MD_CTX_free(ctx);
        OPENSSL_free(pubkey);
        printf("---------------------------------------------------------------\n");
        handleErrors();
        printf("---------------------------------------------------------------\n");
        return EVP_VERIFY_INIT_ERROR; // Signature verification initialization failed
    }

    // Update the context with the message to be verified
    if(EVP_VerifyUpdate(ctx, message, message_len) != 1){
        EVP_MD_CTX_free(ctx);
        OPENSSL_free(pubkey);
        printf("---------------------------------------------------------------\n");
        handleErrors();
        printf("---------------------------------------------------------------\n");
        return EVP_VERIFY_UPDATE_ERROR; // Message update failed
    }

    // Verify the signature using the public key
    if(EVP_VerifyFinal(ctx, signature, signature_len, pubkey) != 1){
        EVP_MD_CTX_free(ctx);
        OPENSSL_free(pubkey);
        printf("---------------------------------------------------------------\n");
        handleErrors();
        printf("---------------------------------------------------------------\n");
        return EVP_VERIFY_FINALIZATION_ERROR; // Signature verification failed
    }

    // Clean up
    EVP_MD_CTX_free(ctx);
    OPENSSL_free(pubkey);

    return OK; // Success
}

int get_signed_dh_params(int socket_fd, unsigned char * key_container, unsigned char* nonce, int nonce_len) {
    
    // Set up parameters
    EVP_PKEY *dh_params = NULL;
    BIO *bio = NULL;

    // Create bio from file
    bio = BIO_new_file("ServerParams/dhparam.pem", "r");
    // Check if the bio was created successfully
    if (bio == NULL) {
        printf("---------------------------------------------------------------\n");
        handleErrors();
        printf("---------------------------------------------------------------\n");
        return BIO_INIT_ERROR; // BIO initialization failed
    }

    // Read the DH parameters from the file
    dh_params = PEM_read_bio_Parameters(bio, NULL);
    if (dh_params == NULL) {
        BIO_free(bio);
        printf("---------------------------------------------------------------\n");
        handleErrors();
        printf("---------------------------------------------------------------\n");
        return DH_PARAM_READ_ERROR; // DH parameter reading failed
    }
    BIO_free(bio);

    // Create a new EVP_PKEY_CTX for DH key generation
    EVP_PKEY_CTX * ctx = EVP_PKEY_CTX_new(dh_params, NULL);
    
    // Check if the context was created successfully
    if (ctx == NULL) {
        printf("---------------------------------------------------------------\n");
        handleErrors();
        printf("---------------------------------------------------------------\n");
        return DH_CTX_INIT_ERROR; // DH context initialization failed
    }

    // Generate a new DH key
    EVP_PKEY* my_prvkey = NULL;

    // Initialize the key generation context
    if(EVP_PKEY_keygen_init(ctx) != 1) {
        EVP_PKEY_CTX_free(ctx);
        printf("---------------------------------------------------------------\n");
        handleErrors();
        printf("---------------------------------------------------------------\n");
        return EVP_PKEY_KEYGEN_INIT_ERROR; // DH key generation initialization failed
    }

    // Set the key generation parameters
    if(EVP_PKEY_keygen(ctx, &my_prvkey) != 1) {
        EVP_PKEY_CTX_free(ctx);
        printf("---------------------------------------------------------------\n");
        handleErrors();
        printf("---------------------------------------------------------------\n");
        return EVP_PKEY_KEYGEN_ERROR; // DH key generation failed
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(dh_params);

    // Receive the server's public key
    long server_pubkey_len = 0;
    size_t bytes_received = read(socket_fd, &server_pubkey_len, sizeof(long));
    // Check if the read operation was successful
    if (bytes_received <= 0) {
        EVP_PKEY_free(my_prvkey);
        return SOCKET_READ_ERROR; // Error during reading server's public key length
    }

    // Allocate memory for the server's public key
    unsigned char *server_pubkey = (unsigned char *)malloc(server_pubkey_len + 1);
    
    // Check if memory allocation was successful
    if (server_pubkey == NULL) {
        EVP_PKEY_free(my_prvkey);
        return MALLOC_ERROR; // Memory allocation failed
    }

    // Read the server's public key
    bytes_received = read(socket_fd, server_pubkey, server_pubkey_len);
    if (bytes_received <= 0) {
        EVP_PKEY_free(my_prvkey);
        free(server_pubkey);
        return SOCKET_READ_ERROR; // Error during reading server's public key
    }

    // Read the signature
    int signature_len = 0;
    bytes_received = read(socket_fd, &signature_len, sizeof(int));
    if (bytes_received <= 0) {
        EVP_PKEY_free(my_prvkey);
        free(server_pubkey);
        return SOCKET_READ_ERROR; // Error during reading signature length
    }

    // Allocate memory for the signature
    unsigned char *signature = (unsigned char *)malloc(signature_len);
    if (signature == NULL) {
        EVP_PKEY_free(my_prvkey);
        free(server_pubkey);
        return MALLOC_ERROR; // Memory allocation failed
    }

    // Read the signature
    bytes_received = read(socket_fd, signature, signature_len);
    if (bytes_received <= 0) {
        EVP_PKEY_free(my_prvkey);
        free(server_pubkey);
        free(signature);
        return SOCKET_READ_ERROR; // Error during reading signature
    }

    // Prepare the statement we expect to verify: statement = public_key || user_nonce
    unsigned char *statement;
    int statement_len = server_pubkey_len + nonce_len;

    // Allocate memory for the concatenated message
    statement = malloc(statement_len);
    if (!statement) {
        EVP_PKEY_free(my_prvkey);
        free(server_pubkey);
        free(signature);
        return MALLOC_ERROR; // Memory allocation failed
    }

    // Copy public_key into the beginning of message
    memcpy(statement, server_pubkey, server_pubkey_len);

    // Copy user_nonce right after public_key
    memcpy(statement + server_pubkey_len, nonce, nonce_len);

    //Verify the signature
    if (verify_signature(signature, signature_len, statement, statement_len) != OK) {
        EVP_PKEY_free(my_prvkey);
        free(server_pubkey);
        free(signature);
        free(statement);
        return SIGNATURE_VERIFICATION_ERROR; // Signature verification failed
    }

    // Cleanup
    free(signature);
    free(statement);

    // Null-terminate the PEM public key buffer so it can be treated as a string
    server_pubkey[server_pubkey_len] = '\0';

    // Create a BIO memory buffer to parse the PEM-formatted public key
    bio = BIO_new_mem_buf(server_pubkey, server_pubkey_len);
    if(bio == NULL) {
        EVP_PKEY_free(my_prvkey);
        free(server_pubkey);
        printf("---------------------------------------------------------------\n");
        handleErrors();
        printf("---------------------------------------------------------------\n");
        return BIO_INIT_ERROR;
    }
    EVP_PKEY *server_dhkey = NULL;
    // Read the PEM-formatted public key from the BIO and convert it into an EVP_PKEY struct
    if (((server_dhkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL)) == NULL)){
        EVP_PKEY_free(my_prvkey);
        BIO_free(bio);
        free(server_pubkey);
        printf("---------------------------------------------------------------\n");
        handleErrors();
        printf("---------------------------------------------------------------\n");
        return DH_PARAM_READ_ERROR; // Failed to parse PEM into key
    }

    // Cleanup
    BIO_free(bio);
    free(server_pubkey);

    // Create a BIO to store client's public key in PEM format
    BIO *bio_out = BIO_new(BIO_s_mem());
    if (PEM_write_bio_PUBKEY(bio_out, my_prvkey) != 1) {
        EVP_PKEY_free(my_prvkey);
        EVP_PKEY_free(server_dhkey);
        printf("---------------------------------------------------------------\n");
        handleErrors();
        printf("---------------------------------------------------------------\n");
        return DH_PUBKEY_SEND_ERROR; // Failed to write public key to BIO
    }

    // Extract the PEM-formatted public key string from the BIO
    char *public_key = NULL;
    long public_key_len = BIO_get_mem_data(bio_out, &public_key);

    // Send the length of the public key first
    if (send(socket_fd, &public_key_len, sizeof(long), 0) == -1) {
        EVP_PKEY_free(my_prvkey);
        EVP_PKEY_free(server_dhkey);
        BIO_free(bio_out);
        return SOCKET_WRITE_ERROR;
    }

    // Then send the actual public key
    if (send(socket_fd, public_key, public_key_len, 0) == -1) {
        EVP_PKEY_free(my_prvkey);
        EVP_PKEY_free(server_dhkey);
        BIO_free(bio_out);
        return SOCKET_WRITE_ERROR;
    }

    // Free the BIO after sending the public key
    BIO_free(bio_out);

    // --------------------------
    // ECDH / DH KEY DERIVATION
    // --------------------------
    
    // Create a new context for key derivation using client's private key
    EVP_PKEY_CTX * ctx_drv = EVP_PKEY_CTX_new(my_prvkey, NULL);
    if (ctx_drv == NULL) {
        EVP_PKEY_free(server_dhkey);
        printf("---------------------------------------------------------------\n");
        handleErrors();
        printf("---------------------------------------------------------------\n");
        return EVP_PKEY_CTX_CREATION_ERROR; // Key derivation context creation failed
    }

    // Initialize the context for a key derivation operation
    if(EVP_PKEY_derive_init(ctx_drv) != 1) {
        EVP_PKEY_free(server_dhkey);
        EVP_PKEY_CTX_free(ctx_drv);
         printf("---------------------------------------------------------------\n");
        handleErrors();
        printf("---------------------------------------------------------------\n");
        return EVP_PKEY_KEYGEN_INIT_ERROR; // Key derivation initialization failed
    }

    // Provide the server's public key as the "peer" for the key exchange
    if(EVP_PKEY_derive_set_peer(ctx_drv, server_dhkey) != 1) {
        EVP_PKEY_free(server_dhkey);
        EVP_PKEY_CTX_free(ctx_drv);
        printf("---------------------------------------------------------------\n");
        handleErrors();
        printf("---------------------------------------------------------------\n");
        return EVP_PKEY_DERIVATION_ERROR; // Key derivation peer setting failed
    }

    // Free the server's public key as it is no longer needed
    EVP_PKEY_free(server_dhkey);

    // This will point to client's derived secret
    unsigned char * secret;

    // First call to EVP_PKEY_derive with NULL to retrieve how many bytes the shared secret will be
    size_t secret_len;
        if (EVP_PKEY_derive(ctx_drv, NULL, &secret_len) != 1){
        EVP_PKEY_CTX_free(ctx_drv);
        printf("---------------------------------------------------------------\n");
        handleErrors();
        printf("---------------------------------------------------------------\n");
        return EVP_PKEY_DERIVATION_ERROR;
    }

    // Allocate memory to hold the actual shared secret
    secret = OPENSSL_malloc(secret_len);

    // Perform the actual key derivation: this computes the shared secret
    if (EVP_PKEY_derive(ctx_drv, secret, &secret_len) != 1){
        EVP_PKEY_CTX_free(ctx_drv);
        OPENSSL_free(secret);
        printf("---------------------------------------------------------------\n");
        handleErrors();
        printf("---------------------------------------------------------------\n");
        return EVP_PKEY_SECRET_DERIVATION_ERROR;
    }

    // Clean up the key derivation context and client's private key — no longer needed
    EVP_PKEY_CTX_free(ctx_drv);
    EVP_PKEY_free(my_prvkey);


    // Hash the shared secret using SHA-256 and store the result in `key_container`
    // This ensures consistent length and adds a layer of key derivation
    if (SHA256(secret, secret_len, key_container) == NULL) {
        OPENSSL_free(secret);
        printf("---------------------------------------------------------------\n");
        handleErrors();
        printf("---------------------------------------------------------------\n");
        return EVP_PKEY_SECRET_DERIVATION_ERROR;
    }

    // Free the raw shared secret from memory after hashing it
    OPENSSL_free(secret);

    return OK; // Success
}

// Encrypts data using AES-256 in GCM mode (authenticated encryption)
// Returns the length of the ciphertext, or a negative error code on failure
int gcm_encrypt(unsigned char *plaintext, int plaintext_len,
                unsigned char *aad, int aad_len,    // Optional authenticated data (not encrypted)
                unsigned char *key,                 // 256-bit (32 bytes) AES key
                unsigned char *iv, int iv_len,      // Initialization Vector
                unsigned char *ciphertext,          // Output buffer for encrypted data
                unsigned char *tag)                 // Output buffer for authentication tag (16 bytes)
{
    EVP_CIPHER_CTX *ctx; // OpenSSL encryption context

    int len;

    int ciphertext_len;

    // Create and initialise the context 
    if(!(ctx = EVP_CIPHER_CTX_new())){
        printf("---------------------------------------------------------------\n");
        handleErrors();
        printf("---------------------------------------------------------------\n");
        return EVP_CIPHER_CTX_CREATION_ERROR;
    }
        

    // Initialise the encryption operation
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)){
        EVP_CIPHER_CTX_free(ctx);
        printf("---------------------------------------------------------------\n");
        handleErrors();
        printf("---------------------------------------------------------------\n");
        return EVP_CIPHER_CTX_INIT_ERROR;
    }
        
    // Set the IV length. This is not necessary if the IV is 12 bytes (96 bits), but we do it anyway for future compatibility
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)){
        EVP_CIPHER_CTX_free(ctx);
        printf("---------------------------------------------------------------\n");
        handleErrors();
        printf("---------------------------------------------------------------\n");
        return EVP_CIPHER_CTX_IV_SET_ERROR;
    }
        

    // Initialise key and IV
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)){
        EVP_CIPHER_CTX_free(ctx);
        printf("---------------------------------------------------------------\n");
        handleErrors();
        printf("---------------------------------------------------------------\n");
        return EVP_CIPHER_CTX_INIT_ERROR;
    }

    // Provide any AAD data
    if(aad != NULL && aad_len > 0)
    {
        if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)){
            EVP_CIPHER_CTX_free(ctx);
            printf("---------------------------------------------------------------\n");
            handleErrors();
            printf("---------------------------------------------------------------\n");
            return EVP_CIPHER_CTX_UPDATE_ERROR;
        }
    }

    // Provide the message to be encrypted, and obtain the encrypted output
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)){
        EVP_CIPHER_CTX_free(ctx);
        printf("---------------------------------------------------------------\n");
        handleErrors();
        printf("---------------------------------------------------------------\n");
        return EVP_CIPHER_CTX_UPDATE_ERROR;
    }
    ciphertext_len = len;

    // Finalise the encryption
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)){
        EVP_CIPHER_CTX_free(ctx);
        printf("---------------------------------------------------------------\n");
        handleErrors();
        printf("---------------------------------------------------------------\n");
        return EVP_CIPHER_CTX_FINALIZATION_ERROR;
    }
    ciphertext_len += len;

    // Get the tag
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)){
        EVP_CIPHER_CTX_free(ctx);
        printf("---------------------------------------------------------------\n");
        handleErrors();
        printf("---------------------------------------------------------------\n");
        return EVP_CIPHER_CTX_TAG_RETRIEVAL_ERROR;
    }

    // Cleanup
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len; // Success, return the length of the ciphertext
}

// Decrypts ciphertext using AES-256-GCM mode
// Returns the length of the plaintext on success, or a negative error code on failure
int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *aad, int aad_len,       // Optional authenticated data (not encrypted)
                unsigned char *tag,                    // Authentication tag (16 bytes)
                unsigned char *key,                    // 256-bit (32 bytes) AES key
                unsigned char *iv, int iv_len,         // Initialization Vector
                unsigned char *plaintext)              // Output buffer for decrypted data
{
    EVP_CIPHER_CTX *ctx; // OpenSSL encryption context
    int len;
    int plaintext_len;
    int ret;

    // Create and initialize the encryption context
    if(!(ctx = EVP_CIPHER_CTX_new())){
        printf("---------------------------------------------------------------\n");
        handleErrors();
        printf("---------------------------------------------------------------\n");
        return EVP_CIPHER_CTX_CREATION_ERROR; // Context creation failed
    }

    // Initialise the decryption operation
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)){
        EVP_CIPHER_CTX_free(ctx);
        printf("---------------------------------------------------------------\n");
        handleErrors();
        printf("---------------------------------------------------------------\n");
        return EVP_CIPHER_CTX_INIT_ERROR; // Decryption initialization failed
    }

    // Set IV length. Not necessary if this is 12 bytes (96 bits), but we do it anyway for future compatibility
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)){
        EVP_CIPHER_CTX_free(ctx);
        printf("---------------------------------------------------------------\n");
        handleErrors();
        printf("---------------------------------------------------------------\n");
        return EVP_CIPHER_CTX_IV_SET_ERROR; // IV length setting failed
    }

    // Initialise key and IV
    if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)){
        EVP_CIPHER_CTX_free(ctx);
        printf("---------------------------------------------------------------\n");
        handleErrors();
        printf("---------------------------------------------------------------\n");
        return EVP_CIPHER_CTX_INIT_ERROR; // Decryption initialization failed
    }

    // Provide AAD data, if any
    if(aad != NULL && aad_len > 0){
        if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len)){
            EVP_CIPHER_CTX_free(ctx);
            printf("---------------------------------------------------------------\n");
            handleErrors();
            printf("---------------------------------------------------------------\n");
            return EVP_CIPHER_CTX_UPDATE_ERROR; // AAD update failed
        }
    }

    // Provide the message to be decrypted, and obtain the plaintext output
    if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)){
        EVP_CIPHER_CTX_free(ctx);
        printf("---------------------------------------------------------------\n");
        handleErrors();
        printf("---------------------------------------------------------------\n");
        return EVP_CIPHER_CTX_UPDATE_ERROR; // Decryption update failed
    }
    // Store the length of the plaintext
    plaintext_len = len;

    // Set expected tag value
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag)){
        EVP_CIPHER_CTX_free(ctx);
        printf("---------------------------------------------------------------\n");
        handleErrors();
        printf("---------------------------------------------------------------\n");
        return EVP_CIPHER_CTX_TAG_RETRIEVAL_ERROR; // Tag retrieval failed
    }

    // Finalise the decryption. A positive return value indicates success,
    // anything else is a failure - the plaintext is not trustworthy
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    // Cleanup
    EVP_CIPHER_CTX_free(ctx);

    if(ret > 0) {
        // Success
        plaintext_len += len;
        return plaintext_len;
    } else {
        // Decryption failed
        printf("---------------------------------------------------------------\n");
        handleErrors();
        printf("---------------------------------------------------------------\n");
        return EVP_PKEY_CTX_DECRYPTION_ERROR; // Decryption error, plaintext is not trustworthy
    }
}

int send_encrypted_message(int socket_fd, unsigned char *plaintext, int plaintext_len, unsigned char *key_container) {
        
    // Validate input parameters to avoid null pointers or invalid length
    if (plaintext == NULL || plaintext_len <= 0 || key_container == NULL) {
        return ENCRYPTION_ERROR; // Return error if inputs are invalid
    }

    // Initialization Vector (IV) for AES-GCM is typically 12 bytes
    unsigned char iv[12];

    // Authentication tag for AES-GCM, typically 16 bytes
    unsigned char tag[16];

    // Allocate memory for ciphertext: ciphertext size can be up to plaintext length plus max block length padding
    unsigned char* ciphertext = (unsigned char *)malloc(plaintext_len + EVP_MAX_BLOCK_LENGTH);
    if (ciphertext == NULL) {
        return MALLOC_ERROR; // Return error if memory allocation fails
    }

    unsigned long err;
    int ciphertext_len;

    // Generate a cryptographically secure nonce to use as the IV for encryption
    if (generate_nonce(iv, sizeof(iv), &err) != OK) {
        free(ciphertext);
        return NONCE_GENERATION_ERROR; // Return error if nonce generation fails
    }

        // Allocate a buffer to hold everything: 12 (IV) + 16 (tag) + 4 (length) = 32 bytes
    unsigned char aad[16];

    // Copy IV (12 bytes)
    memcpy(aad, iv, 12);

    // Copy 4-byte representation of plaintext_len (big endian)
    aad[12] = (plaintext_len >> 24) & 0xFF;
    aad[13] = (plaintext_len >> 16) & 0xFF;
    aad[14] = (plaintext_len >> 8) & 0xFF;
    aad[15] = plaintext_len & 0xFF;

    // Perform AES-GCM encryption on the plaintext
    // Arguments: plaintext and its length, no additional authenticated data (NULL, 0),
    // the secret key, IV and its length, output ciphertext buffer, and output authentication tag buffer
    ciphertext_len = gcm_encrypt(plaintext, plaintext_len, aad, sizeof(aad), key_container, iv, sizeof(iv), ciphertext, tag);
    if (ciphertext_len < 0) {
        free(ciphertext);
        return ENCRYPTION_ERROR; // Return error if encryption process fails
    }

    // Send the components of the encrypted message over the socket in this order:
    // 1) IV (nonce), 2) Authentication tag, 3) Ciphertext length, 4) Ciphertext itself
    if (send(socket_fd, iv, sizeof(iv), 0) == -1 ||
        send(socket_fd, tag, sizeof(tag), 0) == -1 ||
        send(socket_fd, &ciphertext_len, sizeof(int), 0) == -1 ||
        send(socket_fd, ciphertext, ciphertext_len, 0) == -1) {
        // If any send operation fails, return socket write error
        free(ciphertext);
        return SOCKET_WRITE_ERROR;
    }

    free(ciphertext); // Free ciphertext buffer after successful send

    return OK; // Indicate success
}

int get_encrypted_message(int socket_fd, unsigned char *key_container, unsigned char **plaintext, int *plaintext_len) {
    // Buffers for Initialization Vector (IV) and authentication tag used in AES-GCM
    unsigned char iv[12];
    unsigned char tag[16];
    int ciphertext_length;

    // Read the IV (nonce) from the socket; must be exactly 12 bytes for AES-GCM
    if (read(socket_fd, iv, sizeof(iv)) <= 0) {
        return SOCKET_READ_ERROR; // Return error if reading IV fails or connection closes unexpectedly
    }

    // Read the authentication tag from the socket; typically 16 bytes for AES-GCM
    if (read(socket_fd, tag, sizeof(tag)) <= 0) {
        return SOCKET_READ_ERROR; // Return error if reading tag fails
    }

    // Read the length of the incoming ciphertext (an integer)
    if (read(socket_fd, &ciphertext_length, sizeof(int)) <= 0) {
        return SOCKET_READ_ERROR; // Return error if reading ciphertext length fails
    }

    // Allocate a buffer to hold everything: 12 (IV) + 16 (tag) + 4 (length) = 32 bytes
    unsigned char aad[16];

    // Copy IV (12 bytes)
    memcpy(aad, iv, 12);

    // Copy 4-byte representation of plaintext_len (big endian)
    aad[12] = (ciphertext_length >> 24) & 0xFF;
    aad[13] = (ciphertext_length >> 16) & 0xFF;
    aad[14] = (ciphertext_length >> 8) & 0xFF;
    aad[15] = ciphertext_length & 0xFF;

    // Allocate memory to store the ciphertext, using the length just read
    unsigned char *ciphertext = (unsigned char *)malloc(ciphertext_length);
    if (ciphertext == NULL) {
        return MALLOC_ERROR; // Return error if memory allocation fails
    }

    // Read the ciphertext itself from the socket
    if (read(socket_fd, ciphertext, ciphertext_length) <= 0) {
        free(ciphertext); // Free allocated memory before returning
        return SOCKET_READ_ERROR; // Return error if reading ciphertext fails
    }

    // Allocate memory to hold the decrypted plaintext
    // Allocate slightly larger buffer to accommodate any padding (EVP_MAX_BLOCK_LENGTH)
    *plaintext = (unsigned char *)malloc(ciphertext_length + EVP_MAX_BLOCK_LENGTH);
    if (*plaintext == NULL) {
        free(ciphertext);
        return MALLOC_ERROR; // Return error if memory allocation fails
    }

    // Perform AES-GCM decryption:
    // Inputs are ciphertext, its length, no additional authenticated data (NULL, 0),
    // the tag, key, IV, IV length, and output buffer for plaintext.
    // The function returns the length of the decrypted plaintext or negative on failure.
    *plaintext_len = gcm_decrypt(ciphertext, ciphertext_length, aad, sizeof(aad), tag, key_container, iv, sizeof(iv), *plaintext);
    
    // Ciphertext buffer no longer needed, free it
    free(ciphertext);

    // Check if decryption was successful
    if (*plaintext_len < 0) {
        free(*plaintext); // Free allocated plaintext buffer on failure
        return DECRYPTION_ERROR; // Return error indicating decryption failed (e.g., tag mismatch)
    }

    return OK; // Decryption successful, plaintext and its length are output parameters
}

// Handles OpenSSL errors by printing them to stderr
void handleErrors() {
    ERR_print_errors_fp(stderr);
}

