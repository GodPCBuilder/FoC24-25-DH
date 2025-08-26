#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <netinet/in.h>

#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/dh.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rsa.h>

#include "params.h"
#include "server_application_protocol.h"
#include "server_authentication_protocol.h"



int sha256_password_salt(const char *password, int password_len, const char *salt, int salt_len, char *output_hex, int output_hex_len) {
    // Check if the password length exceeds maximum allowed or if salt length is not exactly expected
    if(password_len > MAX_PASSWORD_LENGTH || salt_len != SALT_LEN) {
        return BAD_PASSWORD;
    }
    
    unsigned char hash[SHA256_DIGEST_LENGTH]; // Buffer to hold raw SHA-256 hash output
    char concat[password_len + salt_len + 1]; // Buffer to hold concatenated password + salt string (+1 for null terminator)

    // Concatenate password and salt into one string, safely with snprintf
    snprintf(concat, sizeof(concat), "%s%s", password, salt);

    // Compute SHA-256 hash on the concatenated password+salt string
    SHA256((unsigned char*)concat, strlen(concat), hash);

    // Convert each byte of the hash to a two-character hexadecimal representation
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        snprintf(output_hex + (i * 2), 3, "%02x", hash[i]);

    // Verify output buffer is large enough to hold the hex string + null terminator
    if(output_hex_len < SHA256_DIGEST_LENGTH * 2 + 1) {
        return -1; // TODO: Replace with specific error code for buffer too small
    }

    // Null-terminate the output hex string
    output_hex[SHA256_DIGEST_LENGTH * 2] = '\0';

    return OK; // Indicate success
}


int get_user_hello(int socket, char *username) {
    
    int bytes_read = 0;  // Counter for number of bytes read into username
    char ch;             // Temporary variable to store each character read from socket
    
    // Read characters one by one from the socket until max length 16 or null terminator
    while (bytes_read < 16) {
        int result = read(socket, &ch, sizeof(char)); // Read a single byte from socket
        
        if (result < 0) {
            return SOCKET_READ_ERROR; // Error reading from socket
        } else if (result == 0) {
            // End of stream reached; no more data
            break;
        }
        
        if (ch == '\0') {
            // Null terminator received; end of username string
            break;
        }
        
        // Store received character into username buffer
        username[bytes_read] = ch;
        bytes_read++;
    }
    
    if(bytes_read == 0){
        // No valid username characters received
        return BAD_USERNAME;
    }
    
    // Null-terminate username string to make it a proper C-string
    username[bytes_read] = '\0';
    
    return OK; // Success
}


int check_user_password(int socket, unsigned char *key_container, unsigned char *username, int* change_password_flag) {
    unsigned char * password = NULL; // Buffer to hold decrypted password received from client
    int password_len = 0;            // Length of the decrypted password
    int error_code = OK;             // Variable to track error codes

    // Receive encrypted password message from client and decrypt it
    if((error_code = get_encrypted_message(socket, key_container, &password, &password_len)) != OK) {
        return error_code; // Return error if password reception fails
    }

    // Validate the received password against stored user data
    if(is_password_valid(username, password, change_password_flag) != OK) {
        printf("[Server] Invalid password for user %s\n", username);
        free(password); // Free the allocated password buffer
        send_encrypted_message(socket, "NCK", strlen("NCK"), key_container); // Notify client of invalid password
        return BAD_PASSWORD; // Indicate bad password error
    }

    free(password); // Password is valid; free password buffer
    
    // Check if the user must change password (flag set by validation function)
    if((*change_password_flag == 1)) {
        // Notify client to change password
        if((error_code = send_encrypted_message(socket, "CPW", strlen("CPW"), key_container)) != OK) {
            return error_code; // Return error if sending change-password request fails
        }
        return OK; // Successfully indicated need to change password
    }
    else{
        // Notify client that password is accepted (ACK)
        if((error_code = send_encrypted_message(socket, "ACK", strlen("ACK"), key_container)) != OK) {
            return error_code; // Return error if sending ACK fails
        }
    }
    
    return OK; // Password checked and client notified successfully
}


int change_user_password(int socket, unsigned char* key_container, unsigned char* username) {
    unsigned char * password = NULL;  // Buffer to hold decrypted new password from client
    int password_len = 0;             // Length of the new password
    int error_code = OK;              // Variable to track errors

    // Receive the new password from the client encrypted message
    if((error_code = get_encrypted_message(socket, key_container, &password, &password_len)) != OK) {
        return error_code; // Return error if reception fails
    }

    // Generate a new random salt (nonce) and convert it to hexadecimal string
    unsigned long err;
    unsigned char nonce[32];
    unsigned char nonce2hex[65]; // 32 bytes * 2 hex chars + 1 null terminator

    generate_nonce(nonce,32,&err);
    bytes_to_hex(nonce, 32, nonce2hex, 65);

    char computed_hash[SHA256_DIGEST_LENGTH * 2 + 1]; // Buffer for hex hash string
    char concat[512]; // Buffer to concatenate password and salt for hashing

    // Concatenate the plaintext password and the salt (nonce)
    memcpy(concat, password, strlen(password));
    memcpy(concat + strlen(password), nonce, sizeof(nonce));

    unsigned char hash[SHA256_DIGEST_LENGTH]; // Buffer to hold raw SHA256 hash
    // Hash the concatenated password+salt
    SHA256((unsigned char*)concat, strlen(password) + sizeof(nonce), hash);

    // Convert raw hash bytes to hexadecimal string
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        snprintf(computed_hash + (i * 2), 3, "%02x", hash[i]);
    computed_hash[SHA256_DIGEST_LENGTH * 2] = '\0';

    // Open password file for reading and writing
    FILE *fp = fopen("UsersData/passwords.txt", "r+");
    if (!fp) return PWD_FILE_OPEN_ERROR;

    char line[512];
    int found = 0;

    // Iterate through each line in the password file to find the user
    while (fgets(line, sizeof(line), fp)) {
        long line_start_pos = ftell(fp) - strlen(line); // Calculate start position of the line
        line[strcspn(line, "\n")] = '\0'; // Remove newline character

        char *sep1 = strchr(line, ':'); // Find username separator
        if (!sep1) continue;
        *sep1 = '\0';
        const char *file_user = line;

        // If this line corresponds to the user
        if (strcmp(file_user, (char *)username) == 0) {
            found = 1;

            // Build the updated hash and salt string with flag set to '0' (password valid)
            char updated_part[256];
            snprintf(updated_part, sizeof(updated_part), "%s;salt:%s;0", computed_hash, nonce2hex);

            // Move file pointer to the start of the password hash in the line (after username and colon)
            long offset = line_start_pos + strlen(username) + 1; // +1 for the ':'
            fseek(fp, offset, SEEK_SET);

            // Overwrite the old hash+salt with the new one (same length assumed)
            fwrite(updated_part, 1, strlen(updated_part), fp);

            fclose(fp); // Close file after update

            // Notify client of successful password change
            if ((error_code = send_encrypted_message(socket, "ACK", strlen("ACK"), key_container)) != OK) {
                return error_code;
            }

            return OK; // Password successfully updated
        }
    }

    fclose(fp); // Close file if user not found
    return BAD_USERNAME; // Indicate username not found in the file
}

int is_username_valid(char *username) {
    // Open the password file in read mode
    FILE *fp = fopen("UsersData/passwords.txt", "r");
    if (!fp) {
        return PWD_FILE_OPEN_ERROR; // Failed to open file
    }

    char line[512];
    // Read the file line by line
    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\n")] = '\0'; // Strip newline character at the end, if present

        // Look for the first ':' character to split the username from the rest
        char *sep = strchr(line, ':');
        if (!sep) continue; // Malformed line, skip

        *sep = '\0'; // Null-terminate the username portion
        const char *file_user = line; // Pointer to the extracted username

        // Compare the given username with the one from the file
        if (strcmp(file_user, username) == 0) {
            // Match found — now look for the user status flag

            // The flag is expected after the last ';' in the line
            char *last_semicolon = strrchr(sep + 1, ';');
            if (!last_semicolon || !isdigit(*(last_semicolon + 1))) {
                fclose(fp);
                return MALFORMED_USERNAME_LINE_ERROR; // Line does not end with a digit flag
            }

            char flag = *(last_semicolon + 1); // Extract the flag value
            fclose(fp);

            // Interpret the flag
            if (flag == '2') return BAD_USERNAME; // User is blocked or invalid
            else return OK; // User is valid and active
        }
    }

    fclose(fp);
    return BAD_USERNAME; // Username not found in the file
}

int is_password_valid(const char *username, const char *password, int * change_password_flag) {
    // Open the password file for reading
    FILE *fp = fopen("UsersData/passwords.txt", "r");
    if (!fp) return PWD_FILE_OPEN_ERROR;

    char line[512];
    int result = OK;

    // Process the file line by line
    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\n")] = '\0'; // Remove newline character at the end

        // Find the first ':' separator to isolate the username
        char *sep1 = strchr(line, ':');
        if (!sep1) continue; // Malformed line, skip

        *sep1 = '\0'; // Terminate username string
        const char *file_user = line; // Extracted username
        char *hash_and_salt = sep1 + 1; // Move past ':' to reach hash and salt section

        // Find the next ';' which separates hash from the salt
        char *sep2 = strchr(hash_and_salt, ';');
        if (!sep2) continue; // Malformed line, skip

        *sep2 = '\0'; // Terminate the hash string
        char *stored_hash = hash_and_salt;

        // Locate the "salt:" prefix
        char *salt_ptr = strstr(sep2 + 1, "salt:");
        if (!salt_ptr) continue; // Malformed salt entry, skip
        salt_ptr += 5; // Move pointer past "salt:" string

        // Look for the last ';' after the salt, which precedes the flag
        char *sep3 = strchr(salt_ptr, ';');
        if (!sep3 || !sep3[1]) continue; // Malformed line, skip

        *sep3 = '\0'; // Terminate salt value
        const char *salt_value = salt_ptr;

        // The character after the last semicolon is the final flag
        char final_flag = sep3[1];
        if (final_flag != '0' && final_flag != '1') continue; // Validate flag

        /*
            At this point:
            - file_user      = username from file
            - stored_hash    = password hash from file (hex-encoded)
            - salt_value     = salt string (hex-encoded)
            - final_flag     = user status flag ('0' for normal, '1' for password change required)
        */

        // Check if the username matches
        if (strcmp(file_user, username) == 0) {
            // Prepare to hash the provided password with the salt
            unsigned char computed_hash[SHA256_DIGEST_LENGTH * 2 + 1]; // Hex-encoded result
            unsigned char concat[512]; // Buffer for password || salt
            unsigned char salt[32];    // Binary salt value

            // Decode the hex-encoded salt into bytes
            decode_hex_string_to_bytes(salt_value, salt, sizeof(salt));

            // Concatenate password + salt
            memcpy(concat, password, strlen(password));
            memcpy(concat + strlen(password), salt, sizeof(salt));

            // Compute SHA-256 hash of (password || salt)
            unsigned char hash[SHA256_DIGEST_LENGTH];
            SHA256((unsigned char*)concat, strlen(password) + sizeof(salt), hash);

            // Convert binary hash to lowercase hex string
            for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
                snprintf(computed_hash + (i * 2), 3, "%02x", hash[i]);
            computed_hash[SHA256_DIGEST_LENGTH * 2] = '\0';

            fclose(fp); // Close the file after processing the matching user

            // Compare the computed hash with the stored hash
            if (strcmp(stored_hash, computed_hash) == 0) {
                // Password is valid
                if (final_flag == '1') {
                    *change_password_flag = 1; // User must change their password
                } else if (final_flag == '0') {
                    *change_password_flag = 0; // No password change required
                } else {
                    continue; // Shouldn't happen, but safe guard
                }

                return OK;
            } else {
                continue; // Password doesn't match
            }
        }
    }

    // Username not found or password mismatch
    return BAD_USERNAME;
}

int send_NACK(int socket){

    if (send(socket, N_ACK, strlen(N_ACK), 0) < 0) {
        return SOCKET_WRITE_ERROR;
    }
    return OK;
}

int send_ACK(int socket){

    if (send(socket, ACK, strlen(ACK), 0) < 0) {
        return SOCKET_WRITE_ERROR;
    }
    return OK;
}

int getPasskey(char * passkey, int passkey_len){
    // Ensure the buffer is large enough to hold the passkey (64 chars + null terminator)
    if(passkey_len < 65) {
        return PASSKEY_READ_ERROR; // Buffer too small for passkey
    }

    // Open the passkey file in read mode
    FILE *file = fopen("ServerParams/passkey.txt", "r");
    if (!file) {
        return PASSKEY_READ_ERROR; // Error opening passkey file
    }

    // Read the passkey string from the file
    if (fgets(passkey, passkey_len, file) == NULL) {
        fclose(file);
        return PASSKEY_READ_ERROR; // Error reading passkey
    }

    // Remove trailing newline character if it exists
    passkey[strcspn(passkey, "\n")] = 0;

    fclose(file); // Close the file after reading
    return OK; // Successfully read the passkey
}


int generate_nonce(unsigned char* buffer, int buffer_size, unsigned long *err) {
    // Generate a random nonce 
    int rc = RAND_bytes(buffer, buffer_size);
    *err = ERR_get_error();

    if (rc != 1) {
        // RAND_bytes failed
        // err is valid 
        return NONCE_GENERATION_ERROR;
    }

    return OK; // Success
}

int sign(unsigned char **signature, unsigned char *message, int message_len){
    int signature_len;

    // Path to the RSA private key file used for signing
    const char *pubkey_file = "ServerParams/rsa_privkey.pem";

    EVP_PKEY* privkey;
    // Open the private key file for reading in PEM format
    FILE* file = fopen(pubkey_file,"r");
    if(!file) {
        // If the file can't be opened, return an error
        return PRIVATE_KEY_READ_ERROR;
    }

    // Buffer to hold the passphrase needed to decrypt the private key
    char passkey[65] = {0}; // 64 chars + null terminator, matching expected passkey size
    if(getPasskey(passkey, sizeof(passkey)) != OK) {
        fclose(file);
        // Failed to retrieve passphrase from file
        return PASSKEY_READ_ERROR;
    }

    // Read the encrypted private key from the PEM file, using the passphrase
    privkey = PEM_read_PrivateKey(file,NULL,NULL,passkey);
    if(!privkey) {
        // Could not extract the private key, likely due to wrong passphrase or corrupt file
        return PRIVATE_KEY_EXTRACTION_ERROR;
    }
    fclose(file); // Close the key file as it's no longer needed

    // Allocate memory for the signature output based on the key size
    *signature = malloc(EVP_PKEY_size(privkey));
    if (*signature == NULL) {
        // If allocation fails, clean up and return error
        EVP_PKEY_free(privkey);
        return MALLOC_ERROR;
    }

    // Create a new message digest context needed for signing operations
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        // Context creation failed: cleanup and return error
        free(*signature);
        EVP_PKEY_free(privkey);
        printf("OPENSSL DUMP:\n");
        printf("---------------------------------------------------------------\n");
        handleErrors(); // Prints OpenSSL error stack for diagnostics
        printf("---------------------------------------------------------------\n");
        return SIGNING_CONTEXT_INIT_ERROR;
    }

    // Initialize the signing operation specifying SHA-256 as the hashing algorithm
    if(EVP_SignInit(ctx, EVP_sha256()) != 1){
        free(*signature);
        EVP_PKEY_free(privkey);
        EVP_MD_CTX_free(ctx);
        printf("OPENSSL DUMP:\n");
        printf("---------------------------------------------------------------\n");
        handleErrors();
        printf("---------------------------------------------------------------\n");
        return SIGNING_CONTEXT_INIT_ERROR;
    }

    // Feed the data to be signed (the message) into the signing context
    if(EVP_SignUpdate(ctx, message, message_len) != 1){
        free(*signature);
        EVP_PKEY_free(privkey);
        EVP_MD_CTX_free(ctx);
        printf("OPENSSL DUMP:\n");
        printf("---------------------------------------------------------------\n");
        handleErrors();
        printf("---------------------------------------------------------------\n");
        return SIGNING_CONTEXT_UPDATE_ERROR;
    }

    // Finalize the signing operation, which produces the actual signature bytes
    // The signature is written to the allocated buffer, and its length is stored in signature_len
    if(EVP_SignFinal(ctx, *signature, &signature_len, privkey) != 1){
        free(*signature);
        EVP_PKEY_free(privkey);
        EVP_MD_CTX_free(ctx);
        printf("OPENSSL DUMP:\n");
        printf("---------------------------------------------------------------\n");
        handleErrors();
        printf("---------------------------------------------------------------\n");
        return SIGNATURE_FINALIZATION_ERROR;
    };

    // Clean up allocated resources for the private key and signing context
    EVP_PKEY_free(privkey);
    EVP_MD_CTX_free(ctx);

    // Return the length of the generated signature on success
    return signature_len;
}

int send_signed_dh_params(int socket_fd, unsigned char * key_container, unsigned char* user_nonce, int nonce_len) {
    EVP_PKEY *dh_params = NULL;
    BIO *bio = NULL;

    // Create a BIO object to read the DH parameters from the PEM file
    bio = BIO_new_file("ServerParams/dhparam.pem", "r");
    if (bio == NULL) {
        // If BIO initialization fails, print OpenSSL error details and return error code
        printf("OPENSSL DUMP:\n");
        printf("---------------------------------------------------------------\n");
        handleErrors();
        printf("---------------------------------------------------------------\n");
        return BIO_INIT_ERROR;
    }

    // Read DH parameters from the BIO into an EVP_PKEY structure
    dh_params = PEM_read_bio_Parameters(bio, NULL);
    if (dh_params == NULL) {
        // If reading DH parameters fails, clean up BIO and return error
        BIO_free(bio);
        printf("OPENSSL DUMP:\n");
        printf("---------------------------------------------------------------\n");
        handleErrors();
        printf("---------------------------------------------------------------\n");
        return DH_PARAM_READ_ERROR;
    }

    // Free the BIO after successfully reading DH parameters
    BIO_free(bio);

    // Create a new context for DH key generation based on the DH parameters
    EVP_PKEY_CTX * ctx = EVP_PKEY_CTX_new(dh_params, NULL);
    EVP_PKEY_free(dh_params); // Free dh_params since ctx now owns the params
    if (ctx == NULL) {
        // If context creation fails, print errors and return error
        printf("OPENSSL DUMP:\n");
        printf("---------------------------------------------------------------\n");
        handleErrors();
        printf("---------------------------------------------------------------\n");
        return DH_CTX_INIT_ERROR;
    }

    // Initialize key generation operation
    if(EVP_PKEY_keygen_init(ctx) != 1) {
        EVP_PKEY_CTX_free(ctx);
        printf("OPENSSL DUMP:\n");
        printf("---------------------------------------------------------------\n");
        handleErrors();
        printf("---------------------------------------------------------------\n");
        return EVP_PKEY_KEYGEN_INIT_ERROR;
    }

    // Generate a new ephemeral DH private key
    EVP_PKEY* my_prvkey = NULL;
    if(EVP_PKEY_keygen(ctx, &my_prvkey) != 1) {
        EVP_PKEY_CTX_free(ctx);
        printf("OPENSSL DUMP:\n");
        printf("---------------------------------------------------------------\n");
        handleErrors();
        printf("---------------------------------------------------------------\n");
        return EVP_PKEY_KEYGEN_ERROR;
    }

    // Free the key generation context after key generation
    EVP_PKEY_CTX_free(ctx);

    // Create a memory BIO to hold the PEM-encoded public key for sending
    BIO *bio_out = BIO_new(BIO_s_mem());
    if(bio_out == NULL) {
        EVP_PKEY_free(my_prvkey);
        printf("OPENSSL DUMP:\n");
        printf("---------------------------------------------------------------\n");
        handleErrors();
        printf("---------------------------------------------------------------\n");
        return BIO_INIT_ERROR;
    }

    // Write the generated public key to the BIO in PEM format
    if (PEM_write_bio_PUBKEY(bio_out, my_prvkey) != 1) {
        EVP_PKEY_free(my_prvkey);
        printf("OPENSSL DUMP:\n");
        printf("---------------------------------------------------------------\n");
        handleErrors();
        printf("---------------------------------------------------------------\n");
        return DH_PUBKEY_SEND_ERROR;
    }

    // Extract the PEM public key data from the BIO buffer
    char *public_key = NULL;
    long public_key_len = BIO_get_mem_data(bio_out, &public_key);

    // Send the length of the public key PEM string over the socket
    if (send(socket_fd, &public_key_len, sizeof(long), 0) == -1) {
        EVP_PKEY_free(my_prvkey);
        BIO_free(bio_out);
        return SOCKET_WRITE_ERROR;
    }

    // Send the actual public key PEM string bytes over the socket
    if (send(socket_fd, public_key, public_key_len, 0) == -1) {
        EVP_PKEY_free(my_prvkey);
        BIO_free(bio_out);
        return SOCKET_WRITE_ERROR;
    }

    unsigned char *signature = NULL;

    // Prepare the message to be signed: concatenation of the public key and user's nonce
    unsigned char *statement;
    int statement_len = public_key_len + nonce_len;

    // Allocate buffer to hold the concatenated message (public key + nonce)
    statement = malloc(statement_len);
    if (!statement) {
        EVP_PKEY_free(my_prvkey);
        BIO_free(bio_out);
        return MALLOC_ERROR; // Memory allocation failed
    }

    // Copy public key data into the beginning of statement buffer
    memcpy(statement, public_key, public_key_len);

    // Append user's nonce immediately after the public key in the statement buffer
    memcpy(statement + public_key_len, user_nonce, nonce_len);

    // Generate a digital signature over the concatenated statement buffer
    int signature_len = sign(&signature, statement, statement_len);
    if(signature_len < 0) {
        // In case of signing error, free allocated resources and return error code from sign()
        if(signature != NULL) {
            free(signature);
        }
        EVP_PKEY_free(my_prvkey);
        BIO_free(bio_out);
        free(statement);
        return signature_len;
    }

    // Free temporary buffers no longer needed
    free(statement);
    BIO_free(bio_out);

    // Send the length of the signature to the client
    if (send(socket_fd, &signature_len, sizeof(int), 0) == -1) {
        free(signature);
        EVP_PKEY_free(my_prvkey);
        return SOCKET_WRITE_ERROR;
    }

    // Send the actual signature bytes to the client
    if (send(socket_fd, signature, signature_len, 0) == -1) {
        free(signature);
        EVP_PKEY_free(my_prvkey);
        return SOCKET_WRITE_ERROR;
    }

    // Free the signature buffer after sending
    free(signature);

    // Now receive the client's public key length
    long client_pubkey_len = 0;
    size_t bytes_received = read(socket_fd, &client_pubkey_len, sizeof(long));
    if (bytes_received <= 0) {
        EVP_PKEY_free(my_prvkey);
        return SOCKET_READ_ERROR;
    }

    // Allocate buffer for the client's public key PEM string (+1 for null terminator)
    unsigned char *buffer = (unsigned char *)malloc(client_pubkey_len + 1);
    if (buffer == NULL) {
        EVP_PKEY_free(my_prvkey);
        return MALLOC_ERROR;
    }

    // Read the client's public key PEM string from the socket
    bytes_received = read(socket_fd, buffer, client_pubkey_len);
    if (bytes_received <= 0) {
        EVP_PKEY_free(my_prvkey);
        free(buffer);
        return SOCKET_READ_ERROR;
    }

    // Null-terminate the buffer to safely treat it as a string
    buffer[bytes_received] = '\0';

    // Create a BIO memory buffer for the client's public key PEM string
    bio = BIO_new_mem_buf(buffer, bytes_received);
    if(bio == NULL) {
        EVP_PKEY_free(my_prvkey);
        return BIO_INIT_ERROR;
    }

    EVP_PKEY *client_dhkey = NULL;

    // Read the client's DH public key from the BIO buffer
    if (((client_dhkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL)) == NULL)){
        EVP_PKEY_free(my_prvkey);
        BIO_free(bio);
        free(buffer);
        printf("OPENSSL DUMP:\n");
        printf("---------------------------------------------------------------\n");
        handleErrors();
        printf("---------------------------------------------------------------\n");
        return DH_PARAM_READ_ERROR;
    }

    // Free BIO and buffer after extracting the client's DH public key
    BIO_free(bio);
    free(buffer);

    // Create a context for deriving the shared secret using our private key
    EVP_PKEY_CTX * ctx_drv = EVP_PKEY_CTX_new(my_prvkey, NULL);
    if (ctx_drv == NULL) {
        EVP_PKEY_free(client_dhkey);
        printf("OPENSSL DUMP:\n");
        printf("---------------------------------------------------------------\n");
        handleErrors();
        printf("---------------------------------------------------------------\n");
        return EVP_PKEY_CTX_CREATION_ERROR;
    }

    // Initialize key derivation operation
    if(EVP_PKEY_derive_init(ctx_drv) != 1) {
        EVP_PKEY_free(client_dhkey);
        EVP_PKEY_CTX_free(ctx_drv);
        printf("OPENSSL DUMP:\n");
        printf("---------------------------------------------------------------\n");
        handleErrors();
        printf("---------------------------------------------------------------\n");
        return EVP_PKEY_KEYGEN_INIT_ERROR;
    }

    // Set the peer public key (client's DH key) to perform key derivation
    if(EVP_PKEY_derive_set_peer(ctx_drv, client_dhkey) != 1) {
        EVP_PKEY_free(client_dhkey);
        EVP_PKEY_CTX_free(ctx_drv);
        printf("OPENSSL DUMP:\n");
        printf("---------------------------------------------------------------\n");
        handleErrors();
        printf("---------------------------------------------------------------\n");
        return EVP_PKEY_DERIVATION_ERROR;
    }

    // Free the client DH key after setting it as peer
    EVP_PKEY_free(client_dhkey);

    unsigned char * secret;

    // Determine the buffer size needed for the shared secret
    size_t secret_len;
    if (EVP_PKEY_derive(ctx_drv, NULL, &secret_len) != 1){
        EVP_PKEY_CTX_free(ctx_drv);
        printf("OPENSSL DUMP:\n");
        printf("---------------------------------------------------------------\n");
        handleErrors();
        printf("---------------------------------------------------------------\n");
        return EVP_PKEY_DERIVATION_ERROR;
    }

    // Allocate buffer for the shared secret
    secret = OPENSSL_malloc(secret_len);

    // Derive the shared secret into the allocated buffer
    if (EVP_PKEY_derive(ctx_drv, secret, &secret_len) != 1){
        EVP_PKEY_CTX_free(ctx_drv);
        OPENSSL_free(secret);
        printf("OPENSSL DUMP:\n");
        printf("---------------------------------------------------------------\n");
        handleErrors();
        printf("---------------------------------------------------------------\n");
        return EVP_PKEY_SECRET_DERIVATION_ERROR;
    }

    // Free the private key and context after key derivation is done
    EVP_PKEY_free(my_prvkey);
    EVP_PKEY_CTX_free(ctx_drv);

    // Derive a SHA256 hash of the shared secret to obtain the final key material
    if (SHA256(secret, secret_len, key_container) == NULL) {
        OPENSSL_free(secret);
        printf("OPENSSL DUMP:\n");
        printf("---------------------------------------------------------------\n");
        handleErrors();
        printf("---------------------------------------------------------------\n");
        return EVP_PKEY_SECRET_DERIVATION_ERROR;
    }

    // Free the shared secret buffer after hashing
    OPENSSL_free(secret);

    // Success
    return OK;
}


int gcm_encrypt(unsigned char *plaintext, int plaintext_len,
                unsigned char *aad, int aad_len,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *ciphertext,
                unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    // Create and initialise the context
    if(!(ctx = EVP_CIPHER_CTX_new())){
        printf("OPENSSL DUMP:\n");
        printf("---------------------------------------------------------------\n");
        handleErrors();
        printf("---------------------------------------------------------------\n");
        return EVP_CIPHER_CTX_CREATION_ERROR;
    }
        

    // Initialise the encryption operation
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)){
        EVP_CIPHER_CTX_free(ctx);
        printf("OPENSSL DUMP:\n");
        printf("---------------------------------------------------------------\n");
        handleErrors();
        printf("---------------------------------------------------------------\n");
        return EVP_CIPHER_CTX_INIT_ERROR;
    }
        

    
    //Set IV length if default 12 bytes (96 bits) is not appropriate
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)){
        EVP_CIPHER_CTX_free(ctx);
        printf("OPENSSL DUMP:\n");
        printf("---------------------------------------------------------------\n");
        handleErrors();
        printf("---------------------------------------------------------------\n");
        return EVP_CIPHER_CTX_IV_SET_ERROR;
    }
        

    // Initialise key and IV
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)){
        EVP_CIPHER_CTX_free(ctx);
        printf("OPENSSL DUMP:\n");
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
            printf("OPENSSL DUMP:\n");
            printf("---------------------------------------------------------------\n");
            handleErrors();
            printf("---------------------------------------------------------------\n");
            return EVP_CIPHER_CTX_UPDATE_ERROR;
        }
    }

    //Provide the message to be encrypted, and obtain the encrypted output.
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)){
        EVP_CIPHER_CTX_free(ctx);
        printf("OPENSSL DUMP:\n");
        printf("---------------------------------------------------------------\n");
        handleErrors();
        printf("---------------------------------------------------------------\n");
        return EVP_CIPHER_CTX_INIT_ERROR;
    }
    ciphertext_len = len;

    //Finalise the encryption
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)){
        EVP_CIPHER_CTX_free(ctx);
        printf("OPENSSL DUMP:\n");
        printf("---------------------------------------------------------------\n");
        handleErrors();
        printf("---------------------------------------------------------------\n");
        return EVP_CIPHER_CTX_FINALIZATION_ERROR;
    }
    ciphertext_len += len;

    // Get the tag
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)){
        EVP_CIPHER_CTX_free(ctx);
        printf("OPENSSL DUMP:\n");
        printf("---------------------------------------------------------------\n");
        handleErrors();
        printf("---------------------------------------------------------------\n");
        return EVP_CIPHER_CTX_TAG_RETRIEVAL_ERROR;
    }

    // Cleanup
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *aad, int aad_len,
                unsigned char *tag,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    // Create and initialise the context
    if(!(ctx = EVP_CIPHER_CTX_new())){
        printf("OPENSSL DUMP:\n");
        printf("---------------------------------------------------------------\n");
        handleErrors();
        printf("---------------------------------------------------------------\n");
        return EVP_CIPHER_CTX_CREATION_ERROR;
    }

    // Initialise the decryption operation
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)){
        EVP_CIPHER_CTX_free(ctx);
        printf("OPENSSL DUMP:\n");
        printf("---------------------------------------------------------------\n");
        handleErrors();
        printf("---------------------------------------------------------------\n");
        return EVP_CIPHER_CTX_INIT_ERROR;
    }

    // Set IV length. Not necessary if this is 12 bytes (96 bits)
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)){
        EVP_CIPHER_CTX_free(ctx);
        printf("OPENSSL DUMP:\n");
        printf("---------------------------------------------------------------\n");
        handleErrors();
        printf("---------------------------------------------------------------\n");
        return EVP_CIPHER_CTX_IV_SET_ERROR;
    }

    // Initialise key and IV
    if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)){
        EVP_CIPHER_CTX_free(ctx);
        printf("OPENSSL DUMP:\n");
        printf("---------------------------------------------------------------\n");
        handleErrors();
        printf("---------------------------------------------------------------\n");
        return EVP_CIPHER_CTX_INIT_ERROR;
    }

    // Provide any AAD data
    if(aad != NULL && aad_len > 0){
        if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len)){
            EVP_CIPHER_CTX_free(ctx);
            printf("OPENSSL DUMP:\n");
            printf("---------------------------------------------------------------\n");
            handleErrors();
            printf("---------------------------------------------------------------\n");
            return EVP_CIPHER_CTX_UPDATE_ERROR;
        }
    }
    
    //Provide the message to be decrypted, and obtain the plaintext output.
    if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)){
        EVP_CIPHER_CTX_free(ctx);
        printf("OPENSSL DUMP:\n");
        printf("---------------------------------------------------------------\n");
        handleErrors();
        printf("---------------------------------------------------------------\n");
        return EVP_CIPHER_CTX_UPDATE_ERROR;
    }
    plaintext_len = len;

    // Set expected tag value
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag)){
        EVP_CIPHER_CTX_free(ctx);
        printf("OPENSSL DUMP:\n");
        printf("---------------------------------------------------------------\n");
        handleErrors();
        printf("---------------------------------------------------------------\n");
        return EVP_CIPHER_CTX_TAG_RETRIEVAL_ERROR;
    }

    //Finalise the decryption. A positive return value indicates success,
    //anything else is a failure - the plaintext is not trustworthy.
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    // Cleanup 
    EVP_CIPHER_CTX_free(ctx);

    if(ret > 0) {
        // Success
        plaintext_len += len;
        return plaintext_len;
    } else {
        // Verify failed
        printf("OPENSSL DUMP:\n");
        printf("---------------------------------------------------------------\n");
        handleErrors();
        printf("---------------------------------------------------------------\n");
        return EVP_PKEY_CTX_DECRYPTION_ERROR;
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

void handleErrors() {
    ERR_print_errors_fp(stderr);
}
