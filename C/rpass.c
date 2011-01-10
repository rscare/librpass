#include <stdio.h>
#include <gpgme.h>
#include "rpass.h"

static gpgme_ctx_t ctx = NULL;

void rpass_error(const char const *err_msg) {
    fprintf(stderr, err_msg);
}

int create_gpg_data(gpgme_data_t *data, FILE *fp, char *str, int len, int COPY) {
    if (fp != NULL) { // Create file-based data
        switch (gpgme_data_new_from_stream(data, fp)) {
            case GPG_ERR_NO_ERROR:
                return 1;
                break;
            default:
                rpass_error("Failed to create data stream from file.");
                return 0;
                break;
        }
    }

    if (str != NULL) { // Create data-based data
        switch(gpgme_data_new_from_mem(data, str, len, COPY)) {
            case GPG_ERR_NO_ERROR:
                return 1;
                break;
            default:
                rpass_error("Failed to create data stream from memory.");
                return 0;
                break;
        }
    }

    switch (gpgme_data_new(data)) { // Create generic data
        case GPG_ERR_NO_ERROR:
            return 1;
            break;
        default:
            rpass_error("Failed to create data stream.");
            return 0;
            break;
    }
}

int decrypt_object(gpgme_data_t cipher_text, gpgme_data_t plain_text) {
    switch (gpgme_op_decrypt(ctx, cipher_text, plain_text)) {
        case GPG_ERR_NO_ERROR:
            return 0;
            break;
        case GPG_ERR_INV_VALUE:
            rpass_error("Invalid pointer.");
            return 1;
            break;
        case GPG_ERR_NO_DATA:
            rpass_error("No data.");
            return 1;
            break;
        case GPG_ERR_DECRYPT_FAILED:
            rpass_error("Invalid data.");
            return 1;
            break;
        case GPG_ERR_BAD_PASSPHRASE:
            rpass_error("Bad passphrase.");
            return 1;
            break;
        default:
            rpass_error("Unknown error.");
            return 1;
            break;
    }
}

int encrypt_object(gpgme_data_t plain_text, gpgme_data_t cipher_text) {
    gpgme_key_t keys[] = {NULL, NULL};
    gpgme_op_keylist_start(ctx, NULL, 0);
    gpgme_op_keylist_next(ctx, &keys[0]);
 
    // Encryption method
    switch (gpgme_op_encrypt(ctx, keys, 0, plain_text, cipher_text)) {
        case GPG_ERR_UNUSABLE_PUBKEY:
            rpass_error("Unusable public key.\n");
            return 1;
            break;
        case GPG_ERR_INV_VALUE:
            rpass_error("Invalid pointer.\n");
            return 1;
            break;
        case GPG_ERR_NO_ERROR:
            break;
        default:
            rpass_error("Unkown error.\n");
            return 1;
            break;
    }

    // Release the key object
    gpgme_key_release(keys[0]);
    return 0;
}

void print_gpgme_data(gpgme_data_t data) {
    ssize_t size_read = 0;
    char tmp_string[BUF_LEN + 1];

    gpgme_data_seek(data, 0, SEEK_SET);
    while(size_read = gpgme_data_read(data, tmp_string, BUF_LEN)) {
        tmp_string[size_read] = '\0';
        printf("%s", tmp_string);
    }
    putchar('\n');
    gpgme_data_seek(data, 0, SEEK_SET);
}

int initialize_engine() {
    if (ctx != NULL)
        return 0;

    // Verify protocol
    if (gpgme_engine_check_version(PROTOCOL) != GPG_ERR_NO_ERROR) {
        rpass_error("Bad protocol.\n");
        return 1;
    }

    // Verify engine
    if (gpgme_check_version(NULL) == NULL) {
        rpass_error("No gpgme version available.\n");
        return 1;
    }

    // Create context
    switch (gpgme_new(&ctx)) {
        case GPG_ERR_NO_ERROR:
            break;
        case GPG_ERR_INV_VALUE:
            rpass_error("Context is not a valid pointer.\n");
            return 1;
            break;
        case GPG_ERR_ENOMEM:
            rpass_error("Context could not allocate memory.\n");
            return 1;
            break;
        case GPG_ERR_NOT_OPERATIONAL:
            rpass_error("GPGME not initialized.\n");
            return 1;
            break;
        default:
            rpass_error("Unknown error.\n");
            return 1;
            break;
    }

    // Set the context's protocol
    if (gpgme_set_protocol(ctx, PROTOCOL) != GPG_ERR_NO_ERROR) {
        rpass_error("Could not set context protocol.\n");
        return 1;
    }

    return 0;
}
