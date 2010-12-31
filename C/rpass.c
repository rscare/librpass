#include <stdlib.h>
#include <stdio.h>
#include <gpgme.h>

#define PROTOCOL GPGME_PROTOCOL_OpenPGP
#define PREF_ALGO GPGME_PK_RSA
#define PREF_HASH GPGME_MD_SHA256

void rpass_error(const char *err_msg){
    fprintf(stderr, err_msg);
}

int main (int argc, char const *argv[])
{
    const char test_string[] = "Hello Yuri.";

    gpgme_engine_info_t engine_info = NULL;
    gpgme_data_t DH = NULL;
    gpgme_ctx_t ctx = NULL;

    // Check that the engine exists
    if (gpgme_engine_check_version(PROTOCOL) == GPG_ERR_INV_ENGINE) {
        rpass_error("Invalid engine.\n"); 
        return 1;
    }

    // Get the engine's info
    if (gpgme_get_engine_info(&engine_info) != GPG_ERR_NO_ERROR) {
        rpass_error("Could not get engine info.\n"); 
        return 1;
    }

    // Verify protocol
    if (gpgme_engine_check_version(PROTOCOL) != GPG_ERR_NO_ERROR) {
        rpass_error("Bad protocol.\n");
        return 1;
    }

    // Verify engine
    printf("Current version: %s.\n", gpgme_check_version(NULL));

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

    gpgme_set_armor(ctx, 1);

    // Create and populate the new data object
    if (gpgme_data_new_from_mem(&DH, test_string, sizeof(test_string), 1) != GPG_ERR_NO_ERROR) {
        rpass_error("Could not create data object.\n");
        return 1;
    }

    // Encrypt data

    gpgme_op_keylist_start(ctx, NULL, 1);

    //Destroy context
    gpgme_release(ctx);

    // Release the data buffer
    gpgme_data_release(DH);

    return 0;
}
