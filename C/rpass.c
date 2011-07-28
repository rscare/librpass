#include "rpass.h"
#include <stdio.h>
#include <gpgme.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#define RPASS_PROTOCOL GPGME_PROTOCOL_OpenPGP
#define RPASS_PREF_ALGO GPGME_PK_RSA
#define RPASS_PREF_HASH GPGME_MD_SHA256

static gpgme_ctx_t ctx = NULL;

static int log_error(const char * const err_msg) {
    fprintf(stderr, "%s\n", err_msg);
    return 1;
}

int initialize_engine() {
    /* Initializes the gpgme engine and creates a context with which to
     * perform crypto operations. */

    // Perform version check necessary to initialize various internals
    gpgme_check_version(NULL);
    // Check that the used protocol exists
    if (gpgme_engine_check_version(RPASS_PROTOCOL) != GPG_ERR_NO_ERROR) {
        log_error("Engine for default protocol not working...");
        return RPASS_GPG_INIT_ERR;
    }
    // Create global context
    switch (gpgme_new(&ctx)) {
    case GPG_ERR_NO_ERROR:
        break;
    case GPG_ERR_INV_VALUE:
        log_error("Invalid pointer value...");
        return RPASS_GPG_INIT_ERR;
    case GPG_ERR_ENOMEM:
        log_error("Insufficient memory...");
        return RPASS_GPG_INIT_ERR;
    default:
        log_error("Error creating context...");
        return RPASS_GPG_INIT_ERR;
    }
    // Set context's protocol
    if (gpgme_set_protocol(ctx, RPASS_PROTOCOL) != GPG_ERR_NO_ERROR) {
        destroy_engine();
        log_error("Error setting context protocol...");
        return RPASS_GPG_INIT_ERR;
    }

    return RPASS_GPG_NOERR;
}

void destroy_engine() {
    /* Releases resources held by the context and prepares for another
     * possible iteration. */
    gpgme_release(ctx); ctx = NULL;
}

int decrypt_file(const char * const filename, gpgme_data_t ptext) {
    /* Decrypts a file into a plain text data object */
    gpgme_data_t ctext = NULL;
    FILE *fp = NULL;
    if (!(fp = fopen(filename, "rb"))) {
        log_error("Error opening file for decryption...");
        return RPASS_GPG_DECRYPT_ERR;
    }
    if (gpgme_data_new_from_fd(&ctext, fileno(fp)) != GPG_ERR_NO_ERROR) {
        fclose(fp);
        log_error("Error creating crypto object...");
        return RPASS_GPG_DECRYPT_ERR;
    }
    if (gpgme_op_decrypt(ctx, ctext, ptext) != GPG_ERR_NO_ERROR) {
        fclose(fp);
        gpgme_data_release(ctext);
        log_error("Error decrypting crypto object...");
        return RPASS_GPG_DECRYPT_ERR;
    }
    fclose(fp);
    gpgme_data_release(ctext);

    return RPASS_GPG_NOERR;
}

void print_gpgme_data(gpgme_data_t data) {
    /* Prints the data contained in a gpgme data object to stdout. */
    ssize_t size_read = 0;
    char tmp_string[BUFSIZ + 1];

    gpgme_data_seek(data, 0, SEEK_SET);
    while(size_read = gpgme_data_read(data, tmp_string, BUFSIZ)) {
        tmp_string[size_read] = '\0';
        printf("%s", tmp_string);
    }
    putchar('\n');
    gpgme_data_seek(data, 0, SEEK_SET);
}

int GetAccountInfo(gpgme_data_t ptext, const char * const acname, rpass_parent **parent) {
    /* Gets the account info stored in a ptext object with name acname into
     * the pre-initailzed parent object parent. */

    char tmp_string[BUFSIZ + 1], actitle[strlen(acname) + 3];
    char *acstart = NULL, *acend = NULL, *tmp = NULL;
    size_t tmpsize = 0;
    int i = 0;

    // Construct actitle
    snprintf(actitle, strlen(acname) + 3, "[%s]", acname);

    // Extract account string from data object
    gpgme_data_seek(ptext, 0, SEEK_SET);
    while (gpgme_data_read(ptext, tmp_string, BUFSIZ)) {
        tmp_string[BUFSIZ] = '\0';

        tmpsize = strlen(tmp_string) + 1;
        tmpsize += (tmp) ? strlen(tmp) : 0 ;
        tmp = realloc(tmp, sizeof(char) * tmpsize);
        strncpy(tmp + (tmpsize - strlen(tmp_string) - 1), tmp_string, strlen(tmp_string));
        tmp[tmpsize - 1] = '\0';

        if (!acstart)
            acstart = strstr(tmp, actitle);

        if (acstart) {
            acend = strstr(acstart + 3, "\n[");
            if (acend) {
                *acend = '\0';
                break;
            }
        }
    }

    // Create rpass object from string
    if ((i = initialize_rpass_parent_from_string(parent, acstart)) != RPASS_GPG_NOERR)
        return i;

    free(tmp);
    return RPASS_GPG_NOERR;
}

int initialize_rpass_parent_from_string(rpass_parent **parent, const char *entrystr) {
    /* Initializes an rpass parent from an entry string */
    int i;
    char *acstart = NULL, *acend = NULL;
    rpass_entry *entry = NULL, *entry_ptr = NULL;

    if ((i = initialize_rpass_parent(parent)) != RPASS_GPG_NOERR)
        return i;

    // Establishing the acname
    acstart = strchr(entrystr, '['); acend = strchr(acstart, ']');
    (*parent)->acname = malloc(acend - acstart);
    strncpy((*parent)->acname, acstart, (acend - acstart) - 1);
    (*parent)->acname[acend - acstart - 1] = '\0';

    // Taking it line by line
    while (acstart = strchr(entrystr, '\n')) {
        if (++acstart == '\0')
            break;

        if ((i = initialize_rpass_entry(&entry)) != RPASS_GPG_NOERR)
            return i;

        if (!(*parent)->first_entry)
            (*parent)->first_entry = entry;
        else
            entry_ptr->next_entry = entry;

        entry_ptr = entry;

        while (isspace(*(++acstart)))
            ;
        acend = acstart;
        while (!isspace(*acend) && (*acend != '='))
            acend++;

        entry->key = malloc((acend - acstart) + 1);
        strncpy(entry->key, acstart, (acend - acstart));
        entry->key[(acend-acstart)] = '\0';

        acstart = acend;
        while ((*acstart == '=') || (isspace(*acstart)))
            acstart++;
        acend = acstart;
        while (!isspace(*(++acend)))
            ;

        entry->value = malloc((acend - acstart) + 1);
        strncpy(entry->value, acstart, (acend - acstart));
        entry->value[(acend-acstart)] = '\0';

        entrystr = acend; entry = NULL;
    }

    return RPASS_GPG_NOERR;
}

int initialize_rpass_entry(rpass_entry **entry) {
    /* Initializes an rpass entry */

    if (*entry)
        return RPASS_GPG_NOERR;

    if (!(*entry = malloc(sizeof(rpass_entry)))) {
        log_error("Failed to allocate memory...");
        return RPASS_GPG_MEM_ERR;
    }

    (*entry)->key = NULL;
    (*entry)->value = NULL;
    (*entry)->next_entry = NULL;

    return RPASS_GPG_NOERR;
}

int initialize_rpass_parent(rpass_parent **parent) {
    /* Initializes an rpasss parent with default values */

    if (*parent)
        return RPASS_GPG_NOERR;

    if (!(*parent = malloc(sizeof(rpass_parent)))) {
        log_error("Failed to allocate memory...");
        return RPASS_GPG_MEM_ERR;
    }

    (*parent)->acname = NULL;
    (*parent)->next_parent = NULL;
    (*parent)->first_entry = NULL;

    return RPASS_GPG_NOERR;
}

void destroy_rpass_parent(rpass_parent *parent) {
    /* Destroys everything associated with the parent, and all linked
     * parents. */

    if (parent->next_parent)
        destroy_rpass_parent(parent->next_parent);

    if (parent->first_entry)
        destroy_rpass_entry(parent->first_entry);

    free(parent->acname);
    free(parent);
}

void destroy_rpass_entry(rpass_entry *entry) {
    /* Destroys everythign associated with the entry, and all linked
     * entries */

    if (entry->next_entry)
        destroy_rpass_entry(entry->next_entry);

    free(entry->key);
    free(entry->value);
    free(entry);
}
