#ifndef RPASS_H
#define RPASS_H

#include <gpgme.h>

// Error structure
enum RPASS_GPG_ERR { RPASS_GPG_NOERR,
                     RPASS_GPG_INIT_ERR,
                     RPASS_GPG_DECRYPT_ERR,
                     RPASS_GPG_MEM_ERR };

// Entry structure
struct RPASS_ENTRY {
    char *key, *value;
    struct RPASS_ENTRY *next_entry;
};

// Parent structure
struct RPASS_PARENT {
    char * acname;
    struct RPASS_PARENT * next_parent;
    struct RPASS_ENTRY * first_entry;
};

typedef struct RPASS_ENTRY rpass_entry;
typedef struct RPASS_PARENT rpass_parent;

static int log_error(const char * const err_msg);

int initialize_engine();
void destroy_engine();

int decrypt_file(const char * const filename, gpgme_data_t ptext);

void print_gpgme_data(gpgme_data_t data);

int GetAccountInfo(gpgme_data_t ptext, const char * const acname, rpass_parent **parent);

int initialize_rpass_parent(rpass_parent **parent);
void destroy_rpass_parent(rpass_parent *parent);

int initialize_rpass_entry(rpass_entry **entry);
void destroy_rpass_entry(rpass_entry *entry);

int initialize_rpass_parent_from_string(rpass_parent **parent, const char *entrystr);

#endif
