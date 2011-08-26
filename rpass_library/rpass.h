#ifndef RPASS_H
#define RPASS_H

#include <stddef.h>
#include <gcrypt.h>

#define GCRYPT_PREF_VERSION NULL
#define GCRYPT_SECMEM_SIZE 1 // default is 16384
#define GCRYPT_PREFERRED_ALGO GCRY_CIPHER_AES256

#define GCRYPT_CIPHER_MODE GCRY_CIPHER_MODE_CBC
#define GCRYPT_AESWRAP_MODE_OFFSET 8 // when using aeswrap mode, an offset needs to be used

#define GCRYPT_KDF_ALGO GCRY_KDF_ITERSALTED_S2K
#define GCRYPT_KDF_SUBALGO GCRY_MD_SHA256
#define GCRYPT_KDF_SALT "fw,l3od0"
#define GCRYPT_KDF_SALTLEN 8
#define GCRYPT_KDF_ITERATIONS 3

#define SOCKET_NAME "/tmp/rpassdsocket"

#define RPASS_DAEMON_MSG_DECRYPTFILE "DECRYPTFILE"
#define RPASS_DAEMON_MSG_ENCRYPTFILE "ENCRYPTFILE"
#define RPASS_DAEMON_MSG_ENCRYPTDATATOFILE "ENCRYPTDATATOFILE"
#define RPASS_DAEMON_MSG_GETACCOUNTS "GETACCOUNTS"
#define RPASS_DAEMON_MSG_STOP "STOP"

#define RPASS_DAEMON_AC_START "RPASSDACSTART"

struct __RPASS_ENTRY {
    char *key, *value;
    struct __RPASS_ENTRY *next_entry;
};

struct __RPASS_PARENT {
    char *acname;
    struct __RPASS_PARENT *next_parent;
    struct __RPASS_ENTRY *first_entry;
};

typedef struct __RPASS_ENTRY rpass_entry;
typedef struct __RPASS_PARENT rpass_parent;

enum {
    REGEX = 1,
    CASE_INSENSITIVE = 2,
    ALL_ACCOUNTS = 4
};

#ifdef RPASS_SUPPORT
int getRpassAccounts(const char * const acname, rpass_parent **parent,
                     const char * const filename, const int flags,
                     const char * const fields);
void searchStringForRpassParents(rpass_parent **parent, const char * const acname,
                                 const void * const fdata, const size_t fdata_size,
                                 const int flags);
void allocateRpassParent(rpass_parent **parent);
void allocateRpassEntry(rpass_entry **entry);
void freeRpassParent(rpass_parent *parent);
void freeRpassParents(rpass_parent *parent);
void freeRpassEntries(rpass_entry *entry);
#endif

gcry_error_t encryptDataToFile(const void *data, size_t data_size, const char * const filename);
gcry_error_t encryptFile(const char * const in_filename, const char * out_filename);
gcry_error_t decryptFile(const char * const filename, void **data, size_t *data_size);

void *attemptSecureAlloc(size_t N);

void forgetCipher();

void isDaemon();

#endif
