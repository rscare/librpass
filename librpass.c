#include "rpass.h"
#include <gcrypt.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ncurses.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#ifdef USE_GTK2
#include "getpassphrasegtk.h"
#endif

#ifdef USE_NCURSES
#include "getpassphrasencurses.h"
#endif

static gcry_error_t initializeEncryptionEngine();
static gcry_error_t setupCipher();
static gcry_error_t getKey();
static gcry_error_t createKey(const char *passphrase);
static int engineInitialized();
static void report_gpg_error(gpg_error_t err);
static void report_gcry_error(gcry_error_t err);
static size_t getFileHandleSize(FILE *fh);

static gcry_cipher_hd_t HD;

static size_t keylen, blklen;
static void *keybuffer = NULL;

static int haskey = 0, hascipher = 0;

static gpg_error_t gpg_err;
static gcry_error_t gcry_err;

void * attemptSecureAlloc(size_t N) {
    initializeEncryptionEngine();
    void *ptr = gcry_malloc_secure(N);
    if (ptr == NULL) {
        ptr = gcry_malloc(N);
    }
    return ptr;
}

static size_t getFileHandleSize(FILE *fh) {
    size_t retval;
    fseek(fh, 0L, SEEK_END);
    retval = ftell(fh);
    fseek(fh, 0L, SEEK_SET);
    return retval;
}

static void report_gpg_error(gpg_error_t err) {
    fprintf(stderr, "Error in %s: %s.\n", gpg_strsource(err), gpg_strerror(err));
}

static void report_gcry_error(gcry_error_t err) {
    fprintf(stderr, "Error in %s: %s.\n", gcry_strsource(err), gcry_strerror(err));
}

static gcry_error_t getKey() {
    char *passphrase = NULL;
    if (getenv("DISPLAY")) {
#ifdef USE_GTK2
        passphrase = getPassphraseGTK();
#endif
    }

    if (passphrase == NULL) {
#ifdef USE_NCURSES
        passphrase = getPassphraseNcurses();
#endif
    }

    gcry_err = createKey(passphrase);
    gcry_free(passphrase);
    return gcry_err;
}

gcry_error_t encryptFile(const char * const in_filename, const char * out_filename) {
    void *data;
    size_t data_size;
    gcry_error_t err;
    void *msg;

    if (out_filename == NULL)
        out_filename = in_filename;

    FILE * fh = fopen(in_filename, "rb");

    data_size = getFileHandleSize(fh) + 1;
    data = attemptSecureAlloc(data_size);
    fread(data, sizeof(char), data_size - 1, fh);
    fclose(fh);

    err = encryptDataToFile(data, data_size, out_filename);

    gcry_free(data);

    return err;
}

gcry_error_t encryptDataToFile(const void * data, size_t data_size, const char * const filename) {
    void *IV, *ndata, *edata;
    size_t remain, nsize;
    FILE *fh;
    void *msg, *tmp;

    if ((gcry_err = initializeEncryptionEngine()) != GPG_ERR_NO_ERROR) {
        report_gcry_error(gcry_err);
        return gcry_err;
    }

    if (!haskey) {
        if ((gcry_err = getKey()) != GPG_ERR_NO_ERROR) {
            report_gcry_error(gcry_err);
            return gcry_err;
        }
    }

    // Set up data to be a multiple of block length
    if (data_size < blklen) {
        nsize = data_size + (blklen - data_size);
    }
    else if ((remain = data_size % blklen) != 0) {
        nsize = data_size + blklen - remain;
    }
    else
        nsize = data_size + 1;
    if ((ndata = attemptSecureAlloc(nsize)) == NULL) {
        return GPG_ERR_GENERAL;
    }

    memcpy(ndata, data, data_size);
    memset(ndata + data_size, (char)(nsize - data_size), nsize - data_size);

    IV = gcry_random_bytes_secure(blklen, GCRY_STRONG_RANDOM);

    if ((gcry_err = gcry_cipher_setiv(HD, IV, blklen)) != GPG_ERR_NO_ERROR) {
        gcry_free(ndata);
        gcry_free(IV);
        gcry_cipher_reset(HD);

        report_gcry_error(gcry_err);
        return gcry_err;
    }
    if ((gcry_err = gcry_cipher_encrypt(HD, ndata, nsize, NULL, 0)) != GPG_ERR_NO_ERROR) {
        gcry_free(ndata);
        gcry_free(IV);
        gcry_cipher_reset(HD);

        report_gcry_error(gcry_err);
        return gcry_err;
    }

    fh = fopen(filename, "wb");
    fwrite(IV, sizeof(char), blklen, fh);
    fwrite(ndata, sizeof(char), nsize, fh);
    fclose(fh);

    gcry_free(ndata);
    gcry_free(IV);
    gcry_cipher_reset(HD);

    return GPG_ERR_NO_ERROR;
}

gcry_error_t decryptFileToData(const char * const filename, void **pdata, size_t *pdata_size) {
    FILE *fh;
    void *IV;
    long fsize;
    size_t data_size;
    char extra_data;
    void *msg;

    if ((gcry_err = initializeEncryptionEngine()) != GPG_ERR_NO_ERROR) {
        report_gcry_error(gcry_err);
        return gcry_err;
    }

    if (!haskey) {
        if ((gcry_err = getKey()) != GPG_ERR_NO_ERROR) {
            report_gcry_error(gcry_err);
            return gcry_err;
        }
    }

    if ((IV = attemptSecureAlloc(blklen)) == NULL) {
        return GPG_ERR_NO_ERROR;
    }


    fh = fopen(filename, "rb");

    fsize = getFileHandleSize(fh);

    if (fsize < blklen) {
        *pdata = NULL;
        *pdata_size = 0;
        return GPG_ERR_NO_ERROR;
    }

    data_size = fsize - blklen;
    if ((*pdata = attemptSecureAlloc(data_size)) == NULL) {
        gcry_free(IV);

        return GPG_ERR_NO_ERROR;
    }

    fread(IV, sizeof(char), blklen, fh);
    fread(*pdata, sizeof(char), data_size, fh);
    fclose(fh);

    if ((gcry_err = gcry_cipher_setiv(HD, IV, blklen)) != GPG_ERR_NO_ERROR) {
        gcry_free(IV);
        gcry_free(*pdata);
        *pdata = NULL;

        report_gcry_error(gcry_err);
        return gcry_err;
    }
    if ((gcry_err = gcry_cipher_decrypt(HD, *pdata, data_size, NULL, 0)) != GPG_ERR_NO_ERROR) {
        gcry_free(IV);
        gcry_free(*pdata);
        *pdata = NULL;

        report_gcry_error(gcry_err);
        return gcry_err;
    }

    gcry_free(IV);
    gcry_cipher_reset(HD);

    extra_data = ((char *)*pdata)[data_size - 1];
    *pdata_size = data_size - (size_t)extra_data;

    return GPG_ERR_NO_ERROR;
}

gcry_error_t createKey(const char *passphrase) {
    if (keybuffer != NULL)
        gcry_free(keybuffer);
    keybuffer = attemptSecureAlloc(keylen);

    gcry_kdf_derive((void *)passphrase, strlen(passphrase),
                    GCRYPT_KDF_ALGO, GCRYPT_KDF_SUBALGO,
                    (void *)GCRYPT_KDF_SALT, GCRYPT_KDF_SALTLEN, GCRYPT_KDF_ITERATIONS,
                    keylen, keybuffer);

    gcry_cipher_setkey(HD, keybuffer, keylen);
    haskey = 1;

    return GPG_ERR_NO_ERROR;
}

gcry_error_t initializeEncryptionEngine() {
    if (!engineInitialized()) {
        gcry_control(GCRYCTL_ENABLE_M_GUARD); // Enable built-in memory guard
        if (!gcry_check_version(GCRYPT_PREF_VERSION)) {
            fputs("Libgcrypt version too low.\n", stderr);
            return GPG_ERR_GENERAL;
        }
        gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);
        // Allocate secure memory
        if ((gcry_err = gcry_control(GCRYCTL_INIT_SECMEM, GCRYPT_SECMEM_SIZE, 0)) != GPG_ERR_NO_ERROR) {
            report_gcry_error(gcry_err);
            return gcry_err;
        }
        gcry_control(GCRYCTL_RESUME_SECMEM_WARN);
        gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
    }
    return setupCipher();
}

static gcry_error_t setupCipher() {
    if (hascipher)
        return GPG_ERR_NO_ERROR;

    if ((gcry_err = gcry_cipher_open(&HD,
                                     GCRYPT_PREFERRED_ALGO,
                                     GCRYPT_CIPHER_MODE,
                                     GCRY_CIPHER_SECURE)) != GPG_ERR_NO_ERROR) {
        report_gcry_error(gcry_err);
        return gcry_err;
    }
    gcry_cipher_algo_info(GCRYPT_PREFERRED_ALGO, GCRYCTL_GET_KEYLEN, 0, &keylen);
    gcry_cipher_algo_info(GCRYPT_PREFERRED_ALGO, GCRYCTL_GET_BLKLEN, 0, &blklen);
    hascipher = 1;

    return GPG_ERR_NO_ERROR;
}

static int engineInitialized() {
    return gcry_control(GCRYCTL_INITIALIZATION_FINISHED_P);
}

void forgetCipher() {
    if (hascipher)
        gcry_cipher_close(HD);
    haskey = 0;
    hascipher = 0;
}

gcry_error_t changePassphrase(const char * const filename) {
    void *data; size_t data_size;

    decryptFileToData(filename, &data, &data_size);
    forgetCipher();
    encryptDataToFile(data, data_size, filename);

    gcry_free(data);

    return GPG_ERR_NO_ERROR;
}
