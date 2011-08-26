#ifndef RPASS_H
#define RPASS_H

#include "rpass_sys_config.h"

#ifdef RPASS_SUPPORT
#include "password_functions.h"
#endif

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
#define RPASS_DAEMON_MSG_STOP "STOP"

#define RPASS_DAEMON_AC_START "RPASSDACSTART"

void constructDaemonString(void **msg, size_t * const msg_size,
                           size_t totsize, int nargs, ...);
void sendToDaemon(const void * const msg, const size_t msg_size,
                         void **output, size_t *output_size);

gcry_error_t encryptDataToFile(const void *data, size_t data_size, const char * const filename);
gcry_error_t encryptFile(const char * const in_filename, const char * out_filename);
gcry_error_t decryptFileToData(const char * const filename, void **data, size_t *data_size);

void *attemptSecureAlloc(size_t N);

void forgetCipher();

void isDaemon();
int amDaemon();

#endif
