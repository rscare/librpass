#ifndef RPASS_H
#define RPASS_H

#include <stdio.h>
#include <gpgme.h>

#define PROTOCOL GPGME_PROTOCOL_OpenPGP
#define PREF_ALGO GPGME_PK_RSA
#define PREF_HASH GPGME_MD_SHA256
#define BUF_LEN 20

void rpass_error(const char const *err_msg);

int initialize_engine();

int decrypt_object(gpgme_data_t ctext, gpgme_data_t ptext);
int encrypt_object(gpgme_data_t ptext, gpgme_data_t ctext);

int create_gpg_data(gpgme_data_t *data, FILE *fp, char *str, int len, int COPY);

void print_gpgme_data(gpgme_data_t data);

#endif
