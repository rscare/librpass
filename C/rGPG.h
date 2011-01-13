#ifndef RGPG_H
#define RGPG_H

#include <stdio.h>
#include <gpgme.h>

void rGPG_errlog(const char const *err_msg);

int initialize_engine(int ARMOR, gpgme_error_t (*passphrase_cb)(void *, const char *, const char *, int, int));
void destroy_engine();

int decrypt_object(gpgme_data_t ctext, gpgme_data_t ptext);
int encrypt_object(gpgme_data_t ptext, gpgme_data_t ctext);

char * gpg_object_to_string(gpgme_data_t data);

int create_gpg_data(gpgme_data_t *data, FILE *fp, char *str, int len, int COPY);
void destroy_gpg_data(gpgme_data_t data);

void print_gpgme_data(gpgme_data_t data);

#endif
