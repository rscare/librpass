#include "rpass.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TESTSTRING "[Test Account 1]\nuser = test_user_1\npass = test_pass_1\n"

#define INFILE "infile"
#define OUTFILE "outfile"

int main(int argc, char *argv[])
{
    void *data;
    size_t data_size;
    rpass_parent *parent;

    encryptDataToFile(TESTSTRING, strlen(TESTSTRING) + 1, OUTFILE);
    decryptFileToData(OUTFILE, &data, &data_size);
    puts(data);
    gcry_free(data);
    getRpassAccounts("test", &parent, OUTFILE, REGEX|CASE_INSENSITIVE, "pass");
    puts(parent->acname);
    puts(parent->first_entry->key);
    puts(parent->first_entry->value);
    freeRpassParents(parent);
    return 0;
}
