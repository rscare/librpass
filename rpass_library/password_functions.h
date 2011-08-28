#ifndef PASSWORD_FUNCTIONS_H
#define PASSWORD_FUNCTIONS_H

#include "rpass_sys_config.h"
#include "rpass.h"
#include <stdlib.h>

#define RPASS_DAEMON_MSG_GETACCOUNTS "GETACCOUNTS"
#define RPASS_DAEMON_MSG_ADDACCOUNT "ADDACCOUNT"

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

int getRpassAccounts(const char * const acname, rpass_parent **parent,
                     const char * const filename, const int flags,
                     const char * const fields);
void searchStringForRpassParents(rpass_parent **parent, const char * const acname,
                                 const void * const fdata, const size_t fdata_size,
                                 const int flags);
void createRpassParentFromString(rpass_parent **parent, const char * acstr);
void addRpassParent(rpass_parent * const parent, const char * const filename);
void createStringFromRpassParents(const rpass_parent * const parent, char **string);
void createStringFromRpassParent(const rpass_parent * const parent, char **string);

void allocateRpassParent(rpass_parent **parent);
void allocateRpassEntry(rpass_entry **entry);
void freeRpassParent(rpass_parent *parent);
void freeRpassParents(rpass_parent *parent);
void freeRpassEntries(rpass_entry *entry);

#endif
