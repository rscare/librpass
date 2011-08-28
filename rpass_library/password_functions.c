#include "rpass_sys_config.h"
#include "rpass.h"
#include "password_functions.h"

#include <gcrypt.h>
#include <regex.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static int regexMatcher(const char * const regex, const char * const string, const int flags);
static size_t calculateRparentStringSize(const rpass_parent * const parent);

int getRpassAccounts(const char * const acname, rpass_parent **parent,
                     const char * const filename, const int flags,
                     const char * const fields) {
    char *fdata; size_t fdata_size = 0, tmp, fields_size, acname_size, msg_size;
    void *msg;

    if (!amDaemon()) {
        tmp = strlen(RPASS_DAEMON_MSG_GETACCOUNTS)
            + strlen(filename)
            + 2 * strlen(RPASS_DAEMON_AC_START)
            + sizeof(int);

        if (fields == NULL)
            fields_size = 0;
        else
            fields_size = strlen(fields);

        if (acname == NULL)
            acname_size = 0;
        else
            acname_size = strlen(acname);

        tmp += fields_size + acname_size;
        constructDaemonString(&msg, &msg_size, tmp,
                              7,
                              RPASS_DAEMON_MSG_GETACCOUNTS, strlen(RPASS_DAEMON_MSG_GETACCOUNTS),
                              filename, strlen(filename),
                              RPASS_DAEMON_AC_START, strlen(RPASS_DAEMON_AC_START),
                              acname, acname_size,
                              RPASS_DAEMON_AC_START, strlen(RPASS_DAEMON_AC_START),
                              &flags, sizeof(int),
                              fields, fields_size);
        sendToDaemon(msg, msg_size, (void **)&fdata, &fdata_size);
        free(msg);
        searchStringForRpassParents(parent, NULL, fdata, fdata_size, ALL_ACCOUNTS);
        gcry_free(fdata);
        return 0;
    }

    decryptFileToData(filename, (void **)&fdata, &fdata_size);
    searchStringForRpassParents(parent, acname, fdata, fdata_size, flags);
    gcry_free(fdata);

    return 0;
}

void searchStringForRpassParents(rpass_parent **parent, const char * const acname, const void * const fdata, const size_t fdata_size, const int flags) {
    const char *dend, *cur, *acstart, *acend;
    char *acname_copy;
    char *acstr;

    rpass_parent *cur_parent = NULL, *tmp_parent;

    int matches;

    dend = fdata + fdata_size;
    *parent = NULL;
    for (cur = fdata; cur < dend; ++cur) {
        // If we notice the start of an account
        if ((*cur == '[') && ((cur == fdata) || (*(cur - 1) == '\n'))) {
            // Put the account name into acname_copy
            acend = cur + 1;
            while ((acend < dend) && (*acend != ']'))
                ++acend;

            if (*acend != ']')
                continue;

            acname_copy = malloc(acend - cur);
            memcpy(acname_copy, cur + 1, acend - (cur + 1));
            acname_copy[acend - (cur + 1)] = '\0';

            if (flags & ALL_ACCOUNTS) {
                matches = 1;
            }
            else {
                matches = (flags & REGEX) ?
                    regexMatcher(acname, acname_copy, flags) :
                    !strcmp(acname, acname_copy);
            }

            free(acname_copy);

            acstart = cur;
            cur = acend;
            while ((cur < dend) && ((*(cur + 1) != '[') || (*cur != '\n')))
                ++cur;

            if (matches) {
                acstr = attemptSecureAlloc(cur - acstart + 1);
                memcpy(acstr, acstart, cur - acstart);
                acstr[cur - acstart] = '\0';

                if (*parent == NULL) {
                    createRpassParentFromString(parent, acstr);
                    cur_parent = *parent;
                }
                else {
                    if (cur_parent == NULL)
                        cur_parent = *parent;
                    tmp_parent = NULL;
                    createRpassParentFromString(&tmp_parent, acstr);
                    cur_parent->next_parent = tmp_parent;
                    cur_parent = cur_parent->next_parent;
                }
                gcry_free(acstr);
            }
        }
    }
}

static void createRpassParentFromString(rpass_parent **parent, const char * const acstr) {
    const char *acstart, *acend, *cur, *tmp;
    rpass_entry *entry = NULL, *entry_ptr;

    allocateRpassParent(parent);

    // Finding the account name
    acstart = strchr(acstr, '[') + 1; acend = strchr(acstart, ']');
    (*parent)->acname = attemptSecureAlloc(acend - acstart + 1);
    memcpy((*parent)->acname, acstart, (acend - acstart));
    (*parent)->acname[acend - acstart] = '\0';

    // Set up actual acstart/acend
    acstart = acend;
    acend = (acstr + strlen(acstr));
    while ((++acstart < acend) && (*acstart != '\n'))
        ;

    if ((++acstart) == acend) {
        freeRpassParent(*parent);
        return;
    }

    for (cur = acstart; cur < acend; ++cur) {
        while ((cur < acend) && isspace(*cur))
            ++cur;
        tmp = cur;
        while ((++tmp < acend) && !isspace(*tmp) && (*tmp != '='))
            ;

        if (tmp > cur) {
            allocateRpassEntry(&entry);
            if ((*parent)->first_entry == NULL)
                (*parent)->first_entry = entry;
            else
                entry_ptr->next_entry = entry;

            entry_ptr = entry;

            entry->key = attemptSecureAlloc((tmp - cur) + 1);
            memcpy(entry->key, cur, tmp - cur);
            entry->key[(tmp - cur)] = '\0';

            cur = tmp;
            while ((++cur < acend) && (*cur == '=') || (isspace(*cur)))
                ;
            tmp = cur;
            while ((++tmp < acend) && (*tmp != '\n'))
                ;

            entry->value = attemptSecureAlloc((tmp - cur) + 1);
            memcpy(entry->value, cur, tmp - cur);
            entry->value[(tmp - cur)] = '\0';

            cur = tmp;
            while ((cur < acend) && (*cur != '\n'))
                ++cur;

            entry = NULL;
        }
    }
}

void allocateRpassParent(rpass_parent **parent) {
    if (*parent != NULL)
        return;

    *parent = attemptSecureAlloc(sizeof(rpass_parent));
    (*parent)->acname = NULL;
    (*parent)->next_parent = NULL;
    (*parent)->first_entry = NULL;
}

void allocateRpassEntry(rpass_entry **entry) {
    if (*entry)
        return;

    *entry = attemptSecureAlloc(sizeof(rpass_entry));
    (*entry)->key = NULL;
    (*entry)->value = NULL;
    (*entry)->next_entry = NULL;
}

void freeRpassParent(rpass_parent *parent) {
    if (parent->first_entry)
        freeRpassEntries(parent->first_entry);
    gcry_free(parent->acname);
    gcry_free(parent);
    parent = NULL;
}

void freeRpassParents(rpass_parent *parent) {
    if (parent->next_parent)
        freeRpassParents(parent->next_parent);
    freeRpassParent(parent);
}

void freeRpassEntries(rpass_entry *entry) {
    if (entry->next_entry)
        freeRpassEntries(entry->next_entry);
    gcry_free(entry->key);
    gcry_free(entry->value);
    gcry_free(entry);
    entry = NULL;
}

static int regexMatcher(const char * const regex, const char * const string, const int flags) {
    regex_t patt;
    int regex_flags = REG_EXTENDED|REG_NEWLINE|REG_NOSUB, err;
    if (flags & CASE_INSENSITIVE)
        regex_flags |= REG_ICASE;
    if ((err = regcomp(&patt, regex, regex_flags)) != 0) {
        fputs("Error in constructing regular expression.", stderr);
        return 0;
    }
    if ((err = regexec(&patt, string, 0, NULL, REG_NOTBOL|REG_NOTEOL)) == REG_ESPACE) {
        fputs("Error in executing regular expression.", stderr);
        regfree(&patt);
        return 0;
    }
    regfree(&patt);
    return !err;
}
