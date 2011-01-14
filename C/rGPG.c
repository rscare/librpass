#include <stdio.h>
#include <stdlib.h>
#include <gpgme.h>
#include <string.h>
#include <errno.h>
#include <ncurses.h>
#include <curses.h>
#include <ctype.h>
#include <sys/stat.h>

#include "rGPG.h"
#include "passphrase_dialog.h"

#define RGPG_PROTOCOL GPGME_PROTOCOL_OpenPGP
#define RGPG_PREF_ALGO GPGME_PK_RSA
#define RGPG_PREF_HASH GPGME_MD_SHA256
#define RGPG_OUTPUT_BUF_LEN 100
#define RGPG_PROCPATH "/proc/"

#define PID_BUF

static gpgme_ctx_t ctx = NULL;

static gpgme_error_t default_passphrase_cb_gtk2(void *HOOK, const char *UID_HINT, const char *PASSPHRASE_INFO, int PREV_WAS_BAD, int FD) {
    char *pass = NULL;
    int written = 0;
    int pass_len = 0;
    int off = 0;

    gpg_passphrase_cb_dialog(&pass);

    if (pass && ((pass_len = strlen(pass)) > 0)) {
        do {
            written = write(FD, &pass[off], pass_len - off);
            off += written;
        } while ((written > 0) && off < pass_len);

        free(pass);

        if (off != written)
            return gpgme_error_from_errno(errno);
    }

    if (!write(FD, "\n", 1))
        return gpgme_error_from_errno(errno);

    return 0;
}

static gpgme_error_t default_passphrase_cb(void *HOOK, const char *UID_HINT, const char *PASSPHRASE_INFO, int PREV_WAS_BAD, int FD) {
    int ch;
    char pass[RGPG_OUTPUT_BUF_LEN];
    int written = 0;
    int off = 0;
    int res = 0;
    int y,x = 0;

    initscr();
    raw(); // Turn off buffering
    noecho(); // Turn off echoing
    clear();

    mvprintw(0, 0, "Passphrase for %s: ", UID_HINT); refresh();
    move(1, 0);
    curs_set(2);
    while (ch = getch()) {
        if (ch == '') {
            if (written > 0)
                --written;
                getyx(stdscr, y, x);
                mvaddch(y, x-1,' ');
                move(y, x-1);
                refresh();
            continue;
        }

        pass[written++] = ch;
        if ((ch == '\n') || (written >= RGPG_OUTPUT_BUF_LEN)) {
            // Writing stuff in pass to file
            do {
                res = write(FD, &pass[off], written - off);
                off += res;
            } while ((res > 0) && (off != written));

            if (off != written)
                return gpgme_error_from_errno(errno);

            if (ch == '\n')
                break;
            else
                res = off = written = 0;
        }
        addch('*'); refresh();
    }
    clear();
    endwin();

    if (ch == '\n')
        return 0;
    else
        return gpgme_error_from_errno(errno);
}

static int rGPG_agent_is_running() {
    char *agent_info = getenv("GPG_AGENT_INFO");
    char *begin_pid,*end_pid,*agent_pid;
    char *proc_path;
    struct stat info;

    if (!agent_info)
        return 0;

    begin_pid = strchr(agent_info, ':');
    if (!begin_pid)
        return 0;

    begin_pid++;

    end_pid = strchr(begin_pid, ':');

    if (!end_pid || (end_pid == begin_pid))
        return 0;

    agent_pid = malloc(end_pid - begin_pid + 1);
    strncpy(agent_pid, begin_pid, end_pid - begin_pid);

    proc_path = malloc(strlen(RGPG_PROCPATH) + strlen(agent_pid) + 1);
    memcpy(proc_path, RGPG_PROCPATH, strlen(RGPG_PROCPATH));
    strncpy(proc_path + strlen(RGPG_PROCPATH), agent_pid, strlen(agent_pid));

    free(agent_pid);

    if (stat(proc_path, &info)) {
        free(proc_path);
        return 0;
    }

    free(proc_path);

    if (S_ISDIR(info.st_mode))
        return 1;
    else
        return 0;
}

void rGPG_errlog(const char const *err_msg) {
    fprintf(stderr, err_msg);
}

int create_gpg_data(gpgme_data_t *data, FILE *fp, char *str, int len, int COPY) {
    if (fp != NULL) { // Create file-based data
        switch (gpgme_data_new_from_stream(data, fp)) {
            case GPG_ERR_NO_ERROR:
                return 1;
                break;
            default:
                rGPG_errlog("Failed to create data stream from file.");
                return 0;
                break;
        }
    }

    if (str != NULL) { // Create data-based data
        switch(gpgme_data_new_from_mem(data, str, len, COPY)) {
            case GPG_ERR_NO_ERROR:
                return 1;
                break;
            default:
                rGPG_errlog("Failed to create data stream from memory.");
                return 0;
                break;
        }
    }

    switch (gpgme_data_new(data)) { // Create generic data
        case GPG_ERR_NO_ERROR:
            return 1;
            break;
        default:
            rGPG_errlog("Failed to create data stream.");
            return 0;
            break;
    }
}

void destroy_gpg_data(gpgme_data_t data) {
    size_t len = 0;
    void *buf_ptr = NULL;
    buf_ptr = gpgme_data_release_and_get_mem(data, &len);
    if (buf_ptr != NULL)
        gpgme_free(buf_ptr);
}

int decrypt_object(gpgme_data_t cipher_text, gpgme_data_t plain_text) {
    switch (gpgme_op_decrypt(ctx, cipher_text, plain_text)) {
        case GPG_ERR_NO_ERROR:
            return 1;
            break;
        case GPG_ERR_INV_VALUE:
            rGPG_errlog("Invalid pointer.");
            return 0;
            break;
        case GPG_ERR_NO_DATA:
            rGPG_errlog("No data.");
            return 0;
            break;
        case GPG_ERR_DECRYPT_FAILED:
            rGPG_errlog("Invalid data.");
            return 0;
            break;
        case GPG_ERR_BAD_PASSPHRASE:
            rGPG_errlog("Bad passphrase.");
            return 0;
            break;
        default:
            rGPG_errlog("Unknown error.");
            return 0;
            break;
    }
}

int encrypt_object(gpgme_data_t plain_text, gpgme_data_t cipher_text) {
    gpgme_key_t keys[] = {NULL, NULL};
    gpgme_op_keylist_start(ctx, NULL, 0);
    gpgme_op_keylist_next(ctx, &keys[0]);
 
    // Encryption method
    switch (gpgme_op_encrypt(ctx, keys, 0, plain_text, cipher_text)) {
        case GPG_ERR_NO_ERROR:
            break;
        case GPG_ERR_UNUSABLE_PUBKEY:
            rGPG_errlog("Unusable public key.\n");
            gpgme_key_release(keys[0]);
            return 0;
            break;
        case GPG_ERR_INV_VALUE:
            rGPG_errlog("Invalid pointer.\n");
            gpgme_key_release(keys[0]);
            return 0;
            break;
        default:
            rGPG_errlog("Unkown error.\n");
            gpgme_key_release(keys[0]);
            return 0;
            break;
    }

    // Release the key object
    gpgme_key_release(keys[0]);
    return 1;
}

void print_gpgme_data(gpgme_data_t data) {
    ssize_t size_read = 0;
    char tmp_string[RGPG_OUTPUT_BUF_LEN + 1];

    gpgme_data_seek(data, 0, SEEK_SET);
    while(size_read = gpgme_data_read(data, tmp_string, RGPG_OUTPUT_BUF_LEN)) {
        tmp_string[size_read] = '\0';
        printf("%s", tmp_string);
    }
    putchar('\n');
    gpgme_data_seek(data, 0, SEEK_SET);
}

int initialize_engine(int ARMOR, gpgme_error_t (*passphrase_cb)(void *, const char *, const char *, int, int)) {
    if ((passphrase_cb == NULL) && !rGPG_agent_is_running()) {
        if (getenv("DISPLAY"))
            passphrase_cb = &default_passphrase_cb_gtk2;
        else
            passphrase_cb = &default_passphrase_cb;
    }

    if (ctx != NULL) {
        gpgme_set_armor(ctx, ARMOR);
        if (passphrase_cb != NULL)
            gpgme_set_passphrase_cb(ctx, passphrase_cb, NULL);
        return 1;
    }

    // Verify protocol
    if (gpgme_engine_check_version(RGPG_PROTOCOL) != GPG_ERR_NO_ERROR) {
        rGPG_errlog("Bad protocol.\n");
        return 0;
    }

    // Verify engine
    if (gpgme_check_version(NULL) == NULL) {
        rGPG_errlog("No gpgme version available.\n");
        return 0;
    }

    // Create context
    switch (gpgme_new(&ctx)) {
        case GPG_ERR_NO_ERROR:
            break;
        case GPG_ERR_INV_VALUE:
            rGPG_errlog("Context is not a valid pointer.\n");
            return 0;
            break;
        case GPG_ERR_ENOMEM:
            rGPG_errlog("Context could not allocate memory.\n");
            return 0;
            break;
        case GPG_ERR_NOT_OPERATIONAL:
            rGPG_errlog("GPGME not initialized.\n");
            return 0;
            break;
        default:
            rGPG_errlog("Unknown error.\n");
            return 0;
            break;
    }

    // Set the context's protocol
    if (gpgme_set_protocol(ctx, RGPG_PROTOCOL) != GPG_ERR_NO_ERROR) {
        rGPG_errlog("Could not set context protocol.\n");
        destroy_engine();
        return 0;
    }

    // Set armor
    gpgme_set_armor(ctx, ARMOR);

    // Set passphrase callback
    if (passphrase_cb != NULL)
        gpgme_set_passphrase_cb(ctx, passphrase_cb, NULL);

    return 1;
}

void destroy_engine() {
    gpgme_release(ctx);
    ctx = NULL;
}

char * gpg_object_to_string(gpgme_data_t data) {
    char *str = NULL;
    size_t cur_size = 0;
    char *ptmp = NULL;

    ssize_t read = 0;
    char tmp_buf[RGPG_OUTPUT_BUF_LEN];

    gpgme_data_seek(data, 0, SEEK_SET);

    while (read = gpgme_data_read(data, tmp_buf, RGPG_OUTPUT_BUF_LEN)) {
        if (str == NULL) {
            cur_size += read + 1;
            str = malloc(cur_size);
            ptmp = str;
        }
        else {
            str = realloc(str, cur_size + read);
            ptmp = str + cur_size - 1;
            cur_size += read;
        }
        memcpy(ptmp, tmp_buf, read);
        ptmp += read;
        *(ptmp) = '\0';
    }

    return str;
}
