#include "getpassphrasencurses.h"
#include "rpass.h"
#include <ncurses.h>
#include <stdlib.h>

#define PASSPHRASE_SIZE_INCS 121

char * getPassphraseNcurses() {
    size_t size = PASSPHRASE_SIZE_INCS;
    char *ph = attemptSecureAlloc(size), *tmp;
    int written = 0, x, y;
    int ch;

    initscr();
    raw(); // Turn off buffering
    noecho(); // Turn off echoing
    keypad(stdscr, TRUE);
    clear();

    mvprintw(0, 0, "Enter decryption key: ");
    move(1, 0);
    curs_set(2);
    refresh();
    while (ch = getch()) {
        if (written >= PASSPHRASE_SIZE_INCS) {
            tmp = gcry_realloc(ph, size + PASSPHRASE_SIZE_INCS);
            if (tmp != NULL) {
                ph = tmp; written = 0;
            }
            else {
                getyx(stdscr, y, x);
                mvprintw(y + 1, 0, "Not enough memory for a longer passphrase.");
                move(y, x);
                refresh();
            }
        }

        if ((ch == KEY_BACKSPACE) || (ch == KEY_DC)) {
            if (written > 0) {
                --written;
                getyx(stdscr, y, x);
                move(y, x - 1);
                delch();
                refresh();
            }
            continue;
        }

        if (ch == '\n') {
            ph[written++] = '\0';
            break;
        }
        else {
            ph[written++] = ch;
            addch('*' | A_BOLD); refresh();
        }
    }
    clear();
    endwin();

    return ph;
}
