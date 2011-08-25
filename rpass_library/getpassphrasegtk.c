#include "rpass.h"
#include <gtk/gtk.h>
#include <string.h>

static char *tmp = NULL;
static GtkWidget *window;

static void get_passphrase(GtkWidget *widget, gpointer data);
static void cancel_passphrase(GtkWidget *widget, gpointer data);
static gboolean delete_event(GtkWidget *widget, GdkEvent *event, gpointer data);
static void destroy(GtkWidget *widget, gpointer data);

static void get_passphrase(GtkWidget *widget, gpointer data) {
    int buffer_size = gtk_entry_get_text_length(GTK_ENTRY(data));
    tmp = (char *)attemptSecureAlloc(buffer_size + 1);
    memcpy(tmp, gtk_entry_get_text(GTK_ENTRY(data)), buffer_size);
    *(tmp + buffer_size) = '\0';
    destroy(widget, NULL);
}

static void cancel_passphrase(GtkWidget *widget, gpointer data) {
    tmp = NULL;
    destroy(widget, NULL);
}

static gboolean delete_event(GtkWidget *widget, GdkEvent *event, gpointer data) {
    return TRUE;
}

static void destroy(GtkWidget *widget, gpointer data) {
    gtk_widget_destroy(window);
    gtk_main_quit();
}

char *getPassphraseGTK() {
    GtkWidget
        *buttonOK,
        *buttonCancel,
        *passphraseEntry,
        *passphraseLabel,
        *buttonBox,
        *mainBox;

    if (gtk_init_check(NULL, NULL) == FALSE)
        return NULL;

    // Set up window
    window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_resizable(GTK_WINDOW(window), FALSE);
    gtk_window_set_modal(GTK_WINDOW(window), TRUE);
    gtk_window_set_keep_above(GTK_WINDOW(window), TRUE);
    gtk_window_set_decorated(GTK_WINDOW(window), FALSE);
    gtk_window_set_deletable(GTK_WINDOW(window), FALSE);
    gtk_window_set_position(GTK_WINDOW(window), GTK_WIN_POS_CENTER_ALWAYS);
    gtk_window_stick(GTK_WINDOW(window));
    gtk_window_set_focus_on_map(GTK_WINDOW(window), TRUE);

    gtk_container_set_border_width(GTK_CONTAINER(window), 10);

    gtk_signal_connect(GTK_OBJECT(window), "delete-event", G_CALLBACK(delete_event), NULL);
    gtk_signal_connect(GTK_OBJECT(window), "destroy", G_CALLBACK(destroy), NULL);

    // Set up label
    passphraseLabel = gtk_label_new("Enter passphrase:");

    // Set up text entry
    passphraseEntry = gtk_entry_new();
    gtk_entry_set_visibility(GTK_ENTRY(passphraseEntry), FALSE);
    gtk_signal_connect(GTK_OBJECT(passphraseEntry), "activate", G_CALLBACK(get_passphrase), (gpointer) passphraseEntry);

    // Set up OK button
    buttonOK = gtk_button_new_with_mnemonic("_OK");
    gtk_signal_connect(GTK_OBJECT(buttonOK), "clicked", G_CALLBACK(get_passphrase), (gpointer) passphraseEntry);

    // Set up Cancel button
    buttonCancel = gtk_button_new_with_mnemonic("_Cancel");
    gtk_signal_connect(GTK_OBJECT(buttonCancel), "clicked", G_CALLBACK(cancel_passphrase), NULL);

    // Set up main box
    mainBox = gtk_vbox_new(FALSE, 7);
    gtk_container_add(GTK_CONTAINER(window), mainBox);
    gtk_widget_show(mainBox);

    // Show label
    gtk_box_pack_start(GTK_BOX(mainBox), passphraseLabel, TRUE, TRUE, 0);
    gtk_widget_show(passphraseLabel);

    // Show text entry
    gtk_box_pack_start(GTK_BOX(mainBox), passphraseEntry, TRUE, TRUE, 0);
    gtk_widget_show(passphraseEntry);

    // Set up button box
    buttonBox = gtk_hbox_new(FALSE, 7);
    gtk_box_pack_end(GTK_BOX(mainBox), buttonBox, TRUE, TRUE, 0);
    gtk_widget_show(buttonBox);

    // Add buttons to the button box
    gtk_box_pack_end(GTK_BOX(buttonBox), buttonCancel, TRUE, FALSE, 0);
    gtk_box_pack_end(GTK_BOX(buttonBox), buttonOK, TRUE, FALSE, 0);

    gtk_widget_show(buttonOK);
    gtk_widget_show(buttonCancel);

    gtk_widget_show(window);

    gtk_main();

    return tmp;
}
