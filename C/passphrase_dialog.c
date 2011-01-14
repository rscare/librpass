#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gtk/gtk.h>

static char *tmp = NULL;

static void get_passphrase(GtkWidget *widget, gpointer data) {
    int buffer_size = gtk_entry_get_text_length(GTK_ENTRY(data));
    tmp = malloc(buffer_size + 1);
    memcpy(tmp, gtk_entry_get_text(GTK_ENTRY(data)), buffer_size);
    *(tmp + buffer_size) = '\0';
}

static gboolean delete_event(GtkWidget *widget, GdkEvent *event, gpointer data) {
    gtk_main_quit();
    return FALSE;
}

int gpg_passphrase_cb_dialog(char **pass) {
    GtkWidget *window;
    GtkWidget *button;
    GtkWidget *text_entry;
    GtkWidget *table;

    gtk_init(NULL, NULL);

    window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_resizable(GTK_WINDOW(window), FALSE);
    gtk_window_set_modal(GTK_WINDOW(window), TRUE);
    gtk_window_set_keep_above(GTK_WINDOW(window), TRUE);
    gtk_window_set_decorated(GTK_WINDOW(window), FALSE);
    gtk_window_set_deletable(GTK_WINDOW(window), FALSE);

    gtk_container_set_border_width(GTK_CONTAINER(window), 10);

    gtk_signal_connect(window, "delete-event", G_CALLBACK(delete_event), NULL);

    table = gtk_table_new(2, 2, TRUE);
    gtk_container_add(GTK_CONTAINER(window), table);

    text_entry = gtk_entry_new();
    g_signal_connect(text_entry, "activate", G_CALLBACK(get_passphrase), (gpointer)text_entry);
    g_signal_connect(text_entry, "activate", G_CALLBACK(delete_event), NULL);
    gtk_entry_set_visibility(GTK_ENTRY(text_entry), FALSE);
    gtk_table_attach(GTK_TABLE(table), text_entry, 0, 2, 0, 1, GTK_FILL, GTK_SHRINK, 3, 3);
    gtk_widget_show(text_entry);

    button = gtk_button_new_with_mnemonic("_Cancel");
    g_signal_connect(button, "clicked", G_CALLBACK(delete_event), NULL);
    gtk_table_attach(GTK_TABLE(table), button, 0, 1, 1, 2, GTK_FILL, GTK_SHRINK, 3, 3);
    gtk_widget_show(button);

    button = gtk_button_new_with_mnemonic("_OK");
    g_signal_connect(button, "clicked", G_CALLBACK(get_passphrase), (gpointer)text_entry);
    g_signal_connect(button, "clicked", G_CALLBACK(delete_event), NULL);
    gtk_table_attach(GTK_TABLE(table), button, 1, 2, 1, 2, GTK_FILL, GTK_SHRINK, 3, 3);
    gtk_widget_show(button);

    gtk_widget_show(table);
    gtk_widget_show(window);
    gtk_main();

    *pass = tmp;
    return 0;
}
