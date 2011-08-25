extern "C" {
#include "rpass.h"
}
#include <unistd.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <iostream>
#include <sstream>
#include <map>
#include <vector>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cctype>
#include <gcrypt.h>

#define ALLOWED_CONNECTIONS 3

typedef void (*OPERATOR_FUNCTION)(const std::vector<std::string> &args, std::vector<char> &retval);

using namespace std;

void daemonize();
void close_std_fds();
void setupSocket();

string d_decryptFile(const vector<string> &filename);
string d_encryptFile(const vector<string> &filenames);
string d_getRpassAccounts(const vector<string> &options);

vector<string> splitArgs(const string &args);

string rparentsToString(const rpass_parent * const parent, const vector<string> &field);

void setupOperators(map<string, OPERATOR_FUNCTION> &o);

void daemonize () {
    pid_t pid;

    if (getppid() == 1)
        return;

    pid = fork();
    if (pid < 0)
        exit(1);
    if (pid > 0)
        exit(0);

    if (setsid() < 0)
        exit(1);

    if (chdir("/tmp") < 0)
        exit(1);

    close_std_fds();
}

void close_std_fds() {
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
}

string rparentsToString(const rpass_parent * const parent, const vector<string> &field) {
    const rpass_parent * cur = parent;
    const rpass_entry * rentry = NULL;
    string retval = "";
    while (cur) {
        retval.append("[");
        retval.append(parent->acname);
        retval.append("]");

        rentry = cur->first_entry;
        while (rentry) {
            if ((field.size() == 0) ||
                (find(field.begin(), field.end(), string(rentry->key)) != field.end())) {
                retval.append("\n");
                retval.append(rentry->key);
                retval.append(" = ");
                retval.append(rentry->value);
            }
            rentry = rentry->next_entry;
        }
        retval.append("\n");
        cur = cur->next_parent;
    }
    return retval;
}

vector<string> splitArgs(const string &args) {
    vector<string> parsed_args;
    stringstream ss(args);
    string item;
    while (getline(ss, item, ' ')) {
        parsed_args.push_back(item);
    }
    return parsed_args;
}

void d_encryptDataToFile(const vector<string> &args, vector<char> &retval) {
    string noerr = "NOERR";
    string err = "ERR";
    vector<string>::const_iterator i = args.begin();

    string filename = *i;
    string data = "";
    for (++i; i < args.end(); ++i) {
        data.append(i->data(), i->length()); data.append(" ");
    }
    data.erase(data.length() - 1);
    encryptDataToFile(data.data(), data.length(), filename.c_str());
    retval = vector<char>(noerr.begin(), noerr.end());
}

void d_decryptFile(const vector<string> &filename, vector<char> &retval) {
    char *data = NULL;
    size_t data_size;
    decryptFile(filename[0].c_str(), (void **)&data, &data_size);
    retval.resize(data_size);
    copy(data, data + data_size, retval.begin());
    gcry_free(data);
}

void d_encryptFile(const vector<string> &filenames, vector<char> &retval) {
    string noerr = "NOERR";
    string err = "ERR";

    if (filenames.size() == 1) {
        encryptFile(filenames[0].c_str(), NULL);
        retval = vector<char>(noerr.begin(), noerr.end());
    }
    else if (filenames.size() == 2) {
        encryptFile(filenames[0].c_str(), filenames[1].c_str());
        retval = vector<char>(noerr.begin(), noerr.end());
    }
    retval = vector<char>(err.begin(), err.end());
}

void d_getRpassAccounts(const vector<string> &options, vector<char> &retval) {
    vector<string>::const_iterator i = options.begin();
    vector<string> fields;

    // First argument is filename
    string filename = *(i++);
    // Second argument indicates start/end of searchstring
    string search_start = *(i++);
    string sstring = "";
    for (; i < options.end(); ++i) {
        if (*i != search_start) {
            sstring.append(*i);
            sstring.append(" ");
        }
        else
            break;
    }
    sstring.erase(sstring.length() - 1); ++i;

    int flags = *((int *)((i++)->data()));

    for (; i < options.end(); ++i) {
        fields.push_back(*i);
    }

    rpass_parent *parent;

    getRpassAccounts(sstring.c_str(), &parent, filename.c_str(), flags, NULL);

    string retstring = rparentsToString(parent, fields);
    retval = vector<char>(retstring.begin(), retstring.end());
    retval.push_back('\0');

    freeRpassParents(parent);
}

void setupSocket() {
    unsigned int s1 = socket(AF_UNIX, SOCK_STREAM, 0), s2;
    sockaddr_un local;
    char buffer[BUFSIZ];
    string instructions = "";
    vector<char> retval;
    vector<string> args;
    ssize_t read_size;

    map<string, OPERATOR_FUNCTION>::iterator found;
    map<string, OPERATOR_FUNCTION> instructions_operator;

    setupOperators(instructions_operator);

    local.sun_family = AF_UNIX;
    strcpy(local.sun_path, SOCKET_NAME);
    unlink(local.sun_path);

    bind(s1, (struct sockaddr *)&local, strlen(local.sun_path) + sizeof(local.sun_family));
    listen(s1, ALLOWED_CONNECTIONS);

    while (1) {
        s2 = accept(s1, NULL, NULL);
        while ((read_size = recv(s2, buffer, BUFSIZ, 0)) > 0) {
            instructions.append(buffer, read_size);
            if (read_size < BUFSIZ)
                break;
        }

        if (instructions.length() > 0) {
            args = splitArgs(instructions);
            if (args[0] == RPASS_DAEMON_MSG_STOP)
                break;

            if ((found = instructions_operator.find(args[0])) != instructions_operator.end()) {
                args.erase(args.begin());
                found->second(args, retval);
                send(s2, (void *)&retval[0], retval.size(), 0);
            }
        }

        instructions = "";
        close(s2);
    }

    close(s1);
    unlink(local.sun_path);
}

void setupOperators(map<string, OPERATOR_FUNCTION> &o) {
    o[RPASS_DAEMON_MSG_DECRYPTFILE] = d_decryptFile;
    o[RPASS_DAEMON_MSG_ENCRYPTFILE] = d_encryptFile;
    o[RPASS_DAEMON_MSG_GETACCOUNTS] = d_getRpassAccounts;
    o[RPASS_DAEMON_MSG_ENCRYPTDATATOFILE] = d_encryptDataToFile;
}

int main(int argc, char *argv[]) {
    bool foreground = false, verbose = false;

    if (argc > 1) {
        for (int c = 1; c < argc; ++c) {
            if ((string("--help") == argv[c]) || (string("-h") == argv[c])) {
                cout << "Options: [--foreground|-F] [--verbose|-v]" << endl;
                exit(0);
            }
            if ((string("--foreground") == argv[c]) || (string("-F") == argv[c])) {
                foreground = true;
            }
            if ((string("--verbose") == argv[c]) || (string("-v") == argv[c])) {
                verbose = true;
            }
        }
    }

    isDaemon();

    if (!foreground) {
        if (verbose)
            cout << "Daemonizing process..." << endl;
        daemonize();
    }

    if (verbose)
        cout << "Setting up socket..." << endl;

    setupSocket();

    return 0;
}
