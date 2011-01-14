from distutils.core import setup, Extension
import os

def get_compiler_info(command):
    from subprocess import Popen,PIPE

    proc = Popen(command, shell=True, stdout=PIPE)
    res = str(proc.communicate()[0], encoding="utf-8")
    compiler_dict = {"include_dirs": [], "library_dirs": [], "libraries": [], "extra_compiler_args": []}
    for item in res.split():
        if item[:2] == "-I":
            compiler_dict["include_dirs"].append(item[2:])
        elif item[:2] == "-L":
            compiler_dict["library_dirs"].append(item[2:])
        elif item[:2] == "-l":
            compiler_dict["libraries"].append(item[2:])
        else:
            compiler_dict["extra_compiler_args"].append(item)

    return compiler_dict

libraries = ['ncurses']
include_dirs = []
library_dirs = []
if os.name == 'posix':
    from subprocess import call
    print("Building manpage...")
    try:
        call('a2x -d manpage -f manpage README.asciidoc'.split(' '))
    except OSError:
        print("Failed to build manpage...using cached version")

    print("Getting library directories...")

    gpgme_args = get_compiler_info("gpgme-config --cflags --libs")
    gtk_args = get_compiler_info("pkg-config --cflags --libs gtk+-2.0")

    libraries.extend(gpgme_args["libraries"])
    libraries.extend(gtk_args["libraries"])

    include_dirs.extend(gpgme_args['include_dirs'])
    include_dirs.extend(gtk_args['include_dirs'])

    library_dirs.extend(gpgme_args['library_dirs'])
    library_dirs.extend(gtk_args['library_dirs'])

print("{0}\n{1}\n{2}".format(libraries, include_dirs, library_dirs))

rGPG = Extension('rGPG',
        sources = [ 'C/rGPGmodule.c', 'C/rGPG.c', 'C/passphrase_dialog.c'],
        libraries = libraries,
        include_dirs = include_dirs,
        library_dirs = library_dirs,
        )

setup(name = 'rpass',
        version = '7.3',
        description = 'GPG-based commandline password manager.',
        author = 'Yuri D. Lenskiy',
        author_email = 'yuri.lenskiy@gmail.com',
        py_modules = ['rpass'],
        scripts = ['rpass', 'rpass_py_interface', 'rp', 'ru'],
        data_files = [('share/man/man1', ['rpass.1']),
            ('share/rpass', ['rpass.example.conf'])],
        ext_modules = [rGPG]
        )
