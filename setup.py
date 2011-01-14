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

    gpgme_args = {}
    try:
        gpgme_args = get_compiler_info("gpgme-config --cflags --libs")
    except OSError:
        print("Unable to get library information for gpgme...using defaults")
        gpgme_args['libraries'] = ['gpgme', 'assuan', 'gpg-error']
        gpgme_args['include_dirs'] = []
        gpgme_args['library_dirs'] = []

    gtk_args = {}
    try:
        gtk_args = get_compiler_info("pkg-config --cflags --libs gtk+-2.0")
    except OSError:
        print("Unable to get library information for gtk+-2.0...using defaults.")
        gtk_args['libraries'] = ['gtk-x11-2.0', 'gdk-x11-2.0', 'atk-1.0', 'gio-2.0', 'pangoft2-1.0', 'pangocairo-1.0', 'gdk_pixbuf-2.0', 'm', 'cairo', 'png14', 'pango-1.0', 'freetype', 'fontconfig', 'gobject-2.0', 'gmodule-2.0', 'gthread-2.0', 'rt', 'glib-2.0']
        gtk_args['include_dirs'] = ['/usr/include/gtk-2.0', '/usr/lib/gtk-2.0/include', '/usr/include/atk-1.0', '/usr/include/cairo', '/usr/include/gdk-pixbuf-2.0', '/usr/include/pango-1.0', '/usr/include/glib-2.0', '/usr/lib/glib-2.0/include', '/usr/include/pixman-1', '/usr/include/freetype2', '/usr/include/libpng14']
        gtk_args['library_dirs'] = []

    libraries.extend(gpgme_args["libraries"])
    libraries.extend(gtk_args["libraries"])

    include_dirs.extend(gpgme_args['include_dirs'])
    include_dirs.extend(gtk_args['include_dirs'])

    library_dirs.extend(gpgme_args['library_dirs'])
    library_dirs.extend(gtk_args['library_dirs'])

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
