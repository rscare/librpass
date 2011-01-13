from distutils.core import setup, Extension
import os

rGPG = Extension('rGPG',
        sources = [ 'C/rGPGmodule.c', 'C/rGPG.c'],
        libraries = [ 'gpgme', 'assuan', 'gpg-error', 'ncurses' ],
        )

if os.name == 'posix':
    from subprocess import call
    print("Building manpage...")
    try:
        call('a2x -d manpage -f manpage README.asciidoc'.split(' '))
    except OSError:
        print("Failed to build manpage...using cached version")

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
