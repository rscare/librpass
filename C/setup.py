#!/usr/bin/python

from distutils.core import setup, Extension

rGPG = Extension('rGPG',
        sources = [ 'rGPGmodule.c', 'rGPG.c'],
        libraries = [ 'gpgme', 'assuan', 'gpg-error' ],
        )

setup (name = 'rGPG', 
        version = '1.0', 
        description = 'GPG module installer.',
        ext_modules = [rGPG]
        )
