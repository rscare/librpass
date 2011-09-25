from distutils.core import setup, Extension
import os

setup(name = 'rpass',
        version = '7.3',
        description = 'Commandline password manager.',
        author = 'Yuri D. Lenskiy',
        author_email = 'yuri.lenskiy@gmail.com',
        py_modules = ['rpass'],
        scripts = ['rpass', 'rp', 'ru'],
        data_files = [('share/man/man1', ['rpass.1']),
            ('share/rpass', ['rpass.example.conf'])],
        )
