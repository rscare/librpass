from distutils.core import setup

setup(name = 'rpass',
        version = '7.3',
        description = 'GPG-based commandline password manager.',
        author = 'Yuri D. Lenskiy',
        author_email = 'yuri.lenskiy@gmail.com',
        py_modules = ['rpass'],
        scripts = ['rpass']
        )
