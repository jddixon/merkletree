#!/usr/bin/python3
# merkletree/setup.py

""" Set up distutils for merkletree package. """

import re
from distutils.core import setup
__version__ = re.search(r"__version__\s*=\s*'(.*)'",
                        open('src/merkletree/__init__.py').read()).group(1)

# see http://docs.python.org/distutils/setupscript.html

setup(name='merkletree',
      version=__version__,
      author='Jim Dixon',
      author_email='jddixon@gmail.com',
      py_modules=[],
      packages=['src/merkletree'],
      # following could be in scripts/ subdir
      scripts=['src/merkleize', ],          # front end module(s)
      # MISSING description
      classifiers=[
          'License :: OSI Approved :: MIT License',
          'Programming Language :: Python :: 3',
      ],)
