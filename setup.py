#!/usr/bin/env python3

from setuptools import setup
from setuptools import find_namespace_packages, find_packages
import pathlib

current_dir = pathlib.Path(__file__).parent.resolve()

setup(name='pyencrypto',
      version='1.0',
      description='Python encryption module to help make the process easier for encryption data and decrypting.',
      author='Kolten Fluckiger',
      author_email='wrtunder@gmail.com',
      url='',
      include_package_data=True,
      packages=['pyencrypto', 'pyencrypto.crypter'],
      install_requires=['cryptography', 'pathlib'],
      python_requires='>=3.6.8'
     )
