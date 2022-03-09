#!/usr/bin/env python3

from setuptools import setup

setup(name='pyencrypto',
      version='1.0',
      description='Python encryption module to help make the process easier for encryption data and decrypting.',
      author='Kolten Fluckiger',
      author_email='wrtunder@gmail.com',
      url='https://github.com/koltenfluckiger/pyencrypto',
      include_package_data=True,
      packages=['pyencrypto', 'pyencrypto.crypter'],
      install_requires=['cryptography', 'pathlib'],
      python_requires='>=3.6.8'
     )
