#!/usr/bin/env python3

from setuptools import setup

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(name='pyencrypto',
      version='1.2',
      description='Python encryption module to help make the process easier for encryption data and decrypting.',
      long_description=long_description,
      long_description_content_type="text/markdown",
      author='Kolten Fluckiger',
      author_email='wrtunder@gmail.com',
      url='https://github.com/koltenfluckiger/pyencrypto',
      include_package_data=True,
      packages=['pyencrypto', 'pyencrypto.crypter', 'pyencrypto.keyer', 'pyencrypto.message'],
      install_requires=['cryptography', 'pathlib'],
      python_requires='>=3.10'
      )
