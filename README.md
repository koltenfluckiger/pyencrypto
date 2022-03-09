<!-- PROJECT SHIELDS -->

<!--
*** I'm using markdown "reference style" links for readability.
*** Reference links are enclosed in brackets [ ] instead of parentheses ( ).
*** See the bottom of this document for the declaration of the reference variables
*** for contributors-url, forks-url, etc. This is an optional, concise syntax you may use.
*** https://www.markdownguide.org/basic-syntax/#reference-style-links
-->

[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
[![MIT License][license-shield]][license-url]
[![LinkedIn][linkedin-shield]][linkedin-url]

  <h3 align="center">Python Encrypter</h3>

  <p align="center">
    Use this python package to help encrypt and decrypt files/messages/objects with a key.
    <br />
    <a href="https://github.com/koltenfluckiger/pyencrypto"><strong>Explore the docs »</strong></a>
    <br />
    <br />
    <a href="https://github.com/koltenfluckiger/pyencrypto">View Demo</a>
    ·
    <a href="https://github.com/koltenfluckiger/pyencrypto/issues">Report Bug</a>
    ·
    <a href="https://github.com/koltenfluckiger/pyencrypto/issues">Request Feature</a>
  </p>
</p>

<!-- TABLE OF CONTENTS -->

<details open="open">
  <summary><h2 style="display: inline-block">Table of Contents</h2></summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#built-with">Built With</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#roadmap">Roadmap</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#contact">Contact</a></li>
    <li><a href="#acknowledgements">Acknowledgements</a></li>
  </ol>
</details>

<!-- ABOUT THE PROJECT -->

## About The Project

This python package allows for ease of use to encrypt/decrypt files/objects/messages.

### Built With

-   [Selenium](https://pypi.org/project/cryptography/)
-   [Python3](https://www.python.org/)

<!-- GETTING STARTED -->

## Getting Started

To get a local copy up and running follow these simple steps.

### Prerequisites

This is an example of how to list things you need to use the software and how to install them.

-   bash
    ```sh
    sudo apt install -y python3 python3-pip
    pip3 install cryptography
    ```

### Installation

1.  Clone the repo
    ```sh
    git clone https://github.com/taosdevops/pyencrypto.git
    ```
2.  Install PIP package
    ```sh
    pip3 install -e pyencrypto
    or
    python setup.py install
    ```

<!-- USAGE EXAMPLES -->

## Usage

Use this space to show useful examples of how a project can be used. Additional screenshots, code examples and demos work well in this space. You may also link to more resources.


```python
# pyencrypto

#!/usr/bin/env python3

from pyencrypto.crypter import Crypter
import pathlib
from time import sleep
def main():
    cwd = pathlib.Path.cwd().joinpath("testing.txt")
    crypter = Crypter('EF2Gtyt3XWsD1mk8gYWn-hJzjljA2dJCqeYnmIYET_E=')
    crypter.set_key_session()
    crypter.encrypt(cwd)
    sleep(1)
    crypter.decrypt(cwd)




if __name__ == '__main__':
    main()
```


<!-- ROADMAP -->

## Roadmap

See the [open issues](https://github.com/koltenfluckiger/pyencrypto/issues) for a list of proposed features (and known issues).

<!-- CONTRIBUTING -->

## Contributing

Contributions are what make the open source community such an amazing place to be learn, inspire, and create. Any contributions you make are **greatly appreciated**.

1.  Fork the Project
2.  Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3.  Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4.  Push to the Branch (`git push origin feature/AmazingFeature`)
5.  Open a Pull Request

<!-- LICENSE -->

## License

Distributed under the MIT License. See `LICENSE` for more information.

<!-- CONTACT -->

## Contact

Project Link: <https://github.com/koltenfluckiger/pyencrypto>

<!-- MARKDOWN LINKS & IMAGES -->

<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->

[contributors-shield]: https://img.shields.io/github/contributors/koltenfluckiger/repo.svg?style=for-the-badge

[contributors-url]: https://github.com/koltenfluckiger/pyencrypto/graphs/contributors

[forks-shield]: https://img.shields.io/github/forks/koltenfluckiger/repo.svg?style=for-the-badge

[forks-url]: https://github.com/koltenfluckiger/pyencrypto/network/members

[stars-shield]: https://img.shields.io/github/stars/koltenfluckiger/repo.svg?style=for-the-badge

[stars-url]: https://github.com/koltenfluckiger/pyencrypto/stargazers

[issues-shield]: https://img.shields.io/github/issues/koltenfluckiger/repo.svg?style=for-the-badge

[issues-url]: https://github.com/koltenfluckiger/pyencrypto/issues

[license-shield]: https://img.shields.io/github/license/koltenfluckiger/repo.svg?style=for-the-badge

[license-url]: https://github.com/koltenfluckiger/pyencrypto/blob/master/LICENSE.txt

[linkedin-shield]: https://img.shields.io/badge/-LinkedIn-black.svg?style=for-the-badge&logo=linkedin&colorB=555

[linkedin-url]: https://linkedin.com/in/koltenfluckiger
