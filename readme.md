# java-common

[![Software License](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square)](LICENSE.md)

This library provides various utilities for parsing [Adscore](https://adscore.com) signatures,
generating custom request payloads, and virtually anything that might be useful for customers doing server-side
integration with the service.

## Compatibility

### Supported Signature v5 algorithms

1. `v5_0200H - OpenSSL CBC, HTTP query`
2. `v5_0200S - OpenSSL CBC, PHP serialize`
3. `v5_0201H - OpenSSL GCM, HTTP query`
4. `v5_0201S - OpenSSL GCM, PHP serialize`
5. `v5_0101H - sodium secretbox, HTTP query`
6. `v5_0101S - sodium secretbox, PHP serialize`
7. `v5_0200J - OpenSSL CBC, JSON`
8. `v5_0201J - OpenSSL GCM, JSON`
9. `v5_0101J - sodium secretbox, JSON`
10. `v5_0101M - sodium secretbox, msgpack`
11. `v5_0200M - OpenSSL CBC, msgpack`
12. `v5_0201M - OpenSSL GCM, msgpack`

### Not supported Signature v5 algorithms

1. `v5_0101I - sodium secretbox, igbinary`
2. `v5_0200I - OpenSSL CBC, igbinary`
3. `v5_0201I - OpenSSL GCM, igbinary`

## Install

JDK version >= 1.8 is required

## Usage