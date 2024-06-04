# SignedAccess
[![CodeQL](https://github.com/JadsonLucena/SignedAccess.js/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/JadsonLucena/SignedAccess.js/actions/workflows/github-code-scanning/codeql)
[![Test](https://github.com/JadsonLucena/SignedAccess.js/workflows/test/badge.svg)](https://github.com/JadsonLucena/SignedAccess.js/actions?workflow=test)
[![Coverage](https://coveralls.io/repos/github/JadsonLucena/SignedAccess.js/badge.svg)](https://coveralls.io/github/JadsonLucena/SignedAccess.js)
[![JavaScript Style Guide](https://img.shields.io/badge/code_style-standard-brightgreen.svg)](https://standardjs.com)
[![Conventional Commits](https://img.shields.io/badge/Conventional%20Commits-1.0.0-%23FE5196?logo=conventionalcommits&logoColor=white)](https://conventionalcommits.org)

Sign and verify URLs and cookies to add a layer of protection to publicly accessible routes

## Which is?
A signed URL or signed cookie provides limited time and permission for non-credentialed origins to perform a number of specific actions on one resource or several based on a common prefix.
The subscription ensures that the permissions for a particular resource are not modified or tampered with.

## Features
- [x] Sign and verify URL and cookie
- [x] Freedom of choice in algorithm and encryption key
- [x] Access validity time
- [x] Possibility of using IP to prevent unauthorized access
- [x] Possibility to restrict which HTTP methods can be used in the request
- [x] Possibility to use nonce values to prevent replay attacks
- [x] Possibility to allow access to multiple URLs based on a common prefix


## Interfaces
Although this is a javascript module, we use a typescript interface to maintain interoperability and better readability. See: [src/SignedAccess.d.ts](src/SignedAccess.d.ts)


> It is recommended to end all pathnames with / unless you intentionally choose to end the pathname with a partial filename.\
> The pathname /data grants access to at least two of the following URLs:\
> example.com/database\
> example.com/data/file1

> The signURL method needs to save the information in the searchParams, so the "expires, ip, method, nonce, prefix and signature" queries are reserved for this module's control. If your original url has one of these queries previously, it will be removed or overwritten to avoid conflicts in the signature verification.

> The nonce is signed in the cookie or URL, but it's up to your application to save them and check if they've already been used.

## Specifications
We strive to maintain complete code coverage in tests. With that, we provide all the necessary use cases for a good understanding of how this module works. See: [test/SignedAccess.spec.js](test/SignedAccess.spec.js)