# SignedAccess
[![Test Pass](https://github.com/JadsonLucena/SignedAccess.js/workflows/Tests/badge.svg)](https://github.com/JadsonLucena/SignedAccess.js/actions?workflow=Tests)
[![Coverage Status](https://coveralls.io/repos/github/JadsonLucena/SignedAccess.js/badge.svg)](https://coveralls.io/github/JadsonLucena/SignedAccess.js)
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
```typescript
/**
 * @constructor
 * @throws {TypeError} Invalid algorithm
 * @throws {TypeError} Invalid ttl
 * @throws {TypeError} Invalid key
 */
SignedAccess(
  {
    algorithm = 'sha512',
    ttl = 86400, // Time to Live in seconds
    key = require('os').networkInterfaces().eth0[0]?.mac
  }: {
    algorithm?: string, // https://nodejs.org/api/crypto.html#cryptogethashes
    ttl?: number, // https://wikipedia.org/wiki/Time_to_live
    key?: string | ArrayBuffer | Buffer | TypedArray | DataView | KeyObject | CryptoKey // https://nodejs.org/api/crypto.html#cryptocreatehmacalgorithm-key-options
  } = {}
)
```

```typescript
/**
 * @getter
 */
algorithm(): string

/**
 * @getter
 */
ttl(): number

/**
 * @getter
 */
key(): string | ArrayBuffer | Buffer | TypedArray | DataView | KeyObject | CryptoKey
```

```typescript
/**
 * @setter
 * @throws {TypeError} Invalid algorithm
 * @see https://nodejs.org/api/crypto.html#cryptogethashes
 */
algorithm(param?: string = 'sha512'): void

/**
 * @setter
 * @throws {TypeError} Invalid ttl
 * @see https://wikipedia.org/wiki/Time_to_live
 */
ttl(param?: number = 86400): void

/**
 * @setter
 * @throws {TypeError} Invalid key
 * @see https://nodejs.org/api/crypto.html#cryptocreatehmacalgorithm-key-options
 */
key(param?: (string | ArrayBuffer | Buffer | TypedArray | DataView | KeyObject | CryptoKey) = require('os').networkInterfaces().eth0[0]?.mac): void
```

```typescript
/**
 * @method
 * @throws {TypeError} Invalid prefix
 * @throws {TypeError} Invalid algorithm
 * @throws {TypeError} Invalid ttl
 * @throws {TypeError} Invalid remoteAddress
 * @throws {TypeError} Invalid key
 * @throws {TypeError} Invalid accessControlAllowMethods
 * @throws {TypeError} Invalid nonce
 */
signCookie(
  prefix: string, // A prefix encodes a scheme (either http:// or https://), FQDN, and an optional path. Ending the path with a / is optional but recommended. The prefix shouldn't include query parameters or fragments such as ? or #.
  {
    algorithm = 'sha512',
    ttl = 86400,
    remoteAddress = '',
    key = require('os').networkInterfaces().eth0[0]?.mac,
    accessControlAllowMethods = '*',
    nonce = ''
  }: {
    algorithm?: string,
    ttl?: number,
    remoteAddress?: string, // https://developer.mozilla.org/en-US/docs/Glossary/IP_Address
    key?: string | ArrayBuffer | Buffer | TypedArray | DataView | KeyObject | CryptoKey,
    accessControlAllowMethods?: string, // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Methods
    nonce?: string // https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes
  } = {}
): string // Cookie signed

/**
 * @method
 * @throws {TypeError} Invalid url
 * @throws {TypeError} Invalid cookie
 * @throws {TypeError} Invalid algorithm
 * @throws {TypeError} Invalid remoteAddress
 * @throws {Error} remoteAddress required
 * @throws {TypeError} Invalid key
 * @throws {TypeError} Invalid method
 * @throws {Error} method required
 */
verifyCookie(
  url: string,
  cookie: string,
  {
    algorithm = 'sha512',
    remoteAddress = '', // will be required if it has been added to the signature
    key = require('os').networkInterfaces().eth0[0]?.mac,
    method = '' // will be required if it has been added to the signature
  }: {
    algorithm?: string,
    remoteAddress?: string,
    key?: string | ArrayBuffer | Buffer | TypedArray | DataView | KeyObject | CryptoKey,
    method?: string // https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods
  } = {}
): boolean

/**
 * @method
 * @throws {TypeError} Invalid url
 * @throws {TypeError} Invalid algorithm
 * @throws {TypeError} Invalid ttl
 * @throws {TypeError} Invalid remoteAddress
 * @throws {TypeError} Invalid key
 * @throws {TypeError} Invalid accessControlAllowMethods
 * @throws {TypeError} Invalid nonce
 * @throws {TypeError} Invalid pathname
 */
signURL(
  url: string,
  {
    algorithm = 'sha512',
    ttl = 86400,
    remoteAddress = '',
    key = require('os').networkInterfaces().eth0[0]?.mac,
    accessControlAllowMethods = '*',
    nonce = '',
    pathname = '' // Must be a valid path contained in the url
  }: {
    algorithm?: string,
    ttl?: number,
    remoteAddress?: string,
    key?: string | ArrayBuffer | Buffer | TypedArray | DataView | KeyObject | CryptoKey,
    accessControlAllowMethods?: string,
    nonce?: string,
    pathname?: string // https://developer.mozilla.org/en-US/docs/Web/API/URL/pathname
  } = {}
): string // URL signed

/**
 * @method
 * @throws {TypeError} Invalid url
 * @throws {TypeError} Invalid algorithm
 * @throws {TypeError} Invalid remoteAddress
 * @throws {Error} remoteAddress required
 * @throws {TypeError} Invalid key
 * @throws {TypeError} Invalid method
 * @throws {Error} method required
 */
verifyURL(
  url: string,
  {
    algorithm = 'sha512',
    remoteAddress = '',
    key = require('os').networkInterfaces().eth0[0]?.mac,
    method = '',
  }: {
    algorithm?: string,
    remoteAddress?: string,
    key?: string | ArrayBuffer | Buffer | TypedArray | DataView | KeyObject | CryptoKey,
    method?: string
  } = {}
): boolean
```

> It is recommended to end all pathnames with / unless you intentionally choose to end the pathname with a partial filename.\
> The pathname /data grants access to at least two of the following URLs:\
> example.com/database\
> example.com/data/file1

> The signURL method needs to save the information in the searchParams, so the "expires, ip, method, nonce, prefix and signature" queries are reserved for this module's control. If your original url has one of these queries previously, it will be removed or overwritten to avoid conflicts in the signature verification.

> The nonce is signed in the cookie or URL, but it's up to your application to save them and check if they've already been used.