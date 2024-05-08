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
```typescript
/**
 * @constructor
 * @throws {TypeError} Invalid key
 * @throws {TypeError} Invalid algorithm
 * @throws {TypeError|SyntaxError} Invalid ttl
 * @throws {AggregateError} Invalid arguments
 */
SignedAccess(
  key: string | ArrayBuffer | Buffer | TypedArray | DataView | KeyObject | CryptoKey, // https://nodejs.org/api/crypto.html#cryptocreatehmacalgorithm-key-options
  {
    algorithm = 'sha512',
    ttl = 86400 // Time to Live in seconds (Natural number)
  }: {
    algorithm?: string, // https://nodejs.org/api/crypto.html#cryptogethashes
    ttl?: number // https://wikipedia.org/wiki/Time_to_live
  }
)
```

```typescript
/**
 * @throws {TypeError} Invalid algorithm
 * @see https://nodejs.org/api/crypto.html#cryptogethashes
 */
set algorithm(param?: string = 'sha512')
get algorithm(): string

/**
 * @throws {TypeError} Invalid key
 * @see https://nodejs.org/api/crypto.html#cryptocreatehmacalgorithm-key-options
 */
set key(param?: string | ArrayBuffer | Buffer | TypedArray | DataView | KeyObject | CryptoKey)
get key(): string | ArrayBuffer | Buffer | TypedArray | DataView | KeyObject | CryptoKey

/**
 * @throws {TypeError|SyntaxError} Invalid ttl
 * @see https://wikipedia.org/wiki/Time_to_live
 */
set ttl(param?: number = 86400)
get ttl(): number
```

```typescript
/**
 * @method
 * @throws {TypeError} Invalid prefix
 * @throws {TypeError|SyntaxError} Invalid accessControlAllowMethods
 * @throws {TypeError} Invalid algorithm
 * @throws {TypeError} Invalid key
 * @throws {TypeError} Invalid nonce
 * @throws {TypeError|SyntaxError} Invalid remoteAddress
 * @throws {TypeError|SyntaxError} Invalid ttl
 * @throws {AggregateError} Invalid arguments
 */
signCookie(
  prefix: string, // A prefix encodes a scheme (either http:// or https://), FQDN, and an optional path. Ending the path with a / is optional but recommended. The prefix shouldn't include query parameters or fragments such as ? or #.
  {
    accessControlAllowMethods = '*',
    algorithm = this.algorithm,
    key = this.key,
    nonce = '',
    remoteAddress = '',
    ttl = this.ttl
  }: {
    accessControlAllowMethods?: string, // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Methods
    algorithm?: string,
    key?: string | ArrayBuffer | Buffer | TypedArray | DataView | KeyObject | CryptoKey,
    nonce?: string, // https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes
    remoteAddress?: string, // https://developer.mozilla.org/en-US/docs/Glossary/IP_Address
    ttl?: number
  }
): string // Cookie signed

/**
 * @method
 * @throws {TypeError} Invalid URL
 * @throws {TypeError} Invalid cookie
 * @throws {TypeError} Invalid algorithm
 * @throws {TypeError} Invalid key
 * @throws {TypeError} Invalid method
 * @throws {TypeError|SyntaxError} Invalid remoteAddress
 * @throws {AggregateError} Invalid arguments
 * @throws {Error} method required
 * @throws {Error} remoteAddress required
 * @throws {AggregateError} Invalid cookie
 */
verifyCookie(
  url: string,
  cookie: string,
  {
    algorithm = this.algorithm,
    key = this.key,
    method = '', // will be required if it has been added to the signature
    remoteAddress = '' // will be required if it has been added to the signature
  }: {
    algorithm?: string,
    key?: string | ArrayBuffer | Buffer | TypedArray | DataView | KeyObject | CryptoKey,
    method?: string, // https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods
    remoteAddress?: string
  }
): boolean

/**
 * @method
 * @throws {TypeError} Invalid URL
 * @throws {TypeError} Invalid algorithm
 * @throws {TypeError|SyntaxError} Invalid accessControlAllowMethods
 * @throws {TypeError} Invalid key
 * @throws {TypeError} Invalid nonce
 * @throws {TypeError|SyntaxError} Invalid pathname
 * @throws {TypeError|SyntaxError} Invalid remoteAddress
 * @throws {TypeError|SyntaxError} Invalid ttl
 * @throws {AggregateError} Invalid arguments
 */
signURL(
  url: string,
  {
    accessControlAllowMethods = '*',
    algorithm = this.algorithm,
    key = this.key,
    nonce = '',
    pathname = '', // Must be a valid path contained in the url
    remoteAddress = '',
    ttl = this.ttl
  }: {
    accessControlAllowMethods?: string,
    algorithm?: string,
    key?: string | ArrayBuffer | Buffer | TypedArray | DataView | KeyObject | CryptoKey,
    nonce?: string,
    pathname?: string, // https://developer.mozilla.org/en-US/docs/Web/API/URL/pathname
    remoteAddress?: string,
    ttl?: number
  }
): string // URL signed

/**
 * @method
 * @throws {TypeError} Invalid URL
 * @throws {TypeError} Invalid algorithm
 * @throws {TypeError} Invalid key
 * @throws {TypeError} Invalid method
 * @throws {TypeError|SyntaxError} Invalid remoteAddress
 * @throws {AggregateError} Invalid arguments
 * @throws {Error} method required
 * @throws {Error} remoteAddress required
 * @throws {AggregateError} Invalid URL
 */
verifyURL(
  url: string,
  {
    algorithm = this.algorithm,
    key = this.key,
    method = '',
    remoteAddress = ''
  }: {
    algorithm?: string,
    key?: string | ArrayBuffer | Buffer | TypedArray | DataView | KeyObject | CryptoKey,
    method?: string,
    remoteAddress?: string
  }
): boolean
```

> It is recommended to end all pathnames with / unless you intentionally choose to end the pathname with a partial filename.\
> The pathname /data grants access to at least two of the following URLs:\
> example.com/database\
> example.com/data/file1

> The signURL method needs to save the information in the searchParams, so the "expires, ip, method, nonce, prefix and signature" queries are reserved for this module's control. If your original url has one of these queries previously, it will be removed or overwritten to avoid conflicts in the signature verification.

> The nonce is signed in the cookie or URL, but it's up to your application to save them and check if they've already been used.

## Specifications
We strive to maintain complete code coverage in tests. With that, we provide all the necessary use cases for a good understanding of how this module works. See: [test/SignedAccess.spec.js](https://github.com/JadsonLucena/SignedAccess.js/blob/main/test/SignedAccess.spec.js)