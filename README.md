# SignedAccess
[![Test Pass](https://github.com/JadsonLucena/SignedAccess.js/workflows/Tests/badge.svg)](https://github.com/JadsonLucena/SignedAccess.js/actions?workflow=Tests)
[![Coverage Status](https://coveralls.io/repos/github/JadsonLucena/SignedAccess.js/badge.svg)](https://coveralls.io/github/JadsonLucena/SignedAccess.js)

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
// Constructor
SignedAccess(
    {
        algorithm = 'sha512',
        ttl = 86400, // Seconds
        key = '{The MAC address of the network interface}'
    }: {
        algorithm?: string, // https://nodejs.org/api/crypto.html#cryptogethashes
        ttl?: number,
        key?: string | ArrayBuffer | Buffer | TypedArray | DataView | KeyObject | CryptoKey // https://nodejs.org/api/os.html#osnetworkinterfaces
    } = {}
)
```

```typescript
// Getters
algorithm(): string

ttl(): number

key(): string | ArrayBuffer | Buffer | TypedArray | DataView | KeyObject | CryptoKey
```

```typescript
// Setters
algorithm(arg?: string = 'sha512'): void

ttl(arg?: number = 86400): void

key(arg?: (string | ArrayBuffer | Buffer | TypedArray | DataView | KeyObject | CryptoKey) = '{The MAC address of the network interface}'): void
```

```typescript
// Methods
signCookie(
    prefix: string, // A prefix encodes a scheme (either http:// or https://), FQDN, and an optional path. Ending the path with a / is optional but recommended. The prefix shouldn't include query parameters or fragments such as ? or #.
    {
        algorithm = 'sha512',
        ttl = 86400,
        ip = '',
        key = '{The MAC address of the network interface}'
        methods = [],
        nonce = -1 // Natural numbers
    }: {
        algorithm?: string,
        ttl?: number,
        ip?: string,
        key?: string | ArrayBuffer | Buffer | TypedArray | DataView | KeyObject | CryptoKey,
        methods?: string | string[],
        nonce?: number
    } = {}
): string // Cookie signed

verifyCookie(
    url: string,
    cookie: string,
    {
        algorithm = 'sha512',
        ip = '', // will be required if it has been added to the signature
        key = '{The MAC address of the network interface}'
        method = '', // will be required if it has been added to the signature
    }: {
        algorithm?: string,
        ip?: string,
        key?: string | ArrayBuffer | Buffer | TypedArray | DataView | KeyObject | CryptoKey,
        method?: string
    } = {}
): boolean

signURL(
    url: string,
    {
        algorithm = 'sha512',
        ttl = 86400,
        ip = '',
        key = '{The MAC address of the network interface}'
        methods = [],
        nonce = -1, // Natural numbers
        pathname = '' // Must be a valid path contained in the url
    }: {
        algorithm?: string,
        ttl?: number,
        ip?: string,
        key?: string | ArrayBuffer | Buffer | TypedArray | DataView | KeyObject | CryptoKey,
        methods?: string | string[],
        nonce?: number,
        pathname?: string // https://developer.mozilla.org/en-US/docs/Web/API/URL/pathname
    } = {}
): string // URL signed

verifyURL(
    url: string,
    {
        algorithm = 'sha512',
        ip = '', // will be required if it has been added to the signature
        key = '{The MAC address of the network interface}'
        method = '', // will be required if it has been added to the signature
    }: {
        algorithm?: string,
        ip?: string,
        key?: string | ArrayBuffer | Buffer | TypedArray | DataView | KeyObject | CryptoKey,
        method?: string
    } = {}
): boolean
```

> It is recommended to end all pathnames with / unless you intentionally choose to end the pathname with a partial filename.\
> The pathname /data grants access to at least two of the following URLs:\
> example.com/database\
> example.com/data/file1

> The URLSign method needs to save the information in the searchParams, so the "expires, ip, method, nonce, prefix and signature" queries are reserved for this module's control. If your original url has one of these queries previously, it will be removed or overwritten to avoid conflicts in the signature verification.