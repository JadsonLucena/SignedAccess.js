# SignedAccess
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
