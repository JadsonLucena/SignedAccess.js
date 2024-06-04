import { KeyObject, webcrypto } from 'crypto'

declare module '@jadsonlucena/signedaccess' {
  export type TypedArray = Int8Array | Uint8Array | Uint8ClampedArray | Int16Array | Uint16Array | Int32Array | Uint32Array | Float32Array | Float64Array | BigInt64Array | BigUint64Array
  export type Key = string | ArrayBuffer | Buffer | TypedArray | DataView | KeyObject | webcrypto.CryptoKey

  /**
   * @classdesc Sign and verify URLs and cookies to add a layer of protection to publicly accessible routes
   */
  export default class SignedAccess {

    /**
     * Create a Signed Access
     * @param {Key} key - One of the supported {@link https://nodejs.org/api/crypto.html#cryptocreatehmacalgorithm-key-options key types}
     * @param {Object} [options]
     * @param {string} [options.algorithm=sha512] - One of the supported {@link https://nodejs.org/api/crypto.html#cryptogethashes hash algorithms}
     * @param {number} [options.ttl=86400] - {@link https://wikipedia.org/wiki/Time_to_live Time to Live} in seconds (Natural number)
     *
     * @throws {TypeError} Invalid key
     * @throws {TypeError} Invalid algorithm
     * @throws {TypeError|SyntaxError} Invalid ttl
     * @throws {AggregateError} Invalid arguments
     */
    constructor(
      key: Key,
      {
        algorithm,
        ttl
      }: {
        algorithm?: string,
        ttl?: number
      }
    )

    /**
     * @default 'sha512'
     *
     * @throws {TypeError} Invalid algorithm
     *
     * @see https://nodejs.org/api/crypto.html#cryptogethashes
     */
    set algorithm(param: string)
    get algorithm(): string

    /**
     * @throws {TypeError} Invalid key
     *
     * @see https://nodejs.org/api/crypto.html#cryptocreatehmacalgorithm-key-options
     */
    set key(param: Key)
    get key(): Key

    /**
     * Time to Live in seconds (Natural number)
     * @default 86400
     *
     * @throws {TypeError|SyntaxError} Invalid ttl
     *
     * @see https://wikipedia.org/wiki/Time_to_live
     */
    set ttl(param: number)
    get ttl(): number

    /**
     * @param {string} prefix - A prefix encodes a scheme (either http:// or https://), {@link Fully_qualified_domain_name FQDN}, and an optional {@link https://developer.mozilla.org/en-US/docs/Web/API/URL/pathname path}. Ending the path with a / is optional but recommended. The prefix shouldn't include query parameters or fragments such as ? or #
     * @param {Object} [options]
     * @param {string} [options.accessControlAllowMethods=*] - {@link https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Methods Access control allow methods}
     * @param {string} [options.algorithm=sha512] - One of the supported {@link https://nodejs.org/api/crypto.html#cryptogethashes hash algorithms}
     * @param {Key} [options.key] - One of the supported {@link https://nodejs.org/api/crypto.html#cryptocreatehmacalgorithm-key-options key types}
     * @param {string} [options.nonce] - Use random {@link https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes Number Once}
     * @param {string} [options.remoteAddress] - {@link https://developer.mozilla.org/en-US/docs/Glossary/IP_Address Client IP}
     * @param {number} [options.ttl=86400] - {@link https://wikipedia.org/wiki/Time_to_live Time to Live} in seconds (Natural number)
     *
     * @throws {TypeError} Invalid prefix
     * @throws {TypeError|SyntaxError} Invalid accessControlAllowMethods
     * @throws {TypeError} Invalid algorithm
     * @throws {TypeError} Invalid key
     * @throws {TypeError} Invalid nonce
     * @throws {TypeError|SyntaxError} Invalid remoteAddress
     * @throws {TypeError|SyntaxError} Invalid ttl
     * @throws {AggregateError} Invalid arguments
     *
     * @return {string} Signed cookie
     */
    signCookie(
      prefix: string,
      {
        accessControlAllowMethods,
        algorithm,
        key,
        nonce,
        remoteAddress,
        ttl
      }: {
        accessControlAllowMethods?: string,
        algorithm?: string,
        key?: Key,
        nonce?: string,
        remoteAddress?: string,
        ttl?: number
      }
    ): string

    /**
     * @param {string} url - Requisition {@link https://nodejs.org/api/url.html#url-strings-and-url-objects URL}
     * @param {string} cookie - Signed {@link https://developer.mozilla.org/pt-BR/docs/Web/HTTP/Cookies cookie}
     * @param {Object} [options]
     * @param {string} [options.algorithm=sha512] - One of the supported {@link https://nodejs.org/api/crypto.html#cryptogethashes hash algorithms}
     * @param {Key} [options.key] - One of the supported {@link https://nodejs.org/api/crypto.html#cryptocreatehmacalgorithm-key-options key types}
     * @param {string} [options.method] - {@link https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods HTTP request methods}
     * @param {string} [options.remoteAddress] - {@link https://developer.mozilla.org/en-US/docs/Glossary/IP_Address Client IP}
     *
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
     *
     * @return {boolean}
     */
    verifyCookie(
      url: string,
      cookie: string,
      {
        algorithm,
        key,
        method,
        remoteAddress
      }: {
        algorithm?: string,
        key?: Key,
        method?: string,
        remoteAddress?: string
      }
    ): boolean

    /**
     * @param {string} url - {@link https://nodejs.org/api/url.html#url-strings-and-url-objects URL} to be signed
     * @param {Object} [options]
     * @param {string} [options.accessControlAllowMethods=*] - {@link https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Methods Access control allow methods}
     * @param {string} [options.algorithm=sha512] - One of the supported {@link https://nodejs.org/api/crypto.html#cryptogethashes hash algorithms}
     * @param {Key} [options.key] - One of the supported {@link https://nodejs.org/api/crypto.html#cryptocreatehmacalgorithm-key-options key types}
     * @param {string} [options.nonce] - Use random {@link https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes Number Once}
     * @param {string} [options.pathname] - Starts with / followed by the {@link https://developer.mozilla.org/en-US/docs/Web/API/URL/pathname URL path}, shouldn't include query parameters or fragments such as ? or #
     * @param {string} [options.remoteAddress] - {@link https://developer.mozilla.org/en-US/docs/Glossary/IP_Address Client IP}
     * @param {number} [options.ttl=86400] - {@link https://wikipedia.org/wiki/Time_to_live Time to Live} in seconds (Natural number)
     *
     * @throws {TypeError} Invalid URL
     * @throws {TypeError} Invalid algorithm
     * @throws {TypeError|SyntaxError} Invalid accessControlAllowMethods
     * @throws {TypeError} Invalid key
     * @throws {TypeError} Invalid nonce
     * @throws {TypeError|SyntaxError} Invalid pathname
     * @throws {TypeError|SyntaxError} Invalid remoteAddress
     * @throws {TypeError|SyntaxError} Invalid ttl
     * @throws {AggregateError} Invalid arguments
     *
     * @return {string} Signed URL
     */
    signURL(
      url: string,
      {
        accessControlAllowMethods,
        algorithm,
        key,
        nonce,
        pathname,
        remoteAddress,
        ttl
      }: {
        accessControlAllowMethods?: string,
        algorithm?: string,
        key?: Key,
        nonce?: string,
        pathname?: string,
        remoteAddress?: string,
        ttl?: number
      }
    ): string

    /**
     * @param {string} url - Signed {@link https://nodejs.org/api/url.html#url-strings-and-url-objects URL}
     * @param {Object} [options]
     * @param {string} [options.algorithm=sha512] - One of the supported {@link https://nodejs.org/api/crypto.html#cryptogethashes hash algorithms}
     * @param {Key} [options.key] - One of the supported {@link https://nodejs.org/api/crypto.html#cryptocreatehmacalgorithm-key-options key types}
     * @param {string} [options.method] - {@link https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods HTTP request methods}
     * @param {string} [options.remoteAddress] - {@link https://developer.mozilla.org/en-US/docs/Glossary/IP_Address Client IP}
     *
     * @throws {TypeError} Invalid URL
     * @throws {TypeError} Invalid algorithm
     * @throws {TypeError} Invalid key
     * @throws {TypeError} Invalid method
     * @throws {TypeError|SyntaxError} Invalid remoteAddress
     * @throws {AggregateError} Invalid arguments
     * @throws {Error} method required
     * @throws {Error} remoteAddress required
     * @throws {AggregateError} Invalid URL
     *
     * @return {boolean}
     */
    verifyURL(
      url: string,
      {
        algorithm,
        key,
        method,
        remoteAddress
      }: {
        algorithm?: string,
        key?: Key,
        method?: string,
        remoteAddress?: string
      }
    ): boolean
  }
}