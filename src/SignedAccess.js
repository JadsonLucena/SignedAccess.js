'use strict'

const crypto = require('node:crypto')
const os = require('node:os')

/**
 * @class
 * @classdesc Sign and verify URLs and cookies to add a layer of protection to publicly accessible routes
 *
 * @typedef {(Int8Array|Uint8Array|Uint8ClampedArray|Int16Array|Uint16Array|Int32Array|Uint32Array|Float32Array|Float64Array|BigInt64Array|BigUint64Array)} TypedArray
 * @typedef {(string|ArrayBuffer|TypedArray|DataView|Buffer|KeyObject|CryptoKey)} key
 */
class SignedAccess {
  #algorithm
  #key
  #ttl

  #HTTPMethods

  /**
   * Create a Signed Access
   * @constructor
   * @param {Object} [options]
   * @param {string} [options.algorithm=sha512] - One of the supported {@link https://nodejs.org/api/crypto.html#cryptogethashes hash algorithms}
   * @param {key} [options.key=require('os').networkInterfaces().eth0[0]?.mac] - One of the supported {@link https://nodejs.org/api/crypto.html#cryptocreatehmacalgorithm-key-options key types}
   * @param {number} [options.ttl=86400] - {@link https://wikipedia.org/wiki/Time_to_live Time to Live} in seconds
   *
   * @throws {TypeError} Invalid algorithm
   * @throws {TypeError} Invalid ttl
   * @throws {TypeError} Invalid key
   */
  constructor ({
    algorithm,
    key,
    ttl
  } = {}) {
    this.algorithm = algorithm
    this.key = key
    this.ttl = ttl

    this.#HTTPMethods = ['CONNECT', 'DELETE', 'GET', 'HEAD', 'OPTIONS', 'PATCH', 'POST', 'PUT', 'TRACE']
  }

  /**
   * @getter
   * @return {string}
   */
  get algorithm () { return this.#algorithm }
  /**
   * @getter
   * @return {key}
   */
  get key () { return this.#key }
  /**
   * @getter
   * @return {number}
   */
  get ttl () { return this.#ttl }

  /**
   * @setter
   * @type {string}
   * @default 'sha512'
   * @see https://nodejs.org/api/crypto.html#cryptogethashes
   */
  set algorithm (
    algorithm = 'sha512' // https://nodejs.org/api/crypto.html#cryptogethashes
  ) {
    if (typeof algorithm !== 'string' || !crypto.getHashes().includes(algorithm.trim())) {
      throw new TypeError('Invalid algorithm')
    }

    this.#algorithm = algorithm
  }

  /**
   * @setter
   * @type {key}
   * @default require('os').networkInterfaces().eth0[0]?.mac
   * @see https://nodejs.org/api/crypto.html#cryptocreatehmacalgorithm-key-options
   */
  set key (
    key = os.networkInterfaces().eth0[0]?.mac
  ) {
    try {
      crypto.createHmac('sha1', key)
    } catch (err) {
      throw new TypeError('Invalid key')
    }

    this.#key = key
  }

  /**
   * Time to Live in seconds
   * @setter
   * @type {number}
   * @default 86400
   * @see https://wikipedia.org/wiki/Time_to_live
   */
  set ttl (
    ttl = 86400 // Seconds
  ) {
    if (!Number.isSafeInteger(ttl) || ttl < 1) {
      throw new TypeError('Invalid ttl')
    }

    this.#ttl = ttl
  }

  #encodePrefix (prefix) {
    prefix = new URL(prefix)

    // The prefix shouldn't include query parameters or fragments such as ? or #
    return Buffer.from(decodeURIComponent(prefix.origin + prefix.pathname), 'ascii').toString('base64url')
  }

  #decodePrefix (prefix) {
    // https://www.w3schools.com/tags/ref_urlencode.asp
    // https://datatracker.ietf.org/doc/html/rfc4648#section-5
    return Buffer.from(prefix, 'base64url').toString('ascii')
  }

  #timestamp (ttl) {
    return Date.now() + parseInt(ttl) * 1000
  }

  #toSign (
    input,
    key,
    algorithm
  ) {
    if (typeof algorithm !== 'string' || !crypto.getHashes().includes(algorithm.trim())) {
      throw new TypeError('Invalid algorithm')
    }

    try {
      return crypto.createHmac(algorithm.trim(), key).update(decodeURIComponent(input)).digest('base64url')
    } catch (err) {
      throw new TypeError('Invalid key')
    }
  }

  /**
   * @method
   * @param {string} url - {@link https://nodejs.org/api/url.html#url-strings-and-url-objects URL} to be signed
   * @param {Object} [options]
   * @param {string} [options.accessControlAllowMethods=*] - {@link https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Methods Access control allow methods}
   * @param {string} [options.algorithm=sha512] - One of the supported {@link https://nodejs.org/api/crypto.html#cryptogethashes hash algorithms}
   * @param {key} [options.key=require('os').networkInterfaces().eth0[0]?.mac] - One of the supported {@link https://nodejs.org/api/crypto.html#cryptocreatehmacalgorithm-key-options key types}
   * @param {string} [options.nonce] - Use random {@link https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes Number Once}
   * @param {string} [options.pathname] - Starts with / followed by the {@link https://developer.mozilla.org/en-US/docs/Web/API/URL/pathname URL path}, shouldn't include query parameters or fragments such as ? or #
   * @param {string} [options.remoteAddress] - {@link https://developer.mozilla.org/en-US/docs/Glossary/IP_Address Client IP}
   * @param {number} [options.ttl=86400] - {@link https://wikipedia.org/wiki/Time_to_live Time to Live} in seconds
   *
   * @throws {TypeError} Invalid url
   * @throws {TypeError} Invalid algorithm
   * @throws {TypeError} Invalid accessControlAllowMethods
   * @throws {TypeError} Invalid key
   * @throws {TypeError} Invalid nonce
   * @throws {TypeError} Invalid pathname
   * @throws {TypeError} Invalid remoteAddress
   * @throws {TypeError} Invalid ttl
   *
   * @return {string} Signed URL
   */
  signURL (
    url,
    {
      accessControlAllowMethods = '*',
      algorithm = this.#algorithm,
      key = this.#key,
      nonce = '',
      pathname = '',
      remoteAddress = '',
      ttl = this.#ttl
    } = {}
  ) {
    url = new URL(url)

    if (!new RegExp(`^\\s*(\\*|(${this.#HTTPMethods.join('|')})(\\s*,\\s*(${this.#HTTPMethods.join('|')}))*)\\s*$`, 'i').test(accessControlAllowMethods)) {
      throw new TypeError('Invalid accessControlAllowMethods')
    } else if (typeof nonce !== 'string') {
      throw new TypeError('Invalid nonce')
    } else if (typeof pathname !== 'string' || !decodeURIComponent(url.pathname).startsWith(pathname)) {
      throw new TypeError('Invalid pathname')
    } else if (typeof remoteAddress !== 'string') {
      throw new TypeError('Invalid remoteAddress')
    } else if (!Number.isSafeInteger(ttl) || ttl < 1) {
      throw new TypeError('Invalid ttl')
    }

    url.searchParams.delete('expires')
    url.searchParams.delete('ip')
    url.searchParams.delete('method')
    url.searchParams.delete('nonce')
    url.searchParams.delete('prefix')
    url.searchParams.delete('signature')

    const searchParams = new URLSearchParams()

    searchParams.set('expires', this.#timestamp(ttl))
    if (remoteAddress.trim()) searchParams.set('ip', remoteAddress.trim())
    if (accessControlAllowMethods.trim() && accessControlAllowMethods.trim() !== '*') [...new Set(accessControlAllowMethods.split(',').map(method => method.trim().toUpperCase()))].forEach(method => searchParams.append('method', method))
    if (nonce.trim()) searchParams.set('nonce', nonce.trim())
    if (pathname.trim()) searchParams.set('prefix', this.#encodePrefix(new URL(pathname.trim(), url.origin).href))

    for (const pair of searchParams.entries()) {
      url.searchParams.append(pair[0], pair[1])
    }

    url.searchParams.set('signature', this.#toSign(searchParams.has('prefix') ? searchParams.toString() : url.href, key, algorithm))

    return decodeURIComponent(url.href)
  }

  /**
   * @method
   * @param {string} url - Signed {@link https://nodejs.org/api/url.html#url-strings-and-url-objects URL}
   * @param {Object} [options]
   * @param {string} [options.algorithm=sha512] - One of the supported {@link https://nodejs.org/api/crypto.html#cryptogethashes hash algorithms}
   * @param {key} [options.key=require('os').networkInterfaces().eth0[0]?.mac] - One of the supported {@link https://nodejs.org/api/crypto.html#cryptocreatehmacalgorithm-key-options key types}
   * @param {string} [options.method] - {@link https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods HTTP request methods}
   * @param {string} [options.remoteAddress] - {@link https://developer.mozilla.org/en-US/docs/Glossary/IP_Address Client IP}
   *
   * @throws {TypeError} Invalid url
   * @throws {TypeError} Invalid algorithm
   * @throws {TypeError} Invalid key
   * @throws {TypeError} Invalid method
   * @throws {TypeError} Invalid remoteAddress
   * @throws {Error} method required
   * @throws {Error} remoteAddress required
   *
   * @return {boolean}
   */
  verifyURL (
    url,
    {
      algorithm = this.#algorithm,
      key = this.#key,
      method = '',
      remoteAddress = ''
    } = {}
  ) {
    url = new URL(url)

    if (typeof method !== 'string' || !['', ...this.#HTTPMethods].includes(method.trim().toUpperCase())) {
      throw new TypeError('Invalid method')
    } else if (typeof remoteAddress !== 'string') {
      throw new TypeError('Invalid remoteAddress')
    }

    if (url.searchParams.has('method') && !method.trim()) {
      throw new SyntaxError('method required')
    } else if (url.searchParams.has('ip') && !remoteAddress.trim()) {
      throw new SyntaxError('remoteAddress required')
    }

    const signature = url.searchParams.get('signature')

    url.searchParams.delete('signature')

    if (url.searchParams.has('prefix')) {
      const searchParams = new URLSearchParams()

      // get the parameters keeping the order
      for (const pair of url.searchParams.entries()) {
        if (['expires', 'ip', 'method', 'nonce', 'prefix'].includes(pair[0])) {
          searchParams.append(pair[0], pair[1])
        }
      }

      return (
        signature === this.#toSign(searchParams.toString(), key, algorithm) &&
                Date.now() < url.searchParams.get('expires') &&
                (url.searchParams.has('ip') ? url.searchParams.get('ip') === remoteAddress.trim() : true) &&
                (url.searchParams.has('method') ? url.searchParams.getAll('method').includes(method.trim().toUpperCase()) : true) &&
                decodeURIComponent(url.href).startsWith(this.#decodePrefix(url.searchParams.get('prefix')))
      )
    } else {
      return (
        signature === this.#toSign(url.href, key, algorithm) &&
                Date.now() < url.searchParams.get('expires') &&
                (url.searchParams.has('ip') ? url.searchParams.get('ip') === remoteAddress.trim() : true) &&
                (url.searchParams.has('method') ? url.searchParams.getAll('method').includes(method.trim().toUpperCase()) : true)
      )
    }
  }

  /**
   * @method
   * @param {string} prefix - A prefix encodes a scheme (either http:// or https://), {@link Fully_qualified_domain_name FQDN}, and an optional {@link https://developer.mozilla.org/en-US/docs/Web/API/URL/pathname path}. Ending the path with a / is optional but recommended. The prefix shouldn't include query parameters or fragments such as ? or #
   * @param {Object} [options]
   * @param {string} [options.accessControlAllowMethods=*] - {@link https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Methods Access control allow methods}
   * @param {string} [options.algorithm=sha512] - One of the supported {@link https://nodejs.org/api/crypto.html#cryptogethashes hash algorithms}
   * @param {key} [options.key=require('os').networkInterfaces().eth0[0]?.mac] - One of the supported {@link https://nodejs.org/api/crypto.html#cryptocreatehmacalgorithm-key-options key types}
   * @param {string} [options.nonce] - Use random {@link https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes Number Once}
   * @param {string} [options.remoteAddress] - {@link https://developer.mozilla.org/en-US/docs/Glossary/IP_Address Client IP}
   * @param {number} [options.ttl=86400] - {@link https://wikipedia.org/wiki/Time_to_live Time to Live} in seconds
   *
   * @throws {TypeError} Invalid prefix
   * @throws {TypeError} Invalid accessControlAllowMethods
   * @throws {TypeError} Invalid algorithm
   * @throws {TypeError} Invalid key
   * @throws {TypeError} Invalid nonce
   * @throws {TypeError} Invalid remoteAddress
   * @throws {TypeError} Invalid ttl
   *
   * @return {string} Signed cookie
   */
  signCookie (
    prefix,
    {
      accessControlAllowMethods = '*',
      algorithm = this.#algorithm,
      key = this.#key,
      nonce = '',
      remoteAddress = '',
      ttl = this.#ttl
    } = {}
  ) {
    if (typeof prefix !== 'string') {
      throw new TypeError('Invalid prefix')
    } else if (!new RegExp(`^\\s*(\\*|(${this.#HTTPMethods.join('|')})(\\s*,\\s*(${this.#HTTPMethods.join('|')}))*)\\s*$`, 'i').test(accessControlAllowMethods)) {
      throw new TypeError('Invalid accessControlAllowMethods')
    } else if (typeof nonce !== 'string') {
      throw new TypeError('Invalid nonce')
    } else if (typeof remoteAddress !== 'string') {
      throw new TypeError('Invalid remoteAddress')
    } else if (!Number.isSafeInteger(ttl) || ttl < 1) {
      throw new TypeError('Invalid ttl')
    }

    const cookie = new URLSearchParams()

    cookie.set('expires', this.#timestamp(ttl))
    if (remoteAddress.trim()) cookie.set('ip', remoteAddress.trim())
    if (accessControlAllowMethods.trim() && accessControlAllowMethods.trim() !== '*') [...new Set(accessControlAllowMethods.split(',').map(method => method.trim().toUpperCase()))].forEach(method => cookie.append('method', method))
    if (nonce.trim()) cookie.set('nonce', nonce.trim())
    cookie.set('prefix', this.#encodePrefix(prefix.trim()))

    cookie.set('signature', this.#toSign(cookie.toString(), key, algorithm))

    return cookie.toString()
  }

  /**
   * @method
   * @param {string} url - Requisition {@link https://nodejs.org/api/url.html#url-strings-and-url-objects URL}
   * @param {string} cookie - Signed {@link https://developer.mozilla.org/pt-BR/docs/Web/HTTP/Cookies cookie}
   * @param {Object} [options]
   * @param {string} [options.algorithm=sha512] - One of the supported {@link https://nodejs.org/api/crypto.html#cryptogethashes hash algorithms}
   * @param {key} [options.key=require('os').networkInterfaces().eth0[0]?.mac] - One of the supported {@link https://nodejs.org/api/crypto.html#cryptocreatehmacalgorithm-key-options key types}
   * @param {string} [options.method] - {@link https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods HTTP request methods}
   * @param {string} [options.remoteAddress] - {@link https://developer.mozilla.org/en-US/docs/Glossary/IP_Address Client IP}
   *
   * @throws {TypeError} Invalid url
   * @throws {TypeError} Invalid cookie
   * @throws {TypeError} Invalid algorithm
   * @throws {TypeError} Invalid key
   * @throws {TypeError} Invalid method
   * @throws {TypeError} Invalid remoteAddress
   * @throws {Error} method required
   * @throws {Error} remoteAddress required
   *
   * @return {boolean}
   */
  verifyCookie (
    url,
    cookie,
    {
      algorithm = this.#algorithm,
      key = this.#key,
      method = '',
      remoteAddress = ''
    } = {}
  ) {
    cookie = new URLSearchParams(cookie)
    url = new URL(url)

    if (!cookie.has('prefix') || !cookie.has('expires') || !cookie.has('signature')) {
      throw new TypeError('Invalid cookie')
    } else if (typeof method !== 'string' || !['', ...this.#HTTPMethods].includes(method.trim().toUpperCase())) {
      throw new TypeError('Invalid method')
    } else if (typeof remoteAddress !== 'string') {
      throw new TypeError('Invalid remoteAddress')
    }

    if (cookie.has('method') && !method.trim()) {
      throw new SyntaxError('method required')
    } else if (cookie.has('ip') && !remoteAddress.trim()) {
      throw new SyntaxError('remoteAddress required')
    }

    const signature = cookie.get('signature')

    cookie.delete('signature')

    return (
      signature === this.#toSign(cookie.toString(), key, algorithm) &&
            Date.now() < cookie.get('expires') &&
            (cookie.has('ip') ? cookie.get('ip') === remoteAddress.trim() : true) &&
            (cookie.has('method') ? cookie.getAll('method').includes(method.trim().toUpperCase()) : true) &&
            decodeURIComponent(url.href).startsWith(this.#decodePrefix(cookie.get('prefix')))
    )
  }
}

module.exports = SignedAccess
