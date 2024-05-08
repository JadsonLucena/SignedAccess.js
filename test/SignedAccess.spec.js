'use strict'

const crypto = require('node:crypto')

const SignedAccess = require('../src/SignedAccess.js')

const key = '9x,9Ku9TrUL'

const signedAccess = new SignedAccess(key)

describe('constructor', () => {
  test('type guards', () => {
    ['xpto', 0, false, null].forEach(input => expect(() => new SignedAccess(key, { algorithm: input })).toThrowError(new TypeError('Invalid algorithm')));
    ['xpto', '', 0, Infinity, NaN, false, null].forEach(input => expect(() => new SignedAccess(key, { ttl: input })).toThrow('Invalid ttl'));
    [false, null, undefined].forEach(input => expect(() => new SignedAccess(input)).toThrowError(new TypeError('Invalid key')))

    expect(() => new SignedAccess(undefined, {
      algorithm: null,
      ttl: null
    })).toThrowError(new AggregateError([
      new TypeError('Invalid key'),
      new TypeError('Invalid algorithm'),
      new Error('Invalid ttl')
    ], 'Invalid arguments'))
  })

  test('default values', () => {
    const signedAccess = new SignedAccess(key)

    expect(signedAccess.algorithm).toBe('sha512')
    expect(signedAccess.ttl).toBe(86400)
    expect(signedAccess.key).toBe(key)
  })

  test('custom values', () => {
    const signedAccess = new SignedAccess(key, {
      algorithm: 'md5',
      ttl: 1
    })

    expect(signedAccess.algorithm).toBe('md5')
    expect(signedAccess.ttl).toBe(1)
    expect(signedAccess.key).toBe(key)

    signedAccess.algorithm = 'sha256'
    signedAccess.ttl = 3600
    signedAccess.key = 'abc'

    expect(signedAccess.algorithm).toBe('sha256')
    expect(signedAccess.ttl).toBe(3600)
    expect(signedAccess.key).toBe('abc')
  })
})

describe('signURL', () => {
  const url = 'https://github.com/JadsonLucena/SignedAccess.js?foo=bar&expires=anything&ip=anything&method=anything&nonce=anything&prefix=anything&signature=anything#id'

  test('type guards', () => {
    [undefined, 0, false, null].forEach(input => expect(() => signedAccess.signURL(input)).toThrowError(new TypeError('Invalid URL')));
    ['xpto', 0, false, null].forEach(input => expect(() => signedAccess.signURL(url, { algorithm: input })).toThrowError(new TypeError('Invalid algorithm')));
    ['tomorrow', 0, false, null].forEach(input => expect(() => signedAccess.signURL(url, { ttl: input })).toThrow('Invalid ttl'));
    ['127.000.000.001', '127.0.0.1/24', 'fhqwhgads', 127001, 0, false, null].forEach(input => expect(() => signedAccess.signURL(url, { remoteAddress: input })).toThrow('Invalid remoteAddress'));
    [0, false, null].forEach(input => expect(() => signedAccess.signURL(url, { key: input })).toThrowError(new TypeError('Invalid key')));
    ['GETTER', 0, false, null].forEach(input => expect(() => signedAccess.signURL(url, { accessControlAllowMethods: input })).toThrow('Invalid accessControlAllowMethods'));
    [0, false, null].forEach(input => expect(() => signedAccess.signURL(url, { nonce: input })).toThrowError(new TypeError('Invalid nonce')));
    ['/github/', 0, false, null].forEach(input => expect(() => signedAccess.signURL(url, { pathname: input })).toThrow('Invalid pathname'))

    expect(() => signedAccess.signURL(undefined, {
      accessControlAllowMethods: null,
      algorithm: null,
      key: null,
      nonce: null,
      pathname: null,
      remoteAddress: null,
      ttl: null
    })).toThrowError(new AggregateError([
      new TypeError('Invalid URL'),
      new Error('Invalid accessControlAllowMethods'),
      new TypeError('Invalid algorithm'),
      new TypeError('Invalid nonce'),
      new Error('Invalid pathname'),
      new Error('Invalid remoteAddress'),
      new Error('Invalid ttl')
    ], 'Invalid arguments'))
  })

  test('default values', () => {
    let signedURL = signedAccess.signURL(url)

    signedURL = new URL(signedURL)
    const searchParams = signedURL.searchParams
    const querys = Array.from(searchParams.keys())

    const URLOriginal = new URL(url)

    expect(signedURL.origin).toBe(URLOriginal.origin)
    expect(signedURL.pathname).toBe(URLOriginal.pathname)
    expect(signedURL.hash).toBe(URLOriginal.hash)
    expect(querys.length).toBe(3)
    expect(querys).toContain('foo')
    expect(querys).toContain('expires')
    expect(querys).not.toContain('ip') // reserved searchParams
    expect(querys).not.toContain('method') // reserved searchParams
    expect(querys).not.toContain('nonce') // reserved searchParams
    expect(querys).not.toContain('prefix') // reserved searchParams
    expect(querys).toContain('signature')
    expect(searchParams.get('foo')).toBe('bar')
    expect(searchParams.get('expires')).not.toBe('anything')
    expect(parseInt(searchParams.get('expires'))).toBeGreaterThan(Date.now())
    expect(searchParams.get('signature')).not.toBe('anything')
    expect(searchParams.get('signature')).toMatch(/[A-Za-z0-9-_.~]+/)
  })

  test('custom values', () => {
    const ttl = 3600
    const remoteAddress = '142.251.129.78'
    const accessControlAllowMethods = 'GET,POST'
    const nonce = crypto.randomUUID()
    const pathname = '/JadsonLucena/'

    let signedURL = signedAccess.signURL(url, {
      ttl,
      remoteAddress,
      accessControlAllowMethods,
      nonce,
      pathname
    })

    signedURL = new URL(signedURL)
    const searchParams = signedURL.searchParams
    const querys = Array.from(searchParams.keys())

    const URLOriginal = new URL(url)

    expect(signedURL.origin).toBe(URLOriginal.origin)
    expect(signedURL.pathname).toBe(URLOriginal.pathname)
    expect(signedURL.hash).toBe(URLOriginal.hash)
    expect(querys.length).toBe(8)
    expect(querys).toContain('foo')
    expect(querys).toContain('expires')
    expect(querys).toContain('ip')
    expect(querys).toContain('method')
    expect(querys).toContain('nonce')
    expect(querys).toContain('prefix')
    expect(querys).toContain('signature')
    expect(searchParams.get('foo')).toBe('bar')
    expect(parseInt(searchParams.get('expires'))).toBeGreaterThan(Date.now())
    expect(searchParams.get('ip')).toBe(remoteAddress)
    expect(searchParams.getAll('method').sort()).toEqual(accessControlAllowMethods.split(',').sort())
    expect(searchParams.get('nonce')).toBe(nonce)
    expect(searchParams.get('prefix')).toMatch(/[A-Za-z0-9-_.~]+/)
    expect(searchParams.get('signature')).toMatch(/[A-Za-z0-9-_.~]+/)
  })
})

describe('verifyURL', () => {
  const url = 'https://github.com/JadsonLucena/SignedAccess.js?foo=bar#id'

  test('type guards', () => {
    const signedURL = signedAccess.signURL(url);

    [undefined, 0, false, null].forEach(input => expect(() => signedAccess.verifyURL(input)).toThrowError(new TypeError('Invalid URL')));
    ['xpto', 0, false, null].forEach(input => expect(() => signedAccess.verifyURL(signedURL, { algorithm: input })).toThrowError(new TypeError('Invalid algorithm')));
    ['127.000.000.001', '127.0.0.1/24', 'fhqwhgads', 127001, 0, false, null].forEach(input => expect(() => signedAccess.verifyURL(signedURL, { remoteAddress: input })).toThrow('Invalid remoteAddress'));
    [0, false, null].forEach(input => expect(() => signedAccess.verifyURL(signedURL, { key: input })).toThrowError(new TypeError('Invalid key')));
    ['GETTER', 0, false, null].forEach(input => expect(() => signedAccess.verifyURL(signedURL, { method: input })).toThrowError(new TypeError('Invalid method')))

    expect(() => signedAccess.verifyURL(undefined, {
      algorithm: null,
      key: null,
      method: null,
      remoteAddress: null
    })).toThrowError(new AggregateError([
      new TypeError('Invalid URL'),
      new TypeError('Invalid method'),
      new Error('Invalid remoteAddress')
    ], 'Invalid arguments'))

    expect(() => signedAccess.verifyURL(signedAccess.signURL(url, {
      accessControlAllowMethods: 'GET',
      remoteAddress: '127.0.0.1'
    }))).toThrowError(new AggregateError([
      new Error('method required'),
      new Error('remoteAddress required')
    ], 'Invalid URL'))
  })

  test('default values', () => {
    const signedURL = signedAccess.signURL(url)

    expect(signedAccess.verifyURL(signedURL)).toBeTruthy()
    expect(signedAccess.verifyURL(signedURL, { algorithm: 'sha1' })).toBeFalsy()
    expect(signedAccess.verifyURL(signedURL, { remoteAddress: '127.0.0.1' })).toBeTruthy() // should be ignored
    expect(signedAccess.verifyURL(signedURL, { key: 'anything' })).toBeFalsy()
    expect(signedAccess.verifyURL(signedURL, { method: 'POST' })).toBeTruthy() // should be ignored
  })

  test('custom values', () => {
    let signedURL = signedAccess.signURL(url, { algorithm: 'sha1' })

    expect(signedAccess.verifyURL(signedURL)).toBeFalsy()
    expect(signedAccess.verifyURL(signedURL, { algorithm: 'sha1' })).toBeTruthy()

    signedURL = signedAccess.signURL(url, { remoteAddress: '127.0.0.1' })

    expect(() => signedAccess.verifyURL(signedURL)).toThrowError(new Error('remoteAddress required'))
    expect(signedAccess.verifyURL(signedURL, { remoteAddress: '142.251.129.78' })).toBeFalsy()
    expect(signedAccess.verifyURL(signedURL, { remoteAddress: '127.0.0.1' })).toBeTruthy()

    signedURL = signedAccess.signURL(url, { key: 'xpto' })

    expect(signedAccess.verifyURL(signedURL)).toBeFalsy()
    expect(signedAccess.verifyURL(signedURL, { key: 'xpto' })).toBeTruthy()

    signedURL = signedAccess.signURL(url, { accessControlAllowMethods: 'POST' })

    expect(() => signedAccess.verifyURL(signedURL)).toThrowError(new Error('method required'))
    expect(signedAccess.verifyURL(signedURL, { method: 'PATCH' })).toBeFalsy()
    expect(signedAccess.verifyURL(signedURL, { method: 'POST' })).toBeTruthy()

    signedURL = signedAccess.signURL('https://example.com/data/file1', {
      pathname: '/data'
    })

    let mockSignedURL = `https://example.com/database?${new URL(signedURL).searchParams.toString()}`

    expect(signedAccess.verifyURL(mockSignedURL)).toBeTruthy()

    mockSignedURL = `https://example.com/data/file2?${new URL(signedURL).searchParams.toString()}`

    expect(signedAccess.verifyURL(mockSignedURL)).toBeTruthy()

    signedURL = signedAccess.signURL('https://example.com/data/file1', {
      pathname: '/data/'
    })

    mockSignedURL = `https://example.com/database?${new URL(signedURL).searchParams.toString()}`

    expect(signedAccess.verifyURL(mockSignedURL)).toBeFalsy()

    mockSignedURL = `https://example.com/data/file2?${new URL(signedURL).searchParams.toString()}`

    expect(signedAccess.verifyURL(mockSignedURL)).toBeTruthy()

    signedURL = signedAccess.signURL(url, {
      remoteAddress: '127.0.0.1',
      accessControlAllowMethods: 'POST, PUT',
      nonce: crypto.randomUUID(),
      pathname: '/JadsonLucena/'
    })

    mockSignedURL = `https://github.com/JadsonLucena/WebSocket.js?${new URL(signedURL).searchParams.toString()}`

    expect(() => signedAccess.verifyURL(mockSignedURL, { method: 'POST' })).toThrowError(new Error('remoteAddress required'))
    expect(() => signedAccess.verifyURL(mockSignedURL, { remoteAddress: '142.251.129.78' })).toThrowError(new Error('method required'))
    expect(signedAccess.verifyURL(mockSignedURL, {
      remoteAddress: '142.251.129.78',
      method: 'DELETE'
    })).toBeFalsy()
    expect(signedAccess.verifyURL(mockSignedURL, {
      remoteAddress: '127.0.0.1',
      method: 'GET'
    })).toBeFalsy()
    expect(signedAccess.verifyURL(mockSignedURL, {
      remoteAddress: '142.251.129.78',
      method: 'POST'
    })).toBeFalsy()
    expect(signedAccess.verifyURL(mockSignedURL, {
      remoteAddress: '127.0.0.1',
      method: 'PUT'
    })).toBeTruthy()
  })
})

describe('signCookie', () => {
  const prefix = 'https://github.com/JadsonLucena/'

  test('type guards', () => {
    [undefined, 0, false, null].forEach(input => expect(() => signedAccess.signCookie(input)).toThrowError(new TypeError('Invalid prefix')));
    ['xpto', 0, false, null].forEach(input => expect(() => signedAccess.signCookie(prefix, { algorithm: input })).toThrowError(new TypeError('Invalid algorithm')));
    ['tomorrow', 0, false, null].forEach(input => expect(() => signedAccess.signCookie(prefix, { ttl: input })).toThrow('Invalid ttl'));
    ['127.000.000.001', '127.0.0.1/24', 'fhqwhgads', 127001, 0, false, null].forEach(input => expect(() => signedAccess.signCookie(prefix, { remoteAddress: input })).toThrow('Invalid remoteAddress'));
    [0, false, null].forEach(input => expect(() => signedAccess.signCookie(prefix, { key: input })).toThrowError(new TypeError('Invalid key')));
    ['GETTER', 0, false, null].forEach(input => expect(() => signedAccess.signCookie(prefix, { accessControlAllowMethods: input })).toThrow('Invalid accessControlAllowMethods'));
    [0, false, null].forEach(input => expect(() => signedAccess.signCookie(prefix, { nonce: input })).toThrowError(new TypeError('Invalid nonce')))

    expect(() => signedAccess.signCookie(prefix, {
      accessControlAllowMethods: null,
      algorithm: null,
      key: null,
      nonce: null,
      remoteAddress: null,
      ttl: null
    })).toThrowError(new AggregateError([
      new TypeError('Invalid prefix'),
      new Error('Invalid accessControlAllowMethods'),
      new TypeError('Invalid algorithm'),
      new TypeError('Invalid nonce'),
      new Error('Invalid remoteAddress'),
      new Error('Invalid ttl')
    ], 'Invalid arguments'))
  })

  test('default values', () => {
    const signedCookie = signedAccess.signCookie(prefix)

    const searchParams = new URLSearchParams(signedCookie)
    const querys = Array.from(searchParams.keys())

    expect(querys.length).toBe(3)
    expect(querys).toContain('expires')
    expect(querys).toContain('prefix')
    expect(querys).toContain('signature')
    expect(parseInt(searchParams.get('expires'))).toBeGreaterThan(Date.now())
    expect(searchParams.get('prefix')).toMatch(/[A-Za-z0-9-_.~]+/)
    expect(searchParams.get('signature')).toMatch(/[A-Za-z0-9-_.~]+/)
  })

  test('custom values', () => {
    const ttl = 3600
    const remoteAddress = '142.251.129.78'
    const accessControlAllowMethods = 'GET,POST'
    const nonce = crypto.randomUUID()

    const signedCookie = signedAccess.signCookie(prefix, {
      ttl,
      remoteAddress,
      accessControlAllowMethods,
      nonce
    })

    const searchParams = new URLSearchParams(signedCookie)
    const querys = Array.from(searchParams.keys())

    expect(querys.length).toBe(7)
    expect(querys).toContain('expires')
    expect(querys).toContain('ip')
    expect(querys).toContain('method')
    expect(querys).toContain('nonce')
    expect(querys).toContain('prefix')
    expect(querys).toContain('signature')
    expect(parseInt(searchParams.get('expires'))).toBeGreaterThan(Date.now())
    expect(searchParams.get('ip')).toBe(remoteAddress)
    expect(searchParams.getAll('method').sort()).toEqual(accessControlAllowMethods.split(',').sort())
    expect(searchParams.get('nonce')).toBe(nonce)
    expect(searchParams.get('prefix')).toMatch(/[A-Za-z0-9-_.~]+/)
    expect(searchParams.get('signature')).toMatch(/[A-Za-z0-9-_.~]+/)
  })
})

describe('verifyCookie', () => {
  const prefix = 'https://github.com/JadsonLucena/'
  const mockURL = 'https://github.com/JadsonLucena/SignedAccess.js?foo=bar#id'

  test('type guards', () => {
    const signedCookie = signedAccess.signCookie(prefix);

    [undefined, 0, false, null].forEach(input => expect(() => signedAccess.verifyCookie(input, signedCookie)).toThrowError(new TypeError('Invalid URL')));
    [undefined, 0, false, null].forEach(input => expect(() => signedAccess.verifyCookie(mockURL, input)).toThrowError(new TypeError('Invalid cookie')));
    ['xpto', 0, false, null].forEach(input => expect(() => signedAccess.verifyCookie(mockURL, signedCookie, { algorithm: input })).toThrowError(new TypeError('Invalid algorithm')));
    ['127.000.000.001', '127.0.0.1/24', 'fhqwhgads', 127001, 0, false, null].forEach(input => expect(() => signedAccess.verifyCookie(mockURL, signedCookie, { remoteAddress: input })).toThrow('Invalid remoteAddress'));
    [0, false, null].forEach(input => expect(() => signedAccess.verifyCookie(mockURL, signedCookie, { key: input })).toThrowError(new TypeError('Invalid key')));
    ['GETTER', 0, false, null].forEach(input => expect(() => signedAccess.verifyCookie(mockURL, signedCookie, { method: input })).toThrowError(new TypeError('Invalid method')))

    expect(() => signedAccess.verifyCookie(undefined, undefined, {
      algorithm: null,
      key: null,
      method: null,
      remoteAddress: null
    })).toThrowError(new AggregateError([
      new TypeError('Invalid URL'),
      new TypeError('Invalid cookie'),
      new TypeError('Invalid method'),
      new Error('Invalid remoteAddress')
    ], 'Invalid arguments'))

    expect(() => signedAccess.verifyCookie(mockURL, signedAccess.signCookie(prefix, {
      accessControlAllowMethods: 'GET',
      remoteAddress: '127.0.0.1'
    }))).toThrowError(new AggregateError([
      new Error('method required'),
      new Error('remoteAddress required')
    ], 'Invalid cookie'))
  })

  test('default values', () => {
    let signedCookie = signedAccess.signCookie(prefix)

    expect(signedAccess.verifyCookie(mockURL, signedCookie)).toBeTruthy()
    expect(signedAccess.verifyCookie(mockURL, signedCookie, { algorithm: 'sha1' })).toBeFalsy()
    expect(signedAccess.verifyCookie(mockURL, signedCookie, { remoteAddress: '127.0.0.1' })).toBeTruthy() // should be ignored
    expect(signedAccess.verifyCookie(mockURL, signedCookie, { key: 'anything' })).toBeFalsy()
    expect(signedAccess.verifyCookie(mockURL, signedCookie, { method: 'POST' })).toBeTruthy() // should be ignored

    signedCookie = signedAccess.signCookie(mockURL)

    expect(signedAccess.verifyCookie(mockURL, signedCookie)).toBeTruthy()
  })

  test('custom values', () => {
    let signedCookie = signedAccess.signCookie(prefix, { algorithm: 'sha256' })

    expect(signedAccess.verifyCookie(mockURL, signedCookie)).toBeFalsy()
    expect(signedAccess.verifyCookie(mockURL, signedCookie, { algorithm: 'sha256' })).toBeTruthy()

    signedCookie = signedAccess.signCookie(prefix, { remoteAddress: '127.0.0.1' })

    expect(() => signedAccess.verifyCookie(mockURL, signedCookie)).toThrowError(new Error('remoteAddress required'))
    expect(signedAccess.verifyCookie(mockURL, signedCookie, { remoteAddress: '142.251.129.78' })).toBeFalsy()
    expect(signedAccess.verifyCookie(mockURL, signedCookie, { remoteAddress: '127.0.0.1' })).toBeTruthy()

    signedCookie = signedAccess.signCookie(prefix, { key: 'xpto' })

    expect(signedAccess.verifyCookie(mockURL, signedCookie)).toBeFalsy()
    expect(signedAccess.verifyCookie(mockURL, signedCookie, { key: 'xpto' })).toBeTruthy()

    signedCookie = signedAccess.signCookie(prefix, { accessControlAllowMethods: 'POST' })

    expect(() => signedAccess.verifyCookie(mockURL, signedCookie)).toThrowError(new Error('method required'))
    expect(signedAccess.verifyCookie(mockURL, signedCookie, { method: 'PATCH' })).toBeFalsy()
    expect(signedAccess.verifyCookie(mockURL, signedCookie, { method: 'POST' })).toBeTruthy()

    signedCookie = signedAccess.signCookie('https://example.com/data')

    expect(signedAccess.verifyCookie('https://example.com/database', signedCookie)).toBeTruthy()
    expect(signedAccess.verifyCookie('https://example.com/data/file1', signedCookie)).toBeTruthy()

    signedCookie = signedAccess.signCookie('https://example.com/data/')

    expect(signedAccess.verifyCookie('https://example.com/database', signedCookie)).toBeFalsy()
    expect(signedAccess.verifyCookie('https://example.com/data/file1', signedCookie)).toBeTruthy()

    signedCookie = signedAccess.signCookie(prefix, {
      remoteAddress: '127.0.0.1',
      accessControlAllowMethods: 'POST, PUT',
      nonce: crypto.randomUUID()
    })

    expect(() => signedAccess.verifyCookie(mockURL, signedCookie, { method: 'POST' })).toThrowError(new Error('remoteAddress required'))
    expect(() => signedAccess.verifyCookie(mockURL, signedCookie, { remoteAddress: '142.251.129.78' })).toThrowError(new Error('method required'))
    expect(signedAccess.verifyCookie(mockURL, signedCookie, {
      remoteAddress: '142.251.129.78',
      method: 'DELETE'
    })).toBeFalsy()
    expect(signedAccess.verifyCookie(mockURL, signedCookie, {
      remoteAddress: '127.0.0.1',
      method: 'GET'
    })).toBeFalsy()
    expect(signedAccess.verifyCookie(mockURL, signedCookie, {
      remoteAddress: '142.251.129.78',
      method: 'POST'
    })).toBeFalsy()
    expect(signedAccess.verifyCookie(mockURL, signedCookie, {
      remoteAddress: '127.0.0.1',
      method: 'PUT'
    })).toBeTruthy()
  })
})
