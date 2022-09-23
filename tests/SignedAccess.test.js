'use strict'

const SignedAccess = require('../src/SignedAccess.js')

const signedAccess = new SignedAccess()

describe('constructor', () => {
  test('type guards', () => {
    ['xyz', 0, false, null].forEach(input => expect(() => new SignedAccess({ algorithm: input })).toThrow('Invalid algorithm'));
    ['xyz', -1, false, null].forEach(input => expect(() => new SignedAccess({ ttl: input })).toThrow('Invalid ttl'));
    [0, false, null].forEach(input => expect(() => new SignedAccess({ key: input })).toThrow('Invalid key'))
  })

  test('default values', () => {
    const signedAccess = new SignedAccess()

    expect(signedAccess.algorithm).toBe('sha512')
    expect(signedAccess.ttl).toBe(86400)
    expect(signedAccess.key).toBe(require('os').networkInterfaces().eth0[0].mac)
  })

  test('custom values', () => {
    const signedAccess = new SignedAccess({
      algorithm: 'md5',
      ttl: 1,
      key: 'xyz'
    })

    expect(signedAccess.algorithm).toBe('md5')
    expect(signedAccess.ttl).toBe(1)
    expect(signedAccess.key).toBe('xyz')

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
    [undefined, 0, false, null].forEach(input => expect(() => signedAccess.signURL(input)).toThrow('Invalid URL'));
    ['xyz', 0, false, null].forEach(input => expect(() => signedAccess.signURL(url, { algorithm: input })).toThrow('Invalid algorithm'));
    ['tomorrow', 0, false, null].forEach(input => expect(() => signedAccess.signURL(url, { ttl: input })).toThrow('Invalid ttl'));
    [127001, 0, false, null].forEach(input => expect(() => signedAccess.signURL(url, { ip: input })).toThrow('Invalid ip'));
    [0, false, null].forEach(input => expect(() => signedAccess.signURL(url, { key: input })).toThrow('Invalid key'));
    ['GETTER', 0, false, null].forEach(input => expect(() => signedAccess.signURL(url, { methods: input })).toThrow('Invalid methods'));
    ['xyz', -2, false, null].forEach(input => expect(() => signedAccess.signURL(url, { nonce: input })).toThrow('Invalid nonce'));
    ['/github/', 0, false, null].forEach(input => expect(() => signedAccess.signURL(url, { pathname: input })).toThrow('Invalid pathname'))
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
    const ip = '142.251.129.78'
    const methods = ['GET', 'POST']
    const nonce = 1
    const pathname = '/JadsonLucena/'

    let signedURL = signedAccess.signURL(url, {
      ttl,
      ip,
      methods,
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
    expect(searchParams.get('ip')).toBe(ip)
    expect(searchParams.getAll('method').sort()).toEqual(methods.sort())
    expect(+searchParams.get('nonce')).toBe(nonce)
    expect(searchParams.get('prefix')).toMatch(/[A-Za-z0-9-_.~]+/)
    expect(searchParams.get('signature')).toMatch(/[A-Za-z0-9-_.~]+/)
  })
})

describe('verifyURL', () => {
  const url = 'https://github.com/JadsonLucena/SignedAccess.js?foo=bar#id'

  test('type guards', () => {
    const signedURL = signedAccess.signURL(url);

    [undefined, 0, false, null].forEach(input => expect(() => signedAccess.verifyURL(input)).toThrow('Invalid URL'));
    ['xyz', 0, false, null].forEach(input => expect(() => signedAccess.verifyURL(signedURL, { algorithm: input })).toThrow('Invalid algorithm'));
    [127001, 0, false, null].forEach(input => expect(() => signedAccess.verifyURL(signedURL, { ip: input })).toThrow('Invalid ip'));
    [0, false, null].forEach(input => expect(() => signedAccess.verifyURL(signedURL, { key: input })).toThrow('Invalid key'));
    ['GETTER', 0, false, null].forEach(input => expect(() => signedAccess.verifyURL(signedURL, { method: input })).toThrow('Invalid method'))
  })

  test('default values', () => {
    const signedURL = signedAccess.signURL(url)

    expect(signedAccess.verifyURL(signedURL)).toBeTruthy()
    expect(signedAccess.verifyURL(signedURL, { algorithm: 'sha1' })).toBeFalsy()
    expect(signedAccess.verifyURL(signedURL, { ip: '127.0.0.1' })).toBeTruthy() // should be ignored
    expect(signedAccess.verifyURL(signedURL, { key: 'anything' })).toBeFalsy()
    expect(signedAccess.verifyURL(signedURL, { method: 'POST' })).toBeTruthy() // should be ignored
  })

  test('custom values', () => {
    let signedURL = signedAccess.signURL(url, { algorithm: 'sha1' })

    expect(signedAccess.verifyURL(signedURL)).toBeFalsy()
    expect(signedAccess.verifyURL(signedURL, { algorithm: 'sha1' })).toBeTruthy()

    signedURL = signedAccess.signURL(url, { ip: '127.0.0.1' })

    expect(() => signedAccess.verifyURL(signedURL)).toThrow('ip required')
    expect(signedAccess.verifyURL(signedURL, { ip: '142.251.129.78' })).toBeFalsy()
    expect(signedAccess.verifyURL(signedURL, { ip: '127.0.0.1' })).toBeTruthy()

    signedURL = signedAccess.signURL(url, { key: 'xyz' })

    expect(signedAccess.verifyURL(signedURL)).toBeFalsy()
    expect(signedAccess.verifyURL(signedURL, { key: 'xyz' })).toBeTruthy()

    signedURL = signedAccess.signURL(url, { methods: 'POST' })

    expect(() => signedAccess.verifyURL(signedURL)).toThrow('method required')
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
      ip: '127.0.0.1',
      methods: ['POST', 'PUT'],
      nonce: 999,
      pathname: '/JadsonLucena/'
    })

    mockSignedURL = `https://github.com/JadsonLucena/WebSocket.js?${new URL(signedURL).searchParams.toString()}`

    expect(() => signedAccess.verifyURL(mockSignedURL)).toThrow('ip required')
    expect(() => signedAccess.verifyURL(mockSignedURL, { ip: '142.251.129.78' })).toThrow('method required')
    expect(signedAccess.verifyURL(mockSignedURL, {
      ip: '142.251.129.78',
      method: 'DELETE'
    })).toBeFalsy()
    expect(signedAccess.verifyURL(mockSignedURL, {
      ip: '127.0.0.1',
      method: 'GET'
    })).toBeFalsy()
    expect(signedAccess.verifyURL(mockSignedURL, {
      ip: '142.251.129.78',
      method: 'POST'
    })).toBeFalsy()
    expect(signedAccess.verifyURL(mockSignedURL, {
      ip: '127.0.0.1',
      method: 'PUT'
    })).toBeTruthy()
  })
})

describe('signCookie', () => {
  const prefix = 'https://github.com/JadsonLucena/'

  test('type guards', () => {
    [undefined, 0, false, null].forEach(input => expect(() => signedAccess.signCookie(input)).toThrow('Invalid prefix'));
    ['xyz', 0, false, null].forEach(input => expect(() => signedAccess.signCookie(prefix, { algorithm: input })).toThrow('Invalid algorithm'));
    ['tomorrow', 0, false, null].forEach(input => expect(() => signedAccess.signCookie(prefix, { ttl: input })).toThrow('Invalid ttl'));
    [127001, 0, false, null].forEach(input => expect(() => signedAccess.signCookie(prefix, { ip: input })).toThrow('Invalid ip'));
    [0, false, null].forEach(input => expect(() => signedAccess.signCookie(prefix, { key: input })).toThrow('Invalid key'));
    ['GETTER', 0, false, null].forEach(input => expect(() => signedAccess.signCookie(prefix, { methods: input })).toThrow('Invalid methods'));
    ['xyz', -2, false, null].forEach(input => expect(() => signedAccess.signCookie(prefix, { nonce: input })).toThrow('Invalid nonce'))
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
    const ip = '142.251.129.78'
    const methods = ['GET', 'POST']
    const nonce = 1

    const signedCookie = signedAccess.signCookie(prefix, {
      ttl,
      ip,
      methods,
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
    expect(searchParams.get('ip')).toBe(ip)
    expect(searchParams.getAll('method').sort()).toEqual(methods.sort())
    expect(+searchParams.get('nonce')).toBe(nonce)
    expect(searchParams.get('prefix')).toMatch(/[A-Za-z0-9-_.~]+/)
    expect(searchParams.get('signature')).toMatch(/[A-Za-z0-9-_.~]+/)
  })
})

describe('verifyCookie', () => {
  const prefix = 'https://github.com/JadsonLucena/'
  const mockURL = 'https://github.com/JadsonLucena/SignedAccess.js?foo=bar#id'

  test('type guards', () => {
    const signedCookie = signedAccess.signCookie(prefix);

    [undefined, 0, false, null].forEach(input => expect(() => signedAccess.verifyCookie(input, signedCookie)).toThrow('Invalid URL'));
    [undefined, 0, false, null].forEach(input => expect(() => signedAccess.verifyCookie(mockURL, input)).toThrow('Invalid cookie'));
    ['xyz', 0, false, null].forEach(input => expect(() => signedAccess.verifyCookie(mockURL, signedCookie, { algorithm: input })).toThrow('Invalid algorithm'));
    [127001, 0, false, null].forEach(input => expect(() => signedAccess.verifyCookie(mockURL, signedCookie, { ip: input })).toThrow('Invalid ip'));
    [0, false, null].forEach(input => expect(() => signedAccess.verifyCookie(mockURL, signedCookie, { key: input })).toThrow('Invalid key'));
    ['GETTER', 0, false, null].forEach(input => expect(() => signedAccess.verifyCookie(mockURL, signedCookie, { method: input })).toThrow('Invalid method'))
  })

  test('default values', () => {
    let signedCookie = signedAccess.signCookie(prefix)

    expect(signedAccess.verifyCookie(mockURL, signedCookie)).toBeTruthy()
    expect(signedAccess.verifyCookie(mockURL, signedCookie, { algorithm: 'sha1' })).toBeFalsy()
    expect(signedAccess.verifyCookie(mockURL, signedCookie, { ip: '127.0.0.1' })).toBeTruthy() // should be ignored
    expect(signedAccess.verifyCookie(mockURL, signedCookie, { key: 'anything' })).toBeFalsy()
    expect(signedAccess.verifyCookie(mockURL, signedCookie, { method: 'POST' })).toBeTruthy() // should be ignored

    signedCookie = signedAccess.signCookie(mockURL)

    expect(signedAccess.verifyCookie(mockURL, signedCookie)).toBeTruthy()
  })

  test('custom values', () => {
    let signedCookie = signedAccess.signCookie(prefix, { algorithm: 'sha256' })

    expect(signedAccess.verifyCookie(mockURL, signedCookie)).toBeFalsy()
    expect(signedAccess.verifyCookie(mockURL, signedCookie, { algorithm: 'sha256' })).toBeTruthy()

    signedCookie = signedAccess.signCookie(prefix, { ip: '127.0.0.1' })

    expect(() => signedAccess.verifyCookie(mockURL, signedCookie)).toThrow('ip required')
    expect(signedAccess.verifyCookie(mockURL, signedCookie, { ip: '142.251.129.78' })).toBeFalsy()
    expect(signedAccess.verifyCookie(mockURL, signedCookie, { ip: '127.0.0.1' })).toBeTruthy()

    signedCookie = signedAccess.signCookie(prefix, { key: 'xyz' })

    expect(signedAccess.verifyCookie(mockURL, signedCookie)).toBeFalsy()
    expect(signedAccess.verifyCookie(mockURL, signedCookie, { key: 'xyz' })).toBeTruthy()

    signedCookie = signedAccess.signCookie(prefix, { methods: 'POST' })

    expect(() => signedAccess.verifyCookie(mockURL, signedCookie)).toThrow('method required')
    expect(signedAccess.verifyCookie(mockURL, signedCookie, { method: 'PATCH' })).toBeFalsy()
    expect(signedAccess.verifyCookie(mockURL, signedCookie, { method: 'POST' })).toBeTruthy()

    signedCookie = signedAccess.signCookie('https://example.com/data')

    expect(signedAccess.verifyCookie('https://example.com/database', signedCookie)).toBeTruthy()
    expect(signedAccess.verifyCookie('https://example.com/data/file1', signedCookie)).toBeTruthy()

    signedCookie = signedAccess.signCookie('https://example.com/data/')

    expect(signedAccess.verifyCookie('https://example.com/database', signedCookie)).toBeFalsy()
    expect(signedAccess.verifyCookie('https://example.com/data/file1', signedCookie)).toBeTruthy()

    signedCookie = signedAccess.signCookie(prefix, {
      ip: '127.0.0.1',
      methods: ['POST', 'PUT'],
      nonce: 111
    })

    expect(() => signedAccess.verifyCookie(mockURL, signedCookie)).toThrow('ip required')
    expect(() => signedAccess.verifyCookie(mockURL, signedCookie, { ip: '142.251.129.78' })).toThrow('method required')
    expect(signedAccess.verifyCookie(mockURL, signedCookie, {
      ip: '142.251.129.78',
      method: 'DELETE'
    })).toBeFalsy()
    expect(signedAccess.verifyCookie(mockURL, signedCookie, {
      ip: '127.0.0.1',
      method: 'GET'
    })).toBeFalsy()
    expect(signedAccess.verifyCookie(mockURL, signedCookie, {
      ip: '142.251.129.78',
      method: 'POST'
    })).toBeFalsy()
    expect(signedAccess.verifyCookie(mockURL, signedCookie, {
      ip: '127.0.0.1',
      method: 'PUT'
    })).toBeTruthy()
  })
})
