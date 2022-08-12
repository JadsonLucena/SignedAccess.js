const SignedAccess = require('../src/SignedAccess.js');


var signedAccess = new SignedAccess();


describe('constructor', () => {

	test('type guards', () => {

		['xyz', 0, false, null].forEach(input => expect(() => new SignedAccess({ algorithm: input })).toThrow());
		['xyz', -1, false, null].forEach(input => expect(() => new SignedAccess({ ttl: input })).toThrow('Invalid ttl'));
		[0, false, null].forEach(input => expect(() => new SignedAccess({ key: input })).toThrow());


		let signedAccess = new SignedAccess();

		['xyz', 0, false, null].forEach(input => expect(() => signedAccess.algorithm = input).toThrow());
		['xyz', -1, false, null].forEach(input => expect(() => signedAccess.ttl = input).toThrow('Invalid ttl'));
		[0, false, null].forEach(input => expect(() => signedAccess.key = input).toThrow());

	});

	test('default values', () => {

		const signedAccess = new SignedAccess();

		expect(signedAccess.algorithm).toBe('sha512');
		expect(signedAccess.ttl).toBe(86400);
		expect(signedAccess.key).toBe(require('os').networkInterfaces()['eth0'][0].mac);

	});

	test('custom values', () => {

		const signedAccess = new SignedAccess({
			algorithm: 'md5',
			ttl: 1,
			key: 'xyz'
		});

		expect(signedAccess.algorithm).toBe('md5');
		expect(signedAccess.ttl).toBe(1);
		expect(signedAccess.key).toBe('xyz');


		signedAccess.algorithm = 'sha256';
		signedAccess.ttl = 3600;
		signedAccess.key = 'abc';

		expect(signedAccess.algorithm).toBe('sha256');
		expect(signedAccess.ttl).toBe(3600);
		expect(signedAccess.key).toBe('abc');

	});

});

describe('signURL', () => {

	let url = 'https://github.com/JadsonLucena/SignedAccess.js?foo=bar&expires=anything&ip=anything&method=anything&nonce=anything&prefix=anything&signature=anything#id';


	test('type guards', () => {

		[undefined, 0, false, null].forEach(input => expect(() => signedAccess.signURL(input)).toThrow('Invalid URL'));
		['xyz', 0, false, null].forEach(input => expect(() => signedAccess.signURL(url, { algorithm: input })).toThrow());
		['tomorrow', 0, false, null].forEach(input => expect(() => signedAccess.signURL(url, { ttl: input })).toThrow('Invalid ttl'));
		[127001, 0, false, null].forEach(input => expect(() => signedAccess.signURL(url, { ip: input })).toThrow('Invalid ip'));
		[0, false, null].forEach(input => expect(() => signedAccess.signURL(url, { key: input })).toThrow());
		['GETTER', 0, false, null].forEach(input => expect(() => signedAccess.signURL(url, { methods: input })).toThrow('Invalid methods'));
		['xyz', -2, false, null].forEach(input => expect(() => signedAccess.signURL(url, { nonce: input })).toThrow('Invalid nonce'));
		['/github/', 0, false, null].forEach(input => expect(() => signedAccess.signURL(url, { pathname: input })).toThrow('Invalid pathname'));

	});

	test('default values', () => {

		let urlSigned = signedAccess.signURL(url);

		urlSigned = new URL(urlSigned);
		let searchParams = urlSigned.searchParams;
		let querys = Array.from(searchParams.keys());

		let URLOriginal = new URL(url);

		expect(urlSigned.origin).toBe(URLOriginal.origin);
		expect(urlSigned.pathname).toBe(URLOriginal.pathname);
		expect(urlSigned.hash).toBe(URLOriginal.hash);
		expect(querys.length).toBe(3);
		expect(querys).toContain('foo');
		expect(querys).toContain('expires');
		expect(querys).not.toContain('ip'); // reserved searchParams
		expect(querys).not.toContain('method'); // reserved searchParams
		expect(querys).not.toContain('nonce'); // reserved searchParams
		expect(querys).not.toContain('prefix'); // reserved searchParams
		expect(querys).toContain('signature');
		expect(searchParams.get('foo')).toBe('bar');
		expect(searchParams.get('expires')).not.toBe('anything');
		expect(parseInt(searchParams.get('expires'))).toBeGreaterThan(Date.now());
		expect(searchParams.get('signature')).not.toBe('anything');
		expect(searchParams.get('signature')).toMatch(/[A-Za-z0-9-_.~]+/);

	});

	test('custom values', () => {

		let ttl = 3600;
		let ip = '142.251.129.78';
		let methods = ['GET', 'POST'];
		let nonce = 1;
		let pathname = '/JadsonLucena/';

		let urlSigned = signedAccess.signURL(url, {
			ttl,
			ip,
			methods,
			nonce,
			pathname
		});

		urlSigned = new URL(urlSigned)
		let searchParams = urlSigned.searchParams;
		let querys = Array.from(searchParams.keys());

		let URLOriginal = new URL(url);

		expect(urlSigned.origin).toBe(URLOriginal.origin);
		expect(urlSigned.pathname).toBe(URLOriginal.pathname);
		expect(urlSigned.hash).toBe(URLOriginal.hash);
		expect(querys.length).toBe(8);
		expect(querys).toContain('foo');
		expect(querys).toContain('expires');
		expect(querys).toContain('ip');
		expect(querys).toContain('method');
		expect(querys).toContain('nonce');
		expect(querys).toContain('prefix');
		expect(querys).toContain('signature');
		expect(searchParams.get('foo')).toBe('bar');
		expect(parseInt(searchParams.get('expires'))).toBeGreaterThan(Date.now());
		expect(searchParams.get('ip')).toBe(ip);
		expect(searchParams.getAll('method').sort()).toEqual(methods.sort());
		expect(+searchParams.get('nonce')).toBe(nonce);
		expect(searchParams.get('prefix')).toMatch(/[A-Za-z0-9-_.~]+/);
		expect(searchParams.get('signature')).toMatch(/[A-Za-z0-9-_.~]+/);

	});

});

describe('verifyURL', () => {

	let url = 'https://github.com/JadsonLucena/SignedAccess.js?foo=bar#id';

	test('type guards', () => {

		let urlSigned = signedAccess.URLSign(url);

		[undefined, 0, false, null].forEach(input => expect(() => signedAccess.verifyURL(input)).toThrow('Invalid URL'));
		['xyz', 0, false, null].forEach(input => expect(() => signedAccess.verifyURL(urlSigned, { algorithm: input })).toThrow());
		[127001, 0, false, null].forEach(input => expect(() => signedAccess.verifyURL(urlSigned, { ip: input })).toThrow('Invalid ip'));
		[0, false, null].forEach(input => expect(() => signedAccess.verifyURL(urlSigned, { key: input })).toThrow());
		['GETTER', 0, false, null].forEach(input => expect(() => signedAccess.verifyURL(urlSigned, { method: input })).toThrow('Invalid method'));

	});

	test('default values', () => {

		let urlSigned = signedAccess.URLSign(url);

		expect(signedAccess.verifyURL(urlSigned)).toBeTruthy();
		expect(signedAccess.verifyURL(urlSigned, { algorithm: 'sha1' })).toBeFalsy();
		expect(signedAccess.verifyURL(urlSigned, { ip: '127.0.0.1' })).toBeTruthy(); // should be ignored
		expect(signedAccess.verifyURL(urlSigned, { key: 'anything' })).toBeFalsy();
		expect(signedAccess.verifyURL(urlSigned, { method: 'POST' })).toBeTruthy(); // should be ignored

	});

	test('custom values', () => {

		let urlSigned = signedAccess.URLSign(url, { algorithm: 'sha1' });

		expect(signedAccess.verifyURL(urlSigned)).toBeFalsy();
		expect(signedAccess.verifyURL(urlSigned, { algorithm: 'sha1' })).toBeTruthy();


		urlSigned = signedAccess.URLSign(url, { ip: '127.0.0.1' });

		expect(() => signedAccess.verifyURL(urlSigned)).toThrow('ip required');
		expect(signedAccess.verifyURL(urlSigned, { ip: '142.251.129.78' })).toBeFalsy();
		expect(signedAccess.verifyURL(urlSigned, { ip: '127.0.0.1' })).toBeTruthy();


		urlSigned = signedAccess.URLSign(url, { key: 'xyz' });

		expect(signedAccess.verifyURL(urlSigned)).toBeFalsy();
		expect(signedAccess.verifyURL(urlSigned, { key: 'xyz' })).toBeTruthy();


		urlSigned = signedAccess.URLSign(url, { methods: 'POST' });

		expect(() => signedAccess.verifyURL(urlSigned)).toThrow('method required');
		expect(signedAccess.verifyURL(urlSigned, { method: 'PATCH' })).toBeFalsy();
		expect(signedAccess.verifyURL(urlSigned, { method: 'POST' })).toBeTruthy();


		urlSigned = signedAccess.URLSign('https://example.com/data/file1', {
			pathname: '/data'
		});

		let mockURLSigned = `https://example.com/database?${new URL(urlSigned).searchParams.toString()}`;

		expect(signedAccess.verifyURL(mockURLSigned)).toBeTruthy();

		mockURLSigned = `https://example.com/data/file2?${new URL(urlSigned).searchParams.toString()}`;

		expect(signedAccess.verifyURL(mockURLSigned)).toBeTruthy();


		urlSigned = signedAccess.URLSign('https://example.com/data/file1', {
			pathname: '/data/'
		});

		mockURLSigned = `https://example.com/database?${new URL(urlSigned).searchParams.toString()}`;

		expect(signedAccess.verifyURL(mockURLSigned)).toBeFalsy();

		mockURLSigned = `https://example.com/data/file2?${new URL(urlSigned).searchParams.toString()}`;

		expect(signedAccess.verifyURL(mockURLSigned)).toBeTruthy();


		urlSigned = signedAccess.URLSign(url, {
			ip: '127.0.0.1',
			methods: ['POST', 'PUT'],
			nonce: 999,
			pathname: '/JadsonLucena/'
		});

		mockURLSigned = `https://github.com/JadsonLucena/WebSocket.js?${new URL(urlSigned).searchParams.toString()}`;

		expect(() => signedAccess.verifyURL(mockURLSigned)).toThrow('ip required');
		expect(() => signedAccess.verifyURL(mockURLSigned, { ip: '142.251.129.78' })).toThrow('method required');
		expect(signedAccess.verifyURL(mockURLSigned, {
			ip: '142.251.129.78',
			method: 'DELETE'
		})).toBeFalsy();
		expect(signedAccess.verifyURL(mockURLSigned, {
			ip: '127.0.0.1',
			method: 'GET'
		})).toBeFalsy();
		expect(signedAccess.verifyURL(mockURLSigned, {
			ip: '142.251.129.78',
			method: 'POST'
		})).toBeFalsy();
		expect(signedAccess.verifyURL(mockURLSigned, {
			ip: '127.0.0.1',
			method: 'PUT'
		})).toBeTruthy();

	});

});

describe('signCookie', () => {

	let prefix = 'https://github.com/JadsonLucena/';


	test('type guards', () => {

		[undefined, 0, false, null].forEach(input => expect(() => signedAccess.signCookie(input)).toThrow('Invalid prefix'));
		['xyz', 0, false, null].forEach(input => expect(() => signedAccess.signCookie(prefix, { algorithm: input })).toThrow());
		['tomorrow', 0, false, null].forEach(input => expect(() => signedAccess.signCookie(prefix, { ttl: input })).toThrow('Invalid ttl'));
		[127001, 0, false, null].forEach(input => expect(() => signedAccess.signCookie(prefix, { ip: input })).toThrow('Invalid ip'));
		[0, false, null].forEach(input => expect(() => signedAccess.signCookie(prefix, { key: input })).toThrow());
		['GETTER', 0, false, null].forEach(input => expect(() => signedAccess.signCookie(prefix, { methods: input })).toThrow('Invalid methods'));
		['xyz', -2, false, null].forEach(input => expect(() => signedAccess.signCookie(prefix, { nonce: input })).toThrow('Invalid nonce'));

	});

	test('default values', () => {

		let cookieSigned = signedAccess.signCookie(prefix);

		let searchParams = new URLSearchParams(cookieSigned);
		let querys = Array.from(searchParams.keys());

		expect(querys.length).toBe(3);
		expect(querys).toContain('expires');
		expect(querys).toContain('prefix');
		expect(querys).toContain('signature');
		expect(parseInt(searchParams.get('expires'))).toBeGreaterThan(Date.now());
		expect(searchParams.get('prefix')).toMatch(/[A-Za-z0-9-_.~]+/);
		expect(searchParams.get('signature')).toMatch(/[A-Za-z0-9-_.~]+/);

	});

	test('custom values', () => {

		let ttl = 3600;
		let ip = '142.251.129.78';
		let methods = ['GET', 'POST'];
		let nonce = 1;

		let cookieSigned = signedAccess.signCookie(prefix, {
			ttl,
			ip,
			methods,
			nonce
		});

		let searchParams = new URLSearchParams(cookieSigned);
		let querys = Array.from(searchParams.keys());

		expect(querys.length).toBe(7);
		expect(querys).toContain('expires');
		expect(querys).toContain('ip');
		expect(querys).toContain('method');
		expect(querys).toContain('nonce');
		expect(querys).toContain('prefix');
		expect(querys).toContain('signature');
		expect(parseInt(searchParams.get('expires'))).toBeGreaterThan(Date.now());
		expect(searchParams.get('ip')).toBe(ip);
		expect(searchParams.getAll('method').sort()).toEqual(methods.sort());
		expect(+searchParams.get('nonce')).toBe(nonce);
		expect(searchParams.get('prefix')).toMatch(/[A-Za-z0-9-_.~]+/);
		expect(searchParams.get('signature')).toMatch(/[A-Za-z0-9-_.~]+/);

	});

});

describe('verifyCookie', () => {

	let prefix = 'https://github.com/JadsonLucena/';
	let mockURL = 'https://github.com/JadsonLucena/SignedAccess.js?foo=bar#id';


	test('type guards', () => {

		let cookieSigned = signedAccess.CookieSign(prefix);

		[undefined, 0, false, null].forEach(input => expect(() => signedAccess.verifyCookie(input, cookieSigned)).toThrow('Invalid URL'));
		[undefined, 0, false, null].forEach(input => expect(() => signedAccess.verifyCookie(mockURL, input)).toThrow('Invalid cookie'));
		['xyz', 0, false, null].forEach(input => expect(() => signedAccess.verifyCookie(mockURL, cookieSigned, { algorithm: input })).toThrow());
		[127001, 0, false, null].forEach(input => expect(() => signedAccess.verifyCookie(mockURL, cookieSigned, { ip: input })).toThrow('Invalid ip'));
		[0, false, null].forEach(input => expect(() => signedAccess.verifyCookie(mockURL, cookieSigned, { key: input })).toThrow());
		['GETTER', 0, false, null].forEach(input => expect(() => signedAccess.verifyCookie(mockURL, cookieSigned, { method: input })).toThrow('Invalid method'));

	});

	test('default values', () => {

		let cookieSigned = signedAccess.CookieSign(prefix);

		expect(signedAccess.verifyCookie(mockURL, cookieSigned)).toBeTruthy();
		expect(signedAccess.verifyCookie(mockURL, cookieSigned, { algorithm: 'sha1' })).toBeFalsy();
		expect(signedAccess.verifyCookie(mockURL, cookieSigned, { ip: '127.0.0.1' })).toBeTruthy(); // should be ignored
		expect(signedAccess.verifyCookie(mockURL, cookieSigned, { key: 'anything' })).toBeFalsy();
		expect(signedAccess.verifyCookie(mockURL, cookieSigned, { method: 'POST' })).toBeTruthy(); // should be ignored


		cookieSigned = signedAccess.CookieSign(mockURL)

		expect(signedAccess.verifyCookie(mockURL, cookieSigned)).toBeTruthy();

	});

	test('custom values', () => {

		let cookieSigned = signedAccess.CookieSign(prefix, { algorithm: 'sha256' });

		expect(signedAccess.verifyCookie(mockURL, cookieSigned)).toBeFalsy();
		expect(signedAccess.verifyCookie(mockURL, cookieSigned, { algorithm: 'sha256' })).toBeTruthy();


		cookieSigned = signedAccess.CookieSign(prefix, { ip: '127.0.0.1' });

		expect(() => signedAccess.verifyCookie(mockURL, cookieSigned)).toThrow('ip required');
		expect(signedAccess.verifyCookie(mockURL, cookieSigned, { ip: '142.251.129.78' })).toBeFalsy();
		expect(signedAccess.verifyCookie(mockURL, cookieSigned, { ip: '127.0.0.1' })).toBeTruthy();


		cookieSigned = signedAccess.CookieSign(prefix, { key: 'xyz' });

		expect(signedAccess.verifyCookie(mockURL, cookieSigned)).toBeFalsy();
		expect(signedAccess.verifyCookie(mockURL, cookieSigned, { key: 'xyz' })).toBeTruthy();


		cookieSigned = signedAccess.CookieSign(prefix, { methods: 'POST' });

		expect(() => signedAccess.verifyCookie(mockURL, cookieSigned)).toThrow('method required');
		expect(signedAccess.verifyCookie(mockURL, cookieSigned, { method: 'PATCH' })).toBeFalsy();
		expect(signedAccess.verifyCookie(mockURL, cookieSigned, { method: 'POST' })).toBeTruthy();


		cookieSigned = signedAccess.CookieSign('https://example.com/data');

		expect(signedAccess.verifyCookie('https://example.com/database', cookieSigned)).toBeTruthy();
		expect(signedAccess.verifyCookie('https://example.com/data/file1', cookieSigned)).toBeTruthy();


		cookieSigned = signedAccess.CookieSign('https://example.com/data/');

		expect(signedAccess.verifyCookie('https://example.com/database', cookieSigned)).toBeFalsy();
		expect(signedAccess.verifyCookie('https://example.com/data/file1', cookieSigned)).toBeTruthy();


		cookieSigned = signedAccess.CookieSign(prefix, {
			ip: '127.0.0.1',
			methods: ['POST', 'PUT'],
			nonce: 111
		});

		expect(() => signedAccess.verifyCookie(mockURL, cookieSigned)).toThrow('ip required');
		expect(() => signedAccess.verifyCookie(mockURL, cookieSigned, { ip: '142.251.129.78' })).toThrow('method required');
		expect(signedAccess.verifyCookie(mockURL, cookieSigned, {
			ip: '142.251.129.78',
			method: 'DELETE'
		})).toBeFalsy();
		expect(signedAccess.verifyCookie(mockURL, cookieSigned, {
			ip: '127.0.0.1',
			method: 'GET'
		})).toBeFalsy();
		expect(signedAccess.verifyCookie(mockURL, cookieSigned, {
			ip: '142.251.129.78',
			method: 'POST'
		})).toBeFalsy();
		expect(signedAccess.verifyCookie(mockURL, cookieSigned, {
			ip: '127.0.0.1',
			method: 'PUT'
		})).toBeTruthy();

	});

});