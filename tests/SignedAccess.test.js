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

});