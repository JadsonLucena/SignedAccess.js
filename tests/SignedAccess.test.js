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