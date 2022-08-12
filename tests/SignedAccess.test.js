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

});