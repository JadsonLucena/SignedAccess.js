const SignedAccess = require('../src/SignedAccess')

const signedAccess = new SignedAccess()

const url = 'https://sample.com/pathname/to/resource?foo=bar#id'

console.log('Signed URL', signedAccess.signURL(url, {
	accessControlAllowMethods: 'get, head, options, trace'
}))

console.log('Signed Cookie', signedAccess.signCookie(url, {
	accessControlAllowMethods: 'get, head, options, trace'
}))