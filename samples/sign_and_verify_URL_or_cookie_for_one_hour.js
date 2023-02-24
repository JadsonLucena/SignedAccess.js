const SignedAccess = require('../src/SignedAccess')

const signedAccess = new SignedAccess({
	ttl: 3600
})

const url = 'https://sample.com/pathname/to/resource?foo=bar#id'

console.log('Signed URL', signedAccess.signURL(url, {
	// ttl: 3600
}))

console.log('Signed Cookie', signedAccess.signCookie(url, {
	// ttl: 3600
}))