const SignedAccess = require('../src/SignedAccess')

const signedAccess = new SignedAccess()

console.log('Signed URL', signedAccess.signURL('https://sample.com/pathname/to/resource?foo=bar#id', {
	pathname: '/pathname/to/'
}))

console.log('Signed Cookie', signedAccess.signCookie('https://sample.com/pathname/to/'))