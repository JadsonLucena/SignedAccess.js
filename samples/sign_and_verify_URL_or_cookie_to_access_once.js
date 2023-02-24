const SignedAccess = require('../src/SignedAccess')

const signedAccess = new SignedAccess()

const url = 'https://sample.com/pathname/to/resource?foo=bar#id'

// Must be a unique key
// The nonce is signed in the cookie or URL, but it's up to your application to save them and check if they've already been used.
const nonce = `${Date.now()}${Math.random()}`


// The client must generate the signed URL to access the resource
const signedURL = signedAccess.signURL(url, {
	nonce
})

console.log('Signed URL', signedURL)

// The resource must verify that the url has a valid signature
// If the signature is valid, checks if the nonce has already been used.
// - If yes, deny the request
// - If not, save the noce in the blocklist
console.log('Verify URL', signedAccess.verifyURL(signedURL))


// The client must generate the signed cookie to access the resource
const signedCookie = signedAccess.signCookie(url, {
	nonce
})

console.log('Signed Cookie', signedCookie)

// The resource must verify that the cookie has a valid signature
// If the signature is valid, checks if the nonce has already been used.
// - If yes, deny the request
// - If not, save the noce in the blocklist
console.log('Verify Cookie', signedAccess.verifyCookie(signedCookie))