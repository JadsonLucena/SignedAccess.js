const SignedAccess = require('../src/SignedAccess')

const signedAccess = new SignedAccess()

const url = 'https://sample.com/pathname/to/resource?foo=bar#id'
const ip = '179.180.147.217'


// The client must generate the signed URL to access the resource
const signedURL = signedAccess.signURL(url, {
	remoteAddress: ip
})

console.log('Signed URL', signedURL)

// The resource must verify that the url has a valid signature
// If the request ip is not the same as the one used in the signature, the verification will fail
console.log('Verify URL', signedAccess.verifyURL(signedURL, {
	remoteAddress: ip
}))


// The client can sign up by URL or cookie, regardless of choice, the step-by-step will be the same


// The signed cookie must be added to the cookie header
const signedCookie = signedAccess.signCookie(url, {
	remoteAddress: ip
})

console.log('Signed Cookie', signedCookie)

// 
console.log('Verify Cookie', signedAccess.verifyCookie(signedCookie, {
	remoteAddress: ip
}))