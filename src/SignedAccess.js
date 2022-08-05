const crypto = require('crypto');
const os = require('os');

class SignedAccess {

    #algorithm;
    #ttl;
    #key;

    #HTTPMethods;

    constructor({
        algorithm,
        ttl,
        key
    } = {}) {

        this.algorithm = algorithm;
        this.ttl = ttl;
        this.key = key;

        this.#HTTPMethods = ['CONNECT', 'DELETE', 'GET', 'HEAD', 'OPTIONS', 'PATCH', 'POST', 'PUT', 'TRACE']

    }


    get algorithm() { return this.#algorithm; }
    get ttl() { return this.#ttl; }
    get key() { return this.#key; }


    set algorithm(
        algorithm = 'sha512' // https://nodejs.org/api/crypto.html#cryptogethashes
    ) {

        crypto.createHmac(algorithm, 'test');

        this.#algorithm = algorithm;

    }

    set ttl(
        ttl = 86400 // Seconds
    ) {

        if (isNaN(ttl) || typeof ttl != 'number' || ttl < 1) {

            throw new TypeError('Invalid ttl');

        }

        this.#ttl = ttl;

    }

    set key(
        key = os.networkInterfaces()['eth0'][0].mac
    ) {

        crypto.createHmac('sha1', key);

        this.#key = key;

    }


    #encodePrefix(prefix) {

        prefix = new URL(prefix);

        // The prefix shouldn't include query parameters or fragments such as ? or #
        return Buffer.from(prefix.origin + prefix.pathname, 'ascii').toString('base64url');

    }

    #decodePrefix(prefix) {

        // https://www.w3schools.com/tags/ref_urlencode.asp
        // https://datatracker.ietf.org/doc/html/rfc4648#section-5
        return Buffer.from(prefix, 'base64url').toString('ascii');

    }

    #timestamp(ttl) {

        return Date.now() + parseInt(ttl) * 1000;

    }

    #toSign(
        input,
        key,
        algorithm
    ) {

        return crypto.createHmac(algorithm, key).update(input).digest('base64url');

    }

    signURL(
        url,
        {
            algorithm = this.#algorithm,
            ttl = this.#ttl,
            ip = '',
            key = this.#key,
            methods = [],
            nonce = -1, // Natural numbers
            path = '',
        } = {}
    ) {

    }

}

module.exports = SignedAccess;