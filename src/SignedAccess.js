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

}

module.exports = SignedAccess;