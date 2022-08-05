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
            pathname = '',
        } = {}
    ) {

        url = new URL(url);


        methods = [].concat(methods);
        methods = [...new Set(methods)];


        if (isNaN(ttl) || typeof ttl != 'number' || ttl < 1) {

            throw new TypeError('Invalid ttl');

        } else if (typeof ip != 'string') {

            throw new TypeError('Invalid ip');

        } else if (!methods.every(method => typeof method == 'string' && this.#HTTPMethods.includes(method.trim().toUpperCase()))) {

            throw new TypeError('Invalid methods');

        } else if (isNaN(nonce) || typeof nonce != 'number' || (nonce != -1 && nonce < 0)) {

            throw new TypeError('Invalid nonce');

        } else if (typeof pathname != 'string' || !url.pathname.startsWith(pathname)) {

            throw new TypeError('Invalid pathname');

        }


        url.searchParams.delete('expires');
        url.searchParams.delete('ip');
        url.searchParams.delete('method');
        url.searchParams.delete('nonce');
        url.searchParams.delete('prefix');
        url.searchParams.delete('signature');


        let searchParams = new URLSearchParams();

        searchParams.set('expires', this.#timestamp(ttl));
        if (ip) searchParams.set('ip', ip.trim());
        if (methods.length) methods.forEach(method => searchParams.append('method', method.trim().toUpperCase()));
        if (nonce >= 0) searchParams.set('nonce', nonce);
        if (pathname) searchParams.set('prefix', this.#encodePrefix(new URL(pathname, url.origin).href));


        for (var pair of searchParams.entries()) {

            url.searchParams.append(pair[0], pair[1]);

        }


        url.searchParams.set('signature', this.#toSign(searchParams.has('prefix') ? searchParams.toString() : url.href, key, algorithm));


        return url.href;

    }

    verifyURL(
        url,
        {
            algorithm = this.#algorithm,
            ip = '',
            key = this.#key,
            method = ''
        } = {}
    ) {

        url = new URL(url);


        if (typeof ip != 'string') {

            throw new TypeError('Invalid ip');

        } else if (typeof method != 'string' || !['', ...this.#HTTPMethods].includes(method.trim().toUpperCase())) {

            throw new TypeError('Invalid method');

        }


        if (url.searchParams.has('ip') && !ip.trim()) {

            throw new Error('ip required');

        } else if (url.searchParams.has('method') && !method.trim().toUpperCase()) {

            throw new Error('method required');

        }


        let signature = url.searchParams.get('signature');


        url.searchParams.delete('signature');


        if (url.searchParams.has('prefix')) {

            let searchParams = new URLSearchParams();


            // get the parameters keeping the order
            for (var pair of url.searchParams.entries()) {

                if (['expires', 'ip', 'method', 'nonce', 'prefix'].includes(pair[0])) {

                    searchParams.append(pair[0], pair[1]);

                }

            }

            return (
                signature == this.#toSign(searchParams.toString(), key, algorithm)
                && Date.now() < url.searchParams.get('expires')
                && (url.searchParams.has('ip') ? url.searchParams.get('ip') == ip.trim() : true)
                && (url.searchParams.has('method') ? url.searchParams.getAll('method').includes(method.trim().toUpperCase()) : true)
                && url.href.startsWith(this.#decodePrefix(url.searchParams.get('prefix')))
            );

        } else {

            return (
                signature == this.#toSign(url.href, key, algorithm)
                && Date.now() < url.searchParams.get('expires')
                && (url.searchParams.has('ip') ? url.searchParams.get('ip') == ip.trim() : true)
                && (url.searchParams.has('method') ? url.searchParams.getAll('method').includes(method.trim().toUpperCase()) : true)
            );

        }

    }

}

module.exports = SignedAccess;