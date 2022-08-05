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

}

module.exports = SignedAccess;