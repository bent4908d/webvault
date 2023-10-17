const CryptTool = (function () {
    const me = {};

    /**
     * base58 encoder & decoder
     *
     * @private
     */
    let base58 = new baseX('123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz');

    /**
     * convert UTF-8 string stored in a DOMString to a standard UTF-16 DOMString
     *
     * Iterates over the bytes of the message, converting them all hexadecimal
     * percent encoded representations, then URI decodes them all
     *
     * @name   CryptTool.utf8To16
     * @function
     * @private
     * @param  {string} message UTF-8 string
     * @return {string} UTF-16 string
     */
    function utf8To16(message)
    {
        return decodeURIComponent(
            message.split('').map(
                function(character)
                {
                    return '%' + ('00' + character.charCodeAt(0).toString(16)).slice(-2);
                }
            ).join('')
        );
    }

    /**
     * convert DOMString (UTF-16) to a UTF-8 string stored in a DOMString
     *
     * URI encodes the message, then finds the percent encoded characters
     * and transforms these hexadecimal representation back into bytes
     *
     * @name   CryptTool.utf16To8
     * @function
     * @private
     * @param  {string} message UTF-16 string
     * @return {string} UTF-8 string
     */
    function utf16To8(message)
    {
        return encodeURIComponent(message).replace(
            /%([0-9A-F]{2})/g,
            function (match, hexCharacter)
            {
                return String.fromCharCode('0x' + hexCharacter);
            }
        );
    }

    /**
     * convert ArrayBuffer into a UTF-8 string
     *
     * Iterates over the bytes of the array, catenating them into a string
     *
     * @name   CryptTool.arraybufferToString
     * @function
     * @private
     * @param  {ArrayBuffer} messageArray
     * @return {string} message
     */
    function arraybufferToString(messageArray)
    {
        const array = new Uint8Array(messageArray);
        let message = '',
            i       = 0;
        while(i < array.length) {
            message += String.fromCharCode(array[i++]);
        }
        return message;
    }

    /**
     * convert UTF-8 string into a Uint8Array
     *
     * Iterates over the bytes of the message, writing them to the array
     *
     * @name   CryptTool.stringToArraybuffer
     * @function
     * @private
     * @param  {string} message UTF-8 string
     * @return {Uint8Array} array
     */
    function stringToArraybuffer(message)
    {
        const messageArray = new Uint8Array(message.length);
        for (let i = 0; i < message.length; ++i) {
            messageArray[i] = message.charCodeAt(i);
        }
        return messageArray;
    }

    /**
     * compress a string (deflate compression), returns buffer
     *
     * @name   CryptTool.compress
     * @async
     * @function
     * @private
     * @param  {string} message
     * @param  {string} mode
     * @param  {object} zlib
     * @throws {string}
     * @return {ArrayBuffer} data
     */
    async function compress(message, mode, zlib)
    {
        message = stringToArraybuffer(
            utf16To8(message)
        );
        if (mode === 'zlib') {
            if (typeof zlib === 'undefined') {
                throw 'Error compressing paste, due to missing WebAssembly support.'
            }
            return zlib.deflate(message).buffer;
        }
        return message;
    }

    /**
     * decompress potentially base64 encoded, deflate compressed buffer, returns string
     *
     * @name   CryptTool.decompress
     * @async
     * @function
     * @private
     * @param  {ArrayBuffer} data
     * @param  {string} mode
     * @param  {object} zlib
     * @throws {string}
     * @return {string} message
     */
    async function decompress(data, mode, zlib)
    {
        if (mode === 'zlib' || mode === 'none') {
            if (mode === 'zlib') {
                if (typeof zlib === 'undefined') {
                    throw 'Error decompressing paste, due to missing WebAssembly support.'
                }
                data = zlib.inflate(
                    new Uint8Array(data)
                ).buffer;
            }
            return utf8To16(
                arraybufferToString(data)
            );
        }
        // detect presence of Base64.js, indicating legacy ZeroBin paste
        if (typeof Base64 === 'undefined') {
            return utf8To16(
                RawDeflate.inflate(
                    utf8To16(
                        atob(
                            arraybufferToString(data)
                        )
                    )
                )
            );
        } else {
            return Base64.btou(
                RawDeflate.inflate(
                    Base64.fromBase64(
                        arraybufferToString(data)
                    )
                )
            );
        }
    }

    /**
     * returns specified number of random bytes
     *
     * @name   CryptTool.getRandomBytes
     * @function
     * @private
     * @param  {int} length number of random bytes to fetch
     * @throws {string}
     * @return {string} random bytes
     */
    function getRandomBytes(length)
    {
        let bytes       = '';
        const byteArray = new Uint8Array(length);
        window.crypto.getRandomValues(byteArray);
        for (let i = 0; i < length; ++i) {
            bytes += String.fromCharCode(byteArray[i]);
        }
        return bytes;
    }

    /**
     * derive cryptographic key from key string and password
     *
     * @name   CryptTool.deriveKey
     * @async
     * @function
     * @private
     * @param  {string} key
     * @param  {string} password
     * @param  {array}  spec cryptographic specification
     * @return {CryptoKey} derived key
     */
    async function deriveKey(key, password, spec)
    {
        spec = spec[0];
        let keyArray = stringToArraybuffer(key);
        if (password.length > 0) {
            // version 1 pastes did append the passwords SHA-256 hash in hex
            if (spec[7] === 'rawdeflate') {
                let passwordBuffer = await window.crypto.subtle.digest(
                    {name: 'SHA-256'},
                    stringToArraybuffer(
                        utf16To8(password)
                    )
                ).catch(Alert.showError);
                password = Array.prototype.map.call(
                    new Uint8Array(passwordBuffer),
                    x => ('00' + x.toString(16)).slice(-2)
                ).join('');
            }
            let passwordArray = stringToArraybuffer(password),
                newKeyArray = new Uint8Array(keyArray.length + passwordArray.length);
            newKeyArray.set(keyArray, 0);
            newKeyArray.set(passwordArray, keyArray.length);
            keyArray = newKeyArray;
        }

        // import raw key
        const importedKey = await window.crypto.subtle.importKey(
            'raw', // only 'raw' is allowed
            keyArray,
            {name: 'PBKDF2'}, // we use PBKDF2 for key derivation
            false, // the key may not be exported
            ['deriveKey'] // we may only use it for key derivation
        );

        // derive a stronger key for use with AES
        return window.crypto.subtle.deriveKey(
            {
                name: 'PBKDF2', // we use PBKDF2 for key derivation
                salt: stringToArraybuffer(atob(spec[1])), // salt used in HMAC
                iterations: spec[2], // amount of iterations to apply
                hash: {name: 'SHA-256'} // can be "SHA-1", "SHA-256", "SHA-384" or "SHA-512"
            },
            importedKey,
            {
                name: 'AES-' + spec[6].toUpperCase(), // can be any supported AES algorithm ("AES-CTR", "AES-CBC", "AES-CMAC", "AES-GCM", "AES-CFB", "AES-KW", "ECDH", "DH" or "HMAC")
                length: spec[3] // can be 128, 192 or 256
            },
            false, // the key may not be exported
            ['encrypt', 'decrypt'] // we may only use it for en- and decryption
        );
    }

    /**
     * gets crypto settings from specification and authenticated data
     *
     * @name   CryptTool.cryptoSettings
     * @function
     * @private
     * @param  {string} adata authenticated data
     * @param  {array}  spec cryptographic specification
     * @return {object} crypto settings
     */
    function cryptoSettings(adata, spec)
    {
        spec[0][0] = atob(spec[0][0]);
        return {
            name: 'AES-' + spec[0][6].toUpperCase(), // can be any supported AES algorithm ("AES-CTR", "AES-CBC", "AES-CMAC", "AES-GCM", "AES-CFB", "AES-KW", "ECDH", "DH" or "HMAC")
            iv: stringToArraybuffer(spec[0][0]), // the initialization vector you used to encrypt
            additionalData: stringToArraybuffer(adata), // the addtional data you used during encryption (if any)
            tagLength: spec[0][4] // the length of the tag you used to encrypt (if any)
        };
    }

    /**
     * compress, then encrypt message with given key and password
     *
     * @name   CryptTool.cipher
     * @async
     * @function
     * @param  {string} key
     * @param  {string} password
     * @param  {string} message
     * @param  {array}  adata
     * @return {array}  encrypted message in base64 encoding & adata containing encryption spec
     */
    me.cipher = async function(key, password, message, adata)
    {
        let zlib = (await z);
        // AES in Galois Counter Mode, keysize 256 bit,
        // authentication tag 128 bit, 10000 iterations in key derivation
        const compression = (
                typeof zlib === 'undefined' ?
                'none' : // client lacks support for WASM
                ($('body').data('compression') || 'zlib')
            ),
            spec = [
                getRandomBytes(16), // initialization vector
                getRandomBytes(8),  // salt
                100000,             // iterations
                256,                // key size
                128,                // tag size
                'aes',              // algorithm
                'gcm',              // algorithm mode
                compression         // compression
            ], encodedSpec = [];
        for (let i = 0; i < spec.length; ++i) {
            encodedSpec[i] = i < 2 ? btoa(spec[i]) : spec[i];
        }
        if (adata.length === 0) {
            // comment
            adata = encodedSpec;
        } else if (adata[0] === null) {
            // paste
            adata[0] = encodedSpec;
        }

        // finally, encrypt message
        return [
            btoa(
                arraybufferToString(
                    await window.crypto.subtle.encrypt(
                        cryptoSettings(JSON.stringify(adata), spec),
                        await deriveKey(key, password, spec),
                        await compress(message, compression, zlib)
                    ).catch(Alert.showError)
                )
            ),
            adata
        ];
    };

    /**
     * decrypt message with key, then decompress
     *
     * @name   CryptTool.decipher
     * @async
     * @function
     * @param  {string} key
     * @param  {string} password
     * @param  {string|object} data encrypted message
     * @return {string} decrypted message, empty if decryption failed
     */
    me.decipher = async function(key, password, data)
    {
        let adataString, spec, cipherMessage, plaintext;
        zlib = (await zlib);
        if (data instanceof Array) {
            // version 2
            adataString = JSON.stringify(data[1][0])
            // clone the array instead of passing the reference
            spec = (data[1][0] instanceof Array ? data[1][0] : data[1]).slice();
            cipherMessage = data[0];
        } else if (typeof data === 'string') {
            // version 1
            let object = JSON.parse(data);
            adataString = atob(object.adata);
            spec = [
                object.iv,
                object.salt,
                object.iter,
                object.ks,
                object.ts,
                object.cipher,
                object.mode,
                'rawdeflate'
            ];
            cipherMessage = object.ct;
        } else {
            throw 'unsupported message format';
        }
        //spec[0] = atob(spec[0]);
        //spec[1] = atob(spec[1]);
        if (spec[7] === 'zlib') {
            if (typeof zlib === 'undefined') {
                throw 'Error decompressing paste, due to missing WebAssembly support.'
            }
        }
        try {
            plaintext = await window.crypto.subtle.decrypt(
                cryptoSettings(adataString, spec),
                await deriveKey(key, password, spec),
                stringToArraybuffer(
                    atob(cipherMessage)
                )
            );
        } catch(err) {
            console.error(err);
            return '';
        }
        try {
            return await decompress(plaintext, spec[0][7], zlib);
        } catch(err) {
            Alert.showError(err);
            return err;
        }
    };

    /**
     * returns a random symmetric key
     *
     * generates 256 bit long keys (8 Bits * 32) for AES with 256 bit long blocks
     *
     * @name   CryptTool.getSymmetricKey
     * @function
     * @throws {string}
     * @return {string} raw bytes
     */
    me.getSymmetricKey = function()
    {
        return getRandomBytes(32);
    };

    /**
     * base58 encode a DOMString (UTF-16)
     *
     * @name   CryptTool.base58encode
     * @function
     * @param  {string} input
     * @return {string} output
     */
    me.base58encode = function(input)
    {
        return base58.encode(
            stringToArraybuffer(input)
        );
    }

    /**
     * base58 decode a DOMString (UTF-16)
     *
     * @name   CryptTool.base58decode
     * @function
     * @param  {string} input
     * @return {string} output
     */
    me.base58decode = function(input)
    {
        return arraybufferToString(
            base58.decode(input)
        );
    }

    return me;
})();
