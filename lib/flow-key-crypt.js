const crypto = require('crypto');
//const basex = require('base-x');
//const base58alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
//const base58 = basex(base58alphabet);

//var Unibabel = require('browserify-unibabel')
module.exports = {

	// Simple encryption methods:
	encrypt,
	decrypt,

	// More advanced encryption methods:
	keyFromPassword,
	encryptWithKey,
	decryptWithKey,

	// Buffer <-> Hex string methods
	serializeBufferForStorage,
	serializeBufferFromStorage,

	generateSalt,
}

// Takes a Pojo, returns cypher text.
function encrypt (password, dataObj) {
	let salt = generateSalt();

	return keyFromPassword(password, salt)
	.then(passwordDerivedKey=>{
		//console.log("passwordDerivedKey", passwordDerivedKey)
		return encryptWithKey(passwordDerivedKey, dataObj)
	})
	.then(payload=>{
		payload.salt = salt
		return JSON.stringify(payload)
	})
}

function encryptWithKey (key, dataObj, algorithm='aes-192-cbc') {
	
	/*
	var vector = global.crypto.getRandomValues(new Uint8Array(16))
	return global.crypto.subtle.encrypt({
		name: 'AES-GCM',
		iv: vector,
	}, key, dataBuffer).then(function (buf) {
		var buffer = new Uint8Array(buf)
		var vectorStr = Unibabel.bufferToBase64(vector)
		var vaultStr = Unibabel.bufferToBase64(buffer)
		return {
			data: vaultStr,
			iv: vectorStr,
		}
	})
	*/
	return new Promise(resolve=>{
		let data = JSON.stringify(dataObj)

		crypto.randomFill(new Uint8Array(16), (err, iv) => {
	    	if (err)
	    		throw err;
	    	//key = Buffer.from(key);
	    	//console.log("key", key.length)
			const cipher = crypto.createCipheriv(algorithm, key, iv);

		    let encrypted = cipher.update(data, 'utf8', 'hex');
		    encrypted += cipher.final('hex');
		    //console.log("encrypted:", encrypted);
		    resolve({
		    	data: encrypted,
		    	iv: Buffer.from(iv).toString('hex')
		    })
		})
	})
}

// Takes encrypted text, returns the restored Pojo.
function decrypt (password, text) {
	const payload = JSON.parse(text)
	const salt = payload.salt
	return keyFromPassword(password, salt)
	.then(key=>{
		return decryptWithKey(key, payload)
	})
}

function decryptWithKey (key, payload, algorithm='aes-192-cbc') {
	return new Promise(resolve=>{
		const iv = Buffer.from(payload.iv, 'hex');
		const decipher = crypto.createDecipheriv(algorithm, key, iv);

		let decrypted = '';
		decipher.on('readable', () => {
		  while (null !== (chunk = decipher.read())) {
		    decrypted += chunk.toString('utf8');
		  }
		});
		decipher.on('end', () => {
			//console.log("decrypted:", decrypted);
			// Prints: some clear text data
			resolve(JSON.parse(decrypted))
		});

		decipher.write(payload.data, 'hex');
		decipher.end();
	})
}

function keyFromPassword (password, salt, iterations=100000, keylen=12, hash="sha512") {
	return new Promise((resolve)=>{
		var passBuffer = Buffer.from(password, 'utf8');
		var saltBuffer = Buffer.from(salt, 'hex');

		//const derivedKey = crypto.hkdfSync('sha512', passBuffer, saltBuffer, info, keylen);
		//let key = Buffer.from(derivedKey).toString('hex');
		crypto.pbkdf2(passBuffer, saltBuffer, iterations, keylen, hash, (err, derivedKey) => {
			if (err)
				throw err;
			//console.log(derivedKey.toString('hex'));  // '3745e48...08d59ae'
			resolve(derivedKey.toString('hex'))
		});
	})
}

function serializeBufferFromStorage (str) {
	var stripStr = (str.slice(0, 2) === '0x') ? str.slice(2) : str
	var buf = new Uint8Array(stripStr.length / 2)
	for (var i = 0; i < stripStr.length; i += 2) {
		var seg = stripStr.substr(i, 2)
		buf[i / 2] = parseInt(seg, 16)
	}
	return buf
}

// Should return a string, ready for storage, in hex format.
function serializeBufferForStorage (buffer) {
	var result = '0x'
	var len = buffer.length || buffer.byteLength
	for (var i = 0; i < len; i++) {
		result += unprefixedHex(buffer[i])
	}
	return result
}

function unprefixedHex (num) {
	var hex = num.toString(16)
	while (hex.length < 2) {
		hex = '0' + hex
	}
	return hex
}

function generateSalt(length=32, hash="sha256"){
	return crypto.createHash(hash).update(crypto.randomBytes(length)).digest('hex');
}
