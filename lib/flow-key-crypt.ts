import * as crypto from 'crypto';

export const writeBuffer = (buf:string|Buffer, appendTo?:Buffer):Buffer=>{
	let textBuf = typeof buf=='string'?Buffer.from(buf, "hex"):buf;
	let lengthBuf = Buffer.alloc(4);
	lengthBuf.writeUInt32LE(textBuf.length);
	if(appendTo)
		return Buffer.concat([appendTo, lengthBuf, textBuf])
	return Buffer.concat([lengthBuf, textBuf])
}

export const writeBuffers = (...args:string[]):Buffer=>{

	let buf = writeBuffer(args[0]);
	args.slice(1).map(arg=>{
		buf = writeBuffer(arg, buf);
	})
	
	return buf;
}

export const readBuffers = (buf:Buffer|string):Buffer[]=>{
	let input = typeof buf=='string'?Buffer.from(buf, "hex"):buf;
	let bufs:Buffer[] = [];
	let pos = 0;
	let read = ()=>{
		let length = input.readUInt16LE();
		let end = 4+length;
		
		let textBuf = input.slice(4, end);
		//console.log("length", length, "end", end, textBuf)
		bufs.push(textBuf);
		input = input.slice(end)
		if(input.length)
			read();
	}
	read();
	return bufs
}

export const generateSalt = (length:number=32, hash:string="sha256"):string=>{
	return crypto.createHash(hash).update(crypto.randomBytes(length)).digest('hex');
}

// Takes a Pojo, returns cypher text.
export const encrypt = (password:string, dataObj:any):Promise<string>=>{
	let salt = generateSalt();

	return keyFromPassword(password, salt)
	.then(passwordDerivedKey=>{
		//console.log("passwordDerivedKey", passwordDerivedKey)
		return encryptWithKey(passwordDerivedKey, dataObj)
	})
	.then((payload:any)=>{
		let {iv, data} = payload;
		let buf = writeBuffers(salt, iv, data);
		return buf.toString("hex");
		//return JSON.stringify(payload)
	})
}

export const encryptWithKey = (key:Buffer, dataObj:any, algorithm:string='aes-192-cbc'):Promise<any>=>{
	return new Promise(resolve=>{
		let data = JSON.stringify(dataObj)

		crypto.randomFill(new Uint8Array(16), (err, iv) => {
	    	if (err)
	    		throw err;
			const cipher = crypto.createCipheriv(algorithm, key.toString("hex"), iv);

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
export const decrypt = (password:string, text:string)=>{
	let payload:{data:string, iv:string, salt:string} = {data:"", iv:"", salt:""};
	if(text.indexOf("{") >-1){
		payload = JSON.parse(text)
	}else{
		let [salt, iv, data] = readBuffers(text).map(b=>b.toString("hex"));
		payload.salt = salt;
		payload.iv = iv;
		payload.data = data;
	}
	const {salt} = payload
	return keyFromPassword(password, salt)
	.then(key=>{
		return decryptWithKey(key, payload)
	})
}

export const  decryptWithKey = (key:Buffer, payload:any, algorithm='aes-192-cbc')=>{
	return new Promise(resolve=>{
		const iv = Buffer.from(payload.iv, 'hex');
		const decipher = crypto.createDecipheriv(algorithm, key.toString("hex"), iv);

		let decrypted = '', chunk;
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

export const keyFromPassword = (
		password:string, salt:string, iterations:number=100000,
		keylen:number=12, hash:string="sha512"): Promise<Buffer> =>{

	return new Promise((resolve)=>{
		var passBuffer = Buffer.from(password, 'utf8');
		var saltBuffer = Buffer.from(salt, 'hex');

		//const derivedKey = crypto.hkdfSync('sha512', passBuffer, saltBuffer, info, keylen);
		//let key = Buffer.from(derivedKey).toString('hex');
		crypto.pbkdf2(passBuffer, saltBuffer, iterations, keylen, hash, (err, derivedKey) => {
			if (err)
				throw err;
			resolve(derivedKey)
		});
	})
}

export const serializeBufferFromStorage = (str:string)=>{
	var stripStr = (str.slice(0, 2) === '0x') ? str.slice(2) : str
	var buf = new Uint8Array(stripStr.length / 2)
	for (var i = 0; i < stripStr.length; i += 2) {
		var seg = stripStr.substr(i, 2)
		buf[i / 2] = parseInt(seg, 16)
	}
	return buf
}

// Should return a string, ready for storage, in hex format.
export const serializeBufferForStorage = (buffer:Buffer)=>{
	var result = '0x'
	var len = buffer.length || buffer.byteLength
	for (var i = 0; i < len; i++) {
		result += unprefixedHex(buffer[i])
	}
	return result
}

export const unprefixedHex = (num:number)=>{
	var hex = num.toString(16)
	while (hex.length < 2) {
		hex = '0' + hex
	}
	return hex
}
