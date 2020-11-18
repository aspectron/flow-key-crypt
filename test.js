const FlowPassworder = require('./index');

let pass = "xyzdgfggdfgdfg";
let data = {x:"1111", y:555, z:6666};
const test = async ()=>{
	let encryptedResult = await FlowPassworder.encrypt(pass, data);
	console.log("encrypted: result ", encryptedResult)
	/*
	let result = JSON.parse(encryptedResult);
	result.data += "ssssss";
	result.iv += "8";
	result.salt += "ddddddddddsdfsd";
	encryptedResult = JSON.stringify(result);
	console.log("result_", encryptedResult)
	*/
	let decryptedResult = await FlowPassworder.decrypt(pass, encryptedResult);
	console.log("decrypted: result", decryptedResult)
}

test();