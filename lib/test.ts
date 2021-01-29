import {encrypt, decrypt, readBuffers, writeBuffer} from './flow-key-crypt';


/*

let buf = writeBuffer("64e9cbb1546f2a604c61b86d3d023aef2c36ca0e5d49803e0635b6f53b11d24e8b0b1b92bee299db2b5124cea67fa9f9121ee0dcfdcdb88a61b248194d545e200e5719fa3913d3b52cc23eb634370300b0e26356404c906debd0a7b8ddab7b70061de1778736abe4a93fda4b07a299e768d1a284373718fd069e747b19f0e3ed61b0331038e8eb2bea9e677b2252a98fe81b44a72b36b7fd8e23a05846daf02895da75988f2997c607324cf2507434606d1c3bdebc4ba6a50cc3e90106a2d79c743f708aa5267ef82a8ca2e0fecb9faf6d53c7812f52860e53c673b9af1bee18")
buf = writeBuffer("cf0ad2cf460f88e1eca1e2a1a5fbbfce", buf)
let hex = buf.toString("hex");
console.log("buf", hex)
let bufs = readBuffers(hex);

console.log("buf2", bufs.map(b=>b.toString()))
*/

let pass = "xyzdgfggdfgdfg";
let data = {x:"1111", y:555, z:6666};
let data2 = '{"data":"64e9cbb1546f2a604c61b86d3d023aef2c36ca0e5d49803e0635b6f53b11d24e8b0b1b92bee299db2b5124cea67fa9f9121ee0dcfdcdb88a61b248194d545e200e5719fa3913d3b52cc23eb634370300b0e26356404c906debd0a7b8ddab7b70061de1778736abe4a93fda4b07a299e768d1a284373718fd069e747b19f0e3ed61b0331038e8eb2bea9e677b2252a98fe81b44a72b36b7fd8e23a05846daf02895da75988f2997c607324cf2507434606d1c3bdebc4ba6a50cc3e90106a2d79c743f708aa5267ef82a8ca2e0fecb9faf6d53c7812f52860e53c673b9af1bee18","iv":"cf0ad2cf460f88e1eca1e2a1a5fbbfce","salt":"acd96e2021478b914438eeaedfd5441288216d4ca40ce97faf0c1de77a5685b6"}'
let data2pass = 's';

const test = async ()=>{

	let decryptedResult = await decrypt(data2pass, data2);
	console.log("old data test:", decryptedResult)

	let encryptedResult = await encrypt(pass, data);
	console.log("encrypted: result ", encryptedResult)
	/*
	let result = JSON.parse(encryptedResult);
	result.data += "ssssss";
	result.iv += "8";
	result.salt += "ddddddddddsdfsd";
	encryptedResult = JSON.stringify(result);
	console.log("result_", encryptedResult)
	*/
	decryptedResult = await decrypt(pass, encryptedResult);
	console.log("decrypted: result", decryptedResult)
}


test();