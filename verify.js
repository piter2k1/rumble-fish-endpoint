const fs = require("fs");
const crypto = require("crypto");

const test = {
  epoch: 1566208962,
  value: 986.359263253936,
  signature:
    "0x9eec98a09ee7662f04336df8337edff5558fff29a09b1b89fb96abf5e6f6f97bdc0f66d5da69443c00e7dba73a51aeabc4b68df8a566845ab5463f82373dfba8"
};

const pem = fs.readFileSync("publicKey.pub");
const publicKey = pem.toString("ascii");

const valueToSign = "" + test.value + test.epoch;
const signature = test.signature.replace(/^0x/, "");

const verifier = crypto.createVerify("RSA-SHA256");
verifier.update(valueToSign);
const status = verifier.verify(publicKey, signature, "hex");

if (status) {
  console.log("This is successfully verified response :)");
} else {
  console.log("This response isn't recognized :(");
}
