"use strict";

const crypto = require("crypto");
const AWS = require("aws-sdk");

AWS.config.update({ region: "us-east-1" });

// Private key stored as encrypted environment key by AWS KMS service.
const privateKeyEncrypted = process.env["PRIVATE_KEY"];
let privateKey;

/*
 * oscillating function: f(t) = A + Bsin(Ct) + Dcos(Et),
 * A, B, C, D, E - constants
 */
const A = 1000,
  B = 100,
  C = 3,
  D = 100,
  E = 4;

function getCurrentEpochTime() {
  return Math.floor(new Date().getTime() / 1000);
}

function generateValue(epochTime) {
  return A + B * Math.sin(C * epochTime) + D * Math.cos(E * epochTime);
}

// signature of (value, t) generated using some private key (known to endpoint only)
function generateSignature(value, epochTime) {
  const signer = crypto.createSign("RSA-SHA256");

  // Concat as string
  const valueToSign = "" + value + epochTime;
  signer.update(valueToSign);
  signer.end();

  return "0x" + signer.sign(privateKey, "hex");
}

function prepareBody() {
  const epoch = getCurrentEpochTime();
  const value = generateValue(epoch);
  const signature = generateSignature(value, epoch);

  return { epoch, value, signature };
}

function transformToRSAFormat(plaintext) {
  plaintext = plaintext.replace(/\s/g, "\n");
  return `-----BEGIN RSA PRIVATE KEY-----\n${plaintext}\n-----END RSA PRIVATE KEY-----`;
}

module.exports.endpoint = (event, context, callback) => {
  if (privateKey) {
    processEvent(event, context, callback);
  } else {
    const kms = new AWS.KMS();
    kms.decrypt(
      { CiphertextBlob: Buffer.from(privateKeyEncrypted, "base64") },
      (err, data) => {
        if (err) {
          console.log("Decrypt error:", err);
          return callback(err);
        }
        // Private key is stored as plaintext with spaces in encrypted environment keys.
        // We need to transform it to properly RSA schema.
        privateKey = transformToRSAFormat(data.Plaintext.toString("ascii"));

        processEvent(event, context, callback);
      }
    );
  }
};

function processEvent(event, context, callback) {
  const response = {
    statusCode: 200,
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify(prepareBody())
  };

  callback(null, response);
}
