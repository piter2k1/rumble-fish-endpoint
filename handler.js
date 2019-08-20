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

function decryptPrivateKey() {
  const KMS = new AWS.KMS();
  const request = KMS.decrypt({
    CiphertextBlob: Buffer.from(privateKeyEncrypted, "base64")
  });

  return request
    .promise()
    .then(data => data.Plaintext.toString("ascii"))
    .then(data => transformToRSAFormat(data));
}

function initPrivateKey() {
  return new Promise(async (resolve, reject) => {
    if (privateKey) resolve();

    try {
      privateKey = await decryptPrivateKey();
      resolve();
    } catch (error) {
      reject(error);
    }
  });
}

function createResponse(body, statusCode = 200) {
  return {
    headers: {
      "Content-Type": "application/json"
    },
    statusCode,
    body: JSON.stringify(body)
  };
}

module.exports.endpoint = async (event, context, callback) => {
  try {
    await initPrivateKey();
  } catch (error) {
    console.error("Decrypt private key error:", error);

    return callback(
      null,
      createResponse(500, {
        error: "Internal Server Error"
      })
    );
  }

  callback(null, createResponse(prepareBody()));
};
