"use strict";

/********* External Imports ********/
const { stringToBuffer, bufferToString, encodeBuffer, decodeBuffer, getRandomBytes } = require("./lib");
const { subtle } = require('crypto').webcrypto;

/********* Constants ********/
const PBKDF2_ITERATIONS = 100000; // number of iterations for PBKDF2 algorithm
const MAX_PASSWORD_LENGTH = 64;   // we can assume no password is longer than this many characters

/********* Implementation ********/
class Keychain {
  constructor() {
    this.data = {}; // Store member variables that you intend to be public here
    this.secrets = {}; // Store member variables that you intend to be private here
  }

  static async init(password) {
    const keychain = new Keychain();
    keychain.secrets.masterKey = await keychain.CreateKey(password);
    return keychain;
  }

  //generating key out of password and randomly generatedsalt
  async CreateKey(password) {
    const salt = getRandomBytes(16);
    const keyMaterial = await subtle.importKey(
      'raw', //raw binary
      stringToBuffer(password),
      { name: 'PBKDF2' },
      false,
      ['deriveKey']);

    const key = await subtle.CreateKey(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: PBKDF2_ITERATIONS,
        hash: 'SHA-256'
      },


      //factors for the newly made key  
      //single key (AES, bits 256)
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
    this.secrets.salt = encodeBuffer(salt);
    return key;
  }
// input
  async set(name, value) {
    const encodedName = encodeBuffer(stringToBuffer(name));
    const encodedValue = encodeBuffer(stringToBuffer(value));
    this.data[encodedName] = encodedValue;
  }
//reading /extracting
  async get(name) {
    const encodedName = encodeBuffer(stringToBuffer(name));
    const encodedValue = this.data[encodedName];
    
    return encodedValue ? bufferToString(decodeBuffer(encodedValue)) : null;
  }
//deleting 
  async remove(name) {
    const encodedName = encodeBuffer(stringToBuffer(name));
    if (encodedName in this.data) {
      delete this.data[encodedName];
      return true;
    }
    return false;
  }

// including the kvs as well as handling the conversion of any string to an encoded cipher returning the hash value and original)
  async dump() {
    const kvs = { ...this.data }; 
    const dataString = JSON.stringify({ kvs });
    const dataBuffer = stringToBuffer(dataString);
    const hashBuffer = await subtle.digest('SHA-256', dataBuffer);
    const hashString = encodeBuffer(hashBuffer);
    return [dataString, hashString];
  }


  //password checker onto json 
  //confirms integrity of stored json against inputed password after encoding it
  static async load(password, repr, IntegrityCheck) {
    const parsedData = JSON.parse(repr);
    if (IntegrityCheck) {
      const dataBuffer = stringToBuffer(repr);
      const hashBuffer = await subtle.digest('SHA-256', dataBuffer);
      const hashString = encodeBuffer(hashBuffer);
      if (hashString !== IntegrityCheck) {
        throw  Error("Integrity check failed try again with valid password ");

      }
    }


    const keychain = new Keychain();
    try {
      // create a key from password  
      keychain.secrets.masterKey = await keychain.CreateKey(password);
    } catch (error) {
      throw new error("invalid password, confirm password and try again"); // If an error is caught, return false indicating invalid password
    }


// convert parased data to kvs and display it
    keychain.data = parsedData.kvs; // Restore the KVS object from the parsed data
    console.log('Restored data:', keychain.data);
    alert(`Data loaded successfully: ${JSON.stringify(keychain.data)}`);

    return keychain
  }
}
//making class keychain available for other modules
module.exports = { Keychain };