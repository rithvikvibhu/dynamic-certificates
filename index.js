const fs = require('fs');
const tls = require('tls');
const forge = require('node-forge');
const pki = forge.pki;

/**
 * Dynamic Certificates
 * Dynamically generate certificates to be used with `https` server
 * @exports
 * @param options Options
 * @param {string} options.pubKey PEM-formatted public key
 * @param {string} options.privKey PEM-formatted private key
 * @param {string} options.pubKeyFile path to file containing public key
 * @param {string} options.privKey path to file containing private key
 */
class DynamicCertificates {
  constructor({ pubKey, privKey, pubKeyFile, privKeyFile }) {
    this.publicKey = null;
    this.privateKey = null;

    let publicKey = pubKey;
    let privateKey = privKey;

    if (!publicKey && pubKeyFile) {
      publicKey = fs.readFileSync(pubKeyFile, 'ascii');
    }
    if (!privateKey && privKeyFile) {
      privateKey = fs.readFileSync(privKeyFile, 'ascii');
    }

    this.importKeyPair(publicKey, privateKey);
  }

  /**
   * Pass as option to https.createServer to use
   * @param {string} serverName
   * @param {function} callback
   */
  sniCallback = (serverName, callback) => {
    // Must be an arrow function to use `this`
    const cert = this.createCertifcate(serverName);

    callback(
      null,
      new tls.createSecureContext({
        cert: pki.certificateToPem(cert.certificate),
        key: pki.privateKeyToPem(cert.privateKey),
      })
    );
  };

  /**
   * Import key pair
   * @param {string} publicKey PEM-formatted public key
   * @param {string} privateKey PEM-formatted private key
   */
  importKeyPair(publicKey, privateKey) {
    this.publicKey = pki.publicKeyFromPem(publicKey);
    this.privateKey = pki.privateKeyFromPem(privateKey);

    return {
      publicKey: this.publicKey,
      privateKey: this.privateKey,
    };
  }

  /**
   * Generate a certificate for a given serverName
   * @param {string} serverName
   */
  createCertifcate(serverName) {
    const cert = pki.createCertificate();

    cert.publicKey = this.publicKey;
    cert.serialNumber = this.createSerial();
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(
      cert.validity.notBefore.getFullYear() + 1
    );
    const attrs = [
      {
        name: 'commonName',
        value: serverName,
      },
    ];
    cert.setSubject(attrs);
    cert.setIssuer(attrs);
    cert.setExtensions([
      {
        name: 'basicConstraints',
        cA: false,
      },
      {
        name: 'keyUsage',
        digitalSignature: true,
        keyEncipherment: true,
      },
      {
        name: 'extKeyUsage',
        serverAuth: true,
        clientAuth: true,
      },
      {
        name: 'subjectAltName',
        altNames: [
          {
            type: 2, // DNS
            value: serverName,
          },
          {
            type: 2, // DNS
            value: '*.' + serverName,
          },
        ],
      },
      {
        name: 'subjectKeyIdentifier',
      },
    ]);

    // Self sign
    cert.sign(this.privateKey, forge.md.sha256.create());

    return {
      certificate: cert,
      privateKey: this.privateKey,
      publicKey: this.publicKey,
    };
  }

  /**
   * Get SHA-256 digest of SPKI for TLSA record (3 1 1)
   */
  getSpkiFingerprint() {
    const hash = pki.getPublicKeyFingerprint(this.publicKey, {
      type: 'SubjectPublicKeyInfo',
      md: forge.md.sha256.create(),
      encoding: 'hex',
      delimiter: '',
    });
    return hash;
  }

  // https://github.com/pinheadmz/handout/blob/d98ed370849dbaaeafca77a72aaf6b8741cc3c29/scripts/hnssec-gen.js#L30
  createSerial() {
    const date = new Date();
    const month = date.getMonth() + 1;
    const day = date.getDate();
    if (day > 1) {
      date.setDate(day - 1);
    } else {
      date.setMonth((month + 11) % 12);
      date.setDate(30);
    }

    const serial =
      String(date.getFullYear()) +
      ('0' + String(month)).slice(-2) +
      ('0' + String(day)).slice(-2) +
      '00';

    return serial;
  }
}

module.exports = {
  DynamicCertificates,
};
