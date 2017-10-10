const execSync = require('child_process').execSync;
const fs = require('fs');
const Path = require('path');

const privateKeyPath = Path.join(__dirname, '../update.key');
const publicKeyPath = Path.join(__dirname, '../update.pub');
const updateCodePath = Path.join(__dirname, '..', 'source', 'update_certs.h');

if (fs.existsSync(privateKeyPath)) {
    console.error(`${privateKeyPath} already exists, refusing to overwrite existing private key`);
    process.exit(1);
}

try {
    execSync(`openssl genrsa -out ${privateKeyPath} 2048`);
    execSync(`openssl rsa -pubout -in ${privateKeyPath} -out ${publicKeyPath}`);
}
catch (ex) {
    console.error('Could not generate public/private key pair. Did you install openssl?', ex);
    process.exit(1);
}

// Now create the certificate keys
let pubkey = execSync(`openssl rsa -pubin -text -noout < ${publicKeyPath}`).toString('utf-8');
let exponent = pubkey.match(/0x(\d+)/)[1];
if (exponent.length === 5) exponent = '0' + exponent; //?? not sure if this is good
let modulus = [];

for (let l of pubkey.split('\n')) {
    if (l.indexOf('    ') === 0) {
        modulus = modulus.concat(l.trim().split(':').filter(f => !!f));
    }
}

let certs = `#ifndef _UPDATE_CERTS_H
#define _UPDATE_CERTS_H

const char * UPDATE_CERT_MODULUS = "${modulus.join('')}";
const char * UPDATE_CERT_EXPONENT = "${exponent}";

#endif // _UPDATE_CERTS_H_
`;
fs.writeFileSync(updateCodePath, certs, 'utf-8');

console.log(`Done, created ${updateCodePath}`);

