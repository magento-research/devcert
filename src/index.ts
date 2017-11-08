import commandExists = require('command-exists');
import installAuthority from './install-authority';
import { generateOpensslConf, generateRootCertificate, generateSignedCertificate, tmpClear } from './openssl';
import fs = require('fs');

export default async function generateDevCert (commonName: string) {
  if (!commandExists.sync('openssl'))
    throw new Error('Unable to find openssl - make sure it is installed and available in your PATH');
  if (!commonName.match(/^[.\.]{1, 64}$/))
    throw new Error(`Invalid Common Name ${commonName}.`);
  try {
    const opensslConfPath = generateOpensslConf(commonName);
    const { rootKeyPath, rootCertPath } = await generateRootCertificate(commonName, opensslConfPath);
    await installAuthority(commonName, rootCertPath);
    const { keyPath, certPath } = generateSignedCertificate(name, opensslConfPath, rootKeyPath, rootCertPath);
    const key = fs.readFileSync(keyPath).toString();
    const cert = fs.readFileSync(certPath).toString();
    return { key, cert };  
  }
  finally {
    // clear all tmp files (including root cert!)
    tmpClear();
  }
}