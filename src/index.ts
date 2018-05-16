import cmdExists = require('command-exists');
import util = require('util');
import fs = require('./fs-promisified');
import installAuthority from './install-authority';

const commandExists = util.promisify(cmdExists);

import {
    generateOpensslConf,
    generateRootCertificate,
    generateSignedCertificate,
    ICertificate,
    tmpClear
} from './openssl';

async function generateDevCert(commonName: string): Promise<ICertificate> {
    if (!(await commandExists('openssl'))) {
        throw new Error(
            'Unable to find openssl - make sure it is installed and available in your PATH'
        );
    }
    if (!commonName.match(/^(.|\.){1,64}$/)) {
        throw new Error(`Invalid Common Name ${commonName}.`);
    }
    try {
        const opensslConfPath = await generateOpensslConf(commonName);
        const caPaths = await generateRootCertificate(
            commonName,
            opensslConfPath
        );
        await installAuthority(commonName, caPaths.certFilePath);
        const { keyFilePath, certFilePath } = await generateSignedCertificate(
            commonName,
            opensslConfPath,
            caPaths
        );
        const [key, cert, ca] = await Promise.all(
            [keyFilePath, certFilePath, caPaths.certFilePath].map(filepath =>
                fs.readFile(filepath, 'utf8')
            )
        );
        return { ca, cert, commonName, key };
    } finally {
        // clear all tmp files (including root cert!)
        await tmpClear();
    }
}

export default generateDevCert;
