import mkdirp = require('mkdirp');
import os = require('os');
import path = require('path');
import _rimraf = require('rimraf');
import util = require('util');
import { exec } from './child_process-promisified';
import * as fs from './fs-promisified';

const rimraf = util.promisify(_rimraf);

// simple temp file pathing, requires manual removal
let tmpPrefix;
let tmpFiles;
export function tmpFile(name: string) {
    if (!tmpFiles) {
        tmpPrefix = path.join(
            os.tmpdir(),
            Math.round(Math.random() * 36 ** 10).toString(36)
        );
        tmpFiles = [];
    }
    const file = tmpPrefix + name;
    let tmpFileUnique = file;
    let uniqueIndex = 0;
    while (tmpFiles.indexOf(tmpFileUnique) !== -1) {
        tmpFileUnique = file + ++uniqueIndex;
    }
    tmpFiles.push(tmpFileUnique);
    return tmpFileUnique;
}

export async function tmpClear() {
    if (tmpFiles) {
        for (const file of tmpFiles) {
            try {
                await fs.unlink(file);
            } catch (e) {
                // do nothing
            }
        }
        tmpFiles = null;
    }
}

let rndFile;
async function openssl(cmd: string) {
    if (!rndFile) {
        rndFile = tmpFile('rnd');
    }
    return exec(`openssl ${cmd}`, {
        env: {
            RANDFILE: rndFile,
            ...process.env
        },
        stdio: 'ignore'
    });
}

interface IOpensslTemplateOpts {
    commonName: string;
    databasePath: string;
    serialPath: string;
}

const newline = /\r\n|\r|\n/g;
const linebreak = process.platform === 'win32' ? '\r\n' : '\n';
function normalizeLinebreaks(str) {
    return str.replace(newline, linebreak);
}

const opensslConfTemplate = ({
    commonName,
    databasePath,
    serialPath
}: IOpensslTemplateOpts) => `[ ca ]
# \`man ca\`
default_ca = CA_default

[ CA_default ]
default_md        = sha256
name_opt          = ca_default
cert_opt          = ca_default
policy            = policy_loose
database          = ${databasePath.replace(/\\/g, '\\\\')}
serial            = ${serialPath.replace(/\\/g, '\\\\')}
prompt            = no

[ policy_loose ]
# Only require minimal information for development certificates
commonName              = supplied

[ req ]
# Options for the \`req\` tool (\`man req\`).
default_bits        = 2048
distinguished_name  = req_distinguished_name
string_mask         = utf8only

# SHA-1 is deprecated, so use SHA-2 instead.
default_md          = sha256

# Extension to add when the -x509 option is used.
x509_extensions     = v3_ca

[ req_distinguished_name ]
# See <https://en.wikipedia.org/wiki/Certificate_signing_request>.
commonName                      = Common Name

[ v3_ca ]
# Extensions for a typical CA (\`man x509v3_config\`).
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ server_cert ]
# Extensions for server certificates (\`man x509v3_config\`).
basicConstraints = CA:FALSE
nsCertType = server
nsComment = "${commonName} Issued Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = ${commonName}
DNS.2 = localhost
DNS.3 = localhost.localdomain
DNS.4 = lvh.me
DNS.5 = *.lvh.me
DNS.6 = [::1]
IP.1 = 127.0.0.1
IP.2 = fe80::1
`;

interface ICachedOpensslConf extends IOpensslTemplateOpts {
    confPath: string;
}
const cachedConfPaths: Map<string, ICachedOpensslConf> = new Map();
export async function generateOpensslConf(commonName: string): Promise<string> {
    let conf = cachedConfPaths.get(commonName);
    if (!conf) {
        conf = {
            commonName,
            confPath: tmpFile('openssl.conf'),
            databasePath: tmpFile('index.txt'),
            serialPath: tmpFile('serial')
        };
        const confText = opensslConfTemplate(conf);
        await Promise.all([
            fs.writeFile(conf.confPath, normalizeLinebreaks(confText)),
            fs.writeFile(conf.databasePath, ''),
            fs.writeFile(
                conf.serialPath,
                Math.round(Math.random() * 16 ** 10).toString(16)
            )
        ]);
        cachedConfPaths.set(commonName, conf);
    }
    return conf.confPath;
}

export interface ICertificate {
    ca?: string;
    cert: string;
    key: string;
    commonName: string;
}

export interface ICertificateFilePair {
    certFilePath: string;
    keyFilePath: string;
}

// cache the root CA in memory so it can sign without further prompting for the
// rest of this process lifetime
const cachedRoot: ICertificate = {
    cert: '',
    commonName: '',
    key: ''
};

async function generateKey(): Promise<string> {
    const keyFile = tmpFile('key');
    if (cachedRoot.key) {
        await fs.writeFile(keyFile, cachedRoot.key, {
            encoding: 'utf8',
            mode: 400
        });
    } else {
        await openssl(`genrsa -out ${keyFile} 2048`);
        cachedRoot.key = await fs.readFile(keyFile, 'utf8');
        await fs.chmod(keyFile, 400);
    }
    return keyFile;
}

export async function generateRootCertificate(
    commonName: string,
    opensslConfPath: string
): Promise<ICertificateFilePair> {
    const certFilePath = tmpFile(`${commonName}.crt`);
    const keyFilePath = await generateKey();
    if (cachedRoot.commonName === commonName) {
        await fs.writeFile(certFilePath, cachedRoot.cert);
    } else {
        await openssl(
            `req -config ${opensslConfPath} -key ${keyFilePath} -out ${certFilePath} -new -subj "/CN=${commonName}" -x509 -days 7000 -extensions v3_ca`
        );
        cachedRoot.cert = await fs.readFile(certFilePath, 'utf8');
        cachedRoot.commonName = commonName;
    }
    return { keyFilePath, certFilePath };
}

export async function generateSignedCertificate(
    commonName: string,
    opensslConfPath: string,
    caPaths: ICertificateFilePair
): Promise<ICertificateFilePair> {
    const keyFilePath = await generateKey();
    process.env.SAN = commonName;
    const csrFile = tmpFile(`${commonName}.csr`);
    await openssl(
        `req -config ${opensslConfPath} -subj "/CN=${commonName}" -key ${keyFilePath} -out ${csrFile} -new`
    );
    const certFilePath = tmpFile(`${commonName}.crt`);

    // needed but not used (see https://www.mail-archive.com/openssl-users@openssl.org/msg81098.html)
    const caCertsDir = path.join(
        os.tmpdir(),
        Math.round(Math.random() * 36 ** 10).toString(36)
    );
    mkdirp.sync(caCertsDir);

    await openssl(
        `ca -config ${opensslConfPath} -in ${csrFile} -out ${certFilePath} -outdir ${caCertsDir} -keyfile ${
            caPaths.keyFilePath
        } -cert ${
            caPaths.certFilePath
        } -notext -md sha256 -days 7000 -batch -extensions server_cert`
    );

    await rimraf(caCertsDir);

    return { keyFilePath, certFilePath };
}
