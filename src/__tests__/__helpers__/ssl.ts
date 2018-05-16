import { ChildProcess, exec } from 'child_process';
import { tmpdir } from 'os';
import { join } from 'path';
import * as x509 from 'x509.js';
import { readFile } from '../../fs-promisified';

const rndFile = join(
    tmpdir(),
    Math.round(Math.random() * 36 ** 10).toString(36)
);
export function openssl(cmd: string, stdin?: string): Promise<string> {
    return new Promise((resolve, reject) => {
        const child: ChildProcess = exec(
            `openssl ${cmd}`,
            {
                env: {
                    RANDFILE: rndFile,
                    ...process.env
                },
                windowsHide: true
            },
            (error: Error, stdout: string, stderr: string): void => {
                if (error) {
                    reject(error);
                } else if (stdout === '' && stderr !== '') {
                    reject(stderr);
                } else {
                    resolve(stdout);
                }
            }
        );
        if (stdin) {
            child.stdin.write(stdin);
        }
    });
}

export async function checkPrivateKey(keyText) {
    return /key ok/.test(await openssl('rsa -check -noout', keyText));
}

export async function checkPrivateKeyFile(keyFile) {
    return checkPrivateKey(await readFile(keyFile, 'utf8'));
}

// Adds openssl purposes (experimental) if available
export async function parseCertificate(certText) {
    const info = x509.parseCert(certText);
    const purposesText = await openssl('x509 -purpose -noout', certText);
    info.purposes = purposesText.split('\n').reduce((out, line) => {
        const matches = line.match(/^\s*(.+?)\s*:\s*(Yes|No)\s*/);
        if (matches) {
            out[matches[1]] = matches[2] === 'Yes';
        }
        return out;
    }, {});
    return info;
}

export async function parseCertificateFile(certFile) {
    return parseCertificate(await readFile(certFile, 'utf8'));
}

export { parse as parseConf } from 'ini';
