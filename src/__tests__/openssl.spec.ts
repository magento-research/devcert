import * as fs from '../fs-promisified';
import * as OpenSSL from '../openssl';
import {
    checkPrivateKeyFile,
    parseCertificateFile,
    parseConf
} from './__helpers__/ssl';

beforeAll(() => {
    jest.spyOn(fs, 'writeFile');
});
beforeEach(() => jest.clearAllMocks());

it('tmpFile() creates unique filenames from a name', () => {
    expect(OpenSSL.tmpFile('foo')).toMatch(/^\/.*foo\d*/);
    // same seed leads to an appended digit
    expect(OpenSSL.tmpFile('foo')).toMatch(/^\/.*foo\d+/);
});

it('tmpClear() removes all tmp files', async () => {
    const files: string[] = ['foo', 'foo'].map(OpenSSL.tmpFile);

    await Promise.all(
        files.map(async (file, i) =>
            fs.writeFile(file, `file${i} contents`, 'utf8')
        )
    );

    await Promise.all(
        files.map(async (file, i) =>
            expect(fs.readFile(file, { encoding: 'utf8' })).resolves.toEqual(
                `file${i} contents`
            )
        )
    );

    await OpenSSL.tmpClear();

    await Promise.all(
        files.map(async file =>
            expect(
                fs.readFile(file, { encoding: 'utf8' })
            ).rejects.toThrowError('ENOENT')
        )
    );
});

it('tmpClear() does not throw when trying to unlink nothing or a missing file', async () => {
    expect(await OpenSSL.tmpClear()).toBeUndefined();
    OpenSSL.tmpFile('foo'); // create the filename, but don't create the file!
    expect(await OpenSSL.tmpClear()).toBeUndefined();
});

it('generateOpensslConf() creates a conf file and returns its path', async () => {
    const confPath: string = await OpenSSL.generateOpensslConf('foo.zoo');
    const confText: string = await fs.readFile(confPath, 'utf8');
    const conf: any = parseConf(confText);
    expect(conf).toMatchObject({
        CA_default: {
            database: expect.stringMatching(/^\/.*/),
            serial: expect.stringMatching(/^\/.*/)
        },
        alt_names: {
            'DNS.1': 'foo.zoo'
        },
        ca: {
            default_ca: 'CA_default'
        },
        server_cert: {
            nsComment: 'foo.zoo Issued Certificate'
        }
    });

    expect(await fs.readFile(conf.CA_default.database, 'utf8')).toEqual('');

    expect(await fs.readFile(conf.CA_default.serial, 'utf8')).toMatch(
        /[0-9a-f]+/i
    );
});

let fooZooRootCert; // shared to determine if they are the same cert

it('generateRootCertificate() creates a root cert and returns its path', async () => {
    const confPath: string = await OpenSSL.generateOpensslConf('foo.zoo');
    const { keyFilePath, certFilePath } = await OpenSSL.generateRootCertificate(
        'foo.zoo',
        confPath
    );

    expect(await checkPrivateKeyFile(keyFilePath)).toBeTruthy();

    fooZooRootCert = await parseCertificateFile(certFilePath);

    expect(fooZooRootCert).toMatchObject({
        issuer: {
            commonName: 'foo.zoo'
        },
        purposes: {
            'Netscape SSL server CA': true,
            'SSL server CA': true
        },
        subject: {
            commonName: 'foo.zoo'
        }
    });

    const notAfter = new Date(fooZooRootCert.notAfter);
    const notBefore = new Date(fooZooRootCert.notBefore);

    expect(notBefore.getTime()).toBeLessThan(Date.now());
    expect(notAfter.getTime()).toBeGreaterThan(Date.now());
});

it('caches and returns the same CA on subsequent calls for the same CN, during process lifetime', async () => {
    const confPath: string = await OpenSSL.generateOpensslConf('foo.zoo');
    const { keyFilePath, certFilePath } = await OpenSSL.generateRootCertificate(
        'foo.zoo',
        confPath
    );

    expect(await checkPrivateKeyFile(keyFilePath)).toBeTruthy();

    expect(await parseCertificateFile(certFilePath)).toMatchObject(
        fooZooRootCert
    );
});

it('creates a different CA if asked for a different commonName', async () => {
    const confPath: string = await OpenSSL.generateOpensslConf('bar.aquarium');
    const { keyFilePath, certFilePath } = await OpenSSL.generateRootCertificate(
        'bar.aquarium',
        confPath
    );

    expect(await checkPrivateKeyFile(keyFilePath)).toBeTruthy();

    const barAquariumRootCert = await parseCertificateFile(certFilePath);

    expect(barAquariumRootCert).not.toEqual(fooZooRootCert);

    expect(barAquariumRootCert).toMatchObject({
        issuer: {
            commonName: 'bar.aquarium'
        },
        purposes: {
            'Netscape SSL server CA': true,
            'SSL server CA': true
        },
        subject: {
            commonName: 'bar.aquarium'
        }
    });
});

it('creates an SSL cert signed by the root CA', async () => {
    const openSSLConfPath: string = await OpenSSL.generateOpensslConf(
        'foo.zoo'
    );
    const caPaths = await OpenSSL.generateRootCertificate(
        'foo.zoo',
        openSSLConfPath
    );
    const {
        keyFilePath,
        certFilePath
    } = await OpenSSL.generateSignedCertificate(
        'foo.zoo',
        openSSLConfPath,
        caPaths
    );

    expect(await checkPrivateKeyFile(keyFilePath)).toBeTruthy();

    const certificate = await parseCertificateFile(certFilePath);

    expect(certificate).toMatchObject({
        altNames: expect.arrayContaining(['foo.zoo', 'localhost', '[::1]']),
        issuer: {
            commonName: 'foo.zoo'
        },
        purposes: {
            'Netscape SSL server': true,
            'Netscape SSL server CA': false,
            'SSL server': true,
            'SSL server CA': false
        },
        subject: {
            commonName: 'foo.zoo'
        }
    });
});
