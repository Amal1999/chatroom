const forge = require('node-forge');
const fs = require('fs');

class CertificateAuthority {

    instance = null;
    ca = null;

    constructor() {

        if (fs.existsSync('server/certifs/ca_certif.pem')) {
            const pem = fs.readFileSync('server/certifs/ca_certif.pem', 'utf-8');
            this.ca = forge.pki.certificateFromPem(pem);
        } else {

            // Generate a key pair for the certificate authority
            var keys = forge.pki.rsa.generateKeyPair(2048);

            // Create a new certificate authority (CA)
            this.ca = forge.pki.createCertificate();

            // Set the public key for the CA
            this.ca.publicKey = keys.publicKey;

            // Set the subject information for the CA
            this.ca.setSubject([
                {
                    name: 'commonName',
                    value: 'CertifAuth'
                },
                {
                    name: 'countryName',
                    value: 'TN'
                },
                {
                    shortName: 'ST',
                    value: 'Tunis'
                },
                {
                    name: 'localityName',
                    value: 'Tunis'
                },
                {
                    name: 'organizationName',
                    value: 'INSAT'
                }
            ]);

            // Set the validity period for the CA
            this.ca.validity.notBefore = new Date();
            this.ca.validity.notAfter = new Date();
            this.ca.validity.notAfter.setFullYear(this.ca.validity.notBefore.getFullYear() + 10);

            // Self-sign the CA certificate
            this.ca.sign(keys.privateKey);

            // Set the validity period for the CA
            this.ca.validity.notBefore = new Date();
            this.ca.validity.notAfter = new Date();
            this.ca.validity.notAfter.setFullYear(this.ca.validity.notBefore.getFullYear() + 10);

            // Self-sign the CA certificate
            this.ca.sign(keys.privateKey);

            const pem = forge.pki.certificateToPem(this.ca);
            // Write the certificate to a file
            fs.writeFileSync('server/certifs/ca_certif.pem', pem);
            console.log('Certificate written to my-root-ca.pem')
        }
    }

    getInstance() {
        if (this.instance == null) {
            this.instance = new CertificateAuthority()
        }
        return this.instance
    }

    createCertification(username) {
        // Generate a new RSA keypair
        const keys = forge.pki.rsa.generateKeyPair(2048);

        // Create a certificate signing request (CSR)
        const csr = forge.pki.createCertificationRequest();
        csr.publicKey = keys.publicKey;
        csr.setSubject([{ name: 'commonName', value: username }]);
        csr.sign(keys.privateKey);

        // Create a self-signed root CA certificate
        const cert = forge.pki.createCertificate();
        cert.publicKey = csr.publicKey;
        cert.setSubject(csr.subject.attributes);
        cert.setIssuer(this.ca.subject);
        cert.setExtensions([{ name: 'basicConstraints', cA: true }]);
        cert.sign(keys.privateKey);

        console.log(forge.pki.certificateToPem(cert));

        const pem = forge.pki.certificateToPem(cert);

        // Write the certificate to a file
        fs.writeFileSync("server/certifs/" + username + '_certif.pem', pem);
        console.log('Certificate written to my-root-ca.pem')
    }

    verficateCertification(username) {

        // Load the CA public key from a PEM file
        var caPublicKey = forge.pki.publicKeyFromPem(fs.readFileSync('server/certifs/ca_certif.pem', 'utf8'));

        // Load the certificate to be verified from a PEM file
        var cert = forge.pki.certificateFromPem(fs.readFileSync("server/certifs/" + username + '_certif.pem', 'utf8'));

        // Verify the certificate against the CA public key
        var verified = cert.verify(caPublicKey);

        if (verified) {
            console.log("Certificate is valid and issued by the CA.");
        } else {
            console.log("Certificate is not valid or not issued by the CA.");
        }
        return verified;
    }

}

module.exports = CertificateAuthority;







