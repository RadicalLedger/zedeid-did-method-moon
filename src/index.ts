import * as secp256k1 from 'secp256k1';

export default class MoonMethod {
    /**
     *
     * @param node BIP32Interface
     * @returns {KeysInterface} { did, address, privateKey, publicKey, chainCode, didDocument }.
     */
    async getKeys(node: BIP32Interface): Promise<KeysInterface> {
        const privateKey = node.privateKey?.toString('hex');
        const chainCode = node.chainCode?.toString('hex');
        const address = node.publicKey?.toString('hex') as string;
        const publicKey = address;
        const did = `did:moon:0x${address}`;

        const { didDocument } = await this.getDocument(privateKey as string);

        return { did, address, privateKey, publicKey, chainCode, didDocument };
    }

    /**
     *
     * @param privateKey - private key as a hex string
     * @returns {CreateDidDocumentInterface}
     */
    async getDocument(privateKey: string): Promise<CreateDidDocumentInterface> {
        const verificationKey: VerificationKeyInterface =
            await this.createVerificationMethod(privateKey);

        const authentication = {
            type: 'Secp256k1SignatureAuthentication2018',
            publicKey: verificationKey.id
        };

        const didDocument = {
            '@context': 'https://w3id.org/did/v1',
            id: verificationKey.owner,
            publicKey: [verificationKey],
            authentication: [authentication],
            assertionMethod: [authentication],
            service: []
        };

        return { didDocument };
    }

    /**
     *
     * @param seed - seed as a hex string
     * @param includePrivateKey - include private key
     * @returns {VerificationKeyInterface}
     */
    async createVerificationMethod(
        seed: string,
        includePrivateKey: boolean = false
    ): Promise<VerificationKeyInterface> {
        let jwk: VerificationKeyInterface = {
            id: '',
            owner: '',
            type: 'Secp256k1VerificationKey2018',
            ethereumAddress: ''
        };
        const privateKey = new Uint8Array(Buffer.from(seed, 'hex'));
        const verified = secp256k1.privateKeyVerify(privateKey);

        if (verified) {
            const publicKey = secp256k1.publicKeyCreate(privateKey, true);
            jwk.ethereumAddress = `0x${Buffer.from(publicKey).toString('hex')}`;
            jwk.owner = `did:moon:0x${Buffer.from(publicKey).toString('hex')}`;
            jwk.id = `${jwk.owner}#owner`;

            if (includePrivateKey) {
                jwk.publicKeyHex = privateKey;
            }
        }

        return jwk;
    }
}
