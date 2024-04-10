import * as secp256k1 from 'secp256k1';
import keccak256 from 'keccak256';

export default class MoonMethod {
    /**
     *
     * @param node BIP32Interface
     * @returns {KeysInterface} { did, address, privateKey, publicKey, chainCode, didDocument }.
     */
    async getKeys(node: BIP32Interface): Promise<KeysInterface> {
        const privateKey = node.privateKey?.toString('hex');
        const chainCode = node.chainCode?.toString('hex');
        const publicKey = node.publicKey?.toString('hex') as string;
        const address = this.getAddressFromPublicKey(publicKey);
        const did = `did:moon:${address}`;

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
            const publicKeyBuffer = secp256k1.publicKeyCreate(privateKey, true);
            const publicKey = Buffer.from(publicKeyBuffer).toString('hex');
            jwk.ethereumAddress = this.getAddressFromPublicKey(publicKey);
            jwk.owner = `did:moon:${jwk.ethereumAddress}`;
            jwk.id = `${jwk.owner}#owner`;

            if (includePrivateKey) {
                jwk.publicKeyHex = privateKey;
            }
        }

        return jwk;
    }

    private getAddressFromPublicKey(publicKey: string): string {
        const hashPublicKey = keccak256(publicKey).toString('hex');
        /* Calculate the starting index to get the last twenty bytes. Each byte is represented by 2 characters in a hex string */
        const startIndex = hashPublicKey.length - 20 * 2;
        /* Extract the last twenty bytes */
        const lastTwentyBytes = hashPublicKey.substring(startIndex);

        return `0x${lastTwentyBytes}`;
    }
}
