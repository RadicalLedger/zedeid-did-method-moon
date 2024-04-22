import * as secp256k1 from 'secp256k1';
import keccak256 from 'keccak256';

export default class MoonMethod {
    private chain: string = 'moon';

    /**
     *
     * @param chain - chain type
     */
    constructor(chain?: string) {
        if (chain) this.chain += `:${chain}`;
    }

    /**
     *
     * @param node BIP32Interface
     * @returns {KeysInterface} { did, address, privateKey, publicKey, chainCode, didDocument }.
     */
    async getKeys(node: BIP32Interface): Promise<KeysInterface> {
        const privateKey = node.privateKey?.toString('hex');
        const chainCode = node.chainCode?.toString('hex');
        const publicKey = node.publicKey?.toString('hex') as string;
        const address = this.getAddressFromPublicKey(
            this.getPublicKey(privateKey as string, false)
        );
        const did = `did:${this.chain}:${address}`;

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
            jwk.ethereumAddress = this.getAddressFromPublicKey(this.getPublicKey(seed, false));
            jwk.owner = `did:${this.chain}:${jwk.ethereumAddress}`;
            jwk.id = `${jwk.owner}#owner`;

            if (includePrivateKey) {
                jwk.publicKeyHex = privateKey;
            }
        }

        return jwk;
    }

    private getPublicKey(privateKey: string, compressed: boolean = true): string {
        const privateKeyBuffer = Buffer.from(Buffer.from(privateKey, 'hex'));

        let publicKeyBuffer = secp256k1.publicKeyCreate(privateKeyBuffer, compressed);

        /* remove compressed flag */
        if (!compressed) publicKeyBuffer = publicKeyBuffer.slice(1);

        return Buffer.from(publicKeyBuffer).toString('hex');
    }

    private getAddressFromPublicKey(publicKey: string): string {
        const publicKeyBuffer = Buffer.from(publicKey, 'hex');
        const addressBuffer = Buffer.from(keccak256(publicKeyBuffer)).slice(-20);

        return `0x${addressBuffer.toString('hex')}`;
    }
}
