import * as secp256k1 from 'secp256k1';
import { keccak_256 } from '@noble/hashes/sha3';

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
        const recoveryMethod: VerificationKeyInterface =
            await this.createRecoveryMethod(privateKey);

        const didDocument = {
            '@context': [
                'https://www.w3.org/ns/did/v1',
                'https://w3id.org/security/suites/secp256k1recovery-2020/v2',
                'https://w3id.org/security/v3-unstable'
            ],
            id: `did:${this.chain}:${this.getAddressFromPublicKey(this.getPublicKey(privateKey, false))}`,
            verificationMethod: [recoveryMethod, verificationKey],
            authentication: [recoveryMethod.id, verificationKey.id],
            assertionMethod: [recoveryMethod.id, verificationKey.id]
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
            type: 'EcdsaSecp256k1VerificationKey2019',
            controller: '',
            publicKeyHex: ''
        };
        const privateKey = new Uint8Array(Buffer.from(seed, 'hex'));
        const verified = secp256k1.privateKeyVerify(privateKey);

        if (verified) {
            let ethereumAddress = this.getAddressFromPublicKey(this.getPublicKey(seed, false));
            jwk.publicKeyHex = this.getPublicKey(seed);
            jwk.controller = `did:${this.chain}:${ethereumAddress}`;
            jwk.id = `${jwk.controller}#delegate-1`;

            if (includePrivateKey) {
                jwk.privateKeyHex = privateKey;
            }
        }

        return jwk;
    }

    /**
     *
     * @param seed - seed as a hex string
     * @param includePrivateKey - include private key
     * @returns {VerificationKeyInterface}
     */
    async createRecoveryMethod(
        seed: string,
        includePrivateKey: boolean = false
    ): Promise<VerificationKeyInterface> {
        let jwk: VerificationKeyInterface = {
            id: '',
            type: 'EcdsaSecp256k1RecoveryMethod2020',
            controller: '',
            blockchainAccountId: ''
        };
        const privateKey = new Uint8Array(Buffer.from(seed, 'hex'));
        const verified = secp256k1.privateKeyVerify(privateKey);

        if (verified) {
            let ethereumAddress = this.getAddressFromPublicKey(this.getPublicKey(seed, false));
            jwk.blockchainAccountId = `eip155:1287:${ethereumAddress}`;
            jwk.controller = `did:${this.chain}:${ethereumAddress}`;
            jwk.id = `${jwk.controller}#controller`;

            if (includePrivateKey) {
                jwk.privateKeyHex = privateKey;
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
        const addressBuffer = Buffer.from(keccak_256(publicKeyBuffer)).slice(-20);

        return `0x${addressBuffer.toString('hex')}`;
    }
}
