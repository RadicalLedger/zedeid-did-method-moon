export default class MoonMethod {
    /**
     *
     * @param node BIP32Interface
     * @returns {KeysInterface} { did, address, privateKey, publicKey, chainCode, didDocument }.
     */
    getKeys(node: BIP32Interface): Promise<KeysInterface>;
    /**
     *
     * @param privateKey - private key as a hex string
     * @returns {CreateDidDocumentInterface}
     */
    getDocument(privateKey: string): Promise<CreateDidDocumentInterface>;
    /**
     *
     * @param seed - seed as a hex string
     * @param includePrivateKey - include private key
     * @returns {VerificationKeyInterface}
     */
    createVerificationMethod(
        seed: string,
        includePrivateKey?: boolean
    ): Promise<VerificationKeyInterface>;
    private getAddressFromPublicKey;
}
