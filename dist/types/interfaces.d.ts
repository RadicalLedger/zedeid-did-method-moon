interface VerificationKeyInterface {
    id: string;
    owner: string;
    ethereumAddress: string;
    [x: string | symbol]: any;
}

interface KeysInterface {
    did: string;
    address: string | undefined;
    privateKey: string | undefined;
    publicKey: string;
    chainCode: string;
    didDocument: DidDocumentInterface;
}

interface BIP32Interface {
    chainCode: Buffer;
    privateKey?: Buffer;
    publicKey?: Buffer;
    [x: string | symbol]: any;
}

interface DidDocumentInterface {
    '@context'?: string;
    id: string;
    publicKey: Object;
    authentication: Object;
    assertionMethod: Object;
    service: Object;
}

interface CreateDidDocumentInterface {
    didDocument: DidDocumentInterface;
}

interface MethodInterface {
    getKeys(node: BIP32Interface): Promise<KeysInterface>;
    getMasterKeys(): Promise<KeysInterface>;
    getDocument(): Promise<CreateDidDocumentInterface>;
    createVerificationMethod(): Promise<VerificationKeyInterface>;
}
