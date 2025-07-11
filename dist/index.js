'use strict';
var __createBinding =
    (this && this.__createBinding) ||
    (Object.create
        ? function (o, m, k, k2) {
              if (k2 === undefined) k2 = k;
              var desc = Object.getOwnPropertyDescriptor(m, k);
              if (!desc || ('get' in desc ? !m.__esModule : desc.writable || desc.configurable)) {
                  desc = {
                      enumerable: true,
                      get: function () {
                          return m[k];
                      }
                  };
              }
              Object.defineProperty(o, k2, desc);
          }
        : function (o, m, k, k2) {
              if (k2 === undefined) k2 = k;
              o[k2] = m[k];
          });
var __setModuleDefault =
    (this && this.__setModuleDefault) ||
    (Object.create
        ? function (o, v) {
              Object.defineProperty(o, 'default', { enumerable: true, value: v });
          }
        : function (o, v) {
              o['default'] = v;
          });
var __importStar =
    (this && this.__importStar) ||
    function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null)
            for (var k in mod)
                if (k !== 'default' && Object.prototype.hasOwnProperty.call(mod, k))
                    __createBinding(result, mod, k);
        __setModuleDefault(result, mod);
        return result;
    };
var __importDefault =
    (this && this.__importDefault) ||
    function (mod) {
        return mod && mod.__esModule ? mod : { default: mod };
    };
Object.defineProperty(exports, '__esModule', { value: true });
const secp256k1 = __importStar(require('secp256k1'));
const keccak256_1 = __importDefault(require('keccak256'));
class MoonMethod {
    /**
     *
     * @param chain - chain type
     */
    constructor(chain) {
        this.chain = 'moon';
        if (chain) this.chain += `:${chain}`;
    }
    /**
     *
     * @param node BIP32Interface
     * @returns {KeysInterface} { did, address, privateKey, publicKey, chainCode, didDocument }.
     */
    async getKeys(node) {
        var _a, _b, _c;
        const privateKey =
            (_a = node.privateKey) === null || _a === void 0 ? void 0 : _a.toString('hex');
        const chainCode =
            (_b = node.chainCode) === null || _b === void 0 ? void 0 : _b.toString('hex');
        const publicKey =
            (_c = node.publicKey) === null || _c === void 0 ? void 0 : _c.toString('hex');
        const address = this.getAddressFromPublicKey(this.getPublicKey(privateKey, false));
        const did = `did:${this.chain}:${address}`;
        const { didDocument } = await this.getDocument(privateKey);
        return { did, address, privateKey, publicKey, chainCode, didDocument };
    }
    /**
     *
     * @param privateKey - private key as a hex string
     * @returns {CreateDidDocumentInterface}
     */
    async getDocument(privateKey) {
        const verificationKey = await this.createVerificationMethod(privateKey);
        const recoveryMethod = await this.createRecoveryMethod(privateKey);
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
    async createVerificationMethod(seed, includePrivateKey = false) {
        let jwk = {
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
    async createRecoveryMethod(seed, includePrivateKey = false) {
        let jwk = {
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
    getPublicKey(privateKey, compressed = true) {
        const privateKeyBuffer = Buffer.from(Buffer.from(privateKey, 'hex'));
        let publicKeyBuffer = secp256k1.publicKeyCreate(privateKeyBuffer, compressed);
        /* remove compressed flag */
        if (!compressed) publicKeyBuffer = publicKeyBuffer.slice(1);
        return Buffer.from(publicKeyBuffer).toString('hex');
    }
    getAddressFromPublicKey(publicKey) {
        const publicKeyBuffer = Buffer.from(publicKey, 'hex');
        const addressBuffer = Buffer.from((0, keccak256_1.default)(publicKeyBuffer)).slice(-20);
        return `0x${addressBuffer.toString('hex')}`;
    }
}
exports.default = MoonMethod;
//# sourceMappingURL=index.js.map
