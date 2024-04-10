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
        const address = this.getAddressFromPublicKey(publicKey);
        const did = `did:moon:${address}`;
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
    async createVerificationMethod(seed, includePrivateKey = false) {
        let jwk = {
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
    getAddressFromPublicKey(publicKey) {
        const hashPublicKey = (0, keccak256_1.default)(publicKey).toString('hex');
        /* Calculate the starting index to get the last twenty bytes. Each byte is represented by 2 characters in a hex string */
        const startIndex = hashPublicKey.length - 20 * 2;
        /* Extract the last twenty bytes */
        const lastTwentyBytes = hashPublicKey.substring(startIndex);
        return `0x${lastTwentyBytes}`;
    }
}
exports.default = MoonMethod;
//# sourceMappingURL=index.js.map
