import { BIP32Factory } from 'bip32';
import * as ecc from 'tiny-secp256k1';
import MoonMethod from '../src/index';

describe('HD Wallet Moon Alpha Method', function () {
    it('create master node', async () => {
        const seed = '000102030405060708090a0b0c0d0e0f';

        const bip32 = BIP32Factory(ecc);
        const masterNode = bip32.fromSeed(Buffer.from(seed, 'hex'));
        const etherNode = masterNode.derivePath("m/44'/60'/0'/0/0");

        const moonMethod = new MoonMethod('alpha');
        const keys = await moonMethod.getKeys(etherNode);

        expect(keys).toEqual({
            did: 'did:moon:alpha:0x022b971dff0c43305e691ded7a14367af19d6407',
            address: '0x022b971dff0c43305e691ded7a14367af19d6407',
            privateKey: 'e22f5526ce620ec69441c3453d7a0acbc26c3fc7543023f338123fd45c7d44b3',
            publicKey: '03844a5d329470697de9926c9c98839ea33b6dd9507a896194ae2b91d71faa16d6',
            chainCode: 'dac0c414d5006b7350e3b7750e5b535af7ecd9b5a2ad00648d427349885f4358',
            didDocument: {
                '@context': [
                    'https://www.w3.org/ns/did/v1',
                    'https://w3id.org/security/suites/secp256k1recovery-2020/v2',
                    'https://w3id.org/security/v3-unstable'
                ],
                id: 'did:moon:alpha:0x022b971dff0c43305e691ded7a14367af19d6407',
                verificationMethod: [
                    {
                        id: 'did:moon:alpha:0x022b971dff0c43305e691ded7a14367af19d6407#controller',
                        controller: 'did:moon:alpha:0x022b971dff0c43305e691ded7a14367af19d6407',
                        type: 'EcdsaSecp256k1RecoveryMethod2020',
                        blockchainAccountId:
                            'eip155:1287:0x022b971dff0c43305e691ded7a14367af19d6407'
                    },
                    {
                        id: 'did:moon:alpha:0x022b971dff0c43305e691ded7a14367af19d6407#delegate-1',
                        controller: 'did:moon:alpha:0x022b971dff0c43305e691ded7a14367af19d6407',
                        type: 'EcdsaSecp256k1VerificationKey2019',
                        publicKeyHex:
                            '03844a5d329470697de9926c9c98839ea33b6dd9507a896194ae2b91d71faa16d6'
                    }
                ],
                authentication: [
                    'did:moon:alpha:0x022b971dff0c43305e691ded7a14367af19d6407#controller',
                    'did:moon:alpha:0x022b971dff0c43305e691ded7a14367af19d6407#delegate-1'
                ],
                assertionMethod: [
                    'did:moon:alpha:0x022b971dff0c43305e691ded7a14367af19d6407#controller',
                    'did:moon:alpha:0x022b971dff0c43305e691ded7a14367af19d6407#delegate-1'
                ]
            }
        });
    });
});
