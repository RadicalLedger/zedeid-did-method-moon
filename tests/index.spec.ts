import { BIP32Factory } from 'bip32';
import * as ecc from 'tiny-secp256k1';
import MoonMethod from '../src/index';

describe('HD Wallet Moon Method', function () {
    it('create master node', async () => {
        const seed = '000102030405060708090a0b0c0d0e0f';

        const bip32 = BIP32Factory(ecc);
        const masterNode = bip32.fromSeed(Buffer.from(seed, 'hex'));

        const moonMethod = new MoonMethod();
        const keys = await moonMethod.getKeys(masterNode);

        expect(keys).toEqual({
            did: 'did:moon:0x0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2',
            address: '0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2',
            privateKey: 'e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35',
            publicKey: '0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2',
            chainCode: '873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508',
            didDocument: {
                '@context': 'https://w3id.org/did/v1',
                id: 'did:moon:0x0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2',
                publicKey: [
                    {
                        id: 'did:moon:0x0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2#owner',
                        owner: 'did:moon:0x0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2',
                        type: 'Secp256k1VerificationKey2018',
                        ethereumAddress:
                            '0x0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2'
                    }
                ],
                authentication: [
                    {
                        type: 'Secp256k1SignatureAuthentication2018',
                        publicKey:
                            'did:moon:0x0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2#owner'
                    }
                ],
                assertionMethod: [
                    {
                        type: 'Secp256k1SignatureAuthentication2018',
                        publicKey:
                            'did:moon:0x0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2#owner'
                    }
                ],
                service: []
            }
        });
    });
});
