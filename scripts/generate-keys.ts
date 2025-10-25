// scripts/generate-keys.ts
import { CryptoUtils } from '../src/utils/crypto';

const keys = CryptoUtils.generateRSAKeyPair();

console.log('Private Key:');
console.log(keys.privateKey);
console.log('\nPublic Key:');
console.log(keys.publicKey);
console.log('\nKey ID:');
console.log('auth-service-key-1');