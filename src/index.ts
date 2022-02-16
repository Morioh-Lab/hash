import { randomBytes, scryptSync, createCipheriv, createDecipheriv, createHash } from 'crypto';

const random = (bytes: number = 8) => randomBytes(bytes).toString('hex');

const encrypt = (input: string, secret: string) => {
    let iv = randomBytes(16);
    const key = scryptSync(secret, 'salt', 32);
    let cipher = createCipheriv('aes-256-cbc', key, iv);
    // let cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(secret), iv);
    let encrypted = cipher.update(input);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
}

const decrypt = (input: string, secret: string) => {
    let a = input.split(':');
    let iv = Buffer.from(a[0], 'hex');
    const key = scryptSync(secret, 'salt', 32);
    let decipher = createDecipheriv('aes-256-cbc', key, iv);
    let decrypted = decipher.update(Buffer.from(a[1], 'hex'));
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
}

const md5 = (...args: string[] | number[]) => createHash('md5').update(args.join(''), 'utf8').digest('hex');

const sha256 = (input: string) => createHash('sha256').update(input, 'utf8').digest('hex');

const sha512 = (input: string) => createHash('sha512').update(input, 'utf8').digest('hex');

const password = (input: string) => sha256(sha512(input));

export { random, encrypt, decrypt, md5, sha256, sha512, password };