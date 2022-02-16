declare const random: (bytes?: number) => string;
declare const encrypt: (input: string, secret: string) => string;
declare const decrypt: (input: string, secret: string) => string;
declare const md5: (...args: string[] | number[]) => string;
declare const sha256: (input: string) => string;
declare const sha512: (input: string) => string;
declare const password: (input: string) => string;
export { random, encrypt, decrypt, md5, sha256, sha512, password };
