import crypto from 'crypto';

export function hmac_sha_512(
  key: string | Buffer,
  data: string | Buffer
): string {
  var signature = crypto.createHmac('sha512', key).update(data).digest('hex');

  return signature;
}

export function hmac_sha_512_256(
  key: string | Buffer,
  data: string | Buffer
): string {
  var signature = hmac_sha_512(key, data).slice(0, 64);

  return signature;
}

/**
 * HMAC using SHA-512/256 as per https://latacora.micro.blog/2018/04/03/cryptographic-right-answers.html
 * to avoid length extension attacks.
 *
 * @param key key to use for the HMAC as a string or buffer
 * @param data data to authenticate as a string or buffer
 * @returns HMAC as hex string
 */
export function hmac(key: string | Buffer, data: string | Buffer): string {
  return hmac_sha_512_256(key, data);
}
