import axios from 'axios';

import { hmac_sha_512 } from './crypto/hmac';

/**
 *  A **Wallet** manages a set of private keys which are used to sign
 *  transactions, messages and other common payloads.
 *
 */
export class Wallet {
  #host: string;
  #apiKey: string;

  /**
   *  Create a new wallet for Keychain %%host%% with %%apiKey%%.
   */
  constructor(host: string, apiKey: string) {
    this.#host = host;
    this.#apiKey = apiKey;
  }

  #createSignature(method: string, path: string, body: string): string {
    // Unix timestamp in milliseconds
    const timestamp = Date.now();

    const uppercaseMethod = method.toUpperCase();
    const message = `${timestamp}${uppercaseMethod}${path}${body}`;
    const signature = hmac_sha_512(this.#apiKey, message);

    return signature;
  }

  async getAddress(assetId: string, user: string): Promise<string> {
    const method = 'get';
    const path = `/v1/addresses/${assetId}/${user}`;
    const body = '';

    const signature = this.#createSignature(method, path, body);

    const res = await axios.request({
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
        'x-api-signature': signature,
      },
      method: method,
      timeout: 5 * 1000,
      url: `${this.#host}${path}`,
    });

    return res.data.address;
  }
}
