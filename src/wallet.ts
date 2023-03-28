import axios, { AxiosResponse } from 'axios';

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

  #createSignature(
    timestamp: number,
    method: string,
    path: string,
    body: string
  ): string {
    const uppercaseMethod = method.toUpperCase();
    const message = `${timestamp}${uppercaseMethod}${path}${body}`;
    const signature = hmac_sha_512(this.#apiKey, message);

    return signature;
  }

  #walletRequest(
    method: string,
    path: string,
    body?: string
  ): Promise<AxiosResponse> {
    // Unix timestamp in milliseconds
    const timestamp = Date.now();
    body = body || '';
    const signature = this.#createSignature(timestamp, method, path, body);

    return axios.request({
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
        'x-map3-api-signature': signature,
        'x-map3-api-timestamp': timestamp,
      },
      method: method,
      timeout: 5 * 1000,
      url: `${this.#host}${path}`,
    });
  }

  async getAddress(assetId: string, user: string): Promise<string> {
    const method = 'get';
    const path = `/v1/addresses/${assetId}/${user}`;

    const res = await this.#walletRequest(method, path);
    return res.data.address;
  }
}
