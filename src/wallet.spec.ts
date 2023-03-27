import axios from 'axios';

import { Wallet } from './wallet';

describe('Wallet', () => {
  test('getAddress', async () => {
    jest
      .spyOn(axios, 'request')
      .mockResolvedValue({ data: { address: 'test' } });
    jest.spyOn(Date, 'now').mockReturnValue(1234567890);
    const wallet = new Wallet('http://keychain.prod', 'test');

    const address = await wallet.getAddress('ALGO', 'test');

    expect(axios.request).toHaveBeenCalledWith({
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
        'x-api-signature':
          '40da2c49cb22296bca9ae71097956cef19e0f161a2c03adeabcdc9dc7e766ae3f9178430bf2bedbaf15dba0a64e5db417e3b738acf6f2ee82498de7afc211a2b',
      },
      method: 'get',
      timeout: 5000,
      url: 'http://keychain.prod/v1/addresses/ALGO/test',
    });

    expect(address).toEqual('test');
  });
});
