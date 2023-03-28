import { hmac, hmac_sha_512, hmac_sha_512_256 } from './hmac';

const testVectors = [
  {
    dataHex: '4869205468657265',
    dataString: 'Hi There',
    description: '',
    hmacSha512:
      '87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854',
    keyHex: '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b',
    keyString: undefined,
    title: 'Test Case 1',
  },
  {
    dataHex: '7768617420646f2079612077616e7420666f72206e6f7468696e673f',
    dataString: 'what do ya want for nothing?',
    description: 'Test with a key shorter than the length of the HMAC output.',
    hmacSha512:
      '164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737',
    keyHex: '4a656665',
    keyString: 'Jefe',
    title: 'Test Case 2',
  },
  {
    dataHex:
      'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
    dataString: undefined,
    description:
      'Test with a combined length of key and data that is larger than 64 bytes (= block-size of SHA-224 and SHA-256).',
    hmacSha512:
      'fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb',
    keyHex: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    keyString: undefined,
    title: 'Test Case 3',
  },
  {
    dataHex:
      'cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd',
    dataString: undefined,
    description:
      'Test with a combined length of key and data that is larger than 64 bytes (= block-size of SHA-224 and SHA-256).',
    hmacSha512:
      'b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd',
    keyHex: '0102030405060708090a0b0c0d0e0f10111213141516171819',
    keyString: undefined,
    title: 'Test Case 4',
  },
  // Truncation is not supported
  // {
  //   dataHex: '546573742057697468205472756e636174696f6e',
  //   dataString: 'Test With Truncation',
  //   description: 'Test with a truncation of output to 128 bits.',
  //   hmacSha512: '415fad6271580a531d4179bc891d87a6',
  //   keyHex: '0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c',
  //   keyString: undefined,
  //   title: 'Test Case 5',
  // },
  {
    dataHex:
      '54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374',
    dataString: 'Test Using Larger Than Block-Size Key - Hash Key First',
    description:
      'Test with a key larger than 128 bytes (= block-size of SHA-384 and SHA-512).',
    hmacSha512:
      '80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598',
    keyHex:
      'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    keyString: undefined,
    title: 'Test Case 6',
  },
  {
    dataHex:
      '5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e',
    dataString:
      'This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.',
    description:
      'Test with a key and data that is larger than 128 bytes (= block-sizeof SHA-384 and SHA-512).',
    hmacSha512:
      'e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58',
    keyHex:
      'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    keyString: undefined,
    title: 'Test Case 7',
  },
];

describe('hmac_sha_512 conforms to [RFC 4231](https://www.rfc-editor.org/rfc/rfc4231) test vectors', () => {
  testVectors.forEach(
    ({
      dataHex,
      dataString,
      description,
      hmacSha512,
      keyHex,
      keyString,
      title,
    }) => {
      it(`${title} (key and data as buffer) - ${description}`, () => {
        expect(
          hmac_sha_512(Buffer.from(keyHex, 'hex'), Buffer.from(dataHex, 'hex'))
        ).toEqual(hmacSha512);
      });

      if (dataString) {
        it(`${title} (key as buffer and data as string) - ${description}`, () => {
          expect(hmac_sha_512(Buffer.from(keyHex, 'hex'), dataString)).toEqual(
            hmacSha512
          );
        });
      }

      if (keyString) {
        it(`${title} (key as string and data as buffer) - ${description}`, () => {
          expect(hmac_sha_512(keyString, Buffer.from(dataHex, 'hex'))).toEqual(
            hmacSha512
          );
        });
      }

      if (dataString && keyString) {
        it(`${title} (key and data as string) - ${description}`, () => {
          expect(hmac_sha_512(keyString, dataString)).toEqual(hmacSha512);
        });
      }
    }
  );
});

describe('hmac_sha_512_256 passes hmac_sha_512 tests with HMAC returning 256 bit length', () => {
  testVectors.forEach(
    ({
      dataHex,
      dataString,
      description,
      hmacSha512,
      keyHex,
      keyString,
      title,
    }) => {
      it(`${title} (key and data as buffer) - ${description}`, () => {
        expect(
          hmac_sha_512_256(
            Buffer.from(keyHex, 'hex'),
            Buffer.from(dataHex, 'hex')
          )
        ).toEqual(hmacSha512.slice(0, 64));
      });

      if (dataString) {
        it(`${title} (key as buffer and data as string) - ${description}`, () => {
          expect(
            hmac_sha_512_256(Buffer.from(keyHex, 'hex'), dataString)
          ).toEqual(hmacSha512.slice(0, 64));
        });
      }

      if (keyString) {
        it(`${title} (key as string and data as buffer) - ${description}`, () => {
          expect(
            hmac_sha_512_256(keyString, Buffer.from(dataHex, 'hex'))
          ).toEqual(hmacSha512.slice(0, 64));
        });
      }

      if (dataString && keyString) {
        it(`${title} (key and data as string) - ${description}`, () => {
          expect(hmac_sha_512_256(keyString, dataString)).toEqual(
            hmacSha512.slice(0, 64)
          );
        });
      }
    }
  );
});

describe('hmac has the same result as hmac_sha_512_256', () => {
  testVectors.forEach(
    ({
      dataHex,
      dataString,
      description,
      hmacSha512,
      keyHex,
      keyString,
      title,
    }) => {
      it(`${title} (key and data as buffer) - ${description}`, () => {
        expect(
          hmac_sha_512_256(
            Buffer.from(keyHex, 'hex'),
            Buffer.from(dataHex, 'hex')
          )
        ).toEqual(
          hmac(Buffer.from(keyHex, 'hex'), Buffer.from(dataHex, 'hex'))
        );
      });

      if (dataString) {
        it(`${title} (key as buffer and data as string) - ${description}`, () => {
          expect(
            hmac_sha_512_256(Buffer.from(keyHex, 'hex'), dataString)
          ).toEqual(hmac(Buffer.from(keyHex, 'hex'), dataString));
        });
      }

      if (keyString) {
        it(`${title} (key as string and data as buffer) - ${description}`, () => {
          expect(
            hmac_sha_512_256(keyString, Buffer.from(dataHex, 'hex'))
          ).toEqual(hmac(keyString, Buffer.from(dataHex, 'hex')));
        });
      }

      if (dataString && keyString) {
        it(`${title} (key and data as string) - ${description}`, () => {
          expect(hmac_sha_512_256(keyString, dataString)).toEqual(
            hmac(keyString, dataString)
          );
        });
      }
    }
  );
});
