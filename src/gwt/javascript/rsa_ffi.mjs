import { Result$Ok, Result$Error, BitArray$BitArray } from '../../gleam.mjs';

const { subtle } = globalThis.crypto;
const atob = globalThis.atob;

// from https://developers.google.com/web/updates/2012/06/How-to-convert-ArrayBuffer-to-and-from-String
function str2ab(str) {
  const buf = new ArrayBuffer(str.length);
  const bufView = new Uint8Array(buf);
  for (let i = 0, strLen = str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return buf;
}

export async function importPublicKey(pem, digest) {
  try {
    // fetch the part of the PEM string between header and footer
    const pemContents = pem
      .split('\n')
      .filter(line => !line.includes('-----BEGIN') && !line.includes('-----END'))
      .join('')
      .replace(/\s/g, '');
    // base64 decode the string to get the binary data
    const binaryDerString = atob(pemContents);
    // convert from a binary string to an ArrayBuffer
    const binaryDer = str2ab(binaryDerString);

    return Result$Ok(await subtle.importKey(
      "spki",
      binaryDer,
      {
        name: "RSASSA-PKCS1-v1_5",
        hash: digest,
      },
      true,
      ["verify"],
    ));
  } catch (error) {
    return Result$Error(undefined);
  }
}

export async function importPrivateKey(pem, digest) {
  try {
    // fetch the part of the PEM string between header and footer
    const pemContents = pem
      .split('\n')
      .filter(line => !line.includes('-----BEGIN') && !line.includes('-----END'))
      .join('')
      .replace(/\s/g, '');
    // base64 decode the string to get the binary data
    const binaryDerString = atob(pemContents);
    // convert from a binary string to an ArrayBuffer
    const binaryDer = str2ab(binaryDerString);

    return Result$Ok(await subtle.importKey(
      "pkcs8",
      binaryDer,
      {
        name: "RSASSA-PKCS1-v1_5",
        hash: digest,
      },
      true,
      ["sign"],
    ));
  } catch {
    Result$Error(undefined);
  }
}

export async function sign(msg, key) {
  const encodedMsg = new TextEncoder().encode(msg);
  const signature = await subtle.sign("RSASSA-PKCS1-v1_5", key, encodedMsg);

  return BitArray$BitArray(new Uint8Array(signature));
}

export async function verify(signature, key, data) {
  const encodedData = new TextEncoder().encode(data);
  return await subtle.verify("RSASSA-PKCS1-v1_5", key, signature.rawBuffer, encodedData);
}
