import { errorCodeToString } from "@zondax/ledger-js";
import { ADDRLEN, KEY_LENGTH, PRINCIPAL_LEN } from "./consts";
import { ResponseAddress } from "./types";

export function processGetAddrResponse(response: Buffer): ResponseAddress {
  const errorCodeData = response.subarray(-2);
  const returnCode = errorCodeData[0] * 256 + errorCodeData[1];

  const publicAddress = Buffer.from(response.subarray(0, KEY_LENGTH));
  response = response.subarray(KEY_LENGTH);

  const ivk = Buffer.from(response.subarray(0, KEY_LENGTH));
  response = response.subarray(KEY_LENGTH);

  const ovk = Buffer.from(response.subarray(0, KEY_LENGTH));
  response = response.subarray(KEY_LENGTH);

  return {
    publicAddress,
    ivk,
    ovk,
    returnCode,
    errorMessage: errorCodeToString(returnCode),
  };
}
