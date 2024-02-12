import { INSGeneric, ResponseBase } from "@zondax/ledger-js";

export interface IronfishIns extends INSGeneric {
  GET_VERSION: 0x00;
  GET_ADDR: 0x01;
  SIGN: 0x02;
}

export interface ResponseAddress extends ResponseBase {
  publicAddress?: Buffer;
  ivk?: Buffer;
  ovk?: Buffer;
}

export interface ResponseSign extends ResponseBase {
  preSignHash?: Buffer;
  signatureRS?: Buffer;
  signatureDER?: Buffer;
}
