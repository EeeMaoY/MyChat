/**
 * 身份模块公共 API（设计报告 §4 身份与密钥管理）。
 */
export {
  DID_PREFIX,
  didFromEd25519PublicKey,
  didToEd25519PublicKey,
  isValidDid,
} from "./did";
export {
  IKX_BINDING_PREFIX,
  type Identity,
  createIdentity,
  deserializeIdentity,
  ikxBindingMessage,
  serializeIdentity,
} from "./identity";
export {
  SPK_BINDING_PREFIX,
  type PreKeyBundle,
  decodePreKeyBundle,
  deriveOpkId,
  encodePreKeyBundle,
  issuePreKeyBundle,
  verifyPreKeyBundle,
} from "./bundle";
export {
  makeUserNameRecord,
  signUserNameRecord,
  userNameRecordMessage,
  verifyUserNameRecord,
} from "./username";
