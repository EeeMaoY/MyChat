/**
 * 密码学安全随机数。
 *
 * 原语约束（R4 / NFR-14）：仅使用经审计的库，禁止自研密码学。
 */
import { randomBytes as nobleRandomBytes } from "@noble/hashes/utils";

export { nobleRandomBytes as randomBytes };
