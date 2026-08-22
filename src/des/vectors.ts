/**
 * NIST CAVP known-answer vectors for DES.
 *
 * ## Provenance — read this before trusting the numbers
 *
 * Source archive: `KAT_TDES.zip`, downloaded from the NIST Cryptographic
 * Algorithm Validation Program's block-cipher page on 2026-08-22.
 *
 *   https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/des/KAT_TDES.zip
 *   SHA-256 19d8841f84ae3415350b069a4768bd416c05a0533ee43e905ab099adb8ccb374
 *   118,218 bytes; the .rsp files inside are dated 2011-04-21 and carry the
 *   header "# CAVS 11.1".
 *
 * The archive is named for Triple DES, and that is the trap worth naming: every
 * one of its 55 .rsp files uses the SINGLE-key field `KEYs = <16 hex digits>`,
 * never `KEY1`/`KEY2`/`KEY3`. TDEA with K1 = K2 = K3 is single DES exactly —
 * E then D then E under one key collapses to one E — so these files ARE the
 * classic DES known-answer tables, and NIST never published a DES-only archive.
 * That claim is not taken on faith here: `vectors.test.ts` runs every triple
 * below through this lab's own DES in both directions.
 *
 * The five ECB families and their case counts (64 / 64 / 56 / 32 / 19) are the
 * DES test set defined in NBS SP 500-20 (Revised September 1980), Appendix B,
 * reused by SP 800-17 Appendix B and SP 800-20 Appendix A.
 *
 * ## Everything here is withdrawn, and that is expected
 *
 * DES is a historical cipher with no live normative source, so there is no
 * unwithdrawn specification to cite:
 *
 *   FIPS 46-3    Data Encryption Standard          withdrawn 2005-05-19
 *   SP 800-17    MOVS validation system            withdrawn 2018-08-01
 *   SP 800-20    TMOVS validation system           withdrawn 2018-09-26
 *   SP 800-67r2  Triple DES / TDEA                 withdrawn 2024-01-01
 *
 * NIST's Retired Testing page states the reason for the first outright: FIPS
 * 46-3 "was withdrawn May 19, 2005 because the cryptographic algorithm no
 * longer provided the security that is needed". SP 800-17 was withdrawn
 * because "this validation system is for algorithms that have been deprecated
 * (e.g., DES, Skipjack)". Withdrawn is fine for a historical cipher; unmarked
 * is not. The README's "What It Is" carries the same table for a reader who
 * never opens the source, and the Vectors exhibit prints it in the page.
 *
 * GENERATED FILE — regenerate with `npm run vectors:build` rather than editing.
 */
import type { Result } from './types';

export interface KatVector {
  /** 16 hex digits — the `KEYs` field from the .rsp file. */
  readonly key: string;
  readonly plaintext: string;
  readonly ciphertext: string;
  /** Present only for the CBC family. */
  readonly iv?: string;
}

export interface KatGroup {
  readonly id: string;
  readonly mode: 'ecb' | 'cbc';
  readonly title: string;
  /** What this family exercises, and why NIST included it. */
  readonly note: string;
  /** The .rsp file inside KAT_TDES.zip these came from. */
  readonly file: string;
  readonly vectors: readonly KatVector[];
}

export const KAT_GROUPS: readonly KatGroup[] = [
  {
    id: 'vartext',
    mode: 'ecb',
    title: 'Variable Plaintext KAT',
    note:
      'Key 0101010101010101 and a plaintext that walks a single 1 bit across all 64 positions. Exercises IP and E.',
    file: 'KAT_TDES/TECBvartext.rsp',
    vectors: [
      { key: '0101010101010101', plaintext: '8000000000000000', ciphertext: '95f8a5e5dd31d900' },
      { key: '0101010101010101', plaintext: '4000000000000000', ciphertext: 'dd7f121ca5015619' },
      { key: '0101010101010101', plaintext: '2000000000000000', ciphertext: '2e8653104f3834ea' },
      { key: '0101010101010101', plaintext: '1000000000000000', ciphertext: '4bd388ff6cd81d4f' },
      { key: '0101010101010101', plaintext: '0800000000000000', ciphertext: '20b9e767b2fb1456' },
      { key: '0101010101010101', plaintext: '0400000000000000', ciphertext: '55579380d77138ef' },
      { key: '0101010101010101', plaintext: '0200000000000000', ciphertext: '6cc5defaaf04512f' },
      { key: '0101010101010101', plaintext: '0100000000000000', ciphertext: '0d9f279ba5d87260' },
      { key: '0101010101010101', plaintext: '0080000000000000', ciphertext: 'd9031b0271bd5a0a' },
      { key: '0101010101010101', plaintext: '0040000000000000', ciphertext: '424250b37c3dd951' },
      { key: '0101010101010101', plaintext: '0020000000000000', ciphertext: 'b8061b7ecd9a21e5' },
      { key: '0101010101010101', plaintext: '0010000000000000', ciphertext: 'f15d0f286b65bd28' },
      { key: '0101010101010101', plaintext: '0008000000000000', ciphertext: 'add0cc8d6e5deba1' },
      { key: '0101010101010101', plaintext: '0004000000000000', ciphertext: 'e6d5f82752ad63d1' },
      { key: '0101010101010101', plaintext: '0002000000000000', ciphertext: 'ecbfe3bd3f591a5e' },
      { key: '0101010101010101', plaintext: '0001000000000000', ciphertext: 'f356834379d165cd' },
      { key: '0101010101010101', plaintext: '0000800000000000', ciphertext: '2b9f982f20037fa9' },
      { key: '0101010101010101', plaintext: '0000400000000000', ciphertext: '889de068a16f0be6' },
      { key: '0101010101010101', plaintext: '0000200000000000', ciphertext: 'e19e275d846a1298' },
      { key: '0101010101010101', plaintext: '0000100000000000', ciphertext: '329a8ed523d71aec' },
      { key: '0101010101010101', plaintext: '0000080000000000', ciphertext: 'e7fce22557d23c97' },
      { key: '0101010101010101', plaintext: '0000040000000000', ciphertext: '12a9f5817ff2d65d' },
      { key: '0101010101010101', plaintext: '0000020000000000', ciphertext: 'a484c3ad38dc9c19' },
      { key: '0101010101010101', plaintext: '0000010000000000', ciphertext: 'fbe00a8a1ef8ad72' },
      { key: '0101010101010101', plaintext: '0000008000000000', ciphertext: '750d079407521363' },
      { key: '0101010101010101', plaintext: '0000004000000000', ciphertext: '64feed9c724c2faf' },
      { key: '0101010101010101', plaintext: '0000002000000000', ciphertext: 'f02b263b328e2b60' },
      { key: '0101010101010101', plaintext: '0000001000000000', ciphertext: '9d64555a9a10b852' },
      { key: '0101010101010101', plaintext: '0000000800000000', ciphertext: 'd106ff0bed5255d7' },
      { key: '0101010101010101', plaintext: '0000000400000000', ciphertext: 'e1652c6b138c64a5' },
      { key: '0101010101010101', plaintext: '0000000200000000', ciphertext: 'e428581186ec8f46' },
      { key: '0101010101010101', plaintext: '0000000100000000', ciphertext: 'aeb5f5ede22d1a36' },
      { key: '0101010101010101', plaintext: '0000000080000000', ciphertext: 'e943d7568aec0c5c' },
      { key: '0101010101010101', plaintext: '0000000040000000', ciphertext: 'df98c8276f54b04b' },
      { key: '0101010101010101', plaintext: '0000000020000000', ciphertext: 'b160e4680f6c696f' },
      { key: '0101010101010101', plaintext: '0000000010000000', ciphertext: 'fa0752b07d9c4ab8' },
      { key: '0101010101010101', plaintext: '0000000008000000', ciphertext: 'ca3a2b036dbc8502' },
      { key: '0101010101010101', plaintext: '0000000004000000', ciphertext: '5e0905517bb59bcf' },
      { key: '0101010101010101', plaintext: '0000000002000000', ciphertext: '814eeb3b91d90726' },
      { key: '0101010101010101', plaintext: '0000000001000000', ciphertext: '4d49db1532919c9f' },
      { key: '0101010101010101', plaintext: '0000000000800000', ciphertext: '25eb5fc3f8cf0621' },
      { key: '0101010101010101', plaintext: '0000000000400000', ciphertext: 'ab6a20c0620d1c6f' },
      { key: '0101010101010101', plaintext: '0000000000200000', ciphertext: '79e90dbc98f92cca' },
      { key: '0101010101010101', plaintext: '0000000000100000', ciphertext: '866ecedd8072bb0e' },
      { key: '0101010101010101', plaintext: '0000000000080000', ciphertext: '8b54536f2f3e64a8' },
      { key: '0101010101010101', plaintext: '0000000000040000', ciphertext: 'ea51d3975595b86b' },
      { key: '0101010101010101', plaintext: '0000000000020000', ciphertext: 'caffc6ac4542de31' },
      { key: '0101010101010101', plaintext: '0000000000010000', ciphertext: '8dd45a2ddf90796c' },
      { key: '0101010101010101', plaintext: '0000000000008000', ciphertext: '1029d55e880ec2d0' },
      { key: '0101010101010101', plaintext: '0000000000004000', ciphertext: '5d86cb23639dbea9' },
      { key: '0101010101010101', plaintext: '0000000000002000', ciphertext: '1d1ca853ae7c0c5f' },
      { key: '0101010101010101', plaintext: '0000000000001000', ciphertext: 'ce332329248f3228' },
      { key: '0101010101010101', plaintext: '0000000000000800', ciphertext: '8405d1abe24fb942' },
      { key: '0101010101010101', plaintext: '0000000000000400', ciphertext: 'e643d78090ca4207' },
      { key: '0101010101010101', plaintext: '0000000000000200', ciphertext: '48221b9937748a23' },
      { key: '0101010101010101', plaintext: '0000000000000100', ciphertext: 'dd7c0bbd61fafd54' },
      { key: '0101010101010101', plaintext: '0000000000000080', ciphertext: '2fbc291a570db5c4' },
      { key: '0101010101010101', plaintext: '0000000000000040', ciphertext: 'e07c30d7e4e26e12' },
      { key: '0101010101010101', plaintext: '0000000000000020', ciphertext: '0953e2258e8e90a1' },
      { key: '0101010101010101', plaintext: '0000000000000010', ciphertext: '5b711bc4ceebf2ee' },
      { key: '0101010101010101', plaintext: '0000000000000008', ciphertext: 'cc083f1e6d9e85f6' },
      { key: '0101010101010101', plaintext: '0000000000000004', ciphertext: 'd2fd8867d50d2dfe' },
      { key: '0101010101010101', plaintext: '0000000000000002', ciphertext: '06e7ea22ce92708f' },
      { key: '0101010101010101', plaintext: '0000000000000001', ciphertext: '166b40b44aba4bd6' },
    ],
  },
  {
    id: 'invperm',
    mode: 'ecb',
    title: 'Inverse Permutation KAT',
    note:
      'The Variable Plaintext table transposed: decrypting each of its ciphertexts must give the single-bit basis vector back. SP 800-17 prints no separate table for it.',
    file: 'KAT_TDES/TECBinvperm.rsp',
    vectors: [
      { key: '0101010101010101', plaintext: '95f8a5e5dd31d900', ciphertext: '8000000000000000' },
      { key: '0101010101010101', plaintext: 'dd7f121ca5015619', ciphertext: '4000000000000000' },
      { key: '0101010101010101', plaintext: '2e8653104f3834ea', ciphertext: '2000000000000000' },
      { key: '0101010101010101', plaintext: '4bd388ff6cd81d4f', ciphertext: '1000000000000000' },
      { key: '0101010101010101', plaintext: '20b9e767b2fb1456', ciphertext: '0800000000000000' },
      { key: '0101010101010101', plaintext: '55579380d77138ef', ciphertext: '0400000000000000' },
      { key: '0101010101010101', plaintext: '6cc5defaaf04512f', ciphertext: '0200000000000000' },
      { key: '0101010101010101', plaintext: '0d9f279ba5d87260', ciphertext: '0100000000000000' },
      { key: '0101010101010101', plaintext: 'd9031b0271bd5a0a', ciphertext: '0080000000000000' },
      { key: '0101010101010101', plaintext: '424250b37c3dd951', ciphertext: '0040000000000000' },
      { key: '0101010101010101', plaintext: 'b8061b7ecd9a21e5', ciphertext: '0020000000000000' },
      { key: '0101010101010101', plaintext: 'f15d0f286b65bd28', ciphertext: '0010000000000000' },
      { key: '0101010101010101', plaintext: 'add0cc8d6e5deba1', ciphertext: '0008000000000000' },
      { key: '0101010101010101', plaintext: 'e6d5f82752ad63d1', ciphertext: '0004000000000000' },
      { key: '0101010101010101', plaintext: 'ecbfe3bd3f591a5e', ciphertext: '0002000000000000' },
      { key: '0101010101010101', plaintext: 'f356834379d165cd', ciphertext: '0001000000000000' },
      { key: '0101010101010101', plaintext: '2b9f982f20037fa9', ciphertext: '0000800000000000' },
      { key: '0101010101010101', plaintext: '889de068a16f0be6', ciphertext: '0000400000000000' },
      { key: '0101010101010101', plaintext: 'e19e275d846a1298', ciphertext: '0000200000000000' },
      { key: '0101010101010101', plaintext: '329a8ed523d71aec', ciphertext: '0000100000000000' },
      { key: '0101010101010101', plaintext: 'e7fce22557d23c97', ciphertext: '0000080000000000' },
      { key: '0101010101010101', plaintext: '12a9f5817ff2d65d', ciphertext: '0000040000000000' },
      { key: '0101010101010101', plaintext: 'a484c3ad38dc9c19', ciphertext: '0000020000000000' },
      { key: '0101010101010101', plaintext: 'fbe00a8a1ef8ad72', ciphertext: '0000010000000000' },
      { key: '0101010101010101', plaintext: '750d079407521363', ciphertext: '0000008000000000' },
      { key: '0101010101010101', plaintext: '64feed9c724c2faf', ciphertext: '0000004000000000' },
      { key: '0101010101010101', plaintext: 'f02b263b328e2b60', ciphertext: '0000002000000000' },
      { key: '0101010101010101', plaintext: '9d64555a9a10b852', ciphertext: '0000001000000000' },
      { key: '0101010101010101', plaintext: 'd106ff0bed5255d7', ciphertext: '0000000800000000' },
      { key: '0101010101010101', plaintext: 'e1652c6b138c64a5', ciphertext: '0000000400000000' },
      { key: '0101010101010101', plaintext: 'e428581186ec8f46', ciphertext: '0000000200000000' },
      { key: '0101010101010101', plaintext: 'aeb5f5ede22d1a36', ciphertext: '0000000100000000' },
      { key: '0101010101010101', plaintext: 'e943d7568aec0c5c', ciphertext: '0000000080000000' },
      { key: '0101010101010101', plaintext: 'df98c8276f54b04b', ciphertext: '0000000040000000' },
      { key: '0101010101010101', plaintext: 'b160e4680f6c696f', ciphertext: '0000000020000000' },
      { key: '0101010101010101', plaintext: 'fa0752b07d9c4ab8', ciphertext: '0000000010000000' },
      { key: '0101010101010101', plaintext: 'ca3a2b036dbc8502', ciphertext: '0000000008000000' },
      { key: '0101010101010101', plaintext: '5e0905517bb59bcf', ciphertext: '0000000004000000' },
      { key: '0101010101010101', plaintext: '814eeb3b91d90726', ciphertext: '0000000002000000' },
      { key: '0101010101010101', plaintext: '4d49db1532919c9f', ciphertext: '0000000001000000' },
      { key: '0101010101010101', plaintext: '25eb5fc3f8cf0621', ciphertext: '0000000000800000' },
      { key: '0101010101010101', plaintext: 'ab6a20c0620d1c6f', ciphertext: '0000000000400000' },
      { key: '0101010101010101', plaintext: '79e90dbc98f92cca', ciphertext: '0000000000200000' },
      { key: '0101010101010101', plaintext: '866ecedd8072bb0e', ciphertext: '0000000000100000' },
      { key: '0101010101010101', plaintext: '8b54536f2f3e64a8', ciphertext: '0000000000080000' },
      { key: '0101010101010101', plaintext: 'ea51d3975595b86b', ciphertext: '0000000000040000' },
      { key: '0101010101010101', plaintext: 'caffc6ac4542de31', ciphertext: '0000000000020000' },
      { key: '0101010101010101', plaintext: '8dd45a2ddf90796c', ciphertext: '0000000000010000' },
      { key: '0101010101010101', plaintext: '1029d55e880ec2d0', ciphertext: '0000000000008000' },
      { key: '0101010101010101', plaintext: '5d86cb23639dbea9', ciphertext: '0000000000004000' },
      { key: '0101010101010101', plaintext: '1d1ca853ae7c0c5f', ciphertext: '0000000000002000' },
      { key: '0101010101010101', plaintext: 'ce332329248f3228', ciphertext: '0000000000001000' },
      { key: '0101010101010101', plaintext: '8405d1abe24fb942', ciphertext: '0000000000000800' },
      { key: '0101010101010101', plaintext: 'e643d78090ca4207', ciphertext: '0000000000000400' },
      { key: '0101010101010101', plaintext: '48221b9937748a23', ciphertext: '0000000000000200' },
      { key: '0101010101010101', plaintext: 'dd7c0bbd61fafd54', ciphertext: '0000000000000100' },
      { key: '0101010101010101', plaintext: '2fbc291a570db5c4', ciphertext: '0000000000000080' },
      { key: '0101010101010101', plaintext: 'e07c30d7e4e26e12', ciphertext: '0000000000000040' },
      { key: '0101010101010101', plaintext: '0953e2258e8e90a1', ciphertext: '0000000000000020' },
      { key: '0101010101010101', plaintext: '5b711bc4ceebf2ee', ciphertext: '0000000000000010' },
      { key: '0101010101010101', plaintext: 'cc083f1e6d9e85f6', ciphertext: '0000000000000008' },
      { key: '0101010101010101', plaintext: 'd2fd8867d50d2dfe', ciphertext: '0000000000000004' },
      { key: '0101010101010101', plaintext: '06e7ea22ce92708f', ciphertext: '0000000000000002' },
      { key: '0101010101010101', plaintext: '166b40b44aba4bd6', ciphertext: '0000000000000001' },
    ],
  },
  {
    id: 'varkey',
    mode: 'ecb',
    title: 'Variable Key KAT',
    note:
      'Plaintext 0000000000000000 and a key that walks a single 1 bit across all 56 key bits. Exercises PC-1 and PC-2.',
    file: 'KAT_TDES/TECBvarkey.rsp',
    vectors: [
      { key: '8001010101010101', plaintext: '0000000000000000', ciphertext: '95a8d72813daa94d' },
      { key: '4001010101010101', plaintext: '0000000000000000', ciphertext: '0eec1487dd8c26d5' },
      { key: '2001010101010101', plaintext: '0000000000000000', ciphertext: '7ad16ffb79c45926' },
      { key: '1001010101010101', plaintext: '0000000000000000', ciphertext: 'd3746294ca6a6cf3' },
      { key: '0801010101010101', plaintext: '0000000000000000', ciphertext: '809f5f873c1fd761' },
      { key: '0401010101010101', plaintext: '0000000000000000', ciphertext: 'c02faffec989d1fc' },
      { key: '0201010101010101', plaintext: '0000000000000000', ciphertext: '4615aa1d33e72f10' },
      { key: '0180010101010101', plaintext: '0000000000000000', ciphertext: '2055123350c00858' },
      { key: '0140010101010101', plaintext: '0000000000000000', ciphertext: 'df3b99d6577397c8' },
      { key: '0120010101010101', plaintext: '0000000000000000', ciphertext: '31fe17369b5288c9' },
      { key: '0110010101010101', plaintext: '0000000000000000', ciphertext: 'dfdd3cc64dae1642' },
      { key: '0108010101010101', plaintext: '0000000000000000', ciphertext: '178c83ce2b399d94' },
      { key: '0104010101010101', plaintext: '0000000000000000', ciphertext: '50f636324a9b7f80' },
      { key: '0102010101010101', plaintext: '0000000000000000', ciphertext: 'a8468ee3bc18f06d' },
      { key: '0101800101010101', plaintext: '0000000000000000', ciphertext: 'a2dc9e92fd3cde92' },
      { key: '0101400101010101', plaintext: '0000000000000000', ciphertext: 'cac09f797d031287' },
      { key: '0101200101010101', plaintext: '0000000000000000', ciphertext: '90ba680b22aeb525' },
      { key: '0101100101010101', plaintext: '0000000000000000', ciphertext: 'ce7a24f350e280b6' },
      { key: '0101080101010101', plaintext: '0000000000000000', ciphertext: '882bff0aa01a0b87' },
      { key: '0101040101010101', plaintext: '0000000000000000', ciphertext: '25610288924511c2' },
      { key: '0101020101010101', plaintext: '0000000000000000', ciphertext: 'c71516c29c75d170' },
      { key: '0101018001010101', plaintext: '0000000000000000', ciphertext: '5199c29a52c9f059' },
      { key: '0101014001010101', plaintext: '0000000000000000', ciphertext: 'c22f0a294a71f29f' },
      { key: '0101012001010101', plaintext: '0000000000000000', ciphertext: 'ee371483714c02ea' },
      { key: '0101011001010101', plaintext: '0000000000000000', ciphertext: 'a81fbd448f9e522f' },
      { key: '0101010801010101', plaintext: '0000000000000000', ciphertext: '4f644c92e192dfed' },
      { key: '0101010401010101', plaintext: '0000000000000000', ciphertext: '1afa9a66a6df92ae' },
      { key: '0101010201010101', plaintext: '0000000000000000', ciphertext: 'b3c1cc715cb879d8' },
      { key: '0101010180010101', plaintext: '0000000000000000', ciphertext: '19d032e64ab0bd8b' },
      { key: '0101010140010101', plaintext: '0000000000000000', ciphertext: '3cfaa7a7dc8720dc' },
      { key: '0101010120010101', plaintext: '0000000000000000', ciphertext: 'b7265f7f447ac6f3' },
      { key: '0101010110010101', plaintext: '0000000000000000', ciphertext: '9db73b3c0d163f54' },
      { key: '0101010108010101', plaintext: '0000000000000000', ciphertext: '8181b65babf4a975' },
      { key: '0101010104010101', plaintext: '0000000000000000', ciphertext: '93c9b64042eaa240' },
      { key: '0101010102010101', plaintext: '0000000000000000', ciphertext: '5570530829705592' },
      { key: '0101010101800101', plaintext: '0000000000000000', ciphertext: '8638809e878787a0' },
      { key: '0101010101400101', plaintext: '0000000000000000', ciphertext: '41b9a79af79ac208' },
      { key: '0101010101200101', plaintext: '0000000000000000', ciphertext: '7a9be42f2009a892' },
      { key: '0101010101100101', plaintext: '0000000000000000', ciphertext: '29038d56ba6d2745' },
      { key: '0101010101080101', plaintext: '0000000000000000', ciphertext: '5495c6abf1e5df51' },
      { key: '0101010101040101', plaintext: '0000000000000000', ciphertext: 'ae13dbd561488933' },
      { key: '0101010101020101', plaintext: '0000000000000000', ciphertext: '024d1ffa8904e389' },
      { key: '0101010101018001', plaintext: '0000000000000000', ciphertext: 'd1399712f99bf02e' },
      { key: '0101010101014001', plaintext: '0000000000000000', ciphertext: '14c1d7c1cffec79e' },
      { key: '0101010101012001', plaintext: '0000000000000000', ciphertext: '1de5279dae3bed6f' },
      { key: '0101010101011001', plaintext: '0000000000000000', ciphertext: 'e941a33f85501303' },
      { key: '0101010101010801', plaintext: '0000000000000000', ciphertext: 'da99dbbc9a03f379' },
      { key: '0101010101010401', plaintext: '0000000000000000', ciphertext: 'b7fc92f91d8e92e9' },
      { key: '0101010101010201', plaintext: '0000000000000000', ciphertext: 'ae8e5caa3ca04e85' },
      { key: '0101010101010180', plaintext: '0000000000000000', ciphertext: '9cc62df43b6eed74' },
      { key: '0101010101010140', plaintext: '0000000000000000', ciphertext: 'd863dbb5c59a91a0' },
      { key: '0101010101010120', plaintext: '0000000000000000', ciphertext: 'a1ab2190545b91d7' },
      { key: '0101010101010110', plaintext: '0000000000000000', ciphertext: '0875041e64c570f7' },
      { key: '0101010101010108', plaintext: '0000000000000000', ciphertext: '5a594528bebef1cc' },
      { key: '0101010101010104', plaintext: '0000000000000000', ciphertext: 'fcdb3291de21f0c0' },
      { key: '0101010101010102', plaintext: '0000000000000000', ciphertext: '869efd7f9f265a09' },
    ],
  },
  {
    id: 'permop',
    mode: 'ecb',
    title: 'Permutation Operation KAT',
    note:
      'Thirty-two keys chosen to exercise the P permutation.',
    file: 'KAT_TDES/TECBpermop.rsp',
    vectors: [
      { key: '1046913489980131', plaintext: '0000000000000000', ciphertext: '88d55e54f54c97b4' },
      { key: '1007103489988020', plaintext: '0000000000000000', ciphertext: '0c0cc00c83ea48fd' },
      { key: '10071034c8980120', plaintext: '0000000000000000', ciphertext: '83bc8ef3a6570183' },
      { key: '1046103489988020', plaintext: '0000000000000000', ciphertext: 'df725dcad94ea2e9' },
      { key: '1086911519190101', plaintext: '0000000000000000', ciphertext: 'e652b53b550be8b0' },
      { key: '1086911519580101', plaintext: '0000000000000000', ciphertext: 'af527120c485cbb0' },
      { key: '5107b01519580101', plaintext: '0000000000000000', ciphertext: '0f04ce393db926d5' },
      { key: '1007b01519190101', plaintext: '0000000000000000', ciphertext: 'c9f00ffc74079067' },
      { key: '3107915498080101', plaintext: '0000000000000000', ciphertext: '7cfd82a593252b4e' },
      { key: '3107919498080101', plaintext: '0000000000000000', ciphertext: 'cb49a2f9e91363e3' },
      { key: '10079115b9080140', plaintext: '0000000000000000', ciphertext: '00b588be70d23f56' },
      { key: '3107911598080140', plaintext: '0000000000000000', ciphertext: '406a9a6ab43399ae' },
      { key: '1007d01589980101', plaintext: '0000000000000000', ciphertext: '6cb773611dca9ada' },
      { key: '9107911589980101', plaintext: '0000000000000000', ciphertext: '67fd21c17dbb5d70' },
      { key: '9107d01589190101', plaintext: '0000000000000000', ciphertext: '9592cb4110430787' },
      { key: '1007d01598980120', plaintext: '0000000000000000', ciphertext: 'a6b7ff68a318ddd3' },
      { key: '1007940498190101', plaintext: '0000000000000000', ciphertext: '4d102196c914ca16' },
      { key: '0107910491190401', plaintext: '0000000000000000', ciphertext: '2dfa9f4573594965' },
      { key: '0107910491190101', plaintext: '0000000000000000', ciphertext: 'b46604816c0e0774' },
      { key: '0107940491190401', plaintext: '0000000000000000', ciphertext: '6e7e6221a4f34e87' },
      { key: '19079210981a0101', plaintext: '0000000000000000', ciphertext: 'aa85e74643233199' },
      { key: '1007911998190801', plaintext: '0000000000000000', ciphertext: '2e5a19db4d1962d6' },
      { key: '10079119981a0801', plaintext: '0000000000000000', ciphertext: '23a866a809d30894' },
      { key: '1007921098190101', plaintext: '0000000000000000', ciphertext: 'd812d961f017d320' },
      { key: '100791159819010b', plaintext: '0000000000000000', ciphertext: '055605816e58608f' },
      { key: '1004801598190101', plaintext: '0000000000000000', ciphertext: 'abd88e8b1b7716f1' },
      { key: '1004801598190102', plaintext: '0000000000000000', ciphertext: '537ac95be69da1e1' },
      { key: '1004801598190108', plaintext: '0000000000000000', ciphertext: 'aed0f6ae3c25cdd8' },
      { key: '1002911598100104', plaintext: '0000000000000000', ciphertext: 'b3e35a5ee53e7b8d' },
      { key: '1002911598190104', plaintext: '0000000000000000', ciphertext: '61c79c71921a2ef8' },
      { key: '1002911598100201', plaintext: '0000000000000000', ciphertext: 'e2f5728f0995013c' },
      { key: '1002911698100101', plaintext: '0000000000000000', ciphertext: '1aeac39a61f0a464' },
    ],
  },
  {
    id: 'subtab',
    mode: 'ecb',
    title: 'Substitution Table KAT',
    note:
      'Nineteen key/plaintext pairs chosen so that every entry of every S-box is used.',
    file: 'KAT_TDES/TECBsubtab.rsp',
    vectors: [
      { key: '7ca110454a1a6e57', plaintext: '01a1d6d039776742', ciphertext: '690f5b0d9a26939b' },
      { key: '0131d9619dc1376e', plaintext: '5cd54ca83def57da', ciphertext: '7a389d10354bd271' },
      { key: '07a1133e4a0b2686', plaintext: '0248d43806f67172', ciphertext: '868ebb51cab4599a' },
      { key: '3849674c2602319e', plaintext: '51454b582ddf440a', ciphertext: '7178876e01f19b2a' },
      { key: '04b915ba43feb5b6', plaintext: '42fd443059577fa2', ciphertext: 'af37fb421f8c4095' },
      { key: '0113b970fd34f2ce', plaintext: '059b5e0851cf143a', ciphertext: '86a560f10ec6d85b' },
      { key: '0170f175468fb5e6', plaintext: '0756d8e0774761d2', ciphertext: '0cd3da020021dc09' },
      { key: '43297fad38e373fe', plaintext: '762514b829bf486a', ciphertext: 'ea676b2cb7db2b7a' },
      { key: '07a7137045da2a16', plaintext: '3bdd119049372802', ciphertext: 'dfd64a815caf1a0f' },
      { key: '04689104c2fd3b2f', plaintext: '26955f6835af609a', ciphertext: '5c513c9c4886c088' },
      { key: '37d06bb516cb7546', plaintext: '164d5e404f275232', ciphertext: '0a2aeeae3ff4ab77' },
      { key: '1f08260d1ac2465e', plaintext: '6b056e18759f5cca', ciphertext: 'ef1bf03e5dfa575a' },
      { key: '584023641aba6176', plaintext: '004bd6ef09176062', ciphertext: '88bf0db6d70dee56' },
      { key: '025816164629b007', plaintext: '480d39006ee762f2', ciphertext: 'a1f9915541020b56' },
      { key: '49793ebc79b3258f', plaintext: '437540c8698f3cfa', ciphertext: '6fbf1cafcffd0556' },
      { key: '4fb05e1515ab73a7', plaintext: '072d43a077075292', ciphertext: '2f22e49bab7ca1ac' },
      { key: '49e95d6d4ca229bf', plaintext: '02fe55778117f12a', ciphertext: '5a6b612cc26cce4a' },
      { key: '018310dc409b26d6', plaintext: '1d9d5c5018f728c2', ciphertext: '5f4c038ed12b2e41' },
      { key: '1c587f1c13924fef', plaintext: '305532286d6f295a', ciphertext: '63fac0d034d9f793' },
    ],
  },
  {
    id: 'cbcvartext',
    mode: 'cbc',
    title: 'Variable Plaintext KAT (CBC)',
    note:
      'The same single-bit sweep run in CBC with an all-zero IV, so the mode is gated by CAVP too rather than only by a round-trip.',
    file: 'KAT_TDES/TCBCvartext.rsp',
    vectors: [
      { key: '0101010101010101', iv: '0000000000000000', plaintext: '8000000000000000', ciphertext: '95f8a5e5dd31d900' },
      { key: '0101010101010101', iv: '0000000000000000', plaintext: '4000000000000000', ciphertext: 'dd7f121ca5015619' },
      { key: '0101010101010101', iv: '0000000000000000', plaintext: '2000000000000000', ciphertext: '2e8653104f3834ea' },
      { key: '0101010101010101', iv: '0000000000000000', plaintext: '1000000000000000', ciphertext: '4bd388ff6cd81d4f' },
      { key: '0101010101010101', iv: '0000000000000000', plaintext: '0800000000000000', ciphertext: '20b9e767b2fb1456' },
      { key: '0101010101010101', iv: '0000000000000000', plaintext: '0400000000000000', ciphertext: '55579380d77138ef' },
      { key: '0101010101010101', iv: '0000000000000000', plaintext: '0200000000000000', ciphertext: '6cc5defaaf04512f' },
      { key: '0101010101010101', iv: '0000000000000000', plaintext: '0100000000000000', ciphertext: '0d9f279ba5d87260' },
      { key: '0101010101010101', iv: '0000000000000000', plaintext: '0080000000000000', ciphertext: 'd9031b0271bd5a0a' },
      { key: '0101010101010101', iv: '0000000000000000', plaintext: '0040000000000000', ciphertext: '424250b37c3dd951' },
      { key: '0101010101010101', iv: '0000000000000000', plaintext: '0020000000000000', ciphertext: 'b8061b7ecd9a21e5' },
      { key: '0101010101010101', iv: '0000000000000000', plaintext: '0010000000000000', ciphertext: 'f15d0f286b65bd28' },
      { key: '0101010101010101', iv: '0000000000000000', plaintext: '0008000000000000', ciphertext: 'add0cc8d6e5deba1' },
      { key: '0101010101010101', iv: '0000000000000000', plaintext: '0004000000000000', ciphertext: 'e6d5f82752ad63d1' },
      { key: '0101010101010101', iv: '0000000000000000', plaintext: '0002000000000000', ciphertext: 'ecbfe3bd3f591a5e' },
      { key: '0101010101010101', iv: '0000000000000000', plaintext: '0001000000000000', ciphertext: 'f356834379d165cd' },
      { key: '0101010101010101', iv: '0000000000000000', plaintext: '0000800000000000', ciphertext: '2b9f982f20037fa9' },
      { key: '0101010101010101', iv: '0000000000000000', plaintext: '0000400000000000', ciphertext: '889de068a16f0be6' },
      { key: '0101010101010101', iv: '0000000000000000', plaintext: '0000200000000000', ciphertext: 'e19e275d846a1298' },
      { key: '0101010101010101', iv: '0000000000000000', plaintext: '0000100000000000', ciphertext: '329a8ed523d71aec' },
      { key: '0101010101010101', iv: '0000000000000000', plaintext: '0000080000000000', ciphertext: 'e7fce22557d23c97' },
      { key: '0101010101010101', iv: '0000000000000000', plaintext: '0000040000000000', ciphertext: '12a9f5817ff2d65d' },
      { key: '0101010101010101', iv: '0000000000000000', plaintext: '0000020000000000', ciphertext: 'a484c3ad38dc9c19' },
      { key: '0101010101010101', iv: '0000000000000000', plaintext: '0000010000000000', ciphertext: 'fbe00a8a1ef8ad72' },
      { key: '0101010101010101', iv: '0000000000000000', plaintext: '0000008000000000', ciphertext: '750d079407521363' },
      { key: '0101010101010101', iv: '0000000000000000', plaintext: '0000004000000000', ciphertext: '64feed9c724c2faf' },
      { key: '0101010101010101', iv: '0000000000000000', plaintext: '0000002000000000', ciphertext: 'f02b263b328e2b60' },
      { key: '0101010101010101', iv: '0000000000000000', plaintext: '0000001000000000', ciphertext: '9d64555a9a10b852' },
      { key: '0101010101010101', iv: '0000000000000000', plaintext: '0000000800000000', ciphertext: 'd106ff0bed5255d7' },
      { key: '0101010101010101', iv: '0000000000000000', plaintext: '0000000400000000', ciphertext: 'e1652c6b138c64a5' },
      { key: '0101010101010101', iv: '0000000000000000', plaintext: '0000000200000000', ciphertext: 'e428581186ec8f46' },
      { key: '0101010101010101', iv: '0000000000000000', plaintext: '0000000100000000', ciphertext: 'aeb5f5ede22d1a36' },
      { key: '0101010101010101', iv: '0000000000000000', plaintext: '0000000080000000', ciphertext: 'e943d7568aec0c5c' },
      { key: '0101010101010101', iv: '0000000000000000', plaintext: '0000000040000000', ciphertext: 'df98c8276f54b04b' },
      { key: '0101010101010101', iv: '0000000000000000', plaintext: '0000000020000000', ciphertext: 'b160e4680f6c696f' },
      { key: '0101010101010101', iv: '0000000000000000', plaintext: '0000000010000000', ciphertext: 'fa0752b07d9c4ab8' },
      { key: '0101010101010101', iv: '0000000000000000', plaintext: '0000000008000000', ciphertext: 'ca3a2b036dbc8502' },
      { key: '0101010101010101', iv: '0000000000000000', plaintext: '0000000004000000', ciphertext: '5e0905517bb59bcf' },
      { key: '0101010101010101', iv: '0000000000000000', plaintext: '0000000002000000', ciphertext: '814eeb3b91d90726' },
      { key: '0101010101010101', iv: '0000000000000000', plaintext: '0000000001000000', ciphertext: '4d49db1532919c9f' },
      { key: '0101010101010101', iv: '0000000000000000', plaintext: '0000000000800000', ciphertext: '25eb5fc3f8cf0621' },
      { key: '0101010101010101', iv: '0000000000000000', plaintext: '0000000000400000', ciphertext: 'ab6a20c0620d1c6f' },
      { key: '0101010101010101', iv: '0000000000000000', plaintext: '0000000000200000', ciphertext: '79e90dbc98f92cca' },
      { key: '0101010101010101', iv: '0000000000000000', plaintext: '0000000000100000', ciphertext: '866ecedd8072bb0e' },
      { key: '0101010101010101', iv: '0000000000000000', plaintext: '0000000000080000', ciphertext: '8b54536f2f3e64a8' },
      { key: '0101010101010101', iv: '0000000000000000', plaintext: '0000000000040000', ciphertext: 'ea51d3975595b86b' },
      { key: '0101010101010101', iv: '0000000000000000', plaintext: '0000000000020000', ciphertext: 'caffc6ac4542de31' },
      { key: '0101010101010101', iv: '0000000000000000', plaintext: '0000000000010000', ciphertext: '8dd45a2ddf90796c' },
      { key: '0101010101010101', iv: '0000000000000000', plaintext: '0000000000008000', ciphertext: '1029d55e880ec2d0' },
      { key: '0101010101010101', iv: '0000000000000000', plaintext: '0000000000004000', ciphertext: '5d86cb23639dbea9' },
      { key: '0101010101010101', iv: '0000000000000000', plaintext: '0000000000002000', ciphertext: '1d1ca853ae7c0c5f' },
      { key: '0101010101010101', iv: '0000000000000000', plaintext: '0000000000001000', ciphertext: 'ce332329248f3228' },
      { key: '0101010101010101', iv: '0000000000000000', plaintext: '0000000000000800', ciphertext: '8405d1abe24fb942' },
      { key: '0101010101010101', iv: '0000000000000000', plaintext: '0000000000000400', ciphertext: 'e643d78090ca4207' },
      { key: '0101010101010101', iv: '0000000000000000', plaintext: '0000000000000200', ciphertext: '48221b9937748a23' },
      { key: '0101010101010101', iv: '0000000000000000', plaintext: '0000000000000100', ciphertext: 'dd7c0bbd61fafd54' },
      { key: '0101010101010101', iv: '0000000000000000', plaintext: '0000000000000080', ciphertext: '2fbc291a570db5c4' },
      { key: '0101010101010101', iv: '0000000000000000', plaintext: '0000000000000040', ciphertext: 'e07c30d7e4e26e12' },
      { key: '0101010101010101', iv: '0000000000000000', plaintext: '0000000000000020', ciphertext: '0953e2258e8e90a1' },
      { key: '0101010101010101', iv: '0000000000000000', plaintext: '0000000000000010', ciphertext: '5b711bc4ceebf2ee' },
      { key: '0101010101010101', iv: '0000000000000000', plaintext: '0000000000000008', ciphertext: 'cc083f1e6d9e85f6' },
      { key: '0101010101010101', iv: '0000000000000000', plaintext: '0000000000000004', ciphertext: 'd2fd8867d50d2dfe' },
      { key: '0101010101010101', iv: '0000000000000000', plaintext: '0000000000000002', ciphertext: '06e7ea22ce92708f' },
      { key: '0101010101010101', iv: '0000000000000000', plaintext: '0000000000000001', ciphertext: '166b40b44aba4bd6' },
    ],
  },
];

/** Every vector, flattened, tagged with the family it came from. */
export const ALL_VECTORS: readonly (KatVector & { group: string; mode: 'ecb' | 'cbc' })[] = KAT_GROUPS.flatMap(
  (g) => g.vectors.map((v) => ({ ...v, group: g.id, mode: g.mode }))
);

/** How many distinct CAVP triples this file carries. */
export const VECTOR_COUNT = ALL_VECTORS.length;

/**
 * Each triple is asserted in BOTH directions, which is what the .rsp files'
 * paired [ENCRYPT] and [DECRYPT] sections ask a validating implementation to
 * do — the two sections carry the same triples, verified when this file was
 * generated, so storing them once and testing twice covers every CAVP case
 * without duplicating the data.
 */
export const ASSERTION_COUNT = VECTOR_COUNT * 2;

export interface KatOutcome {
  readonly vector: KatVector;
  readonly group: string;
  readonly direction: 'encrypt' | 'decrypt';
  readonly expected: string;
  readonly actual: string;
  readonly pass: boolean;
}

/** A KAT run, or the parse failure that stopped it. */
export type KatRun = Result<readonly KatOutcome[]>;
