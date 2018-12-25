(import (chicken blob)
        srfi-4)

;;

(define +zeros-pt+
  (make-u8vector 16 0))

(define +zeros-key+
  (make-u8vector 16 0))

(define +zeros-ct+
  (blob->u8vector/shared
   #${66e94bd4ef8a2c3b884cfa59ca342b2e}))

(define +zeros-nonce+
  (blob->u64vector #${0000000000000000}))

(define (+zeros-ctr+)
  (blob->u64vector #${0000000000000000}))

(define +zeros-ctr-inc+
  (blob->u64vector #${0000000000000001}))

;; fips-197 vectors (block)

(define +c1-pt+
  (blob->u8vector/shared
   #${00112233445566778899aabbccddeeff}))

(define +c1-key+
  (blob->u8vector/shared
   #${000102030405060708090a0b0c0d0e0f}))

(define +c1-ct+
  (blob->u8vector/shared
   #${69c4e0d86a7b0430d8cdb78070b4c55a}))

(define +c2-pt+
  (blob->u8vector/shared
   #${00112233445566778899aabbccddeeff}))

(define +c2-key+
  (blob->u8vector/shared
   #${000102030405060708090a0b0c0d0e0f1011121314151617}))

(define +c2-ct+
  (blob->u8vector/shared
   #${dda97ca4864cdfe06eaf70a0ec0d7191}))

(define +c3-pt+
  (blob->u8vector/shared
   #${00112233445566778899aabbccddeeff}))

(define +c3-key+
  (blob->u8vector/shared
   #${000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f}))

(define +c3-ct+
  (blob->u8vector/shared
   #${8ea2b7ca516745bfeafc49904b496089}))

;; nist 800-38a vectors (ctr)

;; common

(define +fx-init+
  (blob->u64vector/shared
   #${f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff}))

(define +fx-nonce+
  (subu64vector +fx-init+ 0 1))

(define (+fx-ctr+)
  (subu64vector +fx-init+ 1 2))

(define +fx-ctr-inc+
  (blob->u64vector/shared #${f8f9fafbfcfdff03}))

;;

(define +f5-key+
  (blob->u8vector/shared
   #${2b7e151628aed2a6abf7158809cf4f3c}))

(define +f5-pt+
  (blob->u8vector/shared
   #${6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710}))

(define +f5-ct+
  (blob->u8vector/shared
   #${874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee}))

;;

(define +f6-key+
  (blob->u8vector/shared
   #${8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b}))

(define +f6-pt+
  (blob->u8vector/shared
   #${6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710}))

(define +f6-ct+
  (blob->u8vector/shared
   #${1abc932417521ca24f2b0459fe7e6e0b090339ec0aa6faefd5ccc2c6f4ce8e941e36b26bd1ebc670d1bd1d665620abf74f78a7f6d29809585a97daec58c6b050}))

;;

(define +f7-key+
  (blob->u8vector/shared
   #${603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4}))

(define +f7-pt+
  (blob->u8vector/shared
   #${6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710}))

(define +f7-ct+
  (blob->u8vector/shared
   #${601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c52b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6}))
