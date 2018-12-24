(import (chicken blob)
        srfi-4
        rijndael)

(include "tests/vectors.scm")

;; api

(define (key->schedule key-schedule! key)
  (let* ((key-bits (* 8 (u8vector-length key)))
         (schedule (make-u32vector max-schedule-len))
         (rounds (key-schedule! schedule key key-bits)))
    (values schedule rounds)))

(define (make-chunk-cipher key-schedule! cipher!)
  (lambda (key buf-in nonce ctr)
    (let-values (((schedule rounds) (key->schedule key-schedule! key)))
      (let* ((len (u8vector-length buf-in))
             (buf-out (make-u8vector len))
             (write-len (cipher! schedule rounds buf-in buf-out len nonce ctr)))
        (values (subu8vector buf-out 0 write-len) write-len (u64vector-ref ctr 0))))))

(define chunk-cipher
  (make-chunk-cipher
   foreign-rijndael-key-schedule-encrypt!
   foreign-chunk-cipher!))

(define (blob->u64 blob)
  (u64vector-ref (blob->u64vector blob) 0))

;; tests

(test-group
 "sanity"
 (test-values "zeros encrypt"
   (list +zeros-ct+ 16 (blob->u64 #${0000000000000001}))
   (chunk-cipher +zeros-key+ +zeros-pt+ +zeros-nonce+ (+zeros-ctr+)))

 (test-values "zeros decrypt"
   (list +zeros-pt+ 16 (blob->u64 #${0000000000000001}))
   (chunk-cipher +zeros-key+ +zeros-ct+ +zeros-nonce+ (+zeros-ctr+))))

(test-group
 "nist 800-38a"
 (test-values "f5/aes-128 encrypt"
   (list +f5-ct+ 64 (blob->u64 #${f8f9fafbfcfdff03}))
   (chunk-cipher +f5-key+ +f5-pt+ +f5-nonce+ (+f5-ctr+)))

 (test-values "f5/aes-128 decrypt"
   (list +f5-pt+ 64 (blob->u64 #${f8f9fafbfcfdff03}))
   (chunk-cipher +f5-key+ +f5-ct+ +f5-nonce+ (+f5-ctr+)))

 (test-values "f6/aes-192 encrypt"
   (list +f6-ct+ 64 (blob->u64 #${f8f9fafbfcfdff03}))
   (chunk-cipher +f6-key+ +f6-pt+ +f6-nonce+ (+f6-ctr+)))

 (test-values "f6/aes-192 decrypt"
   (list +f6-pt+ 64 (blob->u64 #${f8f9fafbfcfdff03}))
   (chunk-cipher +f6-key+ +f6-ct+ +f6-nonce+ (+f6-ctr+)))

 (test-values "f7/aes-256 encrypt"
   (list +f7-ct+ 64 (blob->u64 #${f8f9fafbfcfdff03}))
   (chunk-cipher +f7-key+ +f7-pt+ +f7-nonce+ (+f7-ctr+)))

 (test-values "f7/aes-256 decrypt"
   (list +f7-pt+ 64 (blob->u64 #${f8f9fafbfcfdff03}))
   (chunk-cipher +f7-key+ +f7-ct+ +f7-nonce+ (+f7-ctr+))))
