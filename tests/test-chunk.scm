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
  (lambda (key nonce ctr buf-in)
    (let-values (((schedule rounds) (key->schedule key-schedule! key)))
      (let* ((len (u8vector-length buf-in))
             (buf-out (make-u8vector len))
             (write-len (cipher! schedule rounds nonce ctr buf-in buf-out len)))
        (values (subu8vector buf-out 0 write-len) write-len ctr)))))

(define chunk-cipher
  (make-chunk-cipher
   foreign-rijndael-key-schedule-encrypt!
   foreign-chunk-cipher!))

;; tests

(test-group
 "sanity"
 (test-values "zeros encrypt"
   (list +zeros-ct+ 16 +zeros-ctr-inc+)
   (chunk-cipher +zeros-key+ +zeros-nonce+ (+zeros-ctr+) +zeros-pt+))

 (test-values "zeros decrypt"
   (list +zeros-pt+ 16 +zeros-ctr-inc+)
   (chunk-cipher +zeros-key+ +zeros-nonce+ (+zeros-ctr+) +zeros-ct+)))

(test-group
 "nist 800-38a"
 (test-values "f5/aes-128 encrypt"
   (list +f5-ct+ 64 +fx-ctr-inc+)
   (chunk-cipher +f5-key+ +fx-nonce+ (+fx-ctr+) +f5-pt+))

 (test-values "f5/aes-128 decrypt"
   (list +f5-pt+ 64 +fx-ctr-inc+)
   (chunk-cipher +f5-key+ +fx-nonce+ (+fx-ctr+) +f5-ct+))

 (test-values "f6/aes-192 encrypt"
   (list +f6-ct+ 64 +fx-ctr-inc+)
   (chunk-cipher +f6-key+ +fx-nonce+ (+fx-ctr+) +f6-pt+))

 (test-values "f6/aes-192 decrypt"
   (list +f6-pt+ 64 +fx-ctr-inc+)
   (chunk-cipher +f6-key+ +fx-nonce+ (+fx-ctr+) +f6-ct+))

 (test-values "f7/aes-256 encrypt"
   (list +f7-ct+ 64 +fx-ctr-inc+)
   (chunk-cipher +f7-key+ +fx-nonce+ (+fx-ctr+) +f7-pt+))

 (test-values "f7/aes-256 decrypt"
   (list +f7-pt+ 64 +fx-ctr-inc+)
   (chunk-cipher +f7-key+ +fx-nonce+ (+fx-ctr+) +f7-ct+)))
