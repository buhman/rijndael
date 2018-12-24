(import srfi-4
        rijndael)

(include "tests/vectors.scm")

;; api

(define (block-decrypt key in-buf)
  (let* ((key-bits (* 8 (u8vector-length key)))
         (out-buf (make-u8vector 16 1))
         (schedule (make-u32vector max-schedule-len))
         (rounds (foreign-rijndael-key-schedule-decrypt! schedule key key-bits)))
    (foreign-rijndael-decrypt! schedule rounds in-buf out-buf)
    out-buf))

(define (block-encrypt key in-buf)
  (let* ((key-bits (* 8 (u8vector-length key)))
         (out-buf (make-u8vector 16 1))
         (schedule (make-u32vector max-schedule-len))
         (rounds (foreign-rijndael-key-schedule-encrypt! schedule key key-bits)))
    (foreign-rijndael-encrypt! schedule rounds in-buf out-buf)
    out-buf))

;; tests

(test-group
 "sanity"
 (test "zeros encrypt"
   +zeros-ct+
   (block-encrypt +zeros-key+ +zeros-pt+))
 (test "zeros decrypt"
   +zeros-pt+
   (block-decrypt +zeros-key+ +zeros-ct+)))

(test-group
 "fips-197"
 (test "c1/aes-128 encrypt"
   +c1-ct+
   (block-encrypt +c1-key+ +c1-pt+))
 (test "c1/aes-128 decrypt"
   +c1-pt+
   (block-decrypt +c1-key+ +c1-ct+))
 (test "c2/aes-192 encrypt"
   +c2-ct+
   (block-encrypt +c2-key+ +c2-pt+))
 (test "c2/aes-192 decrypt"
   +c2-pt+
   (block-decrypt +c2-key+ +c2-ct+))
 (test "c3/aes-256 encrypt"
   +c3-ct+
   (block-encrypt +c3-key+ +c3-pt+))
 (test "c3/aes-256 decrypt"
   +c3-pt+
   (block-decrypt +c3-key+ +c3-ct+)))
