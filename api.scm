(import (chicken blob)
        (chicken random)
        (srfi-4))

(define (generate-zero-key key-bits)
  (let ((vec (make-u8vector (/ key-bits 8) 0)))
    vec))

(define (generate-random-key key-bits)
  (let* ((len (/ key-bits 8))
         (buf (make-blob len)))
    (blob->u8vector/shared (random-bytes buf len))))
