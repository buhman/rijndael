(import (chicken file)
        (chicken blob)
        (chicken io)
        srfi-1
        srfi-4
        rijndael)

(include "tests/vectors.scm")

(define (pt-sequence)
  (apply circular-list (iota 256)))

(define u8vector->string
  (o blob->string u8vector->blob/shared))

(define (pt-sequence-vec len)
  (list->u8vector (take (pt-sequence) len)))

(define (write-pt-sequence len)
  (let ((path (string-append "tests/seq-" (number->string len) "-pt")))
    (with-output-to-file path
      (lambda ()
        (write-string (u8vector->string (pt-sequence-vec len)))))))

(define (write-ct-sequence len)
  (let ((path (string-append "tests/seq-" (number->string len) "-ct")))
    (with-output-to-file path
      (lambda ()
        (let* ((buf-in (pt-sequence-vec len))
               (buf-out (make-u8vector len)))
          (chunk-cipher! +zeros-key+ +zeros-nonce+ (+zeros-ctr+) buf-in buf-out)
          (write-string (u8vector->string buf-out)))))))

(write-pt-sequence 6144)
(write-ct-sequence 6144)
