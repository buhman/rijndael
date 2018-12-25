(import (chicken blob)
        (chicken random)
        (chicken condition)
        (srfi-4))

(define strerror (foreign-lambda c-string "strerror" int))

(define (generate-zero-key len)
  (let ((vec (make-u8vector len 0)))
    vec))

(define (generate-random-key len)
  (let* ((buf (make-blob len)))
    (blob->u8vector/shared (random-bytes buf len))))

(define +max-rounds+ 14)
(define +max-schedule-len+ (* 4 (+ +max-rounds+ 1)))

(define (key->schedule key)
  (let* ((key-bits (* 8 (u8vector-length key)))
         (schedule (make-u32vector +max-schedule-len+))
         (rounds (foreign-rijndael-key-schedule-encrypt! schedule key key-bits)))
    (values schedule rounds)))

(define (chunk-cipher! key nonce ctr buf-in buf-out)
  (let-values (((schedule rounds) (key->schedule key)))
    (let* ((len (u8vector-length buf-in))
           (write-len (foreign-chunk-cipher! schedule rounds nonce ctr buf-in buf-out len)))
      (values buf-out write-len ctr))))

(define (stream-cipher key nonce ctr in-fd out-fd)
  (let* ((key-bits (* 8 (u8vector-length key)))
         (errorp (make-u32vector 1 0))
         (len (foreign-stream-cipher key key-bits nonce ctr in-fd out-fd errorp)))
    (unless (< 0 len)
      (let* ((errno (u32vector-ref errorp 0))
             (message (strerror errno)))
        (signal (condition `(exn location stream-cipher
                                 message ,message)
                           '(i/o)
                           `(posix errno ,errno)))))
    len))
