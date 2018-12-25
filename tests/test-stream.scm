(import (chicken file)
        (chicken file posix)
        (chicken blob)
        (chicken io)
        rijndael)

(include "tests/vectors.scm")

;; api

(define (close/delete fd path)
  (file-close fd)
  (delete-file path))

(define (call-with-temp-fds func)
  (let-values (((in-fd in-path) (file-mkstemp "/tmp/test-in.XXXXXX"))
               ((out-fd out-path) (file-mkstemp "/tmp/test-out.XXXXXX")))
    (let ((len (func in-fd out-fd)))
      (close/delete in-fd in-path)
      (close/delete out-fd out-path)
      len)))

(define (call-with-u8vector-fds vec-in func)
  (call-with-temp-fds
   (lambda (in-fd out-fd)
     (file-write in-fd (u8vector->blob/shared vec-in))
     (set-file-position! in-fd 0 seek/set)
     (let* ((len (func in-fd out-fd))
            (blob (make-blob len)))
       (set-file-position! out-fd 0 seek/set)
       (assert (= len (cadr (file-read out-fd len blob))))
       (blob->u8vector/shared blob)))))

(define (test-stream-cipher key nonce ctr vec)
  (call-with-u8vector-fds vec
   (lambda (in-fd out-fd)
     (stream-cipher key nonce ctr in-fd out-fd))))

;; large vectors

(define string->u8vector
  (o blob->u8vector string->blob))

(define (vector-from-file path)
  (with-input-from-file path
    (lambda ()
      (string->u8vector (read-string)))))

(define +seq-6144-pt+
  (vector-from-file "tests/seq-6144-pt"))

(define +seq-6144-ct+
  (vector-from-file "tests/seq-6144-ct"))

;; tests

(test-group
 "sanity"
 (test "zeros encrypt"
   +zeros-ct+
   (test-stream-cipher +zeros-key+ +zeros-nonce+ (+zeros-ctr+) +zeros-pt+))

 (test "zeros encrypt"
   +zeros-pt+
   (test-stream-cipher +zeros-key+ +zeros-nonce+ (+zeros-ctr+) +zeros-ct+)))

(test-group
 "partial block/chunk"
 (test "36-byte encrypt"
   (subu8vector +f6-ct+ 0 36)
   (test-stream-cipher +f6-key+ +fx-nonce+ (+fx-ctr+) (subu8vector +f6-pt+ 0 36)))

 (test "36-byte decrypt"
   (subu8vector +f6-pt+ 0 36)
   (test-stream-cipher +f6-key+ +fx-nonce+ (+fx-ctr+) (subu8vector +f6-ct+ 0 36)))

 (test "6144-byte encrypt"
   +seq-6144-ct+
   (test-stream-cipher +zeros-key+ +zeros-nonce+ (+zeros-ctr+) +seq-6144-pt+))

 (test "6144-byte decrypt"
   +seq-6144-pt+
   (test-stream-cipher +zeros-key+ +zeros-nonce+ (+zeros-ctr+) +seq-6144-ct+)))

(test-group
 "error handling"
 (test-error "bad fd"
   (stream-cipher +zeros-key+ +zeros-nonce+ (+zeros-ctr+) -1 -1)))
