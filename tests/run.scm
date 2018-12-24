(import test)

(define-syntax test-values
  (syntax-rules ()
    ((_ name expect (expr ...))
     (test name expect (call-with-values (lambda () (expr ...)) list)))))

;; shared by several low-level tests

(define max-rounds 14)
(define max-schedule-len (* 4 (+ max-rounds 1)))

;; tests

(test-group
 "block"
 (include "tests/test-block.scm"))

(test-group
 "chunk"
 (include "tests/test-chunk.scm"))
