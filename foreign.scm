(foreign-declare "#include \"rijndael-impl.h\"")
(foreign-declare "#include \"stream-ctr.h\"")

(define foreign-rijndael-key-schedule-encrypt!
  (foreign-lambda int "rijndael_key_schedule_encrypt"
    u32vector u8vector integer))

(define foreign-rijndael-key-schedule-decrypt!
  (foreign-lambda int "rijndael_key_schedule_decrypt"
    u32vector u8vector integer))

(define foreign-rijndael-encrypt!
  (foreign-lambda void "rijndael_encrypt"
    u32vector integer u8vector u8vector))

(define foreign-rijndael-decrypt!
  (foreign-lambda void "rijndael_decrypt"
    u32vector integer u8vector u8vector))

(define foreign-chunk-cipher!
  (foreign-lambda unsigned-integer64 "chunk_encrypt"
    u32vector integer u8vector u8vector unsigned-integer64 u64vector u64vector))

(define foreign-stream-cipher!
  (foreign-lambda integer64 "stream_encrypt"
    u8vector integer u64vector integer integer))
