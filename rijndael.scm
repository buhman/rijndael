(module rijndael
    (;; foreign
     foreign-rijndael-key-schedule-encrypt!
     foreign-rijndael-key-schedule-decrypt!
     foreign-rijndael-encrypt!
     foreign-rijndael-decrypt!
     foreign-chunk-cipher!
     foreign-stream-cipher!
     ;; api
     generate-zero-key
     generate-random-key)

  (import scheme (chicken base) (chicken foreign)
          srfi-4)

  (include "foreign.scm")
  (include "api.scm"))
