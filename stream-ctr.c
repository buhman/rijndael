#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

#include "rijndael-impl.h"
#include "stream-ctr.h"

/* nist test vectors count in big endian */

static inline void
swap_endian(uint64_t value,
            uint64_t * dest)
{
  value =
    ((value & 0xFF00000000000000u) >> 56u) |
    ((value & 0x00FF000000000000u) >> 40u) |
    ((value & 0x0000FF0000000000u) >> 24u) |
    ((value & 0x000000FF00000000u) >>  8u) |
    ((value & 0x00000000FF000000u) <<  8u) |
    ((value & 0x0000000000FF0000u) << 24u) |
    ((value & 0x000000000000FF00u) << 40u) |
    ((value & 0x00000000000000FFu) << 56u);
  memcpy(dest, &value, sizeof (uint64_t));
}

static inline void
block_encrypt(const uint32_t * schedule,
              int rounds,
              const uint8_t * rbuf,
              uint8_t * wbuf,
              uint64_t * nonce,
              uint64_t ctr)
{
  uint128_t seed, pad;

  /* big endian */
  seed = (((uint128_t)ctr) << 64) | *nonce;

  /* CTR mode uses a psuedorandom pad in both directions */
  rijndael_encrypt(schedule, rounds,
                   (const uint8_t *)&seed,
                   (uint8_t *)&pad);

  *((uint128_t *)wbuf) = *((const uint128_t *)rbuf) ^ pad;
}

size_t
chunk_encrypt(const uint32_t * schedule,
              int rounds,
              const uint8_t * rbuf,
              uint8_t * wbuf,
              size_t len,
              uint64_t * nonce,
              uint64_t * ctr)
{
  size_t offset = 0;
  uint64_t new_ctr;

  while (offset + BLOCK_SIZE <= len) {
    block_encrypt(schedule,
                  rounds,
                  (rbuf + offset),
                  (wbuf + offset),
                  nonce, *ctr);

    offset += BLOCK_SIZE;

    swap_endian(*ctr, &new_ctr);
    new_ctr += 1;
    swap_endian(new_ctr, ctr);
  }

  return offset;
}

ssize_t
stream_encrypt(const uint8_t * cipher_key,
               int key_bits,
               uint64_t * nonce,
               int in_fd, int out_fd)
{
  ssize_t len = 0, ret;
  size_t offset = 0, clen;
  uint8_t rbuf[CHUNK_SIZE];
  uint8_t wbuf[CHUNK_SIZE];
  uint64_t ctr = 0;
  int rounds;
  uint32_t schedule[MAXSCH];

  rounds = rijndael_key_schedule_encrypt(schedule,
                                             cipher_key,
                                             key_bits);

  while (true) {
    ret = read(in_fd, rbuf + offset, CHUNK_SIZE - offset);
    if (ret < 0) {
      len = ret;
      goto exit;
    }

    if (ret == 0) { /* eof */
      break;
    }

    clen = chunk_encrypt(schedule, rounds,
                             rbuf, wbuf, ret, nonce, &ctr);

    ret = write(out_fd, wbuf, clen);
    if (ret < 0) {
      len = ret;
      goto exit;
    }

    memcpy(rbuf, rbuf + clen, offset);
    offset = clen - ret;
    len += clen;
  }

  /* handle remainder */
  if (offset > 0) {
    memset(rbuf + offset, 0, BLOCK_SIZE - offset);

    block_encrypt(schedule, rounds,
                      rbuf, wbuf,
                      nonce, ctr);

    write(out_fd, wbuf, offset);

    len += offset;
  }

 exit:
  return len;
}
