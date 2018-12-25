#pragma once

#define BLOCK_SIZE 16
#define CHUNK_SIZE 4096
#define MAXSCH (4 * (MAXNR + 1))

typedef __int128_t int128_t;
typedef __uint128_t uint128_t;

size_t
chunk_encrypt(const uint32_t * schedule,
							int rounds,
							const uint64_t * nonce,
							uint64_t * ctr,
							const uint8_t * rbuf,
							uint8_t * wbuf,
							size_t len);

ssize_t
stream_encrypt(const uint8_t * cipher_key,
							 int key_bits,
							 const uint64_t * nonce,
               uint64_t * ctr,
							 int in_fd, int out_fd,
               int * errorp);
