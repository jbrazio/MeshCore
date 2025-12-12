#pragma once

#include <MeshCore.h>
#include <Stream.h>
#include <string.h>

namespace mesh {

class RNG {
public:
  virtual void random(uint8_t* dest, size_t sz) = 0;

  /**
   * \returns  random number between _min (inclusive) and _max (exclusive)
   */
  uint32_t nextInt(uint32_t _min, uint32_t _max);
};

class Utils {
public:
  /**
   * \brief  calculates the SHA256 hash of 'msg', storing in 'hash' and truncating the hash to 'hash_len' bytes.
  */
  static void sha256(uint8_t *hash, size_t hash_len, const uint8_t* msg, int msg_len);

  /**
   * \brief  calculates the SHA256 hash of two fragments, 'frag1' and 'frag2' (in that order), storing in 'hash' and truncating.
  */
  static void sha256(uint8_t *hash, size_t hash_len, const uint8_t* frag1, int frag1_len, const uint8_t* frag2, int frag2_len);

  /**
   * \brief  Encrypts the 'src' bytes using AES128 cipher, using 'shared_secret' as key, with key length fixed at CIPHER_KEY_SIZE.
   *         Final block is padded with zero bytes before encrypt. Result stored in 'dest'.
   * \returns  The length in bytes put into 'dest'. (rounded up to block size)
  */
  static int encrypt(const uint8_t* shared_secret, uint8_t* dest, const uint8_t* src, int src_len);

  /**
   * \brief  Decrypt the 'src' bytes using AES128 cipher, using 'shared_secret' as key, with key length fixed at CIPHER_KEY_SIZE.
   *         'src_len' should be multiple of block size, as returned by 'encrypt()'.
   * \returns  The length in bytes put into 'dest'. (dest may contain trailing zero bytes in final block)
  */
  static int decrypt(const uint8_t* shared_secret, uint8_t* dest, const uint8_t* src, int src_len);

  /**
   * \brief  encrypts bytes in src, then calculates MAC on ciphertext, inserting into leading bytes of 'dest'.
   * \returns  total length of bytes in 'dest' (MAC + ciphertext)
  */
  static int encryptThenMAC(const uint8_t* shared_secret, uint8_t* dest, const uint8_t* src, int src_len);

  /**
   * \brief  checks the MAC (in leading bytes of 'src'), then if valid, decrypts remaining bytes in src.
   * \returns  zero if MAC is invalid, otherwise the length of decrypted bytes in 'dest'
  */
  static int MACThenDecrypt(const uint8_t* shared_secret, uint8_t* dest, const uint8_t* src, int src_len);

  /**
   * @brief  Compresses data using unishox2 if beneficial, otherwise returns original data.
   * @param dest        Output buffer for compressed data
   * @param src         Input data to compress
   * @param src_len     Length of input data
   * @param out_ver     (OUT) Set to PAYLOAD_VER_2 if compressed, PAYLOAD_VER_1 if not
   * @returns  Length of data in dest (may be src copied if compression not beneficial)
   */
  static int compressIfBeneficial(uint8_t* dest, const uint8_t* src, int src_len, uint8_t* out_ver);

  /**
   * @brief  Decompresses data if it was compressed (based on version flag).
   * @param dest        Output buffer for decompressed data
   * @param src         Input data (compressed or not)
   * @param src_len     Length of input data
   * @param payload_ver Version flag (PAYLOAD_VER_1 = no compression, PAYLOAD_VER_2 = compressed)
   * @returns  Length of data in dest (decompressed if needed, or copied if not compressed)
   */
  static int decompressIfNeeded(uint8_t* dest, const uint8_t* src, int src_len, uint8_t payload_ver);

  /**
   * @brief  Attempts to compress a payload with a fixed-size binary header, considering AES encryption padding.
   *         Only compresses if it will save RF bytes after AES encryption (which pads to 16-byte blocks).
   * @param dest           Output buffer for result (either compressed or original data)
   * @param src            Input data (header + text)
   * @param src_len        Length of input data
   * @param header_size    Size of binary header to skip (will not be compressed)
   * @param out_ver        (OUT) Set to PAYLOAD_VER_2 if compressed, PAYLOAD_VER_1 if not
   * @param debug_label    Label for debug output (e.g., "GRP" or "TXT_MSG")
   * @returns  Length of data in dest
   */
  static int compressPayloadWithHeader(uint8_t* dest, const uint8_t* src, int src_len, 
                                       int header_size, uint8_t* out_ver, const char* debug_label);

  /**
   * @brief  Decompresses a payload with a fixed-size binary header if needed.
   *         Handles the case where AES padding (0x00 bytes) may be present after compressed data.
   * @param dest           Output buffer for decompressed data
   * @param src            Input data (header + compressed/uncompressed text)
   * @param src_len        Length of input data
   * @param header_size    Size of binary header to skip (not compressed)
   * @param payload_ver    Version flag (PAYLOAD_VER_1 = no compression, PAYLOAD_VER_2 = compressed)
   * @param debug_label    Label for debug output (e.g., "GRP" or "TXT_MSG")
   * @returns  Length of data in dest, or -1 on error
   */
  static int decompressPayloadWithHeader(uint8_t* dest, const uint8_t* src, int src_len,
                                         int header_size, uint8_t payload_ver, const char* debug_label);

  /**
   * \brief  converts 'src' bytes with given length to Hex representation, and null terminates.
  */
  static void toHex(char* dest, const uint8_t* src, size_t len);

  /**
   * \brief  converts 'src_hex' hexadecimal string (should be null term) back to raw bytes, storing in 'dest'.
   * \param dest_size   must be exactly the expected size in bytes.
   * \returns  true if successful
  */
  static bool fromHex(uint8_t* dest, int dest_size, const char *src_hex);

  /**
   * \brief  Prints the hexadecimal representation of 'src' bytes of given length, to Stream 's'.
  */
  static void printHex(Stream& s, const uint8_t* src, size_t len);

  /**
   * \brief  parse 'text' into parts separated by 'separator' char.
   * \param  text  the text to parse (note is MODIFIED!)
   * \param  parts  destination array to store pointers to starts of parse parts
   * \param  max_num  max elements to store in 'parts' array
   * \param  separator  the separator character
   * \returns  the number of parts parsed (in 'parts')
   */
  static int parseTextParts(char* text, const char* parts[], int max_num, char separator=',');

  static bool isHexChar(char c);
};

}
