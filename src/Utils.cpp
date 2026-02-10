#include "Utils.h"
#include "Packet.h"
#include "unishox2.h"
#include <AES.h>
#include <SHA256.h>

#ifdef ARDUINO
  #include <Arduino.h>
#endif

namespace mesh {

uint32_t RNG::nextInt(uint32_t _min, uint32_t _max) {
  uint32_t num;
  random((uint8_t *) &num, sizeof(num));
  return (num % (_max - _min)) + _min;
}

void Utils::sha256(uint8_t *hash, size_t hash_len, const uint8_t* msg, int msg_len) {
  SHA256 sha;
  sha.update(msg, msg_len);
  sha.finalize(hash, hash_len);
}

void Utils::sha256(uint8_t *hash, size_t hash_len, const uint8_t* frag1, int frag1_len, const uint8_t* frag2, int frag2_len) {
  SHA256 sha;
  sha.update(frag1, frag1_len);
  sha.update(frag2, frag2_len);
  sha.finalize(hash, hash_len);
}

int Utils::decrypt(const uint8_t* shared_secret, uint8_t* dest, const uint8_t* src, int src_len) {
  AES128 aes;
  uint8_t* dp = dest;
  const uint8_t* sp = src;

  aes.setKey(shared_secret, CIPHER_KEY_SIZE);
  while (sp - src < src_len) {
    aes.decryptBlock(dp, sp);
    dp += 16; sp += 16;
  }

  return sp - src;  // will always be multiple of 16
}

int Utils::encrypt(const uint8_t* shared_secret, uint8_t* dest, const uint8_t* src, int src_len) {
  AES128 aes;
  uint8_t* dp = dest;

  aes.setKey(shared_secret, CIPHER_KEY_SIZE);
  while (src_len >= 16) {
    aes.encryptBlock(dp, src);
    dp += 16; src += 16; src_len -= 16;
  }
  if (src_len > 0) {  // remaining partial block
    uint8_t tmp[16];
    memset(tmp, 0, 16);
    memcpy(tmp, src, src_len);
    aes.encryptBlock(dp, tmp);
    dp += 16;
  }
  return dp - dest;  // will always be multiple of 16
}

int Utils::encryptThenMAC(const uint8_t* shared_secret, uint8_t* dest, const uint8_t* src, int src_len) {
  int enc_len = encrypt(shared_secret, dest + CIPHER_MAC_SIZE, src, src_len);

  SHA256 sha;
  sha.resetHMAC(shared_secret, PUB_KEY_SIZE);
  sha.update(dest + CIPHER_MAC_SIZE, enc_len);
  sha.finalizeHMAC(shared_secret, PUB_KEY_SIZE, dest, CIPHER_MAC_SIZE);

  return CIPHER_MAC_SIZE + enc_len;
}

int Utils::MACThenDecrypt(const uint8_t* shared_secret, uint8_t* dest, const uint8_t* src, int src_len) {
  if (src_len <= CIPHER_MAC_SIZE) return 0;  // invalid src bytes

  uint8_t hmac[CIPHER_MAC_SIZE];
  {
    SHA256 sha;
    sha.resetHMAC(shared_secret, PUB_KEY_SIZE);
    sha.update(src + CIPHER_MAC_SIZE, src_len - CIPHER_MAC_SIZE);
    sha.finalizeHMAC(shared_secret, PUB_KEY_SIZE, hmac, CIPHER_MAC_SIZE);
  }
  if (memcmp(hmac, src, CIPHER_MAC_SIZE) == 0) {
    return decrypt(shared_secret, dest, src + CIPHER_MAC_SIZE, src_len - CIPHER_MAC_SIZE);
  }
  return 0; // invalid HMAC
}

static const char hex_chars[] = "0123456789ABCDEF";

void Utils::toHex(char* dest, const uint8_t* src, size_t len) {
  while (len > 0) {
    uint8_t b = *src++;
    *dest++ = hex_chars[b >> 4];
    *dest++ = hex_chars[b & 0x0F];
    len--;
  }
  *dest = 0;
}

void Utils::printHex(Stream& s, const uint8_t* src, size_t len) {
  while (len > 0) {
    uint8_t b = *src++;
    s.print(hex_chars[b >> 4]);
    s.print(hex_chars[b & 0x0F]);
    len--;
  }
}

static uint8_t hexVal(char c) {
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= '0' && c <= '9') return c - '0';
  return 0;
}

bool Utils::isHexChar(char c) {
  return c == '0' || hexVal(c) > 0;
}

bool Utils::fromHex(uint8_t* dest, int dest_size, const char *src_hex) {
  int len = strlen(src_hex);
  if (len != dest_size*2) return false;  // incorrect length

  uint8_t* dp = dest;
  while (dp - dest < dest_size) {
    char ch = *src_hex++;
    char cl = *src_hex++;
    *dp++ = (hexVal(ch) << 4) | hexVal(cl);
  }
  return true;
}

int Utils::parseTextParts(char* text, const char* parts[], int max_num, char separator) {
  int num = 0;
  char* sp = text;
  while (*sp && num < max_num) {
    parts[num++] = sp;
    while (*sp && *sp != separator) sp++;
    if (*sp) {
       *sp++ = 0;  // replace the seperator with a null, and skip past it
    }
  }
  // if we hit the maximum parts, make sure LAST entry does NOT have separator 
  while (*sp && *sp != separator) sp++;
  if (*sp) {
    *sp = 0;  // replace the separator with null
  }
  return num;
}

/**
 * @brief  Compresses data using unishox2 algorithm if it provides size benefit.
 * 
 * This function attempts to compress the input data using unishox2. It only uses
 * the compressed version if it saves at least 3 bytes compared to the original,
 * to account for protocol overhead. If compression is not beneficial, the original
 * data is copied to the destination buffer.
 * 
 * @param dest      Output buffer for compressed (or copied) data. Must be large enough
 *                  to hold worst-case compressed size (typically same as src_len).
 * @param src       Input data to compress.
 * @param src_len   Length of input data in bytes.
 * @param out_ver   Pointer to store the version flag (PAYLOAD_VER_2 if compressed,
 *                  PAYLOAD_VER_1 if not compressed).
 * @returns         Length of data written to dest (compressed size or original size).
 * 
 * @note The function handles the case where dest == src (in-place operation not supported
 *       for compression, but will copy if compression is skipped).
 * @note Compression uses unishox2_compress_simple() which is optimized for text data.
 */
int Utils::compressIfBeneficial(uint8_t* dest, const uint8_t* src, int src_len, uint8_t* out_ver) {
  // Try compression using optimized preset
  // USX_PSET_DFLT provides optimized parameters for general-purpose text compression
  // We assume dest buffer is large enough (typically MAX_PACKET_PAYLOAD or MAX_TEXT_LEN)
  int compressed_len = unishox2_compress_lines((const char*)src, src_len, 
                                               (char*)dest, MAX_PACKET_PAYLOAD,
                                               USX_PSET_DFLT, NULL);
  
  // Only use compression if it saves at least 3 bytes (to account for overhead)
  // Note: Due to AES encryption padding to 16-byte blocks, compression may not
  // always reduce the final encrypted packet size, but it can still reduce CPU usage
  if (compressed_len > 0 && compressed_len < src_len - 2) {
    *out_ver = PAYLOAD_VER_2;  // Mark as compressed
    int savings = src_len - compressed_len;
    MESH_DEBUG_PRINTLN("Utils::compressIfBeneficial(): compressed %d -> %d bytes (saved %d bytes, %.1f%%)", 
                       src_len, compressed_len, savings, (savings * 100.0f) / src_len);
    return compressed_len;
  }
  
  // Compression not beneficial, copy original data
  if (compressed_len <= 0) {
    MESH_DEBUG_PRINTLN("Utils::compressIfBeneficial(): compression failed (returned %d), using original %d bytes", 
                       compressed_len, src_len);
  } else if (compressed_len >= src_len - 2) {
    MESH_DEBUG_PRINTLN("Utils::compressIfBeneficial(): compression not beneficial (%d -> %d bytes, savings too small), using original", 
                       src_len, compressed_len);
  }
  
  if (dest != src) {
    memcpy(dest, src, src_len);
  }
  *out_ver = PAYLOAD_VER_1;  // Mark as uncompressed
  return src_len;
}

/**
 * @brief  Decompresses data if it was compressed, based on payload version flag.
 * 
 * This function checks the payload_ver flag to determine if the data is compressed.
 * If PAYLOAD_VER_2, it decompresses using unishox2. If PAYLOAD_VER_1 or any other
 * version, it simply copies the data. If decompression fails, it falls back to
 * copying the raw data and logs a debug message.
 * 
 * @param dest         Output buffer for decompressed (or copied) data. Must be large
 *                     enough to hold the decompressed output (typically MAX_PACKET_PAYLOAD).
 * @param src          Input data (compressed or uncompressed).
 * @param src_len      Length of input data in bytes.
 * @param payload_ver  Version flag indicating compression state (PAYLOAD_VER_1 = uncompressed,
 *                     PAYLOAD_VER_2 = compressed with unishox2).
 * @returns            Length of data written to dest (decompressed size or original size).
 * 
 * @note If decompression fails (returns <= 0), the function gracefully falls back to
 *       copying the raw data and returns the original length.
 * @note The function handles the case where dest == src (in-place copy when needed).
 */
int Utils::decompressIfNeeded(uint8_t* dest, const uint8_t* src, int src_len, uint8_t payload_ver) {
  if (payload_ver == PAYLOAD_VER_2) {
    // Data is compressed, decompress it using optimized preset
    // USX_PSET_DFLT must match the preset used during compression
    int decompressed_len = unishox2_decompress((const char*)src, src_len, 
                                               (char*)dest, MAX_PACKET_PAYLOAD,
                                               USX_PSET_DFLT);
    
    if (decompressed_len > 0) {
      MESH_DEBUG_PRINTLN("Utils::decompressIfNeeded(): decompressed %d -> %d bytes (expanded %.1f%%)", 
                         src_len, decompressed_len, ((decompressed_len - src_len) * 100.0f) / src_len);
      return decompressed_len;
    }
    
    // Decompression failed, fall back to copying raw data
    MESH_DEBUG_PRINTLN("Utils::decompressIfNeeded(): decompression failed, using raw data");
    if (dest != src) {
      memcpy(dest, src, src_len);
    }
    return src_len;
  }
  
  // Not compressed (PAYLOAD_VER_1 or other), just copy if needed
  if (dest != src) {
    memcpy(dest, src, src_len);
  }
  return src_len;
}

/**
 * @brief  Compresses a payload with a fixed-size binary header, considering AES encryption padding.
 * 
 * This function is designed for payloads that have a fixed binary header (e.g., timestamp + type)
 * followed by text data. It only compresses the text portion, leaving the header uncompressed,
 * because binary data doesn't compress well with unishox2.
 * 
 * IMPORTANT: Due to AES encryption padding to 16-byte blocks, this function only uses compression
 * if it will actually save RF bytes. For example:
 * - 21 bytes -> 17 bytes compressed: Both encrypt to 32 bytes (NO savings, won't compress)
 * - 39 bytes -> 28 bytes compressed: Encrypts 48 -> 32 bytes (saves 16 bytes, will compress)
 * 
 * @param dest           Output buffer (header + compressed text, or original data)
 * @param src            Input data (header + text)
 * @param src_len        Total length of input
 * @param header_size    Size of binary header to skip (e.g., 5 bytes for timestamp+type)
 * @param out_ver        (OUT) Set to PAYLOAD_VER_2 if compressed, PAYLOAD_VER_1 if not
 * @param debug_label    Label for debug output (e.g., "GRP" or "TXT_MSG")
 * @returns              Length of data in dest
 */
int Utils::compressPayloadWithHeader(uint8_t* dest, const uint8_t* src, int src_len, 
                                     int header_size, uint8_t* out_ver, const char* debug_label) {
  *out_ver = PAYLOAD_VER_1;  // default: uncompressed
  
  // If there's no text after the header, just copy everything
  if (src_len <= header_size) {
    if (dest != src) {
      memcpy(dest, src, src_len);
    }
    return src_len;
  }
  
  // Copy header unchanged
  if (dest != src) {
    memcpy(dest, src, header_size);
  }
  
  // Try to compress only the text portion
  uint8_t comp_ver = PAYLOAD_VER_1;
  int text_len = src_len - header_size;
  int compressed_text_len = compressIfBeneficial(
    dest + header_size,     // destination: after header
    src + header_size,      // source: text only
    text_len,               // length: text only
    &comp_ver
  );
  
  // Check if compression was attempted
  if (comp_ver == PAYLOAD_VER_2) {
    // Calculate encrypted sizes (AES padding to 16-byte blocks)
    int original_encrypted_size = ((src_len + 15) / 16) * 16;
    int compressed_total = header_size + compressed_text_len;
    int compressed_encrypted_size = ((compressed_total + 15) / 16) * 16;
    
    // Only use compression if it actually saves RF bytes after encryption
    if (compressed_encrypted_size < original_encrypted_size) {
      *out_ver = PAYLOAD_VER_2;
      MESH_DEBUG_PRINTLN("%s: compression saves RF bytes: %d -> %d encrypted (-%d bytes)", 
                        debug_label, original_encrypted_size, compressed_encrypted_size, 
                        original_encrypted_size - compressed_encrypted_size);
      return compressed_total;
    } else {
      // Compression doesn't save RF bytes, restore original text
      MESH_DEBUG_PRINTLN("%s: compression doesn't save RF bytes due to AES padding: %d -> %d encrypted (same)", 
                        debug_label, original_encrypted_size, compressed_encrypted_size);
      if (dest != src) {
        memcpy(dest + header_size, src + header_size, text_len);
      }
      return src_len;
    }
  }
  
  // Compression wasn't beneficial at text level, use original
  return src_len;
}

/**
 * @brief  Decompresses a payload with a fixed-size binary header if needed.
 * 
 * This function handles decompression of payloads that have a binary header followed by
 * (possibly compressed) text. It handles the case where AES padding (0x00 bytes) may be
 * present after the compressed data due to block cipher encryption.
 * 
 * The function scans for the first 0x00 byte after the header to determine the actual
 * length of compressed data. This works because unishox2 compressed output never contains
 * null bytes (0x00), so the first null is always AES padding.
 * 
 * @param dest           Output buffer for decompressed data
 * @param src            Input data (header + compressed/uncompressed text + possibly padding)
 * @param src_len        Length of input data
 * @param header_size    Size of binary header to skip
 * @param payload_ver    PAYLOAD_VER_1 (uncompressed) or PAYLOAD_VER_2 (compressed)
 * @param debug_label    Label for debug output (e.g., "GRP" or "TXT_MSG")
 * @returns              Length of data in dest, or -1 on error
 */
int Utils::decompressPayloadWithHeader(uint8_t* dest, const uint8_t* src, int src_len,
                                       int header_size, uint8_t payload_ver, const char* debug_label) {
  // Check minimum size
  if (src_len < header_size) {
    MESH_DEBUG_PRINTLN("%s: decompression error - payload too short (%d < %d)", 
                      debug_label, src_len, header_size);
    return -1;
  }
  
  // Copy header unchanged
  memcpy(dest, src, header_size);
  
  int text_len = src_len - header_size;
  
  // If compressed, we need to find the actual compressed data length
  // by scanning for the first 0x00 byte (AES padding)
  if (payload_ver == PAYLOAD_VER_2) {
    // Scan for first 0x00 byte to find actual compressed length
    int actual_compressed_len = text_len;
    for (int i = 0; i < text_len; i++) {
      if (src[header_size + i] == 0x00) {
        actual_compressed_len = i;
        break;
      }
    }
    
    if (actual_compressed_len < text_len) {
      MESH_DEBUG_PRINTLN("%s: found AES padding at offset %d (total %d, compressed %d)", 
                        debug_label, header_size + actual_compressed_len, text_len, actual_compressed_len);
    }
    
    // Decompress only the actual compressed data (not the padding)
    int decompressed_len = decompressIfNeeded(
      dest + header_size,
      src + header_size,
      actual_compressed_len,
      payload_ver
    );
    
    return header_size + decompressed_len;
  } else {
    // Not compressed, just copy
    memcpy(dest + header_size, src + header_size, text_len);
    return src_len;
  }
}

}