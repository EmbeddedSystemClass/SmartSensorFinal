#ifndef _ENCRYPTION_ENGINE_H_
#define _ENCRYPTION_ENGINE_H_

#include <iostream>
#include <unordered_map>
#include <memory>

#include <cryptopp/hex.h>
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include <cryptopp/cryptlib.h>
using CryptoPP::BufferedTransformation;
using CryptoPP::AuthenticatedSymmetricCipher;

#include <cryptopp/filters.h>
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::AuthenticatedDecryptionFilter;

#include <cryptopp/aes.h>
using CryptoPP::AES;

#include <cryptopp/gcm.h>
using CryptoPP::GCM;
using CryptoPP::GCM_TablesOption;

#include <cryptopp/osrng.h>
#include <cryptopp/base64.h>

#define KEY_FINGERPRINT_SIZE 44
#define MSG_KEY_SIZE 20

#define KEY_LENGTH 128/8

namespace lncf {
	class CryptoEngine
	{
	public:
		//Keys management
		static std::string RegisterKey(unsigned char* key, std::size_t keyLength);
		static std::string GenerateKey();
		static void UnregisterKey(std::string& keyFingerprint);
		static void ListKeys();

		/** AESEncrypt
			Encrypt a message using AES128 CBC.

			@param message byte* the message as CBC is used, the message have to be a multiple of AES BlockSize (16 bytes)
			@param message_size size_t the size of the message
			@param keyFingerprint std::string& the key fingerprint that will be used to retrieve the encryption key
			@param iv byte* the IV for this encryption
			@return std::tuple<byte*,size_t> base64 a tuple containing first the encrypted message and second its size
		*/
		static std::tuple<byte*, size_t> AESEncrypt(byte* message, size_t message_size, std::string& keyFingerprint, unsigned char* iv);
		static std::tuple<std::string, std::string> LNCFEncrypt(byte* packet, size_t packet_size);

		/** AESDecrypt
			Decrypt a message using AES128 CBC

			@param message byte* the message
			@param message_size size_t the size of the message
			@param keyFingerprint std::string& the key fingerprint that will be used to retrieve the encryption key
			@param iv byte* the IV for this encryption
			@return std::tuple<byte*,size_t> base64 a tuple containing first the clear message and second its size
		*/
		static std::tuple<byte*, size_t> AESDecrypt(byte* message, size_t message_size, std::string& keyFingerprint, byte* iv);
		static std::tuple<bool, byte*, size_t> LNCFDecrypt(byte* packet, size_t packet_size);

		/** CRC32
			Compute the CRC32 of a message

			@param message byte* the message
			@param message_size size_t the size of the message
			@return int32_t crc32
		*/
		static int32_t CRC32(byte* message, size_t message_size);

		/** SHA1
			Compute the SHA1 of a message

			@param message byte* the message
			@param message_size size_t the size of the message
			@return byte* sha1 (size 20 bytes)
		*/
		static byte* SHA1(byte* message, size_t message_size);

		/** SHA256
			Compute the SHA256 of a message

			@param message byte* the message
			@param message_size size_t the size of the message
			@return byte* sha256 (size 32 bytes)
		*/
		static byte* SHA256(byte* message, size_t message_size);

		/** HMAC256
			Compute the HMAC of a message

			@param keyFingerprint std::string& the key fingerprint that will be used to retrieve the encryption key
			@param message byte* the message
			@param message_size size_t the size of the message
			@return byte* hmac
		*/
		static byte* HMAC256(std::string& keyFingerprint, byte* message, size_t message_size);

		/** VerifyHMAC256
			Verify the HMAC on the message

			@param keyFingerprint std::string& the key fingerprint that will be used to retrieve the encryption key
			@param message byte* the message containing the HMAC at the end
			@param message_size size_t the size of the message
			@return boolean result
		*/
		static bool VerifyHMAC256(std::string& keyFingerprint, byte* message, size_t message_size);

		/** Base64Encrypt
			Encrypt a message in base64

			@param message byte* the message
			@param message_size size_t the size of the message
			@return std::tuple<byte*,size_t> base64 a tuple containing first the base64 and second its size
		*/
		static std::tuple<byte*,size_t> Base64Encrypt(byte* message, size_t message_size);

		/** Base64Decrypt
			Decrypt a message in base64

			@param message byte* the message
			@param message_size size_t the size of the message
			@return std::tuple<byte*,size_t> clearMsg a tuple containing first the message in clear and second its size
		*/
		static std::tuple<byte*, size_t> Base64Decrypt(byte* message, size_t message_size);

	private:
		static std::unordered_map<std::string, CryptoPP::SecByteBlock> _keys;

		static std::string GenerateKeyFingerprint(CryptoPP::SecByteBlock key);
		static std::tuple<byte*, byte*> LNCF_KDF(byte* messageKey, size_t messageKeySize, std::string& keyFingerprint);
	};
}



#endif

