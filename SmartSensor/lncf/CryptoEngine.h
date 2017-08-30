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

		static CryptoEngine* Instance();

		//Keys management
		std::string RegisterKey(unsigned char* key, std::size_t keyLength);
		std::string GenerateKey();
		void UnregisterKey(std::string& keyFingerprint);
		void ListKeys();

		/** AESEncrypt
			Encrypt a message using AES128 CBC.

			@param message byte* the message as CBC is used, the message have to be a multiple of AES BlockSize (16 bytes)
			@param message_size size_t the size of the message
			@param keyFingerprint std::string& the key fingerprint that will be used to retrieve the encryption key
			@param iv byte* the IV for this encryption
			@return std::tuple<byte*,size_t> base64 a tuple containing first the encrypted message and second its size
		*/
		std::tuple<byte*, size_t> AESEncrypt(byte* message, size_t message_size, std::string& keyFingerprint, unsigned char* iv);

		/** AESEncrypt
		Encrypt a message using AES128 CBC.

		@param message byte* the message as CBC is used, the message have to be a multiple of AES BlockSize (16 bytes)
		@param message_size size_t the size of the message
		@param key byte* the bytes for the key used in the algorithm
		@param keyLength size_t the length (in bytes) of the key
		@param iv byte* the IV for this encryption
		@return std::tuple<byte*,size_t> base64 a tuple containing first the encrypted message and second its size
		*/
		std::tuple<byte*, size_t> AESEncrypt(byte* message, size_t message_size, byte* key, size_t keyLength, unsigned char* iv);

		/** LNCFEncrypt
		Encrypt a message using LNCF algorithm

		@param packet byte* the packet to decrypt (without LNCF header and CRC32)
		@param packet_size size_t the size of the packet
		@param keyFingerprint std::string& the key fingerprint that will be used to retrieve the encryption key
		@return std::tuple<bool, byte*, size_t> a tuple containing first a flag containing the failure or success of the encryption, second the packet encrypted and finally its size
		*/
		std::tuple<bool, byte*, size_t> LNCFEncrypt(byte* packet, size_t packet_size, std::string& keyFingerprint);

		/** AESDecrypt
			Decrypt a message using AES128 CBC

			@param message byte* the message
			@param message_size size_t the size of the message
			@param keyFingerprint std::string& the key fingerprint that will be used to retrieve the encryption key
			@param iv byte* the IV for this encryption
			@return std::tuple<byte*,size_t> base64 a tuple containing first the clear message and second its size
		*/
		std::tuple<byte*, size_t> AESDecrypt(byte* message, size_t message_size, std::string& keyFingerprint, byte* iv);

		/** LNCFDecrypt
		Decrypt a message using LNCF algorithm

		@param packet byte* the packet to decrypt (without LNCF header and CRC32)
		@param packet_size size_t the size of the packet
		@return std::tuple<bool, byte*, size_t> a tuple containing first a flag containing the failure or success of the decryption, second the packet uncrypted and finally its size
		*/
		std::tuple<bool, byte*, size_t> LNCFDecrypt(byte* packet, size_t packet_size);

		/** CRC32
			Compute the CRC32 of a message

			@param message byte* the message
			@param message_size size_t the size of the message
			@return int32_t crc32
		*/
		int32_t CRC32(byte* message, size_t message_size);

		/** SHA1
			Compute the SHA1 of a message

			@param message byte* the message
			@param message_size size_t the size of the message
			@return byte* sha1 (size 20 bytes)
		*/
		byte* SHA1(byte* message, size_t message_size);

		/** SHA256
			Compute the SHA256 of a message

			@param message byte* the message
			@param message_size size_t the size of the message
			@return byte* sha256 (size 32 bytes)
		*/
		byte* SHA256(byte* message, size_t message_size);

		/** HMAC256
			Compute the HMAC of a message

			@param keyFingerprint std::string& the key fingerprint that will be used to retrieve the encryption key
			@param message byte* the message
			@param message_size size_t the size of the message
			@return byte* hmac
		*/
		byte* HMAC_SHA1(std::string& keyFingerprint, byte* message, size_t message_size);

		/** VerifyHMAC256
			Verify the HMAC on the message

			@param keyFingerprint std::string& the key fingerprint that will be used to retrieve the encryption key
			@param message byte* the message containing the HMAC at the end
			@param message_size size_t the size of the message
			@return boolean result
		*/
		bool VerifyHMAC_SHA1(std::string& keyFingerprint, byte* message, size_t message_size);

		/** Base64Encrypt
			Encrypt a message in base64

			@param message byte* the message
			@param message_size size_t the size of the message
			@return std::tuple<byte*,size_t> base64 a tuple containing first the base64 and second its size
		*/
		std::tuple<byte*,size_t> Base64Encrypt(byte* message, size_t message_size);

		/** Base64Decrypt
			Decrypt a message in base64

			@param message byte* the message
			@param message_size size_t the size of the message
			@return std::tuple<byte*,size_t> clearMsg a tuple containing first the message in clear and second its size
		*/
		std::tuple<byte*, size_t> Base64Decrypt(byte* message, size_t message_size);

	private:
		CryptoEngine();

		static CryptoEngine* _me;
		std::unordered_map<std::string, CryptoPP::SecByteBlock> _keys;

		std::string GenerateKeyFingerprint(CryptoPP::SecByteBlock key);
		std::tuple<byte*, byte*> LNCF_KDF(byte* messageKey, size_t messageKeySize, std::string& keyFingerprint);
		CryptoPP::AutoSeededRandomPool _random;
		void Init();
	};
}

#endif

