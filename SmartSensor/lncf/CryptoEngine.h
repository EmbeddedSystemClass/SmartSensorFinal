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

namespace lncf {
	class CryptoEngine
	{
	public:
		//Keys management
		static std::string RegisterKey(unsigned char* key, std::size_t keyLength);
		static std::string GenerateKey();
		static void UnregisterKey(std::string& keyFingerprint);
		static void ListKeys();

		//Encryption
		static std::tuple<byte*, size_t> Encrypt(byte* message, size_t message_size, std::string& keyFingerprint, unsigned char* iv);

		//Decryption
		static std::tuple<byte*, size_t> Decrypt(byte* message, size_t message_size, std::string& keyFingerprint, byte* iv);

		//Hash
		static int32_t CRC32(byte* message, size_t message_size);
		static std::tuple<byte*, size_t> SHA1(byte* message, size_t message_size);
		static std::tuple<byte*, size_t> SHA256(byte* message, size_t message_size);

		//Auth
		static std::tuple<byte*, size_t> HMAC256(std::string& keyFingerprint, byte* message, size_t message_size);

		//Base64
		static std::tuple<byte*,size_t> Base64Encrypt(byte* message, size_t message_size);
		static std::tuple<byte*, size_t> Base64Decrypt(byte* message, size_t message_size);

	private:
		static std::unordered_map<std::string, CryptoPP::SecByteBlock> _keys;

		static std::string GenerateKeyFingerprint(CryptoPP::SecByteBlock key);
	};
}



#endif

