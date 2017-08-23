#include <cryptopp/crc.h>
#include <cryptopp/hmac.h>

#include "CryptoEngine.h"

namespace lncf {

	std::unordered_map<std::string, CryptoPP::SecByteBlock> CryptoEngine::_keys;

	std::string CryptoEngine::GenerateKeyFingerprint(CryptoPP::SecByteBlock key)
	{
		//Generate key fingerprint
		//SHA256
		byte digest[CryptoPP::SHA256::DIGESTSIZE];
		CryptoPP::SHA256().CalculateDigest(digest, key, key.size());

		//Base64 encoding
		std::string encoded;
		CryptoPP::Base64Encoder encoder;
		encoder.Put(digest, CryptoPP::SHA256::DIGESTSIZE);
		encoder.MessageEnd();
		CryptoPP::word64 size = encoder.MaxRetrievable();
		//Base64 conversion
		if (size)
		{
			encoded.resize((unsigned int)size);
			encoder.Get((byte*)encoded.data(), encoded.size());
		}

		return encoded;
	}

	std::string CryptoEngine::RegisterKey(unsigned char* key, std::size_t keyLength)
	{
		CryptoPP::SecByteBlock secKey(key, keyLength);

		std::string encoded = GenerateKeyFingerprint(secKey);

		//Storage
		_keys[encoded] = secKey;

		return encoded;
	}

	std::string CryptoEngine::GenerateKey()
	{
		//Generate key
		CryptoPP::AutoSeededRandomPool rnd;
		CryptoPP::SecByteBlock key(0x00, AES::DEFAULT_KEYLENGTH);
		rnd.GenerateBlock(key, key.size());

		std::string encoded = GenerateKeyFingerprint(key);

		//Storage
		_keys[encoded] = key;

		return encoded;
	}

	void CryptoEngine::UnregisterKey(std::string& keyFingerprint)
	{
		if (_keys.find(keyFingerprint) != _keys.end()) {
			_keys.erase(keyFingerprint);
		}
	}

	void CryptoEngine::ListKeys()
	{
		std::cout << "List of all registered keys" << std::endl;
		for (auto it = _keys.begin(); it != _keys.end(); ++it)
		{
			std::cout << "\t" << it->first << std::endl;
		}
	}

	std::tuple<byte*, size_t> CryptoEngine::Encrypt(byte* message, size_t message_size, std::string& keyFingerprint, unsigned char* iv)
	{
		if (_keys.find(keyFingerprint) == _keys.end()) {
			throw std::exception("Key unknown");
		}

		if (message_size % AES::BLOCKSIZE != 0) {
			throw std::exception("Invalid message length");
		}

		byte* output = new byte[message_size];
		CryptoPP::CBC_Mode<AES>::Encryption cbcEncryption(_keys[keyFingerprint], _keys[keyFingerprint].size(), iv);
		cbcEncryption.ProcessData(output, message, message_size);

		return std::make_tuple(output, message_size);
	}

	std::tuple<byte*, size_t> CryptoEngine::Decrypt(byte* message, size_t message_size, std::string& keyFingerprint, byte* iv)
	{
		if (_keys.find(keyFingerprint) == _keys.end()) {
			throw std::exception("Key unknown");
		}

		byte* output = new byte[message_size];
		CryptoPP::CBC_Mode<AES>::Decryption cbcDecryption(_keys[keyFingerprint], _keys[keyFingerprint].size(), iv);
		cbcDecryption.ProcessData(output, message, message_size);

		return std::make_tuple(output,message_size);
	}

	int32_t CryptoEngine::CRC32(byte* message, size_t message_size)
	{
		int32_t crc32_hash;
		CryptoPP::CRC32().CalculateDigest((byte*)&crc32_hash, message, message_size);
		return crc32_hash;
	}

	std::tuple<byte*, size_t> CryptoEngine::SHA1(byte* message, size_t message_size)
	{
		byte* output = new byte[CryptoPP::SHA1::DIGESTSIZE];
		CryptoPP::SHA1().CalculateDigest(output, message, message_size);
		return std::make_tuple(output, CryptoPP::SHA1::DIGESTSIZE);
	}

	std::tuple<byte*, size_t> CryptoEngine::SHA256(byte* message, size_t message_size)
	{
		byte* output = new byte[CryptoPP::SHA256::DIGESTSIZE];
		CryptoPP::SHA256().CalculateDigest(output, message, message_size);
		return std::make_tuple(output, CryptoPP::SHA256::DIGESTSIZE);
	}

	std::tuple<byte*, size_t> CryptoEngine::HMAC256(std::string& keyFingerprint, byte* message, size_t message_size)
	{
		if (_keys.find(keyFingerprint) == _keys.end()) {
			throw std::exception("Key unknown");
		}
		byte* output = new byte[CryptoPP::SHA256::DIGESTSIZE];
		CryptoPP::HMAC<CryptoPP::SHA256> hmac(_keys[keyFingerprint], _keys[keyFingerprint].size());
		hmac.CalculateDigest(output, message, message_size);
		return std::make_tuple(output, CryptoPP::SHA256::DIGESTSIZE);
	}

	std::tuple<byte*, size_t> CryptoEngine::Base64Encrypt(byte* message, size_t message_size)
	{
		CryptoPP::Base64Encoder encoder;
		encoder.Put(message,message_size);
		encoder.MessageEnd();
		
		CryptoPP::lword size = encoder.MaxRetrievable();
		if (size)
		{
			byte* output = new byte[size];
			encoder.Get(output, size);
			return std::make_tuple(output, size);
		}
		return std::make_tuple(nullptr, -1);
	}

	std::tuple<byte*, size_t> CryptoEngine::Base64Decrypt(byte* message, size_t message_size)
	{
		CryptoPP::Base64Decoder decoder;
		decoder.Put(message, message_size);
		decoder.MessageEnd();
		
		CryptoPP::word64 size = decoder.MaxRetrievable();
		if (size)
		{
			byte* output = new byte[size];
			decoder.Get(output, size);
			return std::make_tuple(output, size);
		}
		return std::make_tuple(nullptr,-1);
	}

}