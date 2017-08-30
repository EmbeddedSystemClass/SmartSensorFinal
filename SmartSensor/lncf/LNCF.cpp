#include <cstring>

#include <boost/asio.hpp>
#include <boost/bind.hpp>

#include "CryptoEngine.h"

#include "LNCF.h"

namespace lncf {
	LNCF::LNCF(boost::asio::io_service* service)
	{
		_service = service;
	}

	LNCF::~LNCF()
	{
		if (_sender_endpoint != nullptr) {
			delete _sender_endpoint;
		}
		
		if (_listener_endpoint != nullptr) {
			delete _listener_endpoint;
		}
		
		if (_socket != nullptr) {
			delete _socket;
		}

		//Clear the handlers list
		for (std::pair<std::string,std::vector<LNCFHandler*>*> keyPair : _handlers) {
			if (keyPair.second != nullptr) {
				delete keyPair.second;
			}
			_handlers.erase(keyPair.first);
		}
	}

	void LNCF::Init(boost::asio::ip::address listen_address, boost::asio::ip::address group_address, int lncf_port /*= 6666*/)
	{
		//Addresses and endpoints
		_send_addr = group_address;
		_listen_addr = listen_address;
		_sender_endpoint = new boost::asio::ip::udp::endpoint(_send_addr, lncf_port);
		_listener_endpoint = new boost::asio::ip::udp::endpoint(_listen_addr, lncf_port);

		//Socket
		_socket = new boost::asio::ip::udp::socket(*_service);
	}

	void LNCF::ListenAndServe()
	{
		//Configure ASIO socket in order to listen and serve
		_socket->open(_listener_endpoint->protocol());
		_socket->set_option(boost::asio::ip::udp::socket::reuse_address(true));
		_socket->bind(*_listener_endpoint);
		// Join the multi cast group.
		_socket->set_option(boost::asio::ip::multicast::join_group(_send_addr));
		//Start the async receive
		_socket->async_receive_from(boost::asio::buffer(_data, MAX_LENGTH), *_sender_endpoint, boost::bind(&LNCF::handle_receive_from, this, boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));

	}

	void LNCF::Stop()
	{
		_socket->shutdown(boost::asio::ip::udp::socket::shutdown_both);
		_socket->close();
	}

	void LNCF::SendClearMessage(std::string& topic, std::string& message)
	{
		if (topic.length() > 255) {
			throw std::exception(std::string("Topic is too long"));
		}
		//9 bytes is the minimum size of a packet without data
		if (topic.length() + message.length() + 8 > MAX_LENGTH) {
			throw std::exception(std::string("Data is too long"));
		}

		long packet_length = topic.length() + message.length() + 8;
		unsigned char* packet = new unsigned char[packet_length];
		packet[0] = 0;
		packet[1] = (topic.length() & 0x000000FF);

		memcpy_s((void*)(packet + 2), packet_length, topic.c_str(), topic.length());

		packet[2 + topic.length()] = (message.length() & 0x0000FF00) >> 8;
		packet[2 + topic.length() + 1] = message.length() & 0x000000FF;

		memcpy_s((void*)(packet + 2 + topic.length() + 2), packet_length, message.c_str(), message.length());

		int32_t crc32 = CryptoEngine::Instance()->CRC32((byte*)packet, 2 + topic.length() + 2 + message.length());
		packet[2 + topic.length() + 1 + message.length() + 1] = (crc32 & 0xFF000000) >> 24;
		packet[2 + topic.length() + 1 + message.length() + 2] = (crc32 & 0x00FF0000) >> 16;
		packet[2 + topic.length() + 1 + message.length() + 3] = (crc32 & 0x0000FF00) >> 8;
		packet[2 + topic.length() + 1 + message.length() + 4] = (crc32 & 0x000000FF);

		size_t bytes_send = _socket->send_to(boost::asio::buffer(packet, packet_length), *_sender_endpoint);

		delete[] packet;
	}

	void LNCF::SendEncryptedMessage(std::string& topic, std::string& message, std::string& key_fingerprint)
	{
		if (topic.length() > 255) {
			throw std::exception(std::string("Topic is too long"));
		}
		//9 bytes is the minimum size of a packet without data
		if (topic.length() + message.length() + 8 > MAX_LENGTH) {
			throw std::exception(std::string("Data is too long"));
		}

		long dataLength = topic.length() + message.length() + 4;
		unsigned char* dataToEncrypt = new unsigned char[dataLength];
		dataToEncrypt[0] = (topic.length() & 0x000000FF);
		memcpy_s((void*)(dataToEncrypt + 2), dataLength, topic.data(), topic.length());
		dataToEncrypt[1 + topic.length()] = (message.length() & 0x0000FF00) >> 8;
		dataToEncrypt[1 + topic.length() + 1] = message.length() & 0x000000FF;
		memcpy_s((void*)(dataToEncrypt + 2 + topic.length() + 2), dataLength, message.data(), message.length());

		bool success;
		byte* encryptedPacket;
		size_t encryptedLength;
		std::tie(success,encryptedPacket,encryptedLength) = CryptoEngine::Instance()->LNCFEncrypt(dataToEncrypt, dataLength, key_fingerprint);

		if (success) {
			long packet_length = encryptedLength + 7;
			unsigned char* packet = new unsigned char[packet_length];
			packet[0] = 0b00000010;
			packet[1] = (encryptedLength & 0x0000FF00) >> 8;
			packet[2] = encryptedLength & 0x000000FF;

			memcpy_s((void*)(packet + 2), packet_length, encryptedPacket, encryptedLength);

			int32_t crc32 = CryptoEngine::Instance()->CRC32((byte*)packet, packet_length - 4);
			packet[2 + encryptedLength] = (crc32 & 0xFF000000) >> 24;
			packet[2 + encryptedLength + 1] = (crc32 & 0x00FF0000) >> 16;
			packet[2 + encryptedLength + 2] = (crc32 & 0x0000FF00) >> 8;
			packet[2 + encryptedLength + 3] = (crc32 & 0x000000FF);

			size_t bytes_send = _socket->send_to(boost::asio::buffer(packet, packet_length), *_sender_endpoint);

			delete[] packet;

		}

		delete[] dataToEncrypt;
		delete encryptedPacket;
	}

	void LNCF::SendDiscoveryRequest(std::string& request)
	{

	}

	void LNCF::RegisterService()
	{

	}

	void LNCF::Handle(std::string topic, LNCFHandler* handler)
	{
		if (_handlers.find(topic) == _handlers.end()) {
			_handlers[topic] = new std::vector<LNCFHandler*>();
		}

		_handlers[topic]->push_back(handler);
	}

	void LNCF::RemoveHandler(std::string topic, LNCFHandler* handler)
	{
		if (_handlers.find(topic) != _handlers.end()) {
			_handlers[topic]->erase(std::remove(_handlers[topic]->begin(), _handlers[topic]->end(), handler), _handlers[topic]->end());
		}
	}

	std::string LNCF::RegisterEncryptionKey(unsigned char* key)
	{
		return CryptoEngine::Instance()->RegisterKey(key, KEY_LENGTH);
	}

	std::string LNCF::GenerateEncryptionKey()
	{
		return CryptoEngine::Instance()->GenerateKey();
	}

	void LNCF::RemoveEncryptionKey(std::string& keyFingerprint)
	{
		CryptoEngine::Instance()->UnregisterKey(keyFingerprint);
	}

	void LNCF::handle_receive_from(boost::system::error_code error, size_t bytes_recvd)
	{
		//Minimum packet size is 9 bytes (1 for options + 1 for topic length + 1 for minimum topic + 2 for data length + 4 for CRC)
		if (bytes_recvd < 9) {
			return;
		}

		//Check CRC32
		int32_t crc = CryptoEngine::Instance()->CRC32((byte*)_data, bytes_recvd - 4);
		int32_t receivedCRC = (((int)_data[bytes_recvd - 4]) & 0x000000FF) << 24 | 
							  (((int)_data[bytes_recvd - 3]) & 0x000000FF) << 16 | 
							  (((int)_data[bytes_recvd - 2]) & 0x000000FF) << 8 |
							  (((int)_data[bytes_recvd - 1]) & 0x000000FF);

		if (crc != receivedCRC) {
			return;
		}

		//Parse packet
		switch ((_data[0] >> 5))
		{
		case 0:
			parse_lncf_v1(bytes_recvd);
		default:
			break;
		}
		_socket->async_receive_from(boost::asio::buffer(_data, MAX_LENGTH), *_sender_endpoint, boost::bind(&LNCF::handle_receive_from, this, boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));
	}

	void LNCF::parse_lncf_v1(size_t packet_size)
	{
		if ((_data[0] & 0b00000010) == 2) {
			//Encrypted message
			int16_t data_length = (((int16_t)_data[1]) & 0x00FF) << 8 | (((int16_t)_data[2]) & 0x00FF);
			byte* packet;
			size_t packetLength;
			bool isOK = false;

			std::tie(isOK, packet,packetLength) = CryptoEngine::Instance()->LNCFDecrypt((byte*)_data + 3, data_length);

			if (isOK) {
				handle_message_v1(packet, packetLength);
				delete[] packet;
			}

		}
		else if ((_data[0] & 0b00000001) == 1) {
			//Discovery message
		}
		else if ((_data[0] & 0b00011111) == 0) {
			//Data message
			handle_message_v1((unsigned char*)_data, packet_size);
		}
	}

	void LNCF::handle_message_v1(unsigned char* packet, size_t packet_length)
	{
		int16_t topic_length = packet[1];
		std::string topic((char*)packet + 2, (size_t)topic_length);
		int data_length = (((int16_t)packet[2 + topic_length]) & 0x00FF) << 8 | (((int16_t)packet[2 + topic_length + 1]) & 0x00FF);
		std::string data((char*)packet + 2 + topic_length + 2, data_length);
		std::unordered_map<std::string, std::vector<LNCFHandler*>*>::const_iterator h = _handlers.find(topic);
		if (h != _handlers.end()) {
			for (LNCFHandler* handler : *h->second) {
				if (handler == nullptr) {
					continue;
				}
				handler->Handle(topic, data);
			}
		}
	}
}

