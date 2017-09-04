#ifndef _LNCF_H_
#define _LNCF_H_

#include <unordered_map>
#include <queue>
#include <condition_variable>

#include <boost/asio.hpp>
#include <boost/bind.hpp>

#include "LNCFHandler.h"
#include "LNCFMessage.h"

#define MAX_LENGTH 65507

namespace lncf {
	class LNCF
	{
	public:
		LNCF(boost::asio::io_service* service);
		~LNCF();

		void Init(boost::asio::ip::address listen_address, boost::asio::ip::address group_address, int lncf_port = 6666);
		void ListenAndServe();
		void Stop();

		void SendClearMessage(std::string& topic, std::string& message);
		void SendEncryptedMessage(std::string& topic, std::string& message, std::string& key_fingerprint);
		void SendDiscoveryRequest(std::string& request);

		void RegisterService();

		void Handle(std::string topic, LNCFHandler* handler);
		void RemoveHandler(std::string topic, LNCFHandler* handler);

		std::string RegisterEncryptionKey(unsigned char* key);
		std::string GenerateEncryptionKey();
		void RemoveEncryptionKey(std::string& keyFingerprint);
	private:
		std::unordered_map<std::string, std::vector<LNCFHandler*>*> _handlers;
		boost::asio::io_service* _service;

		boost::asio::ip::address _send_addr;
		boost::asio::ip::udp::endpoint* _sender_endpoint;
		boost::asio::ip::address _listen_addr;
		boost::asio::ip::udp::endpoint* _listener_endpoint;

		boost::asio::ip::udp::socket* _socket;

		char _data[MAX_LENGTH];

		std::queue<LNCFMessage*> _messagesQueue;
		std::mutex _queueMutex;
		std::condition_variable _messageAvaiable;

		

		void handle_receive_from(boost::system::error_code error, size_t bytes_recvd);

		void parse_lncf_v1(size_t packet_size);

		void handle_message_v1(unsigned char* packet, size_t packet_length);

		void listen();
	};
}

#endif




