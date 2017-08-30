#include <string>
#include <exception>

#include "LNCFMessage.h"

LNCFMessage::LNCFMessage(unsigned char* data, size_t length)
{
	if (length > 0) {
		_message = new unsigned char[length];
		memcpy(_message, data, length);
	}
	else {
		throw std::logic_error("Message cannot be empty");
	}
}

LNCFMessage::~LNCFMessage()
{
}
