#ifndef _LNCF_MESSAGE_H_
#define _LNCF_MESSAGE_H_

class LNCFMessage
{
public:
	LNCFMessage(unsigned char* data, size_t length);
	~LNCFMessage();

private:
	unsigned char* _message;
};

#endif


