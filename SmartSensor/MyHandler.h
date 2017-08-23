#pragma once
#include "lncf\LNCFHandler.h"

class MyHandler : public lncf::LNCFHandler
{
public:
	MyHandler();
	~MyHandler();

	virtual void Handle(std::string topic, std::string message) override;
	unsigned long numberReceived;

};

