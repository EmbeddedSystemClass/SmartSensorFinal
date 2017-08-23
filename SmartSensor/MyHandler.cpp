#include <iostream>

#include "MyHandler.h"

MyHandler::MyHandler() : numberReceived(0)
{
}


MyHandler::~MyHandler()
{
}

void MyHandler::Handle(std::string topic, std::string message)
{
	//std::cout << topic << ":" << message << std::endl;
	numberReceived++;
}
