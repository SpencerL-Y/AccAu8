#ifndef Server_h
#define Server_h
#include <iostream>
#include <string>
#include <vector>
#include <stdlib.h>
#include <thread>
#include <stdlib.h>
#include <sstream>
#include <stdio.h>
#include <thread>
#include <stdlib.h>
#include <typeinfo>
#include <ibe.h>
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/serialization/map.hpp>
#include <boost/serialization/string.hpp>
#include "../CommLib/NetComm/include/EtherReceiver.hpp"
#include "../CommLib/NetComm/include/EtherSender.hpp"
#include "../CommLib/NetComm/include/UDPSender.hpp"
#include "../CommLib/NetComm/include/UDPReceiver.hpp"
#include "../CryptoLib/include/Cryptor.hpp"
#include "./MQ.h"
#define STATE___init 0
#define STATE___final 1
#define STATE__reqRecved 2
#define STATE__queCreated 3
#define STATE__verifyReqFailed 4
#define STATE__queSent 5
#define STATE__queRespRecved 6
#define STATE__authRespCreated 7
#define STATE__verifyQueRespFailed 8

std::string SELF_IP_STR;
std::string GATEWAY_IP_STR;

class Server {
	private:
		AcAuthReq_G2S acAuthReq_g2s;
		AuthQu authQu;
		AuthQuAck authQuAck;
		AcAuthAns acAuthAns;
		int clientId_int;
		int serverId_int;

		bool breakListen;

		ushort SELF_PORT;
		ushort GATEWAY_PORT;

		
	public: 
		int __currentState;
		ConcurrentQueue cq;

		unsigned char master_privkey[IBE_MASTER_PRIVKEY_LEN];
		unsigned char master_pubkey[IBE_MASTER_PUBKEY_LEN];
		unsigned char usr_privkey[IBE_USR_PRIVKEY_LEN];
		Server(ushort self_port, ushort gate_port);
		~Server();
		void Sign(unsigned char* msg, unsigned char* sig, size_t msglen);
		bool Verify(unsigned char* msg, unsigned char* sig, size_t msglen, int verify_id);
		int receive();
		int send(u_char* data_, int length_);
		void SMLMainServer();
		void initConfig();
};

void initOverallConfig(){
	SELF_IP_STR = "127.0.0.1";
	GATEWAY_IP_STR = "127.0.0.1";
	
}

int Id2Int(ip_address ip){
	int result;
	memcpy(&result, &ip, sizeof(int));
	int tempResult = ntohl(result);
	return tempResult;
}

void recv_thd(Server* server){
	server->receive();
}

void handle_thd(Server* server){
	server->SMLMainServer();
}

void run(Server* server){
	std::thread recv_t(&recv_thd, server);
	std::thread handle_t(&handle_thd, server);

	recv_t.join();
	handle_t.join();
}

//static int __currentState = STATE___init;
int main(int argc, char** argv) {
	initOverallConfig();
	ushort self_prefix = 6000;
	ushort gate_prefix = 8000;
	Server* server[6];
	for(int i = 0; i < 1; i ++){
		server[i] = new Server(self_prefix + i, gate_prefix + i);
	}
	for(int i = 0; i < 1; i++){
		run(server[i]);
	}	
}

#endif

