#ifndef Gateway_h
#define Gateway_h
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
#include <time.h>
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
#include "../CommLib/NetComm/include/packet.hpp"
#include "./MQ.h"
#define STATE___init 0
#define STATE___final 1
#define STATE__reqMsgRecved 2
#define STATE__reqMsgSent 3
#define STATE__authQueRecved 4
#define STATE__authQueSent 5
#define STATE__queRespRecved 6
#define STATE__queRespSent 7
#define STATE__authRespRecved 8
#define MAX_CLIENT_NUM 6
std::string SELF_IP_STR = "127.0.0.1";
std::string SERVER_IP_STR = "127.0.0.1";
static pcap_t* devGateway;
std::map<int, int> clientIp2QIDMap;
std::map<int, ushort> clientIp2PortMap;
ConcurrentQueue cqs[MAX_CLIENT_NUM];

;class Gateway {
	
	private:
		int hostId;
		int gateway;
		int server;		
		GwAnce gwAnce;
		AcAuthReq_C2G acAuthReq_c2g;
		AcAuthReq_G2S acAuthReq_g2s;
		AuthQuAck authQuAck;
		AuthQu authQu;
		AcAuthAns acAuthAns;

		int clientId_int;
		int gatewayId_int;


	public: 
		int __currentState = STATE___init;
		ushort SELF_PORT;
		ushort SERVER_PORT;


        unsigned char master_privkey[IBE_MASTER_PRIVKEY_LEN];
        unsigned char master_pubkey[IBE_MASTER_PUBKEY_LEN];
        unsigned char usr_privkey[IBE_USR_PRIVKEY_LEN];

		Gateway(ushort self_port, ushort server_port);
		~Gateway();
		void Sign(unsigned char* msg, unsigned char* sig, size_t msglen);
		bool Verify(unsigned char* msg, unsigned char* sig, size_t msglen, int verify_id);
		int sendToHost(u_char* data_, int length_, u_char dmac[6]);
		int recvFromServer();
		int sendToServer();
		void SMLMainGateway();
		void initConfig();
};

void initOverallConfig(){
	
}



int main(int argc, char** argv) {
	Gateway obj;
/*Initialize the object by user*/
	obj.SMLMainGateway();
}
#endif

