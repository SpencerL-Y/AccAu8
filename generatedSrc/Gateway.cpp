#include "../generatedHeader/Gateway.h"
int recvFromHost();

int Id2Int(ip_address ip){
	int result;
	memcpy(&result, &ip, sizeof(int));
	int tempResult = ntohl(result);
	return tempResult;
}

void recv_udp_thd(Gateway* gw){
	receive_udp(gw);
}

void recv_ether_thd(){
	recvFromHost();
}

void receive_udp(Gateway* gw){

}

void receive_ether(){

}

void handle_thd(Gateway* gw){
	gw->SMLMainGateway();
}


static void dataHandlerGatewayrecvFromHost(u_char* param, const struct pcap_pkthdr* header, const u_char* packetData){
	ether_header* eh;
	eh = (ether_header*)packetData;
	/*Configure your own protocol number of ethernet frame*/
	if(ntohs(eh->type) == 0x888f){
		/*Add your own packet handling logic, tempData is used to store the packet after breaking the listening loop*/
		auth_header* auth_hdr = (auth_header*)((char*)packetData + sizeof(ether_header));
		
		//TODO: PROBLEM HERE
		std::cout << "ETHER RECV" << std::endl;
		if(auth_hdr->type == 0x10 ){
			std::cout << "gateway ether: recv acauthreq" << std::endl;
			char* tempItem = (char*)malloc(sizeof(AcAuthReq_C2G));
			memcpy(tempItem, auth_hdr, sizeof(AcAuthReq_C2G));
			AcAuthReq_C2G* tempPack = (AcAuthReq_C2G*)auth_hdr;
			int tempId = Id2Int(tempPack->client_id);
			cqs[clientIp2QIDMap[tempId]].Push(tempItem);
		} else if(auth_hdr->type == 0x21){
			std::cout << "gateway ether: recv authquack" << std::endl;
			char* tempItem  = (char*)malloc(sizeof(AuthQuAck));
			memcpy(tempItem, auth_hdr, sizeof(AuthQuAck));
			AuthQuAck* tempPack = (AuthQuAck*)auth_hdr;
			int tempId = Id2Int(tempPack->client_id);
			cqs[clientIp2QIDMap[tempId]].Push(tempItem);
		} else {
			std::cout << "gateway ether: ignored" << std::endl;
		}
	}
}

int recvFromHost(){
	EtherReceiver er;
	pcap_if_t* dev = er.getDevice();
	char errbuf[500];
	pcap_t* selectedAdp = pcap_open_live(dev->name, 65536, 1, 1000, errbuf);
	devGateway = selectedAdp;
	std::cout << dev->name << std::endl;
	/*Add self defined dataHandler to handle data received*/
	/*parameters: u_char* param, const struct pcap_pkthdr* header, const u_char* packetData*/
	er.listenWithHandler(devGateway, dataHandlerGatewayrecvFromHost, NULL);
	return 0;

}

int Gateway::sendToHost(u_char* data_, int length_, u_char dmac[6]){
	/*Configure your own implementation of length_*/
	std::cout << "send size: " << length_ << std::endl;
	//TODO: configure gateway mac
	u_char mac[6];
	mac[0] = 0x48;
	mac[1] = 0x2a;
	mac[2] = 0xe3;
	mac[3] = 0x60;
	mac[4] = 0x31;
	mac[5] = 0xfa;
	EtherSender snd(mac);
	snd.getDevice();
	/*add your identifier of the sender*/
	int result =snd.sendEtherWithMac(data_, length_, dmac);
	return result;
}
int Gateway::recvFromServer(){
	/*Add IP Str and portNUm here*/
	std::string IPStr_ = SELF_IP_STR;
	u_short portNum_ = SELF_PORT;
	UDPReceiver  er;
	/*allocation for dst_ here*/
	while(true){

		char* tempItem = (char*)malloc(150*sizeof(char));
		int result = er.receivePacket((u_char*)tempItem, IPStr_, portNum_);
		std::cout << "UDP RECV" << std::endl;
		auth_header* auth_hdr = (auth_header*)tempItem;
		if(auth_hdr->type == 0x20){
			std::cout << "recv udp: AuthQu" << std::endl;
			char* item = (char*)malloc(sizeof(AuthQu));
			memcpy(item, tempItem, sizeof(AuthQu));
			AuthQu* tempPack = (AuthQu*) auth_hdr;
			int tempId = Id2Int(tempPack->client_id);
			cqs[clientIp2QIDMap[tempId]].Push(item);
			clientId_int = tempId;
			std::cout << "udp recv: " << tempItem << std::endl;
			free(tempItem);
		} else if(auth_hdr->type == 0x11){
			std::cout << "recv udp: AcAuthAns" << std::endl;
			char* item = (char*)malloc(sizeof(AcAuthAns));
			memcpy(item, tempItem, sizeof(AcAuthAns));
			AcAuthAns* tempPack = (AcAuthAns*) auth_hdr;
			int tempId = Id2Int(tempPack->client_id);
			cqs[clientIp2QIDMap[tempId]].Push(item);
			clientId_int = tempId;
			std::cout << "udp recv: " << tempItem << std::endl;
			free(tempItem);
		} else {
			std::cout << "recv udp: ignored" << std::endl; 
			free(tempItem);
		}
	}
	return 0;
}

int Gateway::sendToServer(){
	std::cout << "send to server" << std::endl;
	/*Add Ip Str and portNum here*/
	//TODO: add Server IP here
	std::string IPStr_ =  SERVER_IP_STR;
	u_short portNum_ = this->SERVER_PORT;
	UDPSender snd;
	/*Add length and data content to send here*/

	u_char* data_;
	int length_ = 0;
	bool breakCondition = true;
	while(breakCondition){
		char* item;
		cqs[clientIp2QIDMap[clientId_int]].Pop(item);
		auth_header* auth_hdr = (auth_header*)item;
		if(auth_hdr->type == 0x10){
			breakCondition = true;
			memcpy(&this->acAuthReq_c2g, item, sizeof(AcAuthReq_C2G));
			if(!Verify((unsigned char*)&acAuthReq_c2g, acAuthReq_c2g.client_signature, sizeof(AcAuthReq_C2G) - 16, Id2Int(acAuthReq_c2g.client_id))){
				free(item);
			} else {
				AcAuthReq_C2G* old_packet = (AcAuthReq_C2G*)item;
				data_ = (u_char*)malloc(sizeof(AcAuthReq_G2S));
				
				acAuthReq_g2s.auth_hdr.length = htonl(sizeof(AcAuthReq_G2S) - sizeof(auth_header) - 16);
				acAuthReq_g2s.auth_hdr.serial_num = htonl(ntohl(old_packet->auth_hdr.serial_num));
				acAuthReq_g2s.auth_hdr.timestamp =  htonl(ntohl(old_packet->auth_hdr.timestamp));
				acAuthReq_g2s.auth_hdr.serial_num =  htonl(ntohl(old_packet->auth_hdr.serial_num));
				acAuthReq_g2s.auth_hdr.type = old_packet->auth_hdr.type;
				acAuthReq_g2s.auth_hdr.version = old_packet->auth_hdr.version;
				int tempId = Id2Int(old_packet->client_id);
				int tempTempId = htonl(tempId);
				memcpy(&acAuthReq_g2s.client_id, &tempTempId, sizeof(int));
				memcpy(acAuthReq_g2s.client_mac, old_packet->client_mac, 6*sizeof(char));
				memcpy(acAuthReq_g2s.client_signature, old_packet->client_signature, 16*sizeof(char));
				acAuthReq_g2s.gateway_id = old_packet->gateway_id;
				acAuthReq_g2s.gateway_random_number = old_packet->gateway_random_number;
				Sign((unsigned char*)&acAuthReq_g2s, (unsigned char*)&acAuthReq_g2s.gateway_signature, sizeof(AcAuthReq_G2S) - 16);
				length_ = sizeof(AcAuthReq_G2S);
				memcpy(data_, &acAuthReq_g2s, sizeof(AcAuthReq_G2S));
				free(item);
			}
		} else if(auth_hdr->type = 0x21){
			breakCondition = true;
			memcpy(&this->authQuAck, item, sizeof(AuthQuAck));
			//test the validity TODO
			std::cout << "check serial number" << std::endl;
			if(this->authQuAck.auth_hdr.serial_num == htonl(ntohl(this->authQu.auth_hdr.serial_num))){
				std::cout << "PASSED" << std::endl;
			} else {
				std::cout << "FAILED" << std::endl;
			}
			std::cout << "check serial number" << std::endl;
			if(this->authQuAck.auth_hdr.timestamp == htonl(ntohl(this->authQu.auth_hdr.timestamp))){
				std::cout << "PASSED" << std::endl;
			} else {
				std::cout << "FAILED" << std::endl;
			}
			std::cout << "check timestamp" << std::endl;
			if(this->authQuAck.auth_hdr.timestamp == htonl(ntohl(this->authQu.auth_hdr.timestamp))){
				std::cout << "PASSED" << std::endl;
			} else {
				std::cout << "FAILED" << std::endl;
			}
			data_ = (u_char*)malloc(sizeof(AuthQuAck));
			length_ = sizeof(AuthQuAck);
			memcpy(data_, &this->authQuAck, sizeof(AuthQuAck));
			free(item);
		} else {
			free(item);
		}
	}
	std::cout << "send data_: " << data_ << std::endl;
	int result = snd.sendPacket(data_, length_, IPStr_, portNum_);
	free(data_);
	return result;
}

void Gateway::Sign(unsigned char* msg, unsigned char* sig, size_t msglen){
	//sig = malloc(IBE_SIG_LEN * sizeof(unsigned char));
	if (digital_sign(msg, msglen, usr_privkey, sig) == -1) {
        printf("digital_sign failed\n");
    }
}

bool Gateway::Verify(unsigned char* msg, unsigned char* sig, size_t msglen, int verify_id){
	if(digital_verify(sig, msg, msglen, verify_id, master_pubkey) == -1){
		std::cout << "VERIFY FAILED !!!" << std::endl;
		return false;
	} else {
		std::cout << "VERIFY CORRECT..." << std::endl;
		return true;
	}
}



void Gateway::initConfig(){
	ibe_init();
	// SET GATEWAYID HERE
	gatewayId_int = inet_addr("127.0.0.1");
	unsigned char mprik[IBE_MASTER_PRIVKEY_LEN] = {0x40, 0x8c, 0xe9, 0x67};
	unsigned char mpubk[IBE_MASTER_PUBKEY_LEN] = {0x31, 0x57, 0xcd, 0x29, 0xaf, 0x13, 0x83, 0xb7, 0x5e, 0xa0};
	memcpy(master_privkey, mprik, IBE_MASTER_PRIVKEY_LEN);
	memcpy(master_pubkey, mpubk, IBE_MASTER_PUBKEY_LEN);
	// if (masterkey_gen(master_privkey, master_pubkey) == -1) {
    //         printf("masterkey_gen failed\n");
    // }
	std::cout << "start user key gen" << std::endl;
    userkey_gen(gatewayId_int, master_privkey, usr_privkey);
	std::cout << "start user key over" << std::endl;
}


void Gateway::SMLMainGateway(){
	initConfig();
	while(__currentState != -100) {
		switch(__currentState){
			case STATE___init:{
				std::cout << "--------------------STATE___init" << std::endl;
					
					gwAnce.auth_hdr.length = htonl(sizeof(GwAnce) - sizeof(auth_header) - 16);
					gwAnce.auth_hdr.serial_num = htonl(0);
					gwAnce.auth_hdr.timestamp = htonl(0);
					gwAnce.auth_hdr.type = 0x01;
					gwAnce.auth_hdr.version = 1;
					//TODO: configure gateway ip and mac here
					int tempId = htonl(this->gatewayId_int);
					memcpy(&gwAnce.gateway_id, &tempId, sizeof(int));
					gwAnce.gateway_mac[0] = 0x48;
					gwAnce.gateway_mac[1] = 0x2a;
					gwAnce.gateway_mac[2] = 0xe3;
					gwAnce.gateway_mac[3] = 0x60;
					gwAnce.gateway_mac[4] = 0x31;
					gwAnce.gateway_mac[5] = 0xfa;
					//TODO: configure random number here
					gwAnce.gateway_random_number = htonl(rand());
					time_t t;
					time(&t);
					gwAnce.auth_hdr.timestamp = htonl(t);
					//TODO: add memcpy here
					Sign((unsigned char*)&gwAnce, (unsigned char*)gwAnce.signature, sizeof(GwAnce) - 16);
					//std::cout << sizeof(GwAnce) << std::endl;
					char *sendData = (char*)malloc(sizeof(GwAnce));
					memcpy(sendData, &gwAnce, sizeof(GwAnce));
					sendToHost((u_char*)sendData, sizeof(GwAnce));
					char* item;
					while(true){
						cqs[clientIp2QIDMap[this->clientId_int]].Pop(item);
						auth_header* auth_hdr = (auth_header*)item;
						if(auth_hdr->type == 0x10){
							memcpy(&acAuthReq_c2g, item, sizeof(AcAuthReq_C2G));
							free(item);
							break;
						} else {
							free(item);
						}
					}
				__currentState = STATE__reqMsgRecved;
				
				break;}
			case STATE___final:{
				__currentState = -100;
				std::cout << "--------------------STATE___final" << std::endl;
				break;}
			case STATE__reqMsgRecved:{
				std::cout << "--------------------STATE__reqMsgRecved" << std::endl;

					sendToServer();
				__currentState = STATE__reqMsgSent;
				
				break;}
			case STATE__reqMsgSent:{
				std::cout << "--------------------STATE__reqMsgSent" << std::endl;
				
					recvFromServer();
				__currentState = STATE__authQueRecved;
				
				break;}
			case STATE__authQueRecved:{
				std::cout << "--------------------STATE__authQueRecved" << std::endl;
					char* item;
					while(true){
						cqs[clientIp2QIDMap[this->clientId_int]].Pop(item);
					}
					sendToHost((u_char*)tempDataGateway, sizeof(AuthQu));
				__currentState = STATE__authQueSent;
				
				break;}
			case STATE__authQueSent:{
				std::cout << "--------------------STATE__authQueSent" << std::endl;
				
					recvFromHost();
				__currentState = STATE__queRespRecved;
				
				break;}
			case STATE__queRespRecved:{
				std::cout << "--------------------STATE__queRespRecved" << std::endl;
				
					sendToServer();
				__currentState = STATE__queRespSent;
				
				break;}
			case STATE__queRespSent:{
				std::cout << "--------------------STATE__queRespSent" << std::endl;
				
					recvFromServer();
				__currentState = STATE__authRespRecved;
				
				break;}
			case STATE__authRespRecved:{
				std::cout << "--------------------STATE__authRespRecved" << std::endl;
				
					sendToHost((u_char*)tempDataGateway, sizeof(AcAuthAns));
				__currentState = STATE___final;
				
				break;}
			default: break;
		}
	}
}

