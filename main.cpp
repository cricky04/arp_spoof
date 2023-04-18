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

#pragma pack(push, 1)
struct EthArpPacket final 
{
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() 
{
	printf("syntax: send-arp-test <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2>] ...\n");
	printf("sample: send-arp-test wlan0 192.168.0.102 192.168.0.12\n");
}

//convert MAC address
std::string MacToStr(unsigned char* mac) 
{
    std::stringstream stream;
    stream << std::hex << std::setfill('0');
    for (int i = 0; i < 6; ++i) 
	{
        stream << std::setw(2) << static_cast<int>(mac[i]);
        if (i < 5) 
		{
            stream << ":";
        }
    }
    return stream.str();
}

int main(int argc, char* argv[])
{
	//argv[1]: device, argv[2~]: address pair (target IP, source IP)
	if (argc < 4 || argc % 2 != 0) 
	{
		usage();
		exit(1);
	}

	char* device = argv[1];
	char errorBuffer[PCAP_ERRBUF_SIZE];
	char IPAddress[16];
	int i, result;

	//getIP
	int fd;
	struct ifreq ifr;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) 
	{
		printf("SOCKET ERROR!");
		exit(1);
    }
	memcpy(ifr.ifr_name, device, IFNAMSIZ - 1);
	ioctl(fd, SIOCGIFADDR, &ifr);
	close(fd);
	strcpy(IPAddress, inet_ntoa(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr));
	
	//getMAC
	std::ifstream iface("/sys/class/net/" + std::string(device) + "/address");
  	std::string MACAddress((std::istreambuf_iterator<char>(iface)), std::istreambuf_iterator<char>());

	printf("IP : %s\n", IPAddress);
	printf("MAC : %s", MACAddress.c_str());

	//pcap check
	pcap_t* handle = pcap_open_live(device, BUFSIZ, 1, 1, errorBuffer);
	if (handle == nullptr)
	{
		fprintf(stderr, "cannot open %s\n", device);
		exit(1);
	}

	EthArpPacket packet;
	for(i = 1; i < argc/2; i ++)
	{
		packet.eth_.dmac_ = Mac::broadcastMac();
		packet.eth_.smac_ = Mac(MACAddress);
		packet.eth_.type_ = htons(EthHdr::Arp);
		packet.arp_.hrd_ = htons(ArpHdr::ETHER);
		packet.arp_.pro_ = htons(EthHdr::Ip4);
		packet.arp_.hln_ = Mac::SIZE;
		packet.arp_.pln_ = Ip::SIZE;
		packet.arp_.op_ = htons(ArpHdr::Request);
		packet.arp_.smac_ = Mac(MACAddress);
		packet.arp_.sip_ = htonl(Ip(std::string(IPAddress)));
		packet.arp_.tmac_ = Mac::nullMac();
		packet.arp_.tip_ = htonl(Ip(argv[i * 2]));

		result = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		
		if (result != 0) 
		{
			fprintf(stderr, "pcap_sendpacket return %d error : %s\n", result, pcap_geterr(handle));
		}

		while (true) 
		{
			struct pcap_pkthdr* header;
			const u_char* recievePacket;

			result =  pcap_next_ex(handle, &header, &recievePacket);
			if (result == 0) continue;
			if (result == PCAP_ERROR) 
			{
				printf("pcap_next_ex return %d error: %s\n", result, pcap_geterr(handle));
				break;
			}
			if(result == PCAP_ERROR_BREAK)
			{
				printf("pcap_next_ex return %d error : %s\n", result, pcap_geterr(handle));
				break;
			}

			struct EthArpPacket *arpPacket = (struct EthArpPacket *)recievePacket;
			if(arpPacket->arp_.op() == ArpHdr::Reply && arpPacket->eth_.type() == EthHdr::Arp && arpPacket->arp_.tmac() == Mac(MACAddress) && arpPacket->arp_.sip() == Ip(argv[i * 2]))
			{
				EthArpPacket sendPacket;
				sendPacket.eth_.dmac_ = arpPacket->arp_.smac();
				sendPacket.eth_.smac_ = Mac(MACAddress);
				sendPacket.eth_.type_ = htons(EthHdr::Arp);
				sendPacket.arp_.hrd_ = htons(ArpHdr::ETHER);
				sendPacket.arp_.pro_ = htons(EthHdr::Ip4);
				sendPacket.arp_.hln_ = Mac::SIZE;
				sendPacket.arp_.pln_ = Ip::SIZE;
				sendPacket.arp_.op_ = htons(ArpHdr::Reply);
				sendPacket.arp_.smac_ = Mac(MACAddress);
				sendPacket.arp_.sip_ = htonl(Ip(std::string(argv[i * 2 + 1])));
				sendPacket.arp_.tmac_ = arpPacket->arp_.smac();
				sendPacket.arp_.tip_ = htonl(Ip(argv[i * 2]));

				result = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&sendPacket), sizeof(EthArpPacket));

				if (result != 0)
				{
					fprintf(stderr, "pcap_sendpacket return %d error : %s\n", result, pcap_geterr(handle));
				}
				printf("Finish: packet %d\n", i);
				break;
			}
		}
	}
	pcap_close(handle);
}