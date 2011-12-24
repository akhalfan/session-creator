# developed by Ali Khalfan
# LICENSE: GNU



from scapy.all import *
import random
import math

def dottedQuadToNum(ip):
    "convert decimal dotted quad string to long integer"

    hexn = ''.join(["%02X" % long(i) for i in ip.split('.')])
    return long(hexn, 16)

def numToDottedQuad(n):
    "convert long int to dotted quad string"

    d = 256 * 256 * 256
    q = []
    while d > 0:
        m,n = divmod(n,d)
        q.append(str(m))
        d = d/256

    return '.'.join(q)
def gethost(ipaddress,prefix):

        #possiblehosts = math.pow(2,32-int(prefix))
        possiblehosts = math.pow(2,8)
        selectedhost = random.randint(0,possiblehosts -1)

        #convert fomr dotted to integer
        ipint = dottedQuadToNum(ipaddress)

        #generate new host ip
        newiphost = ipint | selectedhost

        hostipaddress = numToDottedQuad(newiphost)


        # conver new value to dotted

        return hostipaddress


def setthreewayhandshake(sourceip, destinationip, sourceport, destinationport,srcInitSeq,dstInitSeq):


	# set source and destination 

	# 1) source generates SYN
	# 2) destination replies with ACK to SYN
	# 3) source replies with ACK to ACK , session beginsa
	# return list of tcp segments
	

	# SYN packet

	syn_packet = IP(dst=destinationip,src=sourceip)/TCP(sport=sourceport,dport=destinationport,flags="S",seq=srcInitSeq)
	#SYN_ACK packet
	syn_ack_packet =   IP(src=destinationip,dst=sourceip)/TCP(dport=sourceport,sport=destinationport,flags="SA",seq=dstInitSeq,ack=(syn_packet.seq))
	#FINAL ACK packet
	
	ack_ack_packet = IP(dst=destinationip,src=sourceip)/TCP(sport=sourceport,dport=destinationport,seq=syn_packet.seq+1,ack=syn_ack_packet.seq,flags="A")
	# ACK packet

	return [syn_packet, syn_ack_packet,ack_ack_packet]


def setthreewaygoodbyehandshake(sourceip, destinationip, sourceport, destinationport,source_packet,destination_packet):

	#similar to above, but replace SYN with FIN

	#FIN packet 

	fin_packet = IP(dst=destinationip,src=sourceip)/TCP(sport=sourceport,dport=destinationport,flags="FA",seq=(source_packet.seq+len(source_packet.payload) -20) ,ack=destination_packet.seq)
	#FIN_ACK packet
	fin_ack_packet =   IP(src=destinationip,dst=sourceip)/TCP(flags="A",dport=sourceport,sport=destinationport,seq=(destination_packet.seq + len(destination_packet.payload) -20) ,ack=fin_packet.seq)

	# ACK packet
	
	fin_fin_packet = IP(dst=destinationip,src=sourceip)/TCP(sport=sourceport,dport=destinationport,flags="FA",seq=fin_packet.seq+1,ack=(fin_ack_packet.seq))

	


	return [fin_packet, fin_ack_packet, fin_fin_packet]

def generatesessionpackets(sourceip, destinationip , sourceport ,destinationport, syn_ack_packet,ack_ack_packet):

	#on a random count generate packets for the session 

	# generate a random seed n

	# generate for loop with n count and create packets at random (sometimes source and another destianation)
	# return list of tcp segments 


	tcp_packets =  []
	random.seed()

	n = random.randint(2, 100) 	
	source_packet = IP(dst=destinationip,src=sourceip)/TCP(sport=sourceport,dport=destinationport,seq=ack_ack_packet.seq+(len(ack_ack_packet.payload)-20),ack=syn_ack_packet.seq,flags="PA")/("First part ")
	dest_packet = IP(src=destinationip,dst=sourceip)/TCP(dport=sourceport,sport=destinationport,flags="A",seq=syn_ack_packet.seq+(len(syn_ack_packet.payload)-20)+1,ack=source_packet.seq + len(source_packet.payload)-20)/("of session")
	tcp_packets.append(source_packet)
	dstCount = 0
	for i in range(n):

		random.seed()
		direction = random.randint(1,2)
		if direction == 1 :
			teststr = "test"+str(i)	
				
			source_packet =  IP(dst=destinationip,src=sourceip)/TCP(sport=sourceport,dport=destinationport,flags="A",seq=(source_packet.seq+len(source_packet.payload) - 20),ack=dest_packet.seq)/(teststr)
			tcp_packets.append(source_packet)
		
		elif direction == 2:
			if not dstCount ==0:
				dest_packet =  IP(src=destinationip,dst=sourceip)/TCP(dport=sourceport,sport=destinationport,flags="A",seq=(dest_packet.seq+len(dest_packet.payload )- 20) ,ack=source_packet.seq)/("counter strike")
			tcp_packets.append(dest_packet)
			dstCount = dstCount + 1

		sequences = []
	return [tcp_packets, source_packet,dest_packet]

	

def getsocketdetails():

	server_list   = ['192.168.2.0/24', '192.168.3.0/24', '192.168.4.0/24','192.168.5.0/24']
	client_list = ['192.168.6.0/24', '192.168.7.0/24', '192.168.8.0/24', '192.168.9.0/24', '192.168.10.0/24']

	
	random.seed()
	source_subnet = client_list[random.randint(0,len(client_list) -1 )] 
	destination_subnet = server_list[random.randint(0,len(server_list) -1 )] 

	source_subnet_split = source_subnet.split("/")
	destination_subnet_split = destination_subnet.split("/")

	source_ip  =  gethost(source_subnet_split[0], source_subnet_split[1])
	destination_ip  = gethost(destination_subnet_split[0], destination_subnet_split[1])
	

	random.seed()
	source_port = random.randint(1024,65534)
	destination_port = random.randint(10,1023)

	return  [source_ip, destination_ip, source_port, destination_port]


def main():


	# take as arguments the number of sessions you want to create 
	# for loop and call the functions above
	# write packets to pcap file 
	filename = sys.argv[2]
	# create write to write to pcap file
	writer =  PcapWriter(filename, append=True)

	begin_handshake_packets = []
	end_handshake_packets = []
	session_packets = []
	socketdetails = []

	for i in range(int(sys.argv[1])) :
		
		socketdetails = getsocketdetails()
		sourceip  = socketdetails[0]
		destinationip = socketdetails[1]
		sourceport = socketdetails[2]
		destinationport = socketdetails[3]


		random.seed()
		srcSequenceInit = random.randint(0,math.pow(2,32))
		random.seed()
		dstSequenceInit = random.randint(0,math.pow(2,32))

	
		begin_handshake_packets = setthreewayhandshake(sourceip, destinationip, sourceport, destinationport,srcSequenceInit,dstSequenceInit)		
		session_function = generatesessionpackets(sourceip,destinationip,sourceport,destinationport,begin_handshake_packets[1],begin_handshake_packets[2])
		session_packets = session_function[0]
		session_sequences = session_function[1]
		end_handshake_packets = setthreewaygoodbyehandshake(sourceip, destinationip,sourceport,destinationport, session_function[1],session_function[2])


		#write packets to dump file

		for packet in  begin_handshake_packets:
			writer.write(packet)

		for packet in session_packets:
			writer.write(packet)

		for packet in end_handshake_packets:
			writer.write(packet)


	writer.close()

	return

main()
