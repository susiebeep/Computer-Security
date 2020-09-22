from CSVPacket import Packet, CSVPackets
from collections import OrderedDict
import sys

IPProtos = [0 for x in range(256)]
numBytes = 0
numPackets = 0

csvfile = open(sys.argv[1],'r')


for pkt in CSVPackets(csvfile):
    # pkt.__str__ is defined...
    #print pkt
    numBytes += pkt.length
    numPackets += 1
    proto = pkt.proto & 0xff
    IPProtos[proto] += 1


print "numPackets:%u numBytes:%u" % (numPackets,numBytes)
for i in range(256):
    if IPProtos[i] != 0:
        print "%3u: %9u" % (i, IPProtos[i])

# check which flag has been entered
# -stat flag
if "-stats" in sys.argv[2]:
	# point back to the start of the file
	csvfile.seek(0)

	# initialize the count of each port number to 0
	tcpPorts = [0 for x in range(1025)]
	udpPorts = [0 for x in range(1025)]
	

	for pkt1 in CSVPackets(csvfile):
		# TCP
		protoNum = pkt1.proto & 0xff

		if protoNum == 6:
			# add one to the count for that TCP port number if within 1-1024
			tcpPortNum = pkt1.tcpdport
			if tcpPortNum <= 1024:
				tcpPorts[tcpPortNum] += 1
		# UDP
		if protoNum == 17:
			# add one to the count for that UDP port number if within 1-1024
			udpPortNum = pkt1.udpdport
			if udpPortNum <= 1024:
				udpPorts[udpPortNum] += 1

	print "\n"
	print "Destination port no.s TCP:"
	for i in range(1, 1024):
		if tcpPorts[i] != 0:
			print i, ":", tcpPorts[i]

	print "\n"
	print "Destination port no.s UDP:"
	for i in range(1, 1024):
		if udpPorts[i] != 0:
			print i, ":", udpPorts[i]


# -countip flag
if "-countip" in sys.argv[2]:
	# point back to the start of the file
	csvfile.seek(0)
	sourceIP = []
	destIP = []


	for pkt2 in CSVPackets(csvfile):
		# first save unique source addresses in sourceIP list
		if pkt2.ipsrc not in sourceIP:
			sourceIP.append(pkt2.ipsrc)
		# then save unique destination addresses in destIP list	
		if pkt2.ipdst not in destIP:
			destIP.append(pkt2.ipdst)
	
	# count number of unique source and destination addresses and
	# create lists of each size to store the counts
	noSourceAddr = len(sourceIP)
	sourceIPCount = [0 for x in range(noSourceAddr)]

	noDestAddr = len(destIP)
	destIPCount = [0 for x in range(noDestAddr)]

	# point back to the start of the file
	csvfile.seek(0)

	# count number of occurences of each unique source address
	for pkt3 in CSVPackets(csvfile):
		# if that source IP address is listed as a unique source IP address
		if pkt3.ipsrc in sourceIP:
			# return index of that source address
			index = sourceIP.index(pkt3.ipsrc)
			# add one to the count at that index
			sourceIPCount[index] += 1

		# if that destination IP address is listed as a unique destination IP address	
		if pkt3.ipdst in destIP:
			# return index of that destination address
			index1 = destIP.index(pkt3.ipdst)
			# add one to the count at that index
			destIPCount[index1] += 1	

	# combine the two lists to create dictionaries
	sourceDict = {}
	destDict = {}

	for key in sourceIPCount:
		for value in sourceIP:
			sourceDict[key] = value
			sourceIP.remove(value)
			break		
	
	for key1 in destIPCount:
		for value1 in destIP:
			destDict[key1] = value1
			destIP.remove(value1)
			break	

	# print distinct source and destination IP addresses and their respective counts
	print "\n"
	print "Distinct source addresses and their counts:"
	for key2, value2 in sorted(sourceDict.items(), reverse=True):
		print key2, ":", value2

	print "\n"	
	print "Distinct destination addresses and their counts:"
	for key3, value3 in sorted(destDict.items(), reverse=True):
		print key3, ":", value3

	# point back to the start of the file
	csvfile.seek(0)

	# sorted  -countip output
	for pkt4 in CSVPackets(csvfile):
		# get IP protocol number
		protoNum1 = pkt4.proto & 0xff

		#GRE
		if protoNum1 == 47:
			greIP = []

			for pkt5 in CSVPackets(csvfile):
				# save unique IPs addresses in gre list
				if pkt5.ipsrc not in greIP:  
						greIP.append(pkt5.ipsrc)
				if pkt5.ipdst not in greIP:
						greIP.append(pkt5.ipdst)
	
			# count number of unique IP addresses and create list to store the count
			noGreAddr = len(greIP)
			greIPCount = [0 for x in range(noGreAddr)]

			# point back to the start of the file
			csvfile.seek(0)

			# count number of occurences of each unique address
			for pkt6 in CSVPackets(csvfile):
				# if that IP address is listed as a unique IP address
				if pkt6.ipsrc in greIP:
				# return index of that source address
					index = greIP.index(pkt6.ipsrc)
					# add one to the count at that index
					greIPCount[index] += 1

				if pkt6.ipdst in greIP:
				# return index of that source address
					index = greIP.index(pkt6.ipdst)
					# add one to the count at that index
					greIPCount[index] += 1		

			# combine the two lists to create a dictionary
			greDict = {}

			for key in greIPCount:
				for value in greIP:
					greDict[key] = value
					greIP.remove(value)
					break		

			# print distinct IP addresses and their respective counts
			print "\n"
			print "GRE: Distinct IP addresses and their counts:"
			for gkey, gvalue in sorted(greDict.items(), reverse=True):
				print gkey, ":", gvalue

			# point back to the start of the file
			csvfile.seek(0)


		# IPSEC
		if protoNum1 == 50 or protoNum1 == 51:
			ipsecIP = []

			for pkt5 in CSVPackets(csvfile):
				# save unique IPs addresses in gre list
				if pkt5.ipsrc not in ipsecIP:  
						ipsecIP.append(pkt5.ipsrc)
				if pkt5.ipdst not in ipsecIP:
						ipsecIP.append(pkt5.ipdst)
	
			# count number of unique IP addresses and create list to store the count
			noIpsecAddr = len(ipsecIP)
			ipsecIPCount = [0 for x in range(noIpsecAddr)]

			# point back to the start of the file
			csvfile.seek(0)

			# count number of occurences of each unique address
			for pkt6 in CSVPackets(csvfile):
				# if that IP address is listed as a unique IP address
				if pkt6.ipsrc in ipsecIP:
				# return index of that source address
					index = ipsecIP.index(pkt6.ipsrc)
					# add one to the count at that index
					ipsecIPCount[index] += 1

				if pkt6.ipdst in ipsecIP:
				# return index of that source address
					index = ipsecIP.index(pkt6.ipdst)
					# add one to the count at that index
					ipsecIPCount[index] += 1		

			# combine the two lists to create a dictionary
			ipsecDict = {}

			for key in ipsecIPCount:
				for value in ipsecIP:
					ipsecDict[key] = value
					ipsecIP.remove(value)
					break		

			# print distinct IP addresses and their respective counts
			print "\n"
			print "IPSEC: Distinct IP addresses and their counts:"
			for ikey, ivalue in sorted(ipsecDict.items(), reverse=True):
				print ikey, ":", ivalue

			# point back to the start of the file
			csvfile.seek(0)

		# OSPF
		if protoNum1 == 89:
			ospfIP = []

			for pkt5 in CSVPackets(csvfile):
				# save unique IPs addresses in ospfIP list
				if pkt5.ipsrc not in ospfIP:  
						ospfIP.append(pkt5.ipsrc)
				if pkt5.ipdst not in ospfIP:
						ospfIP.append(pkt5.ipdst)
	
			# count number of unique IP addresses and create list to store the count
			noOspfAddr = len(ospfIP)
			ospfIPCount = [0 for x in range(noOspfAddr)]

			# point back to the start of the file
			csvfile.seek(0)

			# count number of occurences of each unique address
			for pkt6 in CSVPackets(csvfile):
				# if that IP address is listed as a unique IP address
				if pkt6.ipsrc in ospfIP:
				# return index of that source address
					index = ospfIP.index(pkt6.ipsrc)
					# add one to the count at that index
					ospfIPCount[index] += 1

				if pkt6.ipdst in ospfIP:
				# return index of that source address
					index = ospfIP.index(pkt6.ipdst)
					# add one to the count at that index
					ospfIPCount[index] += 1		

			# combine the two lists to create a dictionary
			ospfDict = {}

			for key in ospfIPCount:
				for value in ospfIP:
					ospfDict[key] = value
					ospfIP.remove(value)
					break		
	

			# print distinct IP addresses and their respective counts
			print "\n"
			print "OSPF: Distinct IP addresses and their counts:"
			for okey, ovalue in sorted(ospfDict.items(), reverse=True):
				print okey, ":", ovalue

			# point back to the start of the file
			csvfile.seek(0)

# -connto flag
if "-connto" in sys.argv[2]:
	# point back to the start of the file
	csvfile.seek(0)
	# dictionary where the destination IP address is the key and the ipsrc-proto/port mappings are the values
	serverDict = {}	

	for pkt7 in CSVPackets(csvfile):
		# get IP protocol number
		protoNum = pkt7.proto & 0xff

		# TCP
		if protoNum == 6:
			tcpPort = str(pkt7.ipsrc) + "-" + "tcp/" + str(pkt7.tcpdport)

			# if destination IP address already in the dictionary
			if pkt7.ipdst in serverDict:

				# if the ipsrc-proto/port mapping is unique
				if tcpPort not in serverDict[pkt7.ipdst]:
					serverDict[pkt7.ipdst].append(tcpPort)
			
			# if destination IP address not in the dictionary
			else:
				serverDict[pkt7.ipdst] = [tcpPort]


		# UDP
		if protoNum == 17:
			udpPort = str(pkt7.ipsrc) + "-" + "udp/" + str(pkt7.udpdport)
			
			# if destination IP not already in the dictionary
			if pkt7.ipdst in serverDict:
				
				# if the ipsrc-proto/port mapping is unique
				if udpPort not in serverDict[pkt7.ipdst]:
					serverDict[pkt7.ipdst].append(udpPort)
			
			# if destination IP address not in the dictionary
			else:
				serverDict[pkt7.ipdst] = [udpPort]
	
	# convert dictionary to ordered dictionary
	orderedServer = OrderedDict(sorted(serverDict.items(), key=lambda (k,v):len(v), reverse=True))			

	# print a summary for each destination IP address, sorted by the highest number of unique connections
	print "\n"
	for key, value in orderedServer.items():
		portNo = [i.split("-")[1] for i in value]
		print "ipdst", key, "has", len([item for item in value if item]), "distinct ipsrc on ports:", ", ".join(portNo)
