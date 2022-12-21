import dpkt,struct  # required imports


def answerpartA2(flow_packetsl):     
    l = len(flow_packetsl)   #for first 2 transactions (2a)
    count_trans = 0
    prevj = 3
    windowsize = 16384
    print()
    for i in range(3,l):       # finding for the first two sequence packets and ack packets pair
        if count_trans ==2:
            break
        for j in range(prevj+1,l):
            if flow_packetsl[i].sourcePORT == flow_packetsl[j].destinationPORT and flow_packetsl[i].destinationPORT == flow_packetsl[j].sourcePORT:
                rcv_windsize = windowsize * (int(flow_packetsl[i].window)), windowsize * (int(flow_packetsl[j].window))
                prevj = j
                count_trans +=1
                break
    firstpacket = True   #empirical throughput (2b)
    totalbytessent = end_time = start_time = 0     
    for p in flow_packetsl:
        if p.sourceIP == '130.245.145.12' and p.destinationIP == '128.208.2.198':
            if firstpacket:
                start_time = p.timestamp
                firstpacket = False
            totalbytessent += p.length          # estimating total bytes sent from source
        elif p.sourceIP == '128.208.2.198' and p.destinationIP == '130.245.145.12':
            end_time = p.timestamp      # estimating time taken for packets sent
    emp_thru1 = (float(totalbytessent) / (end_time-start_time))/1000000    # empirical throughput from sender

    seq_payloadmap = {}
    for p in flow_packetsl:
        if p.sourceIP == '130.245.145.12' and p.destinationIP == '128.208.2.198':
            seq_payloadmap[str(int(p.seqnumber) + int(p.TCPpayload))] = p    # checking for packets which got acknowlegements from receiver using sequence number & tcp payload values
    bytessentrecv = 0
    for p in flow_packetsl:
        if p.sourceIP == '128.208.2.198' and p.destinationIP == '130.245.145.12':
            if p.acknumber in seq_payloadmap:
                bytessentrecv += seq_payloadmap[p.acknumber].length      # calculation total size of those packets
    packetssent = {}   # loss rate (2c)
    for p in flow_packetsl:
        if p.sourceIP == '130.245.145.12' and p.destinationIP == '128.208.2.198':
            if p.seqnumber not in packetssent:
                packetssent[p.seqnumber] = 0
            packetssent[p.seqnumber] +=1
    total_packets = 0
    
    alreadyrecv = {}
    for p in flow_packetsl:
        if p.sourceIP == '128.208.2.198' and p.destinationIP == '130.245.145.12':
            if p.acknumber not in alreadyrecv:
                alreadyrecv[p.acknumber] = p.timestamp
        if p.sourceIP == '130.245.145.12' and p.destinationIP == '128.208.2.198':
            seq_payload = str(int(p.seqnumber)+int(p.TCPpayload))                # finding packets which got acknowlegements from receiver
            if seq_payload not in alreadysent:
                alreadysent[seq_payload] = p.timestamp
    sumrtt = numrtt = 0
    for seq_payload in alreadysent:
        if seq_payload in alreadyrecv:  
            sumrtt += 1 * (alreadyrecv[seq_payload] - alreadysent[seq_payload])    # calculating rtt for packets acknowledged
            numrtt += 1
    avgrtt = float(sumrtt)/numrtt
    print(f"Average RTT is {avgrtt} secs")
    mss = 1460  #theoritical throughput (2d)
    theo_thru = (((3/2)**(1/2)) * (mss)) / (avgrtt * ( lossr **(1/2)))/1000000    # Theoritical throughput formula
    print(f"Theoretical  throughput : {theo_thru} MBPS")





        

pcap_files = ['assignment2.pcap']     # taking pcap file as input
for file in pcap_files:
    pcap_packets= dpkt.pcap.Reader(open(file,'rb'))    # using dpkt to read pcap file
    mypacklist = []
    unqflows = []
    unqflowpackl = []
    for p in pcap_packets:         
        my_pack = mypacket(p)       # formatting the packets to desired formats
        if my_pack.properpacket:
            mypacklist.append(my_pack)
    for p in mypacklist:
        if p.sourceIP == '130.245.145.12' and p.syn == '1' and p.ack == '0':   # getting the number of flows using "SYN" packets
            unqflows.append([p.sourcePORT,p.destinationPORT])  # storing flow specific source & destination port numbers
    for flowp in unqflows:
        flowpacks = []
        for p in mypacklist:
            if (p.sourcePORT == flowp[1] and p.destinationPORT == flowp[0]) or (p.sourcePORT == flowp[0] and p.destinationPORT == flowp[1]):
                flowpacks.append(p)
        unqflowpackl.append(flowpacks)    # appending packets to appropriate flows

    
    





    










    


