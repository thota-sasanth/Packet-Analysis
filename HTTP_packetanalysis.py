import dpkt,struct

def answerpartC1(flow_packetsl):
    getreqpackets = []
    get_resp = {}
    for p in flow_packetsl:
        if p.req =='GET':   # checking if it is HTTP GET Request packet
            getreqpackets.append(p)
        elif p.resp == 'HTTP' and len(getreqpackets) >0:   # checking if it is HTTP Response packet
            get_resp[getreqpackets[0]] = p
            if len(getreqpackets) >1:
                getreqpackets = getreqpackets[1:]
            else:
                getreqpackets = []



def answerpartC2_3(pcapfile_packetsl):     # printing all details like total packets,rawbytes, pageload time for each pcap file
    starttime = endtime = tot_rawbytes = tot_packets = 0
    first = True
    for p in pcapfile_packetsl:
        if first == True:
            starttime = p.timestamp
            first=False
        endtime = p.timestamp
        tot_packets +=1
        tot_rawbytes += p.length




        
pcap_files = ['http_1080.pcap','tcp_1081.pcap','tcp_1082.pcap']   # pcap files input list
for file in pcap_files:    # similar to partA
    pcap_packets= dpkt.pcap.Reader(open(file,'rb'))
    mypacklist = []
    unqflows = []
    unqflowpackl = []
    for p in pcap_packets:     
        my_pack = mypacket(p)
        if my_pack.properpacket:
            mypacklist.append(my_pack)

            
    for p in mypacklist:
        if p.syn == '1' and p.ack == '0':
            unqflows.append([p.sourcePORT,p.destinationPORT])



            
    for flowp in unqflows:
        flowpacks = []
        for p in mypacklist:
            if (p.sourcePORT == flowp[1] and p.destinationPORT == flowp[0]) or (p.sourcePORT == flowp[0] and p.destinationPORT == flowp[1]):
                flowpacks.append(p)

                
        unqflowpackl.append(flowpacks)
    print("")
    print(f"-----------------------PCAP file: {file}----------------------------")

    
    if file == 'http_1080.pcap':  
        print("")
        for flowpackets in unqflowpackl:
            answerpartC1(flowpackets)    # function to get answers for http_1080.pcap file
    print("")
    flows_count = len(unqflows)


    
    print(f"Total num of tcp flows : {flows_count}")   # printing total flows
    if flows_count > 6:                          # logic for interpreting HTTP protocol for each pcap file
        print(f"Protocol used is HTTP 1.0 ")  
    elif flows_count == 6:
        print(f"Protocol used is HTTP 1.1 ")
    elif flows_count == 1:
        print(f"Protocol used is HTTP 2.0 ")

        
    answerpartC2_3(mypacklist)   # function to get answers for part C section 2,3
