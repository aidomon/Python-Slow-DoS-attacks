#!/usr/local/bin/python3
from scapy.all import *
from time import perf_counter 
from statistics import mean
import subprocess
import logging
logging.basicConfig(filename='ids.log', filemode='a', level=logging.INFO, format='%(asctime)s - %(levelname)s: %(message)s', datefmt='%d-%b-%y %H:%M:%S')

# ids database, IP blacklist and start time definition 
ids_dict = {}
black_list = []
start_time = perf_counter()

# parameters
SC_max_conn_from_IP = 20
SC_max_conn_req_from_IP = 20
SC_max_conn_req_from_IP_time_test = 10
SC_max_from_start_time = 15.0

SN_max_conn_from_IP = 20
SN_max_conn_req_from_IP = 25
SN_max_time_difference = 0.1 
SN_max_time_interval = 2.0
SN_max_size_difference = 10

Max_nonactive_time = 20.0


# needed values filtration form incomming packet ---------------------------------------------------------------------------------
def ids(packet):
    packet_time = perf_counter()
    ip = packet[1].src
    if ip not in black_list:     
        if packet.getlayer(Raw):
            if packet[2].payload:
                tcp_dport = packet[2].dport
                packet_size = len(packet[2].load)
                tcp_sport = packet[2].sport
                string = bytes(packet[2].payload).decode('utf-8')
                # according to dest port can we distinguish
                if tcp_dport == 80:
                    if "\r\n\r\n" in string:
                        isEnded = 1
                    else:
                        isEnded = 0
                # tcp_dport == 22 or tcp_dport == 21
                else:
                    if "\r\n" in string:
                        isEnded = 1
                    else:
                        isEnded = 0
                isEndedCheck_and_store(ip, tcp_sport, tcp_dport, isEnded, packet_time, packet_size) 
         
# checks if in connection are sent either just valid or just invalid packets, if aren't -> no attack is happening ----------------
# then puting values in dictionary and executing potenttial signature detection
def isEndedCheck_and_store(ip, tcp_sport, tcp_dport, isEnded, packet_time, packet_size):
    if ip in ids_dict and tcp_sport in ids_dict.get(ip):
        if ids_dict.get(ip).get(tcp_sport)[2] == isEnded:
            # structure: {src_port : [[arrival times], [packet sizes], isEnded, dst_port]}

            # add last packet arrival time
            ids_dict.get(ip)[tcp_sport][0].append(packet_time)
            # add last packet size
            ids_dict.get(ip)[tcp_sport][1].append(packet_size)            
            
            if isEnded == 0:
                IDS_Slowcomm(ip, tcp_sport, tcp_dport, packet_time)
            else:
                IDS_SlowNext(ip, tcp_sport, tcp_dport, packet_time, packet_size)
        else:
            #delete connnection
            print("Non suspicious connection {} deleted".format(ip))
            del ids_dict[ip]
    elif ip in ids_dict and tcp_sport not in ids_dict.get(ip):
        ids_dict.get(ip)[tcp_sport] = [[packet_time], [packet_size], isEnded, tcp_dport]
        if isEnded == 0:
                IDS_Slowcomm(ip, tcp_sport, tcp_dport, packet_time)
        else:
            IDS_SlowNext(ip, tcp_sport, tcp_dport, packet_time, packet_size)
    # if connection log is not active for 20 seconds -> delete ip log
    elif (packet_time - start_time) > 20.0:
        print("Checking nonactive connections")
        muchTime_del(ip, tcp_sport)
    else:
        ids_dict[ip] = {tcp_sport: [[packet_time], [packet_size], isEnded, tcp_dport]}     
    
# Slowcomm detection -------------------------------------------------------------------------------------------------------------
def IDS_Slowcomm(ip_addr, src_port, dst_port, packet_arrived):
    # if more than 20 connections from one IP -> attack detected
    if len(ids_dict.get(ip_addr)) >= SC_max_conn_from_IP:
        print("ATTACK Slowcomm on port {} from IP {} detected - too many connections from one IP".format(dst_port, ip_addr))
        logging.critical("ATTACK Slowcomm on port {} from IP {} detected - too many connections from one IP".format(dst_port, ip_addr))
        blacklist_del(ip_addr)
        return
    # if more than 20 uncompleted packets send in one connection -> attack detected
    elif len(ids_dict.get(ip_addr).get(src_port)[0]) >= SC_max_conn_req_from_IP:
        print("ATTACK Slowcomm on port {} from IP {} detected - too many uncompleted packets in one connection to finish request".format(dst_port, ip_addr))
        logging.critical("ATTACK Slowcomm on port {} from IP {} detected - too many uncompleted packets in one connection to finish request".format(dst_port, ip_addr))
        blacklist_del(ip_addr)
        return
    # if only uncompleted packets from one connection for 15 seconds -> attack detected
    elif len(ids_dict.get(ip_addr).get(src_port)[0]) >= SC_max_conn_req_from_IP_time_test:
        logging.warning("Suspicious behavior caught on port {} from IP {}".format(dst_port, ip_addr))
        
        # if 15 seconds from the first arrival time of packet in one connection -> attack detected
        if (packet_arrived - ids_dict.get(ip_addr).get(src_port)[0][0]) >= SC_max_from_start_time:
            print("ATTACK Slowcomm on port {} from IP {} detected - too much time for finishing request in one connection".format(dst_port, ip_addr))
            logging.critical("ATTACK Slowcomm on port {} from IP {} detected - too much time for finishing request in one connection".format(dst_port, ip_addr))
            blacklist_del(ip_addr)
            return
        else:
             # if not -> next packet
            return
    else:
         # if not -> next packet
        return

# Slow Next detection ------------------------------------------------------------------------------------------------------------
def IDS_SlowNext(ip_addr, src_port, dst_port, packet_arrived, packet_size):
    # if more than 20 connections from one IP -> attack detected
    if len(ids_dict.get(ip_addr)) >= SN_max_conn_from_IP:
        print("ATTACK Slow Next on port {} from IP {} detected - too many connections from one IP".format(dst_port, ip_addr))
        logging.critical("ATTACK Slow Next on port {} from IP {} detected - too many connections from one IP".format(dst_port, ip_addr))
        blacklist_del(ip_addr)
        return
    
    # if more than 25 completed packets send in one connection -> examine the time difference between incoming packets
    elif len(ids_dict.get(ip_addr).get(src_port)[0]) >= SN_max_conn_req_from_IP:
        # is the time difference same or similar between incoming packets?
            # if yes -> attack detected
        list_time = []
        for item in ids_dict.get(ip_addr).get(src_port)[0]:
            list_time.append(item) 

        if timeDifference_check(list_time) == 1:
            print("ATTACK Slow Next on port {} from IP {} detected - signature response time found".format(dst_port, ip_addr))
            logging.critical("ATTACK Slow Next on port {} from IP {} detected - signature response time found".format(dst_port, ip_addr))
            blacklist_del(ip_addr)
            return
        
        # is the size difference same or similar between incoming packets?
            # if yes -> attack detected
        list_size = []
        for item in ids_dict.get(ip_addr).get(src_port)[1]:
            list_size.append(item)

        if sizeDifference_check(list_size) == 1:
            print("ATTACK Slow Next on port {} from IP {} detected - signature same size found".format(dst_port, ip_addr))
            logging.critical("ATTACK Slow Next on port {} from IP {} detected - signature same size found".format(dst_port, ip_addr))
            blacklist_del(ip_addr)
            return
        return
    else:
         # if not -> next packet
        return
    

# auxiliary methods --------------------------------------------------------------------------------------------------------------
def timeDifference_check(list_val):  
    differences = [j-i for i, j in zip(list_val[:-1], list_val[1:])]
    average = mean(differences)
    if average > SN_max_time_interval and (average - differences[random.randint(1, len(differences))]) < SN_max_time_difference:
        # attack
        return 1
    else:
        # no attack
        return 0

def sizeDifference_check(list_size):
    differences = [j-i for i, j in zip(list_size[:-1], list_size[1:])]
    average = mean(differences)
    if (average - float(differences[0])) <= SN_max_size_difference:
        # attack
        return 1
    else:
        # no attack
        return 0

def muchTime_del(ip_addr, src_port):
    global start_time
    to_Delete = []
    for key_ip in ids_dict:
        for key_port in ids_dict.get(key_ip):
            if (perf_counter() - ids_dict.get(key_ip).get(key_port)[0][0]) > Max_nonactive_time:
                to_Delete.append(key_ip)
            break
            
    for item in to_Delete:
        del ids_dict[item]
    start_time = perf_counter()  

def blacklist_del(ip):
    black_list.append(ip)
    del ids_dict[ip]
# main ---------------------------------------------------------------------------------------------------------------------------
def main():
    # choosing interface and getting it's IP address

    # Returns a list of network interfaces information
    for item in socket.if_nameindex():
        print("{} - {}".format(socket.if_nameindex().index(item) + 1, item[1]))

    print("\nChoose an interface to sniff on please:")
    
    while True:
        try:
            iface_number = int(input())
            command = "ip addr show {}".format(socket.if_nameindex()[iface_number - 1][1]) + " | awk '{ print $2}' | grep -E -o '([0-9]{1,3}[\\.]){3}[0-9]{1,3}'"
            ip_iface = (subprocess.check_output(command, shell=True).strip()).decode("utf-8")
            print("Selected interface is {}, it's IP is {}\nIDS started".format(socket.if_nameindex()[iface_number - 1][1], ip_iface))
            
        except:
            print("You didn't specify a correct number")
            input("Press Enter to try again...")
            continue
        break

    sniff(iface=socket.if_nameindex()[iface_number - 1][1], prn=ids, filter="tcp dst port 21 or 22 or 80 and dst host {}".format(ip_iface))
    print("\n\nIDS SUMMARY: \n{}".format(ids_dict))
    print("Blacklist: \n{}".format(black_list))
    logging.info("\nLog of suspicious connections:\n{}\nLog of blaclisted IP addresses:\n{}".format(ids_dict, black_list))
    print("TERMINATING IDS DETECTION SYSTEM PROCESS")
    logging.info("TERMINATING IDS PROCESS")

if __name__ == "__main__":
    main()

    
    
