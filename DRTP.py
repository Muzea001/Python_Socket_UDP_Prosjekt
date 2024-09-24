import socket
import time
import threading
from header import create_packet, parse_header, parse_flags

socket.setdefaulttimeout(0.5)

def is_last_packet(data):
    _, _, flags, _ = parse_header(data)
    _, _, fin = parse_flags(flags)

    return fin == 1

def SYN_packet(seq, ack, win):
    flags = (1 << 3)  # SYN=1, ACK=0, FIN=0
    return create_packet(seq, ack, flags, win, b'')

def SYN_ACK_packet(seq, ack, win):
    flags = (1 << 2) | (1 << 3)  # SYN=1, ACK=1, FIN=0
    return create_packet(seq, ack, flags, win, b'')

def ACK_packet(seq, ack, win):
    flags = (1 << 2)  # SYN=0, ACK=1, FIN=0
    return create_packet(seq, ack, flags, win, b'')

def FIN_packet(seq, ack, win):
    flags = (1 << 1)  # SYN=0, ACK=0, FIN=1
    return create_packet(seq, ack, flags, win, b'')

# The handshake function is responsible for establishing a connection between the client and the server.
# This is a crucial step in any connection-oriented communication protocol, such as TCP.
# It uses the SYN, SYN-ACK, ACK process, which ensures both sides are ready for communication.
def handshake(server_socket, client_socket, is_server, server_ip=None, server_port=None, init_seq_number=0):
    client_address = None

    # The is_server boolean flag is used to differentiate the server's handshake process from the client's.
    if is_server:
        print("-----Server: Starting handshake process------\n")

        while True:
            try:
               
                # Step 1: Server receives a SYN (Synchronize) message from the client.
                # The SYN message is the client's request to establish a connection.
                data, client_address = server_socket.recvfrom(1472)
                header = data[:12]
                _,_,flags,_ = parse_header(header)
                syn, ack, fin = parse_flags(flags)
            except TimeoutError:
                # If a TimeoutError occurs, the server will keep waiting for the SYN message.
                continue    

            while True:
                    # If the correct SYN flag is received, the server moves to step 2.
                    if flags == (1 << 3):
                        print("Server: Received SYN from client.")
                        # Step 2: Server sends a SYN-ACK (Synchronize-Acknowledge) message back to the client.
                        # This confirms that the server is ready for communication.
                        syn_ack_packet = SYN_ACK_packet(0, 0, 0)
                        server_socket.sendto(syn_ack_packet, client_address)
                        print("Server: Sent SYN-ACK to client.")
                        break
                    else:
                        # If the correct SYN flag is not received, the server keeps waiting.
                        print("Server: Waiting for correct SYN flag.")
                        continue
                
            while True:
                print("Server: Waiting for ACK from client.")
                # Step 3: Server waits for an ACK (Acknowledge) message from the client.
                # The ACK message is the client's confirmation that it is also ready for communication.
                data, _ = server_socket.recvfrom(1472)
                header=data[:12]
                _, _, flags, _ = parse_header(header)

                if flags == (1 << 2):
                    print("Server: Received ACK from client. Handshake completed.")
                    break
                else:
                    # If the correct ACK flag is not received, the server keeps waiting.
                    print("Server: Waiting for correct ACK flag.")
                    continue
            
            break
    else:
        # This part of the function handles the client-side handshake process.
        print("-----Client: Starting handshake process-----\n")
        while True:
            print("Client: Sending SYN to server.")

            # Step 1: Client sends a SYN message to the server to request a connection.
            syn_packet = SYN_packet(0, 0, 0)
            client_socket.sendto(syn_packet, (server_ip, server_port))
            print("Client: Sent SYN to server.")

            # Step 2: The client then waits for a SYN-ACK message from the server.
            print("Client: Waiting for SYN-ACK from server.")
            data, _ = client_socket.recvfrom(1472)
            header = data[:12]
            _, _, flags, _ = parse_header(header)
            syn, ack, fin = parse_flags(flags)

            if flags == (1 << 2) | (1 << 3):
                print("Client: Received SYN-ACK from server.")

                # Step 3: Upon receiving the SYN-ACK message, the client sends an ACK message to the server,
                #  thus completing the handshake.
                ack_packet = ACK_packet(0, 0, 0)
                client_socket.sendto(ack_packet, (server_ip, server_port))
                print("Client: Sent ACK to server. Handshake completed.")

                break
            else:
                print("Client: Waiting for correct SYN-ACK flag.")
                continue
        
    return client_address

# The fin_handshake function handles the termination of the connection between the client and the server.
# This termination follows the FIN, ACK process, which ensures a graceful closing of the connection.
def fin_handshake(server_socket, client_socket, is_server, server_ip=None, server_port=None):
    
    # The 'is_server' flag differentiates between the server-side and client-side termination processes.
    if is_server:
        print("------[Server]: Initiated FIN handshake, awaiting client's FIN packet.---------\n")


        while True:
                try:
                    # Server waits for a FIN (Finish) packet from the client, signaling that the client wants to 
                    # close the connection.                    
                    data, client_address = server_socket.recvfrom(1472)
                    header=data[:12]
                    _, _, flags, _ = parse_header(header)

                    if flags == (1 << 1):
                        print("[Server]: FIN packet received from client. Preparing to send ACK packet back...")

                        # Upon receiving the FIN packet, the server responds with an ACK (Acknowledge) packet.                      
                        ack_packet = ACK_packet(0, 0, 0)
                        server_socket.sendto(ack_packet, client_address)
                        print("[Server]: ACK sent to client, connection closing process is in progress.")
                        break

                    else:
                        print("[Server]: Non-FIN packet received, still waiting for client's FIN...")
                        continue
                except TimeoutError:
                    # If a TimeoutError occurs, the server keeps waiting for the FIN packet.                   
                    continue

    else:
        print("-------[Client]: Initiated FIN handshake.--------\n")

        while True:
            # Client initiates the termination process by sending a FIN packet to the server.            
            fin_packet = FIN_packet(0, 0, 0)
            client_socket.sendto(fin_packet, (server_ip, server_port))
            print("[Client]: Sending FIN to the server. Awaiting response...")

            while True:
                try:
                    # Client waits for an ACK packet from the server to confirm the closing of the connection.
                    data, _ = client_socket.recvfrom(1472)
                    seq, ack, _, _ = parse_header(data)
                    header = data[:12]
                    _, _, flags, _ = parse_header(header)

                    if flags == (1 << 2):
                        print("[Client]: ACK received from server!")
                        break
                    else:
                        print("[Client]: No ACK received from server, awaiting...")
                        continue
                except TimeoutError:
                    # If no ACK packet is received within a certain time frame, the client continues to wait.
                    print("[Client]: No ACK received from server, awaiting...")
                    break
            
            break
            
# The stop_and_wait function implements the Stop-and-Wait protocol for reliable data transmission.
# The sender sends a packet and then waits for an acknowledgement from the receiver before sending the next packet.
# This method is used both by the server to receive data and the client to send data.
def stop_and_wait(socket, is_server, file_data=None, server_ip=None, server_port=None, new_file_name=None, test_case=None):

    # In the start of each transmission, record the start time.
    start_time = time.time()

    # The 'is_server' flag differentiates between the server-side and client-side of the protocol.
    if is_server:
        print("\n------ SERVER: STOP_AND_WAIT IN DRTP METHOD STARTs ------\n")
        
        ack_counter = -2
        
        # Initialize an empty bytearray to store the received data
        received_file_data = bytearray()
        print("Server: Initialized data reception")
        while True:
            try:
                # Server waits for a packet from the client
                ack_counter += 1
                data, client_address = socket.recvfrom(1472)
                payload = data[12:]
                header = data [:12]
                # Parse the packet header to get the sequence number, ACK number, and flags
                seq, ack, flags, _ = parse_header(header)
                print(f"\nServer: Packet seq # {seq} received with ACK #{ack} and flags {flags}")

                # In case the test case is not "skip_ack" or it's not the 3rd packet (ack_counter != 2),
                # the server processes the packet normally.
                if test_case != "skip_ack" or ack_counter != 2:
                    # Add the received payload to the received_file_data bytearray
                    received_file_data.extend(payload)
                    print(f"Server: Data appended, length of received data: {len(received_file_data)} bytes")

                    # Server sends an ACK packet back to the client
                    ack += 1
                    ack_packet = ACK_packet(seq, ack, 0)
                    print(f"Server: Created ACK packet_ack #{ack}")
                    socket.sendto(ack_packet, client_address)
                    print(f"Server: ACK_packet ack #{ack} sent to client\n")
                    
                    # If the FIN flag is set, the server ends the communication
                    if flags == (1 << 1):
                        print(f"Server: Received FIN_flag #{flags}, ending communication")
                        break
                else:
                    # In the "skip_ack" test case for the packet, the server deliberately skips sending an ACK
                    print(f"Test case 'skip_ack': Server is skipped sending Ack #{ack}")
                    continue
            except TimeoutError:
                # If a TimeoutError occurs, the server keeps waiting for the packet.
                continue
                
        # Write the received data to a file    
        with open(new_file_name, 'wb') as file:
            print("Server: Writing received data to file\n")
            file.write(received_file_data)

            
        return received_file_data
        

    else:
        # Client-side of the Stop-and-Wait protocol
        print("\n------ CLIENT: STOP_AND_WAIT IN DRTP METHOD STARTs ------\n")

        # Initialize the sequence number, ACK number, the last received ACK number, and the packet counter
        sequens = 1
        ack = 0
        last_received_ack = -1
        packet_counter = 0

        # The client sends the file data in chunks of 1460 bytes (the maximum payload size) until all the data is sent.
        for i in range(0, len(file_data), 1460):
            chunk = file_data[i:i + 1460]
            print(f"\nClient: Preparing packet #{sequens}")

            # Check if this is the last chunk of data to be sent.
            # If it is, then set the FIN flag to 1, indicating the end of transmission.
            is_last_chunk = i + 1460 >= len(file_data)
            fin_flag = (1 << 1) if is_last_chunk else 0
            
            while True:
                # Increment the packet counter for each packet created.
                packet_counter += 1

                # Create a packet with the FIN flag if it's the last chunk
                packet = create_packet(sequens, ack, fin_flag, 0, chunk)
                print(f"Client: Packet #{sequens} created with ACK #{ack} and flags {fin_flag}")

                # Check if the test case is "lose" and if it's the 2nd packet (packet_counter == 2).
                # If it is, then the client deliberately skips sending this packet.
                if test_case != "lose" or packet_counter != 2:

                    # If it's not the "lose" test case for the 2nd packet,
                    # then the client sends the packet to the server.
                    socket.sendto(packet, (server_ip, server_port))
                    print(f"Client: Packet #{sequens} sent to server")
                
                if test_case == "lose" and packet_counter == 2:
                    print(f"Test case 'lose': Client is skipped sending packet #{sequens}")
                    

                # Wait for the ACK from the server
                try:
                    # Set a timeout
                    data, _ = socket.recvfrom(1472)

                    # Parse the received ACK packet header to get the sequence number, ACK number, and flags
                    header = data[:12]
                    seq, ack, flags, _ = parse_header(header)
                    print(f"\nClient: Received ACK #{ack} with seq #{seq} and flags {flags}")
                    
                    if ack == last_received_ack:  
                        # If a duplicate ACK is received, then the client resends the packet
                        print("Client: Duplicate ACK received, resending the packet")
                        continue
                    else:
                        
                        # If a valid ACK is received (ACK flag is set and the sequence number equals the ACK number),
                        # then the client breaks the loop and moves on to the next packet.
                        if flags == (1 << 2) and seq == ack:
                            last_received_ack = ack
                            sequens += 1
                            print(f"Client: Valid ACK received, preparing the next packet\n")
                            break
                        else:
                            # If the ACK is invalid, then the client keeps waiting for a valid ACK.
                            print("Client: Invalid ACK received, waiting for the valid ACK")
                            continue

                except TimeoutError:
                    print("Client: Timeout, resending the packet")
                    # If a TimeoutError occurs, then the client resends the same packet.
                    continue

            # If it's the last chunk and a valid ACK is received, then the client ends the transmission.    
            if is_last_chunk and flags == (1 << 2):
                # At the end of the transmission, record the end time.
                end_time = time.time()
                

                    # Calculate the total transferred data in MB
                total_data_Mb = (len(file_data)/1000000)*8
                total_data_Kb = (len(file_data) / 1000)*8
                total_data_MB = round(len(file_data)/1000000,2)
                total_data_KB = round(len(file_data)/1000,2)

                # Calculate the time taken in seconds
                duration = round(end_time - start_time,3) # this is in seconds
                time_taken = end_time - start_time
                

                # Calculate the bandwidth in Mbps
                bandwidth = round(total_data_Mb / time_taken if total_data_Mb >= 1 else total_data_Kb / time_taken,2)

                print("----------------------------------------------------------")
                if total_data_Mb >= 1:
                    print(f"DURATION: {duration} s\t DATA SIZE: {total_data_MB} MB\t BANDWIDTH: {bandwidth} Mbps")
                    print("----------------------------------------------------------")
                else:
                    print(f"DURATION: {duration} s\t DATA SIZE: {total_data_KB} KB\t BANDWIDTH: {bandwidth} Kbps")
                    print("----------------------------------------------------------")
                break
                    


"""
The `gbn` function implements the Go-Back-N (GBN) protocol for reliable data transmission over a network.
 It operates in both client and server modes for sending and receiving data, respectively. The function handles
   packet loss scenarios with a sliding window mechanism and acknowledgment packets.
"""
def gbn(socket, is_server, file_data=None, server_ip=None, server_port=None, new_file_name=None, N=5, test_case=None):
    
    # Test case number for simulating specific packet scenarios
    test_case_num = 2

    if is_server:
        
        print("\n------ SERVER: GO-BACK-N IN DRTP METHOD STARTS ------\n")

        # (Server code remains the same until the packet_receiver function)
        
        # Base sequence number for the sliding window
        base = 1
        # Buffer for storing out of order packets
        window_packets = []
        # Lock for synchronizing access to shared resources
        lock = threading.Lock()
        # Byte array for storing received file data
        received_file_data = bytearray()

        # Packet receiver thread function
        def packet_receiver():
            
            print("\nSERVER: packet_receiver: Thread start ------\n")

            # Nonlocal keyword allows us to assign to variables in the nearest enclosing scope that is not global
            nonlocal base
            nonlocal window_packets
            nonlocal received_file_data

            # Continuously listen for incoming packets
            while True:
                try:
                    # Receive a packet from the client
                    data, client_address = socket.recvfrom(1472)
                    seq, ack, flags, _ = parse_header(data[:12])
                    print(f"\n------\nServer: Received packet seq #{seq}, ACK #{ack}, and flags {flags}")
                    payload = data[12:]
                    
                    # If the packet sequence number is equal to the base, it's the packet we're expecting
                    if seq == base:
                        # Append the packet data to our received data
                        print(f"\nServer: Checking if packet seq #{seq} equals base {base}")
                        received_file_data.extend(payload)

                        # Skip acknowledgement for the second packet if test_case is "skip_ack"
                        if test_case == "skip_ack" and seq == test_case_num:
                            print(f"Server: 'Skipping' acknowledgement for packet #{seq} (Test case: 'skip_ack')")
                        else:
                            # Send an acknowledgment packet back to the client
                            ack_packet = create_packet(0, seq, flags, 0, b'')
                            print(f"\nServer: Created ACK packet #{seq}, with flags {flags}")
                            socket.sendto(ack_packet, client_address)
                            print(f"Server: Sent ACK packet #{seq} to client\n------")

                        with lock:
                             # Increase the base sequence number
                            base += 1

                            # Remove the first packet from the window
                            if window_packets:
                                window_packets.pop(0)

                        if flags == (1 << 1):
                            print(f"\nServer: Received FIN flag, ending communication.....")
                            #if received FIN flag, stop listening and receive any more packets.
                            break        

                    elif base < seq:
                        #if the received packet wasn't in order, e.g losing previous packet. it will be ignored and send it
                        #to the window_packets.
                        with lock:
                            window_packets.append((seq, payload))
                            window_packets.sort(key=lambda x: x[0])
                        
                except TimeoutError:
                    #in case of late in receiving more packet, relooping to listening until receiving FIN flag.
                    continue
            print("\n------ SERVER: packet_receiver: Thread finished\n")        
        
        # Start the packet receiver thread
        recv_thread = threading.Thread(target=packet_receiver)
        recv_thread.start()
        
        recv_thread.join()
        
        with open(new_file_name, 'wb') as file:
            print("\n------ Server: Writing received data to file ------\n")
            file.write(received_file_data)

        return received_file_data

    else:
      
        # Client side
        print("------ CLIENT: GO-BACK-N IN DRTP METHOD STARTS ------\n")

        # start time of sending data
        start_time = time.time()

        # `c_base` and `c_next_seq_num` are sequence numbers representing the base of the window 
        # and the next packet to be sent, respectively
        c_base = 1
        c_next_seq_num = 1
        # `c_window_packets` is a list used to keep track of packets within the window that have been sent but not yet acknowledged
        c_window_packets = []
        # `c_lock` is a threading lock used to ensure that operations on shared resources are performed atomically 
        c_lock = threading.Lock()
        packet_counter = 0 # To be used in the double test case

        # `c_packet_sender` is a function to handle the sending of packets
        def c_packet_sender():
            print("CLIENT: c_packet_sender: Thread started ------\n")
            
            # Make `c_base`, `c_next_seq_num`, and `c_window_packets` accessible in this function
            nonlocal c_base
            nonlocal c_next_seq_num
            nonlocal c_window_packets
            nonlocal packet_counter

            # Divide the file data into chunks to send as individual packets
            chunks = [file_data[i:i + 1460] for i in range(0, len(file_data), 1460)]
            # Continuously send packets while there are still chunks left to send
            while True:
                

                # Send all packets in the current window
                while c_next_seq_num < c_base + N and c_next_seq_num <= len(chunks):
                    # Increment the packet counter for each packet created.
                    packet_counter += 1

                    # Create a packet for the current chunk
                    chunk = chunks[c_next_seq_num - 1]
                    print(f"\n------\nClient: Creating chunk #{c_next_seq_num}")
                    fin_flag = (1 << 1) if c_next_seq_num == len(chunks) else 0
                    packet = create_packet(c_next_seq_num, 0, fin_flag, 0, chunk)
                    print(f"Client: Created packet #{c_next_seq_num} with flags {fin_flag}")

                    # Add the packet to the window
                    with c_lock:
                        c_window_packets.append((packet, time.time()))
                        
                    # Check if the test case is "double" and if it's the 2nd packet (packet_counter == 2).
                    # If it is, then the client deliberately sends this packet twice.
                    if test_case == "double" and packet_counter == 2:
                        print(f"Test case 'DOUBLE': Client is sending packet #{c_next_seq_num} twice")
                        socket.sendto(packet, (server_ip, server_port))
                        print(f"Client: Sent packet #{c_next_seq_num} to server\n------")
                        socket.sendto(packet, (server_ip, server_port))
                        print(f"Client: Packet #{c_next_seq_num} sent to server twice")

                    # "Lose" a packet if test_case is "lose" and c_next_seq_num =2 in our case, we can edit it as well.
                    elif test_case == "lose" and c_next_seq_num == test_case_num:
                        print(f"Client: skipped sending packet #{c_next_seq_num} (Test case: 'lose')")
                    else:
                        # Send the packet
                        socket.sendto(packet, (server_ip, server_port))
                        print(f"Client: Sent packet #{c_next_seq_num} to server\n------")
                    
                    c_next_seq_num += 1
                
                # Exit the loop if all packets have been sent
                with c_lock:
                    if fin_flag == (1 << 1):
                        print(f"Client: NO MORE PACKETS TO SEND")
                        break

            print("\n------ CLIENT: c_packet_sender: Thread finished\n")
           

        # `c_packet_receiver` is a function to handle the receiving of acknowledgements
        def c_packet_receiver():
            print("\nCLIENT: c_packet_receiver: Thread started ------\n")

            # Make `c_base` and `c_window_packets` accessible in this function
            nonlocal c_base
            nonlocal c_window_packets

            # Continuously listen for acknowledgements
            while True:
                try:
                    # Receive an acknowledgement from the server
                    data, _ = socket.recvfrom(1472)
                    _, ack, flags, _ = parse_header(data[:12])
                    print(f"\n------\nClient: Received ACK #{ack} with flags {flags}")

                    # Update the window based on the received acknowledgement
                    with c_lock:
                        if ack >= c_base:
                            # Remove all acknowledged packets from the window
                            while c_window_packets:
                                packet, time = c_window_packets[0]
                                seq_num, _, _, _ = parse_header(packet[:12])  # assuming that header is the first 12 bytes
                                if seq_num <= ack:
                                    c_window_packets.pop(0)
                                    print(f"Client: Popped packet #{seq_num} from window_packets")
                                else:
                                    break
                            c_base = ack + 1
                        # If we received a packet with a FIN flag, we end the communication.
                        if flags == (1 << 1):
                            import time
                            print(f"\nClient: Received FIN flag, ending communication......\n")
                            
                            # At the end of the transmission, record the end time.
                            end_time = time.time()
                            
                            # Calculate the total transferred data in MB
                            total_data_Mb = (len(file_data)/1000000)*8
                            total_data_Kb = (len(file_data) / 1000)*8
                            total_data_MB = round(len(file_data)/1000000,2)
                            total_data_KB = round(len(file_data)/1000,2)

                            # Calculate the time taken in seconds
                            duration = round(end_time - start_time,3) # this is in seconds
                            time_taken = end_time - start_time
                            

                            # Calculate the bandwidth in Mbps
                            bandwidth = round(total_data_Mb / time_taken if total_data_Mb >= 1 else total_data_Kb / time_taken,2)

                            print("----------------------------------------------------------")
                            if total_data_Mb >= 1:
                                print(f"DURATION: {duration} s\t DATA SIZE: {total_data_MB} MB\t BANDWIDTH: {bandwidth} Mbps")
                                print("----------------------------------------------------------")
                            else:
                                print(f"DURATION: {duration} s\t DATA SIZE: {total_data_KB} KB\t BANDWIDTH: {bandwidth} Kbps")
                                print("----------------------------------------------------------")
                            break
                except TimeoutError:
                    # If we hit a timeout, it means we haven't received an ACK for a packet. 
                    # We resend all packets in the window.
                    with c_lock:
                        for packet, _ in c_window_packets:
                            socket.sendto(packet, (server_ip, server_port))
                            print(f"\nClient: RESEND Window")

            # Once we have received all ACKs (or hit the maximum number of retries), this thread can finish.    
            print("\n------ CLIENT: c_packet_receiver: Thread finished\n")

        # Start a thread for sending packets and another for receiving ACKs. This allows us to send and receive simultaneously.
        send_thread = threading.Thread(target=c_packet_sender)
        send_thread.start()

        c_recv_thread = threading.Thread(target=c_packet_receiver)
        c_recv_thread.start()

        # We wait until both threads have finished before we continue. This is necessary to ensure that all packets have been 
        # sent and all acknowledgements have been received before the program exits.
        send_thread.join()
        c_recv_thread.join()

# Method implements Selective Repeat protocol.
def sr(socket, is_server, file_data=None, server_ip=None, server_port=None, new_file_name=None, N=5, test_case=None):
    
    #to be used at the test case.
    test_case_num = 2

    # The server side of the protocol
    if is_server:
        print("\n------ SERVER: SELECTIVE REPEAT IN DRTP METHOD STARTS ------")
        
        # Defines the base sequence number and a list to hold received packets
        base = 1
        expected_seq_num = 1
        received_packets = []
        lock = threading.Lock()
        received_file_data = bytearray()

        # A thread that handles receiving packets from the client
        # Handles incoming packets from the client
        # This function runs in its own thread to allow simultaneous sending and receiving
        def packet_receiver():
            # Acknowledgment counter
            ack_counter = 0
            print("\nSERVER: packet_receiver: Thread start ------\n")

            # Local variables to access shared variables
            nonlocal base
            nonlocal expected_seq_num
            nonlocal received_packets
            nonlocal received_file_data

            # Packet receiving loop
            while True:
                
                try:
                    # Receive data from the client
                    data, client_address = socket.recvfrom(1472)

                    # Parse the packet header
                    seq, ack, flags, _ = parse_header(data[:12])
                    print(f"\n------\nServer: Received packet seq #{seq}, ACK #{ack}, and flags {flags}")
                    payload = data[12:]
                    ack_counter += 1

                    # Skip acknowledgement for a packet if test_case is "skip_ack"
                    if test_case == "skip_ack" and ack_counter == 2:
                        print(f"Server: 'Skipping' acknowledgement for packet #{seq} (Test case: 'skip_ack')")
                    else:
                        # Send an ACK back to the client for the received packet
                        ack_packet = create_packet(0, seq, flags, 0, b'')
                        print(f"\nServer: Created ACK packet #{seq}, with flags {flags}")
                        socket.sendto(ack_packet, client_address)
                        print(f"Server: Sent ACK packet #{seq} to client\n------")

                    # If the expected packet is received, append it to the data
                    if seq == expected_seq_num:
                        received_file_data.extend(payload)

                        with lock:
                            expected_seq_num += 1
                            # re-sort the received packets
                            received_packets.sort(key=lambda x: x[0])

                            # keep checking if the next packet has received already and stored in the received_packets array.
                            # and remove it from the array if founded.
                            while received_packets and received_packets[0][0] == expected_seq_num:
                                _, payload = received_packets.pop(0)
                                received_file_data.extend(payload)
                                expected_seq_num += 1

                        if flags == (1 << 1):
                            print(f"\nServer: Received FIN flag, ending communication.....")
                            # Stop the receiving process after received FIN flag.
                            break        

                    # If a packet with a higher sequence number is received, it is stored in received_packets list 
                    # and to handle later in order.
                    elif seq > expected_seq_num:
                        with lock:
                            # store the packet and re-sort the list
                            received_packets.append((seq, payload))
                            received_packets.sort(key=lambda x: x[0])
                        
                except TimeoutError:
                    continue
            print("\n------ SERVER: packet_receiver: Thread finished\n")        

        # Start the packet receiver thread
        recv_thread = threading.Thread(target=packet_receiver)
        recv_thread.start()
        
        # Wait for the packet receiver thread to finish
        recv_thread.join()
        
        # Write the received data to a file
        with open(new_file_name, 'wb') as file:
            print("\n------ Server: Writing received data to file ------\n")
            file.write(received_file_data)

        return received_file_data

    # The client side of the protocol
    else:
        # Client side
        print("------ CLIENT: GO-BACK-N IN DRTP METHOD STARTS ------\n")

        # Defines the base sequence number and a list to hold window packets
        Timeout = 0.5
        c_base = 1
        c_next_seq_num = 1
        c_window_packets = []
        c_lock = threading.Lock()
        packet_counter = 0 # To be used in the double test case

        # start time of sending data
        start_time = time.time()

        # The thread function responsible for sending packets to the server
        def c_packet_sender():
            print("c_packet_sender: Thread started")

            # Local variables to access shared variables
            nonlocal c_base
            nonlocal c_next_seq_num
            nonlocal c_window_packets
            nonlocal packet_counter

            # Divide the file data into chunks of size 1460 (maximum size that can fit into a packet)
            chunks = [file_data[i:i + 1460] for i in range(0, len(file_data), 1460)]
            all_chunks_sent = False

            # Continuously send packets while there are still packets to send
            while True:
                

                while c_next_seq_num < c_base + N and c_next_seq_num <= len(chunks):

                    # Increment the packet counter for each packet created.
                    packet_counter += 1

                    # Create a packet for the current chunk
                    chunk = chunks[c_next_seq_num - 1]
                    print(f"\n------\nClient: Creating chunk #{c_next_seq_num}")

                    # set FIN flag to last packet
                    fin_flag = (1 << 1) if c_next_seq_num == len(chunks) else 0

                    packet = create_packet(c_next_seq_num, 0, fin_flag, 0, chunk)
                    print(f"Client: Created packet #{c_next_seq_num} with flags {fin_flag}")

                    # append all the packets to be poped later after their ACKs be received
                    with c_lock:
                        # here we added the time of adding (sending) the packet, 
                        # to be checked later.
                        c_window_packets.append((c_next_seq_num, packet, time.time()))


                    # Check if the test case is "double" and if it's the 2nd packet (packet_counter == 2).
                    # If it is, then the client deliberately sends this packet twice.
                    if test_case == "double" and packet_counter == 2:
                        
                        socket.sendto(packet, (server_ip, server_port))
                        print(f"Client: Sent packet #{c_next_seq_num} to server")
                        socket.sendto(packet, (server_ip, server_port))
                        print(f"Client: Sent packet #{c_next_seq_num} to server")
                        print(f"Test case 'DOUBLE': Client is sending packet #{c_next_seq_num} twice")

                    # skip sending a packet if test_case is "lose"
                    elif test_case == "lose" and c_next_seq_num == test_case_num:
                        print(f"Client: skipped sending packet #{c_next_seq_num} (Test case: 'lose')")
                    else:
                        # else sent packets as normal
                        socket.sendto(packet, (server_ip, server_port))
                        print(f"Client: Sent packet #{c_next_seq_num} to server\n------")
                    
                    c_next_seq_num += 1

                    # If all chunks have been sent, set the flag all_chunks_sent
                    if c_next_seq_num > len(chunks):
                        all_chunks_sent = True  # All chunks have been sent

                # Check for timed out packets and resend them.
                with c_lock:
                    
                    current_time = time.time()
                    # parse sending time for each packet, if it still in the array more than 0.5 sec, 
                    # it will send again.
                    for seq_num, packet, send_time in c_window_packets:
                        if current_time - send_time > Timeout:  # assuming Timeout is defined somewhere
                            socket.sendto(packet, (server_ip, server_port))
                            print(f"Client RESENT packet: {seq_num} ")

                # If all chunks have been sent and all ACKs have been received, break the loop
                if all_chunks_sent and not c_window_packets:
                    print(f"Client: NO MORE PACKETS TO SEND")
                    break

            print("\n------ CLIENT: c_packet_sender: Thread finished\n")

        # The thread function responsible for receiving ACKs from the server
        def c_packet_receiver():
            print("\nCLIENT: c_packet_receiver: Thread started ------\n")

            # Local variables to access shared variables
            nonlocal c_base
            nonlocal c_window_packets

            # Continuously receive ACKs from the server
            while True:
                try:
                    # Receive an ACK from the server
                    data, _ = socket.recvfrom(1472)

                    # Parse the packet header
                    _, ack, flags, _ = parse_header(data[:12])
                    print(f"\n------\nClient: Received ACK #{ack} with flags {flags}")

                    # Update the window based on the received ACK
                    with c_lock:
                        # Update the timestamp of the acknowledged packet
                        for i in range(len(c_window_packets)):
                            if c_window_packets[i][0] == ack:
                                c_window_packets[i] = (c_window_packets[i][0], c_window_packets[i][1], time.time())
                                break

                        # remove all the ACKed packets.
                        c_window_packets = [(seq_num, packet, send_time) for seq_num, packet, send_time in c_window_packets if seq_num != ack]

                        # Update the base sequence number, where it equal to min ACK in the array.
                        # which mean the min ACK for none ACKed packet.
                        if c_window_packets:
                            c_base = min(seq_num for seq_num, _, _ in c_window_packets)
                        else:
                            # if all the packets ACKed then slide the window.
                            c_base = c_next_seq_num

                        #if the FIN flag received, then Stop receiving.
                        if flags == (1 << 1):
                            print(f"\nClient: Received FIN flag, ending communication......\n")

                            # At the end of the transmission, record the end time.
                            end_time = time.time()
                            
                            # Calculate the total transferred data in MB
                            total_data_Mb = (len(file_data)/1000000)*8
                            total_data_Kb = (len(file_data) / 1000)*8
                            total_data_MB = round(len(file_data)/1000000,2)
                            total_data_KB = round(len(file_data)/1000,2)

                            # Calculate the time taken in seconds
                            duration = round(end_time - start_time,3) # this is in seconds
                            time_taken = end_time - start_time
                            

                            # Calculate the bandwidth in Mbps
                            bandwidth = round(total_data_Mb / time_taken if total_data_Mb >= 1 else total_data_Kb / time_taken,2)

                            print("----------------------------------------------------------")
                            if total_data_Mb >= 1:
                                print(f"DURATION: {duration} s\t DATA SIZE: {total_data_MB} MB\t BANDWIDTH: {bandwidth} Mbps")
                                print("----------------------------------------------------------")
                            else:
                                print(f"DURATION: {duration} s\t DATA SIZE: {total_data_KB} KB\t BANDWIDTH: {bandwidth} Kbps")
                                print("----------------------------------------------------------")
                            break

                except TimeoutError:
                    continue
                
            print("\n------ CLIENT: c_packet_receiver: Thread finished\n")

        # Start the packet sender and receiver threads
        send_thread = threading.Thread(target=c_packet_sender)
        send_thread.start()

        c_recv_thread = threading.Thread(target=c_packet_receiver)
        c_recv_thread.start()

        send_thread.join()
        c_recv_thread.join()




        
       

        
