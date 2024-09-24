import argparse
import socket
import os
from DRTP import handshake, fin_handshake, stop_and_wait, gbn, sr

def server(server_ip, server_port, reliable_method, test_case=None):
    # Set up a UDP server
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((server_ip, server_port))

    print(f"Server is listening on {server_ip}:{server_port} Reliable method: {reliable_method}", end="")
    if test_case:
        print(f"  Test case: {test_case}")
    else:
        print()
        
    while True:

        client_address = handshake(server_socket, None, True)

        # Receive the file name from the client
        file_name_binary, _ = server_socket.recvfrom(1024)
        file_name = file_name_binary.decode('latin1')  # Use latin1 encoding to preserve binary data
        print(f"Server: Received file name '{file_name}' from the client")
        new_file_name = os.path.splitext(file_name)[0] + "_rcv" + os.path.splitext(file_name)[1]
        print(f"Server: Will save the file in name: '{new_file_name}'.")


        # Print the client IP and port after handshake is complete
        print(f"Server: Connected to client at {client_address[0]}:{client_address[1]}")
                       
        if reliable_method == "stop_and_wait":
            stop_and_wait(server_socket, True, new_file_name=new_file_name, test_case=("skip_ack" if test_case == "skip_ack" else None))

        elif reliable_method == "gbn":
            gbn(server_socket, True, server_ip=server_ip, server_port=server_port, new_file_name=new_file_name, test_case=("skip_ack" if test_case == "skip_ack" else None))

        elif reliable_method == "sr":
            sr(server_socket, True, server_ip=server_ip, server_port=server_port, new_file_name=new_file_name, test_case=("skip_ack" if test_case == "skip_ack" else None)) 
            
        # Call the fin_handshake method after receiving the file data 
        fin_handshake(server_socket, None, True)
        # Add a print statement to display that the connection with the client has been closed
        print(f"Server: Connection with client at {client_address[0]}:{client_address[1]} has been closed")
        break



def client(server_ip, server_port, file_path, reliable_method, test_case=None):
    # Set up a UDP client
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    handshake(None, client_socket, False, server_ip, server_port, 1)

    # Send the file name to the server
    file_name = os.path.basename(file_path)
    file_name_binary = file_name.encode('latin1')  # Use latin1 encoding to preserve binary data
    client_socket.sendto(file_name_binary, (server_ip, server_port))
    print(f"Client: Sent file name '{file_name}' to the server\n")

    # Read the file in binary mode
    with open(file_path, 'rb') as file:
        file_data = file.read()

    valid_reliable_methods = ["stop_and_wait", "gbn", "sr"]

    if reliable_method == "stop_and_wait":
        stop_and_wait(client_socket, False, file_data, server_ip, server_port, test_case=("lose" if test_case == "lose" else "double" if test_case == "double" else None)) 

    elif reliable_method == "gbn":
        gbn(client_socket, False, file_data=file_data, server_ip=server_ip, server_port=server_port, test_case=("lose" if test_case == "lose" else "double" if test_case == "double" else None))

    elif reliable_method == "sr":
        sr(client_socket, False, file_data=file_data, server_ip=server_ip, server_port=server_port, test_case=("lose" if test_case == "lose" else "double" if test_case == "double" else None))
    
    


    # Call the fin_handshake method after sending the file data
    fin_handshake(None, client_socket, False, server_ip, server_port)
    print(f"Client: Connection with server at {server_ip}:{server_port} has been closed\n")

def main():
    # Set up argument parsing
    parser = argparse.ArgumentParser(description="Python UDP client-server application")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-s", "--server", action="store_true", help="Run as server")
    group.add_argument("-c", "--client", action="store_true", help="Run as client")
    parser.add_argument("-i", "--ip", type=str, required=True, help="Server IP address")
    parser.add_argument("-p", "--port", type=int, required=True, help="Server port number")
    parser.add_argument("-f", "--file", type=str, help="File to transfer (required for client)")
    parser.add_argument("-r", "--reliable", type=str, required=True, help="Reliable method")
    parser.add_argument("-t", "--test", type=str, help="Test case (optional)")

    args = parser.parse_args()

    valid_reliable_methods = ["stop_and_wait", "gbn", "sr"]
    if args.reliable not in valid_reliable_methods:
        print(f"Error: Invalid reliable method. Use one of {valid_reliable_methods}.")
        return

    valid_test_cases = ["lose", "skip_ack","double", None]
    if args.test not in valid_test_cases:
        print(f"Error: Invalid test case. Use one of {valid_test_cases}.")
        return

    if args.server and args.test == "lose":
        print("Error: 'lose' test case can only be used with -c (client).")
        return
    elif args.client and args.test == "skip_ack":
        print("Error: 'skip_ack' test case can only be used with -s (server).")
        return
    
    if args.server and args.file:
        print("Error: File should not be specified when running as a server. Remove -f argument.")
        return

    if args.server:
        server(args.ip, args.port, args.reliable, args.test)
    elif args.client:
        if args.file:
            client(args.ip, args.port, args.file, args.reliable, args.test)
        else:
            print("Error: File is required when running as a client. Use -f to specify the file.")
    else:
        print("Error: Invalid arguments. Use -s for server or -c for client.")

if __name__ == "__main__":
    main()
