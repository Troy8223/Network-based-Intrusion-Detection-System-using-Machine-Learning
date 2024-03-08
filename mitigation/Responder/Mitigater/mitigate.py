import paramiko

class mitigate():
    def __init__(self) -> None:
        pass
    
    def block_ip(self, config, ip_list):
        hostname = config["ip_address"]
        port = 22
        username = config["username"]
        password = config["password"]

        # IP address to block
        ip_to_block = '192.168.1.100'

        # SSH client
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Connect to the firewall
        ssh_client.connect(hostname, port, username, password)
        
        #implement IP list
        # Execute command to block the IP address
        command = f'echo "kali" | sudo -S iptables -A INPUT -s {ip_to_block} -j DROP'
        command = 'echo "kali" |sudo iptables -L'
        stdin, stdout, stderr = ssh_client.exec_command(command)
        print(stdout.read())
        # Close the SSH connection
        ssh_client.close()
    
    
if __name__ == "__main__":
    m = mitigate()
    m.block_ip()