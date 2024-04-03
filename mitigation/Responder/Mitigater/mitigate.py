import paramiko

class mitigate():
    def __init__(self, logger) -> None:
        self.logger = logger
    
    def block_ip(self, config, ip_list):
        hostname = config["ip_address"]
        port = 22
        username = config["username"]
        password = config["password"]

        # IP address to block
        ip_to_block = set(ip_list)
        #ip_to_block = ['192.168.1.129']

        # SSH client
        try:
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Connect to the firewall
            ssh_client.connect(hostname, port, username, password)
            
            
            for ip in ip_to_block:
                try:
                    if (ip != hostname):
                        self.logger.info(f"Blocking IP address {ip}")
                        #implement modifying firewall to block ip 
                        command = f'echo "{password}" | sudo -S iptables -A INPUT -s {ip} -j DROP'
                        #command = 'echo "kali" |sudo iptables -L'
                        stdin, stdout, stderr = ssh_client.exec_command(command)
                except:
                    self.logger.error(f"Failed to block IP address {ip}", exc_info=True)
                    pass
        except:
            self.logger.error(f"Failed to connect to {hostname}", exc_info=True)
            pass
                
        ssh_client.close()
    
    
    
    
#Functional Testing 
if __name__ == "__main__":
    m = mitigate()
    m.block_ip()