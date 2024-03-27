import http.client 
import smtplib
from paramiko import SSHClient
from scp import SCPClient
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

class notify:
    
    def __init__(self, logger, connection_config) -> None:
        self.logger = logger
        self.smtp_config = connection_config["default_smtp"]
        self.scp_config = connection_config["default_scp"]
        self.http_config = connection_config["default_http"]
        
    def construct_email(self, msg, from_email, to_email):
        email = MIMEMultipart()
        email['From'] = from_email
        email['To'] = to_email
        email['Subject'] = "NIDS Alert: Potential Intrusion Summary"

        email.attach(MIMEText(msg, 'html'))
        return email
        
    def http_notify(self, config, msg):        
        try:
            for url in config["url"]:
                conenction = http.client.HTTPConnection(url)
                self.logger.info(f"HTTP GET request to {url}")
                
                try:
                    conenction.request("GET","/", body=msg)
                    response = conenction.getresponse()
                    if 200 == response.getcode():
                        self.logger.info("Connection Success")
                    else:
                        self.logger.info("Connection Failed")
                        self.logger.info(f"Response, \n{response.info()}")
                except:
                    self.logger.error("HTTP Connection Failed", exc_info=True)
        except:
            self.logger.error(f"Invaild URL! {url}", exc_info=True)
        return True
            
    def smtp_notify(self, config, msg):    
        try:
            sender = self.smtp_config["sender_email"]
            smtp_server = self.smtp_config["smtp_server"]
            smtp_port = self.smtp_config["port"]
            
            with smtplib.SMTP_SSL(host=smtp_server, port=smtp_port) as smtp:
                self.logger.info(f"Connecting to SMTP server {smtp_server}:{smtp_port} with mail account {sender}")
                smtp.ehlo()
                self.logger.info(f"Connecting to SMTP with mail account {sender}")
                smtp.login(sender, self.smtp_config["application_token"])    
                self.logger.info(f"SMTP connection Success.")
                
                for addr in config["client_email_address"]:
                    try:
                        self.logger.info(f"Sending email to {addr}")
                        email = self.construct_email(msg, sender, addr).as_string()
                        smtp.sendmail(sender, addr, email, mail_options=(), rcpt_options=())
                        self.logger.info(f"Email is sent to {addr}")
                    except:
                        self.logger.error("SMTP Connection Failed", exc_info=True)
                        pass
        except:
            self.logger.error("SMTP Connection Failed", exc_info=True)
            
        return True
        
    def scp_notify(self, config, file):
        try:
            ssh = SSHClient()
            ssh.load_system_host_keys()   
            targets = config.keys()
            for target in targets:
                profile = config[target]
                #print(target)
                dst = profile["ip"]
                store_file_path = self.scp_config["store_file_path"]
                ssh.connect(dst, username=profile["username"], password=profile["password"])
                scp = SCPClient(ssh.get_transport())
                
                scp.put(file, recursive=True, remote_path=store_file_path)
                self.logger.info(f"SCP File putting {file.split('/')[-1]} Success to {dst} at {store_file_path}.")
                scp.close()
        except:
            self.logger.error("SCP Connection Failed.", exc_info=True)
        
if __name__ == "__main__":
    import logging 
    import yaml 
    
    with open("config/mitigation.yaml") as file:
        mitigator_yaml = yaml.load(file, Loader= yaml.FullLoader)
    with open("config/common.yaml") as file:
        common_yaml = yaml.load(file, Loader=yaml.FullLoader)
        
    working_directory = common_yaml["working-directory"]
    csv_directory = working_directory + common_yaml["pre-processed_csv_files"]
    adnormal_traffics_csv = working_directory + common_yaml["abnormal_traffics_csv"]
    mitigator_log_file = working_directory + mitigator_yaml["mitigator_log_file"]
    devices_notify_setting = mitigator_yaml["devices_notify_setting"]
    notify_connection_setting = mitigator_yaml["connection_setting"]
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(name)s | %(levelname)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
                        )
    
    logger = logging.getLogger("test")
    
    config  = {"url" : ["127.0.0.1:8000"]}
    config = {"client_email_address": ["ccting6-c@my.cityu.edu.hk"]}
    config = {'target_1': {'ip': '192.168.224.128', 'username': 'kali', 'password': 'kali'}, 'target_2': {'ip': '192.168.224.128', 'username': 'kali', 'password': 'kali'}}
    n = notify(logger, notify_connection_setting)
    #print(devices_notify_setting["device-a"]["scp"])
    #n.http_notify(config, "Hi")
    n.scp_notify(config, "Hi")