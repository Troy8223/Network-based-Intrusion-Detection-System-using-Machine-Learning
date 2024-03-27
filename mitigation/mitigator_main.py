from Responder.Mitigater import mitigate
from Responder.Notifyer.notify import notify
from Responder.Mitigater.mitigate import mitigate
import yaml 
import logging
import os
import pandas as pd
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

def construct_html_table(table_data):
    html_table = '<table border="1" style="width: 40%; margin: 0 auto; padding: 10px; background-color: #f0f0f0; border: 1px solid #ccc; border-radius: 10px; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);">'
    table_data = table_data.split("  ")[:-1]
    for row in table_data:
        html_table += '<tr>'
        for cell in row.split(":"):
            html_table += f'<td>{cell}</td>'
        html_table += '</tr>'
    html_table += '</table>'
    return html_table




if __name__ == "__main__":
#Variable Declaration zone
    
    #File related
    with open("config/mitigation.yaml") as file:
        mitigator_yaml = yaml.load(file, Loader= yaml.FullLoader)
    with open("config/common.yaml") as file:
        common_yaml = yaml.load(file, Loader=yaml.FullLoader)
        
    working_directory = common_yaml["working-directory"]
    csv_directory = working_directory + common_yaml["pre-processed_csv_files"]
    adnormal_traffics_csv = working_directory + common_yaml["abnormal_traffics_csv"]
    mitigator_log_file = working_directory + mitigator_yaml["mitigator_log_file"]
    devices_setting = mitigator_yaml["devices_setting"]
    notify_connection_setting = mitigator_yaml["connection_setting"]
    template_path = working_directory + common_yaml["template"]
    
    #Logger
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(name)s | %(levelname)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
                        )
    formatter = logging.Formatter(
        "%(asctime)s | %(name)s | %(levelname)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    mitigator_log_handler = logging.FileHandler(mitigator_log_file)
    mitigator_log_handler.setFormatter(formatter)
    logger = logging.getLogger('mitigator')
    logger.addHandler(mitigator_log_handler)
    
    notify_logger = logging.getLogger('Notify')
    notify_logger.addHandler(mitigator_log_handler)
    
    threat_handler_logger = logging.getLogger('Threat_Handler')
    threat_handler_logger.addHandler(mitigator_log_handler)
    
    #Mitigation 
    logger.info("Starting mitigator")
    adnormal_traffics_csv_files = os.listdir(adnormal_traffics_csv)
    if len(adnormal_traffics_csv_files):
        for file in adnormal_traffics_csv_files:
            logger.info(f"Processing file: {file}")
            data = pd.read_csv(adnormal_traffics_csv + file)
            device_name = file.split("_")[1]
            
        #Extract Infomation to msg body 
            #Convert timestamp to datetime
            detection_period = pd.to_datetime(data["ts"], unit='s')
            detection_period_from = detection_period.iloc[0]
            detection_period_to = detection_period.iloc[-1]
            logger.info(f"Detection period from {detection_period_from} to {detection_period_to}")
            
            #Detected result simple summary
            detection_result = data["Result"]
            simple_summary = detection_result.value_counts().to_dict()
            category = simple_summary.keys()
            summary_msg = ""
            for key in category:
                msg = f"{key}:{simple_summary[key]}  "
                summary_msg += msg
                logger.warning(f"Potential intrusion, {msg}")

            logger.info(f"Detection Simple Summary as follow, from {detection_period_from} to {detection_period_to}, device {device_name} experienced potential instrusion of {summary_msg}")
            
            logger.info("Writing to template and notify admins.")
            
            send_msg = ""
            summary_msg_table = construct_html_table(summary_msg)
            with open(template_path + mitigator_yaml["email_template"]) as template:
                send_msg = template.read()
            send_msg = send_msg.format(device=device_name
                                  , start=detection_period_from
                                  , end=detection_period_to
                                  , results=summary_msg_table
                                  )            
            if device_name in devices_setting.keys():
                logger.info(f"Start notifying admins for {device_name}")
                notifyer = notify(notify_logger, notify_connection_setting)
                notify_profile = devices_setting[device_name]
                notify_methods = notify_profile.keys()
                
                for method in notify_methods:
                    try:
                        match method:
                            case "http":
                                notifyer.http_notify(notify_profile[method], send_msg)
                                pass
                            case "smtp":
                                notifyer.smtp_notify(notify_profile[method], send_msg)
                                pass
                            case "scp":
                                notifyer.scp_notify(notify_profile[method], adnormal_traffics_csv + file)
                                pass
                    except:
                        logger.error(f"{method.upper} Notify Failed for {device_name}", exc_info=True)
            else:
                logger.error(f"No notify setting found for {device_name} ")
                continue
            
            #Mitigate
            for attack_type, cnt in simple_summary.items():
                if attack_type == "DDoS" or attack_type == "DoS": 
                    logger.info(f"Mitigating {attack_type} attack.") 
                    mitigator = mitigate(threat_handler_logger)
                    try:
                        mitigator.block_ip(devices_setting[device_name], [])
                        
                    except:
                        logger.error(f"Mitigation failed for {attack_type} attack.", exc_info=True)
            

    
    else:
        logger.info("No adnormal traffics at the moment.")
    
    
    pass
    #parse config file
    #Check logic to determine how to notify 
    #And will any mitigation action be taken
    
