import pandas as pd
import os
import yaml
from joblib import load as joblib_load
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import MinMaxScaler, StandardScaler
from Feature_extraction_Module.Data_cleaning import Data_cleaning
import logging

#def main():
if __name__ == "__main__":
#Variable Declaration zone
    
    #File related
    with open("config/common.yaml") as file:
        common_yaml = yaml.load(file, Loader= yaml.FullLoader)
    working_directory = common_yaml["working-directory"]
    #print(common_yaml["model"])
    model = joblib_load(common_yaml["model"])
    csv_directory = working_directory + common_yaml["pre-processed_csv_files"]
    raw_pcap_directory = working_directory + common_yaml["raw_pcap"]
    detection_log_file = working_directory + common_yaml["detection_log_file"]
    cleaner_log_file = working_directory + common_yaml["cleaner_log_file"]
    
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
    detection_log_handler = logging.FileHandler(detection_log_file)
    detection_log_handler.setFormatter(formatter)
    logger = logging.getLogger('detection')
    logger.addHandler(detection_log_handler)
    
    cleaner_logger = logging.getLogger("cleaner")
    cleaner_log_handler = logging.FileHandler(cleaner_log_file)
    cleaner_log_handler.setFormatter(formatter)
    cleaner_logger.addHandler(cleaner_log_handler)

    #AI Model related
    scaler = StandardScaler()
    X_columns = [
    'flow_duration', 'Header_Length', 'Protocol Type', 'Duration', 
       'Rate', 'Srate', 'Drate', 'fin_flag_number', 'syn_flag_number',
       'rst_flag_number', 'psh_flag_number', 'ack_flag_number',
       'ece_flag_number', 'cwr_flag_number', 'ack_count',
       'syn_count', 'fin_count', 'urg_count', 'rst_count', 
    'HTTP', 'HTTPS', 'DNS', 'Telnet', 'SMTP', 'SSH', 'IRC', 'TCP',
       'UDP', 'DHCP', 'ARP', 'ICMP', 'IPv', 'LLC', 'Tot sum', 'Min',
       'Max', 'AVG', 'Std', 'Tot size', 'IAT', 'Number', 'Magnitue',
       'Radius', 'Covariance', 'Variance', 'Weight', 
]
    y_column = 'label'
    

#Pre-process raw_pcap to pre-processed_csv_files
    cleaner  = Data_cleaning(working_directory, cleaner_logger)
    logger.info(f"Starting Data Cleaning at {raw_pcap_directory}")
    cleaner.clean()
    #cleaner.clean_optimized()
    logger.info(f"Raw pcap cleaned. Saved at {csv_directory}")
    #call clean_data module to output desired csv

#detection logic
    logger.info("Starting Detection")
    csv_files = os.listdir(csv_directory)
    if len(csv_files):    
        for csv_file in os.listdir(csv_directory):
            logger.info(f"Processing file {csv_file}")
            #load csv from pre-processed_csv_files and predict
            scaler.fit(pd.read_csv(csv_directory + csv_file)[X_columns])
            data = pd.read_csv(csv_directory + csv_file)
            data[X_columns] = scaler.transform(data[X_columns])
            detection_results = pd.DataFrame(model.predict(data[X_columns]))
            
            #Combine result with original data
            data.insert(0,column="Result",value=detection_results)
            
            #Drop all Benign result
            data.drop(data[data.Result == "Benign"].index, inplace=True)
            
            # transform file name, suspicious_{device}_{datetime}.csv
            filename_attr = csv_file.split('.')[-2].split('_')         #output: ['device', '202402102330']
            filename = "suspicious_{}_{}.csv".format(filename_attr[0],filename_attr[1])
            
            data.to_csv(working_directory + common_yaml["abnormal_traffics_csv"] + filename, index=False)
            logger.info(f"Saved any suspicious traffic as {filename}")
    else:
        logger.info(f"No file to process at {csv_directory}")
        
    #print(detection_results)
    #print(data)
    #if (not 'Normal') then 
    # transform file name, suspicious_{device}_{datetime}.csv
    # parse to abnormal_traffics_csv and call Reciever.update(file) to update(sub and pub)
    
    