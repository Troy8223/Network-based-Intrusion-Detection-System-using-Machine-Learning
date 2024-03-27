from Feature_extraction_Module.Feature_extraction import Feature_extraction
import time
import warnings
warnings.filterwarnings('ignore')
import os
from tqdm import tqdm
from multiprocessing import Process
import numpy as np
import pandas as pd
import logging
import yaml

class Data_cleaning():
    def __init__(self, working_directory, logger) -> None:
        with open("config/common.yaml") as file:
            common_yaml = yaml.load(file, Loader= yaml.FullLoader)
        
        self.subfiles_size = 10 # MB
        self.address =  working_directory
        #self.address = "../../"
        self.split_directory = self.address + 'data/split_temp/'
        self.raw_pcap_directory = self.address + common_yaml["raw_pcap"]
        self.destination_directory = self.address + common_yaml["pre-processed_csv_files"] 
        self.pcap_files = os.listdir(self.raw_pcap_directory)
        self.logger = logger
        
    def pub():
        pass
    
    def clean(self):
        start = time.time()
        pcapfiles = self.pcap_files
        subfiles_size = self.subfiles_size
        split_directory = self.split_directory
        raw_pcap_directory = self.raw_pcap_directory
        destination_directory = self.destination_directory
        n_threads = 8
        
        
        
        
            

        self.logger.info("Start Data Cleaning")
        
        for i in range(len(pcapfiles)):
            lstart = time.time()
            pcap_filename = pcapfiles[i]
            pcap_file = raw_pcap_directory + pcapfiles[i]
            self.logger.debug(pcap_file)
            self.logger.info(f"Splitting the .pcap file: {pcap_filename}")
            try:
                os.system('tcpdump -r '+ pcap_file +' -w ' + split_directory + pcap_filename.split('.')[0] + '_split_temp -C ' + str(subfiles_size))
            except:
                self.logger.error(f"Error occur when splitting pcap file at {pcap_file}. ",exc_info=True)
                pass
            
            subfiles = os.listdir(split_directory)
            
            self.logger.info("Converting (sub) .pcap files to .csv files")
            processes = []
            errors = 0
            
            subfiles_threadlist = np.array_split(subfiles, (len(subfiles)/n_threads)+1)
            for f_list in tqdm(subfiles_threadlist):
                n_processes = min(len(f_list), n_threads)
                assert n_threads >= n_processes
                assert n_threads >= len(f_list)
                processes = []
                for i in range(n_processes):
                    fe = Feature_extraction()
                    f = f_list[i]
                    subpcap_file = split_directory + f
                    p = Process(target=fe.pcap_evaluation, args=(subpcap_file,split_directory + f.split('.')[0],self.logger))
                    p.start()
                    processes.append(p)
                for p in processes:
                    p.join()
            
            #assert len(subfiles)==len(os.listdir(destination_directory))
            self.logger.info("Removing (sub) .pcap files.")
            for sf in subfiles:
                os.remove(split_directory + sf)
                pass
            
            self.logger.info("Merging (sub) .csv files to a summary csv")
            csv_subfiles = os.listdir(split_directory)
            mode = 'w'
            for f in tqdm(csv_subfiles):
                try:
                    pcap_filename = pcap_filename.split('.')[0]
                    if (pcap_filename in f):
                        d = pd.read_csv(split_directory + f)
                        d.to_csv(destination_directory + pcap_filename + '.csv', header=mode=='w', index=False, mode=mode)
                        mode='a'
                except:
                    self.logger.info("Error occured when merging sub csv file.", exc_info=True)
                    pass

            self.logger.info("Removing (sub) .csv files")
            for cf in tqdm(csv_subfiles):
                os.remove(split_directory + cf)
                pass
            self.logger.info(f'Cleaner job done. ({destination_directory+pcap_filename})(' + str(round(time.time()-lstart, 2))+ 's),  total_errors= '+str(errors))
            
        end = time.time()
        self.logger.info(f'Elapsed Time = {(end-start)}s')
        
        
        
