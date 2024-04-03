import subprocess
from Feature_extraction_Module.Feature_extraction import Feature_extraction
import time
import warnings
warnings.filterwarnings('ignore')
import os
from tqdm import tqdm
from multiprocessing import Pool, Process
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
        self.TIMEOUT = 60
        self.n_threads = 8
        
    def pub():
        pass
    
    def clean(self):
        """
            Cleans the data by splitting .pcap files, converting them to .csv files,
            merging the .csv files, and removing temporary files.
        """
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
                os.system('windump -r '+ pcap_file +' -w ' + split_directory + pcap_filename.split('.')[0] + '_split_temp -C ' + str(subfiles_size))
            except:
                self.logger.error(f"Error occur when splitting pcap file at {pcap_file}. ",exc_info=True)
                pass
            
            subfiles = os.listdir(split_directory)
            
            self.logger.info("Converting (sub) .pcap files to .csv files")
            processes = []
            errors = 0
            
            #split files into folders for multiple threads
            subfiles_threadlist = np.array_split(subfiles, (len(subfiles)/n_threads)+1)
            for folder_list in tqdm(subfiles_threadlist):
                n_processes = min(len(folder_list), n_threads)
                assert n_threads >= n_processes
                assert n_threads >= len(folder_list)
                processes = []
                for i in range(n_processes):
                    fe = Feature_extraction()
                    f = folder_list[i]
                    subpcap_file = split_directory + f
                    p = Process(target=fe.pcap_evaluation, args=(subpcap_file,split_directory + f.split('.')[0]))
                    p.start()
                    processes.append(p)
                for p in processes:
                    p.join(self.TIMEOUT)
                    if p.is_alive():
                        self.logger.warning(f"Process {p.pid} is still running. Terminating it.")
                        p.terminate()
            
            #assert len(subfiles)==len(os.listdir(destination_directory))
            self.logger.info("Removing (sub) .pcap files.")
            for sf in subfiles:
                os.remove(split_directory + sf)
                pass
            
            self.logger.info("Merging (sub) .csv files to a summary csv")
            csv_subfiles = os.listdir(split_directory)
            mode = 'w'
            for csv_file in tqdm(csv_subfiles):
                try:
                    pcap_filename = pcap_filename.split('.')[0]
                    if (pcap_filename in csv_file):
                        print("##"+split_directory + csv_file)
                        d = pd.read_csv(split_directory + csv_file)
                        d.to_csv(destination_directory + pcap_filename + '.csv', header=mode=='w', index=False, mode=mode)
                        mode='a'
                except:
                    self.logger.error("Error occured when merging sub csv file.", exc_info=True)
                    pass

            self.logger.info("Removing (sub) .csv files")
            for cf in tqdm(csv_subfiles):
                os.remove(split_directory + cf)
                pass
            self.logger.info(f'Cleaner job done. ({destination_directory+pcap_filename})(' + str(round(time.time()-lstart, 2))+ 's),  total_errors= '+str(errors))
            
        end = time.time()
        self.logger.info(f'Elapsed Time = {(end-start)}s')
        
    def split_pcap_file(self, pcap_filename):
            pcap_file = os.path.join(self.raw_pcap_directory, pcap_filename)
            try:
                self.logger.info(f"Splitting the .pcap file: {pcap_filename}")
                #subprocess.run(['windump', '-r', pcap_file, '-w', os.path.join(self.split_directory, f'{pcap_filename.split(".")[0]}_split_temp'), '-C', str(self.subfiles_size)], check=True)
            except subprocess.CalledProcessError as e:
                self.logger.error(f"Error occurred when splitting pcap file {pcap_file}. {e}")
                pass

    def pcap_evaluation_wrapper(self, subpcap_file):
            fe = Feature_extraction()
            try:
                self.logger.info(f"Converting (sub) .pcap file to .csv file: {subpcap_file}")
                fe.pcap_evaluation(subpcap_file, os.path.join(self.split_directory, os.path.splitext(os.path.basename(subpcap_file))[0]), self.logger)
            except Exception as e:
                self.logger.error(f"Error occurred during evaluation of {subpcap_file}. {e}")
    
        

    def clean_optimized(self):
            pool = Pool(processes=self.n_threads)            
            pcapfiles = self.pcap_files
            
            for pcap_filename in pcapfiles:
                self.split_pcap_file(pcap_filename)
                subfiles = os.listdir(self.split_directory)
                subfiles_paths = [os.path.join(self.split_directory, f) for f in subfiles]
                self.logger.info("Converting (sub) .pcap files to .csv files")
                for _ in tqdm(pool.imap_unordered(self.pcap_evaluation_wrapper, subfiles_paths), total=len(subfiles_paths)):
                    pass
            pool.close()
            pool.join()    