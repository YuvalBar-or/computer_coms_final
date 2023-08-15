import matplotlib
matplotlib.use('agg')
import matplotlib.pyplot as plt
import numpy as np
import matplotlib.pyplot as plt
from scapy.all import *
import pandas as pd
import os

class PacketAnalyzer:
    
    def __init__(self,wireshark_recordings=[]):

        """ This function is the constructor (__init__) of the class PacketAnalyzer. 
        It's used to initialize the attributes of an object when an instance of the class is created. 
        """
        # list of recordings
        self.captures = wireshark_recordings
        self.titles = ["all", "audio", "images", "text", "videos"]

        # list for data frames
        self.data_frames = [] # pd.DataFrame() one for each recording

        # lists for storing data
        self.packet_sizes = []
        self.timestamps = []
        self.inter_message_delays = []
        self.image_counter = 1


    def loop_list(self):

        """" This function processes Wireshark recordings stored in the 'self.captures' attribute, extracts packets using 
        rdpcap, processes the packets using graph_handler (the next function in line), and maintains certain data lists.

        the extraction process using rdpcap: imported form the Scapy library, stands for "read pcap," 
        and it's used to read packet capture files in the PCAP format
        """
        for capture in self.captures:
            #extract packets
            packets = rdpcap(capture)
            # handel packets and return if successful
            first_op = self.graph_handler(packets)
            
            #if succsfully saved to data frame, reset the lists for next dataframe
            if(first_op == 1):
                self.packet_sizes = []
                self.timestamps = []
                self.inter_message_delays = []
            else:
                print("error occured during loop_list functon")
                exit(1)

    
    def graph_handler(self, packets):

        """
        this function process packets from a Wireshark recording and extracts specific data into predefined lists. 
        It also calculates inter-message delays and eventually calls the save_to_pd method to save the collected data to a 
        Pandas DataFrame.
        """
        last_timestamp = None
        for packet in packets:
            if packet.haslayer("Raw"):
                packet_size = len(packet[Raw])
                timestamp = packet.time
                self.packet_sizes.append(packet_size)
                self.timestamps.append(timestamp)
                if last_timestamp is not None:
                    inter_message_delay = timestamp - last_timestamp
                    self.inter_message_delays.append(float(inter_message_delay))
                if last_timestamp is None:
                    self.inter_message_delays.append(0.0)
                    last_timestamp = timestamp
        return self.save_to_pd()

    
    def save_to_pd(self):
        print ("------------------------------")
        print("Packet Sizes Length:", len(self.packet_sizes))
        print("Timestamps Length:", len(self.timestamps))
        print("Inter-Message Delays Length:", len(self.inter_message_delays))
        #print("Inter-Message Delays:", self.inter_message_delays)
        #creating new dataframe with the data
        new_pd = pd.DataFrame({'Size': self.packet_sizes, 'Seconds': self.timestamps, 'Inter-Message Delays': self.inter_message_delays})
        # append new_pd to list
        self.data_frames.append(new_pd)
        #returning success inorder to clean the lists
        return 1
    

    def plot_graphs(self):

        """
        This function is responsible for plotting graphs based on the data stored in the data_frames attribute. 
        The goal is to visualize information related to packet rate and inter-message delay probability density function (PDF)
        """
        #for the number of dataframe
        for i in range(len(self.data_frames)):
            #plot each data frame for the recording
            self.plot_packet_rate(self.data_frames[i]) # size as a function of time (seconds)
            self.plot_delay_pdf(self.data_frames[i]) # probability density function as a function of time (seconds)
        
    
    def plot_packet_rate(self, pd):

        """
        this function is responsible for plotting a bar graph of packet length as a function of time. 
        It also saves the generated graph as an image file.
        """
        plt.figure(figsize=(10, 5))
        plt.bar(pd['Seconds'], pd['Size'], width=0.1)
        plt.xlabel('Timestamp (seconds)')
        plt.ylabel('Packet Length (bytes)')
        # by decreasing one and dividing by 2 we achieve the correct title for the graph 
        plt.title('Packet Length as a Function of Time - {}'.format(self.titles[(self.image_counter -1) //2]))
        plt.grid(True)
        plt.savefig("{}.png".format(str(self.image_counter)))
        self.image_counter+=1


    def calculate_inter_message_delays(self):
        """
        this function calculates the inter-message delays between consecutive timestamps in the self.timestamps list
        """
        self.inter_message_delays = np.diff(self.timestamps)


    def plot_delay_pdf(self, pd):

        """
        this function is responsible for plotting a probability density function (PDF) of inter-message delays based on a Pandas 
        DataFrame. It also fits an exponential distribution to the data and overlays the fitted distribution on the histogram. 
        Finally, it saves the generated plot as an image file.
        """
        inter_message_delays = pd['Inter-Message Delays']
        #inter_message_delays = inter_message_delays[np.isfinite(inter_message_delays)] # Remove non-finite values
        plt.figure(figsize=(10, 5))
        plt.hist(inter_message_delays, bins=50, density=True, alpha=0.7, color='blue', label='Inter-Message Delay Distribution')
        
        # Fitting an exponential distribution to the data
        mean_inter_message_delay = np.mean(inter_message_delays)
        lambda_fit = 1 / mean_inter_message_delay
        x_fit = np.linspace(0, np.max(inter_message_delays), 1000)
        y_fit = lambda_fit * np.exp(-lambda_fit * x_fit)

        # Plotting the fitted exponential distribution
        plt.plot(x_fit, y_fit, color='orange', linewidth=2, label='Fitted Exponential Distribution')

        plt.xlabel('Inter-Message Delay (seconds)')
        plt.ylabel('PDF')
        plt.title('Probability Density Function of Inter-Message Delays - {}'.format(self.titles[(self.image_counter -1) //2]))
        plt.grid(True)

        # Add legend to the plot
        plt.legend()
        
        plt.savefig("{}.png".format(str(self.image_counter)))
        self.image_counter+=1

def get_capture_files(folder_path):

    """
    This function takes a folder path as input and returns a list of full file paths for all the PCAP files present in 
    that folder.
    """
    # Get a list of all files in the folder
    all_files = os.listdir(folder_path)

    # Filter only the PCAP files
    capture_files = [file for file in all_files if file.endswith(".pcap")]
    
    # Create the full file paths by joining the folder path and file names
    capture_files_paths = [os.path.join(folder_path, file) for file in capture_files]

    return capture_files_paths 



def main():
    #extract pcap file to a list
    pcap_folder = 'wireshark_recordings'
    wireshark_recordings = get_capture_files(pcap_folder)

    # Create PacketAnalyzer object
    analyzer = PacketAnalyzer(wireshark_recordings)
    analyzer.loop_list()

    analyzer.plot_graphs()

if __name__ == "__main__":
    main()