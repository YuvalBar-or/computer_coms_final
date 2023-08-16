import matplotlib
matplotlib.use('agg')
import matplotlib.pyplot as plt
import numpy as np
from scapy.all import *
import pandas as pd
import os

class PacketAnalyzer:
    
    def __init__(self,wireshark_recordings=[], images_folder=""):

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
        self.image_folder = images_folder


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
        #plt.savefig("{}.png".format(str(self.image_counter)))
        plt.savefig(os.path.join(self.image_folder, "{}.png".format(str(self.image_counter))))
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
        
        #plt.savefig("{}.png".format(str(self.image_counter)))
        plt.savefig(os.path.join(self.image_folder, "{}.png".format(str(self.image_counter))))
        self.image_counter+=1

    
    def calculate_ccdf(self, data):

        """
        this function calculates the Complementary Cumulative Distribution Function (CCDF) for a given dataset. 
        It first sorts the dataset in ascending order and then generates CCDF values by subtracting the cumulative 
        probabilities from 1. The function returns both the sorted dataset and the corresponding CCDF values, which provide 
        insights into the distribution of data across different thresholds
        """
        sorted_data = np.sort(data)
        ccdf = 1 - np.arange(1, len(sorted_data) + 1) / len(sorted_data)
        return sorted_data, ccdf

    def plot_ccdf(self, pd_list):

        """
        this function generates a combined plot illustrating the Complementary 
        Cumulative Distribution Function (CCDF) for inter-message delays among different groups
        """
        plt.figure(figsize=(10, 5))
        colors = ['green', 'blue', 'red', 'purple', 'orange']  # Use different colors for each group

        for i, pd in enumerate(pd_list):
            sorted_delay, ccdf = self.calculate_ccdf(pd['Inter-Message Delays'])
            plt.semilogx(sorted_delay, ccdf, color=colors[i], linewidth=2, label=self.titles[i])

        plt.xlabel('Inter-Message Delay (seconds)')
        plt.ylabel('CCDF')
        plt.title('Complementary Cumulative Distribution Function (CCDF) of Inter-Message Delays')
        plt.grid(True)
        plt.legend()

        #plt.savefig("ccdf_combined.png")
        plt.savefig(os.path.join(self.image_folder, "ccdf_combined.png"))
        self.image_counter += 1

    def plot_packet_length_cdf(self, pd_list):

        """
        this function plots the Cumulative Distribution Function (CDF) of packet lengths based on the data from multiple 
        recordings. It takes a list of Pandas DataFrames (pd_list) as input, where each DataFrame contains packet size data 
        for a specific recording. The function iterates through the list, calculating the CDF for each recording's packet 
        sizes and then plotting the results.
        """
        plt.figure(figsize=(10, 5))
        colors = ['green', 'blue']  # Use different colors for each group

        for i, pd in enumerate(pd_list):
            sorted_packet_sizes, cdf = self.calculate_cdf(pd['Size'])
            plt.semilogx(sorted_packet_sizes, cdf, color=colors[i], linewidth=2, label=f'Recording {i + 1}')

        plt.xlabel('Packet Length (bytes)')
        plt.ylabel('CDF')
        plt.title('Cumulative Distribution Function (CDF) of Packet Length - {}'.format(self.titles[(self.image_counter -1) //2]))

        plt.grid(True)
        plt.legend()

        #plt.savefig("packet_length_cdf.png")
        plt.savefig(os.path.join(self.image_folder, "packet_length_cdf.png"))
        
        
        self.image_counter += 1


    def calculate_cdf(self, data):

        """
        this function sorts the dataset in ascending order and computes the CDF values as the cumulative probabilities of each data point. 
        The function returns two arrays: one containing the sorted data and the other containing the calculated CDF values.
        """
        sorted_data = np.sort(data)
        cdf = np.arange(1, len(sorted_data) + 1) / len(sorted_data)
        return sorted_data, cdf

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
    #from src folder move up to resources and save path files to wireshark recordings and attacker_attacked and resfolder for saving the images
    current_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(current_dir)
    
    images_folder = os.path.join(parent_dir, 'res')
    pcap_folder = os.path.join(parent_dir, 'resources', 'wireshark_recordings')
    pcap_folder_attacker = os.path.join(parent_dir, 'resources', 'attacker_attacked')

    wireshark_recordings = get_capture_files(pcap_folder)

    analyzer = PacketAnalyzer(wireshark_recordings, images_folder)
    analyzer.loop_list()

    analyzer.plot_graphs()
    analyzer.plot_ccdf(analyzer.data_frames)  # Plot combined CCDF graph

    current_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(current_dir)
    pcap_folder = os.path.join(parent_dir, 'resources', 'wireshark_recordings')

    
    wireshark_recordings2 = get_capture_files(pcap_folder_attacker)

    analyzer1 = PacketAnalyzer(wireshark_recordings2, images_folder)
    analyzer1.loop_list()

    analyzer1.plot_graphs()
    analyzer1.plot_ccdf(analyzer1.data_frames)  # Plot combined CCDF graph
    analyzer1.plot_packet_length_cdf(analyzer1.data_frames)  # Plot packet length CDF graph

if __name__ == "__main__":
    main()