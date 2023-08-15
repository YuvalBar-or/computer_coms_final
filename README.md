# Final Project

### intro 
part of a course on computer comunications, we were instructed to write a custom sniffer code in python that would sniff from our network a whatsapp group that we're part of. <br/>
note this is ethical as we're part of the whatsapp group and just need to store the inter-message delays and the message sizes, we're not interfering or trying to attack the IM application.<br/>

### the paper 
we based our project on the paper "Practical Traffic Analysis Attacks on Secure Messaging Applications." The paper posits that despite the claims of IM applications to ensure complete secrecy, it is possible to gather valuable insights about the transported data using straightforward statistical methods and filtering techniques.
For every distinct group outlined in the paper, we generated visual representations of the inter-message delays and message sizes. Our goal was to identify distinct patterns unique to each group, including messages, images, videos, files, and audio groups.

we will discuss the following points:
1. Are there unique characteristics for each group?
2. Can one deduce the groups you take part in using the techniques detailed in the paper? <br/>
and explored two scenarios:
1. When the targeted user is exclusively active in, at most, a single instant messaging (IM) group.
2. When the targeted user might be concurrently active in multiple IM groups.

### how to run the program 
* clone the repo and open it in the application of your choice (preferably with vscode, or pycharm )
* open an integrated terminal of src/IMProxy-master.
* run the following command; python3 PacketAnalyzer.py.

### about the files
res derectory: source code and results- <br/>
* data Analysis code.
* the graph results. <br/>

other files: <br/>
the dry part; Present our answers to the theoretical segment of the project. This documents encapsulate the content of the Hebrew-written article that serves as the foundation for our project. <br/>
Project_PDF; instructions for this project. 

### wireshark recordings and database
we recorded communication in 5 instant messaging (IM) groups, using WhatsApp Web on a PC, and Wireshark. <br/>
after recording we analyzed the recordings by extracting data from captured network packets, processing it, and generating various graphs for visualization. The PacketAnalyzer class serves as the focal point for consolidating the procedures related to data processing and graph generation. In contrast, the get_capture_files function is designed to gather the file paths associated with the recordings. <br/>

* note - when recording, we filtered by - ip.src && tcp.port 443 <br/>

Our study commenced by capturing traffic from five distinct WhatsApp groups, each centered around a unique theme: images, audio, videos, file transfers, and a mixed group with an emphasis on text messages. Considering the context, we assumed that participants would be active in a single group at a time. Subsequently, we processed the group recordings through the aforementioned filtering procedure. In line with the paper's methodology, we created visual depictions showcasing inter-message delays and message sizes. Additionally, we formulated probability density functions (PDFs) for each distinct group category. These graphical analyses yield valuable insights into traffic patterns and behaviors inherent to each group. <br/>

WhatsApp - IM application: <br/>
WhatsApp employs robust security measures, including end-to-end encryption with the Signal Protocol, to safeguard data during transmission. This encryption process involves encrypting messages at the sender's end using the recipient's public key, ensuring only the recipient's private key can decrypt them. This approach guarantees message confidentiality even if intercepted during transmission. Forward secrecy further enhances security by employing temporary session keys. Additionally, WhatsApp encrypts data stored on its servers and offers security code verification for user confidence. Collectively, these measures ensure the privacy and integrity of user communications.

### Deducing the groups an attacked user take part in using the techniques detailed in the paper
#### The attacked user is always active in (at most) a single IM group.
Presented below are the aforementioned graphs: 
* all group:
<img width="971" alt="Screenshot 2023-08-15 at 14 14 28" src="https://github.com/YuvalBar-or/computer_coms_final/assets/118693941/2b4e3e71-c9da-403b-98a8-b4a38d6d6a0f">

<img width="981" alt="Screenshot 2023-08-15 at 14 14 35" src="https://github.com/YuvalBar-or/computer_coms_final/assets/118693941/a63e8a08-96bf-4aa2-801f-4eae5fc57e7a">

* audio group:

<img width="932" alt="Screenshot 2023-08-15 at 14 15 59" src="https://github.com/YuvalBar-or/computer_coms_final/assets/118693941/377c307e-ba7e-4e09-82c7-eff3b3fb2d5c">

<img width="935" alt="Screenshot 2023-08-15 at 14 16 06" src="https://github.com/YuvalBar-or/computer_coms_final/assets/118693941/818d57c2-34ff-4eb1-8c58-fdfe44240aaa">

* images group:
* 
<img width="982" alt="Screenshot 2023-08-16 at 1 06 52" src="https://github.com/YuvalBar-or/computer_coms_final/assets/118693941/22ef664c-e867-4187-956f-57f5861aa011">

<img width="909" alt="Screenshot 2023-08-16 at 1 06 59" src="https://github.com/YuvalBar-or/computer_coms_final/assets/118693941/2b0fbd73-f311-4cc3-a927-b079821936cd">

* text group:

* video group: 


After analyzing individual groups, our focus shifted to identifying distinct characteristics for each. The algorithm in the referenced article estimates message sizes using distributions, creating unique channels. This estimation employs the Complementary Cumulative Distribution Function (CCDF) as a defining feature. CCDF represents the likelihood of a variable exceeding a value, providing a perspective inverse to the Cumulative Distribution Function (CDF).<br/>

our CCDF: <br/>
In contrast to the conclusions outlined in the article, our CCDF analysis did not reveal a discernible feature unique to any of the groups. Evidently, the distribution patterns among the groups exhibit substantial similarity, despite variations in the specific values. The overall trend remains consistent across all groups.

<img width="987" alt="Screenshot 2023-08-15 at 14 12 50" src="https://github.com/YuvalBar-or/computer_coms_final/assets/118693941/520f70fd-6e52-44de-a35f-7c7071ec83ba">



#### The attacked user may be active in several IM groups simultaneously



## References
* Traffic Analysis of Secure (E2E encrypted) Messaging Apps (E.g., WhatsApp, Signal, Telagram)
[Paper, slides, and video (NDSS'2020)](https://www.ndss-symposium.org/ndss-paper/practical-traffic-analysis-attacks-on-secure-messaging-applications/)
* ChatGPT

## Links:
* https://github.com/YuvalBar-or/computer_coms_final.git
* https://github.com/Joshua-D-Gordon/Final_Project_Comunications.git
