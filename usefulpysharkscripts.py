import pyshark
cap = pyshark.FileCapture("D:/Users/Luke/Documents/SEChallenge2022/DataSet/SECH.IncrementalDelayAndLoss_Eth1.RTPS.pcap")
capout = pyshark.FileCapture("D:/Users/Luke/Documents/SEChallenge2022/DataSet/SECH.IncrementalDelayAndLoss_Eth1.LABEL.pcap")
#print(cap[0])
#dir(cap[0])

#=== Method to get the number of input samples. It's dumb, but seems to be the only way it can be done.
#https://stackoverflow.com/questions/27025827/count-the-number-of-packets-with-pyshark

#one option would be to make the Main process simply run in the "for p in cap"
#though obviously would result in different main loop for live / read captures.

getcaplen = False
if getcaplen == True:
    print("Getting capture length (if needed for utils), this will take a long time")
    caplen = 0
    for p in cap:
        caplen = caplen + 1
        #make sure user is aware this hasn't crashed
        if caplen%200 == 0:
            print('.', end='')
    print("") #above will need a newline
    print("Number of Captures: " + str(caplen))

print("First Sample: ")
#frame time data
print(cap[0].frame_info.time_epoch)
print(cap[0].frame_info.time_relative)
#frame length and capture length (not sure if these ever differ...)
print(cap[0].frame_info.len)
print(cap[0].frame_info.cap_len)

#info ts time data - not going to be useful though!!!
print(cap[0].rtps.info_ts_timestamp)

print("First capture of the LABEL file:")
print(capout[0].frame_info.time_epoch)
print(capout[0].frame_info.time_relative)
#frame length and capture length (not sure if these ever differ...)
print(capout[0].frame_info.len)
print(capout[0].frame_info.cap_len)
print(capout[0].DATA.data)

#pull the data from the label for flags
for c in capout[0].DATA.data_data.split(':'):
	try:
		print(chr(int(c,16)), end='')
	except ValueError:
		pass
