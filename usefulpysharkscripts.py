import pyshark
cap = pyshark.FileCapture("D:/Users/Luke/Documents/SEChallenge2022/DataSet/SECH.IncrementalDelayAndLoss_Eth1.RTPS.pcap")
capout = pyshark.FileCapture("D:/Users/Luke/Documents/SEChallenge2022/DataSet/SECH.IncrementalDelayAndLoss_Eth1.LABEL.pcap")
#print(cap[0])
#dir(cap[0])

#====CONTROL SWITCHES=====
getcaplen = False #Takes a very long time
dumpallerrors = True #Dumps to Shell all the detected errors and their timestamps

errstr_liveliness_changed = "DRIVER on_liveliness_changed"
errstr_requested_deadline_missed = "DRIVER on_requested_deadline_missed"
errstr_sample_lost = "DRIVER on_sample_lost"

timestamps_rtps = []
timestamps_label_err = []
timestamps_label_err_liveliness_changed = []
timestamps_label_err_requested_deadline_missed = []
timestamps_label_err_sample_lost = []


#=== Method to get the number of input samples. It's dumb, but seems to be the only way it can be done.
#https://stackoverflow.com/questions/27025827/count-the-number-of-packets-with-pyshark

#one option would be to make the Main process simply run in the "for p in cap"
#though obviously would result in different main loop for live / read captures.

if getcaplen == True:
    print("Getting RTPS capture length (if needed for utils), this will take a long time")
    caplen = 0
    for p in cap:
        caplen = caplen + 1
        timestamps_rtps.append(p.frame_info.time_relative)
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
print("==FIRST 10 LABELS==")

#find all the error flags
for p in capout:
    chrtemp = ""
    strtemp = ""
    for c in p.DATA.data_data.split(':'):
        try:
            chrtemp = chr(int(c,16))
            strtemp = strtemp + chrtemp
            #print(chr(int(c,16)), end='')
        except ValueError:
            pass
    if errstr_liveliness_changed in strtemp or errstr_requested_deadline_missed in strtemp or errstr_sample_lost in strtemp:
        if dumpallerrors == True:
            print("At time: " + p.frame_info.time_relative + " : ", end='')
            print(strtemp, end='')
        timestamps_label_err.append(p.frame_info.time_relative)
        if errstr_liveliness_changed in strtemp:
            timestamps_label_err_liveliness_changed.append(1)
            timestamps_label_err_requested_deadline_missed.append(0)
            timestamps_label_err_sample_lost.append(0)
        elif errstr_requested_deadline_missed in strtemp:
            timestamps_label_err_liveliness_changed.append(0)
            timestamps_label_err_requested_deadline_missed.append(1)
            timestamps_label_err_sample_lost.append(0)
        elif errstr_sample_lost in strtemp:
            timestamps_label_err_liveliness_changed.append(0)
            timestamps_label_err_requested_deadline_missed.append(0)
            timestamps_label_err_sample_lost.append(1)



        



