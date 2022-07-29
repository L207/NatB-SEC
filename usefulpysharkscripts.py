import pyshark
cap = pyshark.FileCapture("D:/Users/Luke/Documents/SEChallenge2022/DataSet/SECH.IncrementalDelayAndLoss_Eth1.RTPS.pcap")
capout = pyshark.FileCapture("D:/Users/Luke/Documents/SEChallenge2022/DataSet/SECH.IncrementalDelayAndLoss_Eth1.LABEL.pcap")
#print(cap[0])
#dir(cap[0])

#proposal for an initial interface, currently very incomplete. #https://realpython.com/python-data-structures/
#would likely need to pull this into another imported file for others to use.
class inputarray_t:
    def __init__(self, frame_rel_time, frame_len, frame_cap_len):
        self.frame_rel_time = frame_rel_time
        self.frame_len = frame_len
        self.frame_cap_len = frame_cap_len
class outputarray_t:
    def __init__(self, frame_rel_time, err_liveliness_changed, err_requested_deadline_missed, err_sample_lost, err_offset):
        self.frame_rel_time = frame_rel_time
        self.err_liveliness_changed = err_liveliness_changed
        self.err_requested_deadline_missed = err_requested_deadline_missed
        self.err_sample_lost = err_sample_lost
        self.err_offset = err_offset

#====CONTROL SWITCHES=====
dumpallerrors = True #Dumps to Shell all the detected errors and their timestamps

errstr_liveliness_changed = "DRIVER on_liveliness_changed"
errstr_requested_deadline_missed = "DRIVER on_requested_deadline_missed"
errstr_sample_lost = "DRIVER on_sample_lost"

#these names are just terrible but I'll fix it later.
timestamps_rtps = []
timestamps_rtps_frame_len = []
timestamps_rtps_frame_cap_len = []
timestamps_label_err = []
timestamps_label_err_liveliness_changed = []
timestamps_label_err_requested_deadline_missed = []
timestamps_label_err_sample_lost = []
timestamps_rtps_err_liveliness_changed = []
timestamps_rtps_err_requested_deadline_missed = []
timestamps_rtps_err_sample_lost = []
timestamps_rtps_err_offset = []


#=== Method to get the number of input samples. It's dumb, but seems to be the only way it can be done.
#https://stackoverflow.com/questions/27025827/count-the-number-of-packets-with-pyshark

#one option would be to make the Main process simply run in the "for p in cap"
#though obviously would result in different main loop for live / read captures.

getcaplen = True #Takes a very long time - do not disable is now critical to functionality.
if getcaplen == True:
    print("Getting RTPS capture length (if needed for utils), this will take a long time")
    caplen = 0
    for p in cap:
        caplen = caplen + 1
        timestamps_rtps.append(float(p.frame_info.time_relative))
        timestamps_rtps_frame_len.append(int(p.frame_info.len))
        timestamps_rtps_frame_cap_len.append(int(p.frame_info.cap_len))
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
        timestamps_label_err.append(float(p.frame_info.time_relative))
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

#generate output array in RTPS timestamp format with offsets

timestamps_rtps_err_liveliness_changed = [0] * caplen
timestamps_rtps_err_requested_deadline_missed = [0] * caplen
timestamps_rtps_err_sample_lost = [0] * caplen
timestamps_rtps_err_offset = [0] * caplen
i_tle = 0 #position in the timestamps label err array

for i in range(caplen):
    if i_tle < len(timestamps_label_err):
        if timestamps_rtps[i] == timestamps_label_err[i_tle]:
            timestamps_rtps_err_liveliness_changed[i] = timestamps_label_err_liveliness_changed[i_tle]
            timestamps_rtps_err_requested_deadline_missed[i] = timestamps_label_err_requested_deadline_missed[i_tle]
            timestamps_rtps_err_sample_lost[i] = timestamps_label_err_sample_lost[i_tle]
            timestamps_rtps_err_offset[i] = 0
            i_tle = i_tle + 1
        elif timestamps_rtps[i] > timestamps_label_err[i_tle]:
            timestamps_rtps_err_liveliness_changed[i-1] = timestamps_label_err_liveliness_changed[i_tle]
            timestamps_rtps_err_requested_deadline_missed[i-1] = timestamps_label_err_requested_deadline_missed[i_tle]
            timestamps_rtps_err_sample_lost[i-1] = timestamps_label_err_sample_lost[i_tle]
            timestamps_rtps_err_offset[i-1] = timestamps_rtps[i] - timestamps_label_err[i_tle]
            i_tle = i_tle + 1

input_array = inputarray_t(timestamps_rtps, timestamps_rtps_frame_len, timestamps_rtps_frame_cap_len)
output_array = outputarray_t(timestamps_rtps, timestamps_rtps_err_liveliness_changed, timestamps_rtps_err_requested_deadline_missed, timestamps_rtps_err_sample_lost, timestamps_rtps_err_offset)
    


        



