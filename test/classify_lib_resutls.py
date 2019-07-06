import os


def getChipVender(firmware_txt,firmware_bin):
    arch=None
    all_len=os.path.getsize(firmware_bin)
    firmware_txt=open(firmware_txt,'r')
    strr=firmware_txt.read()
    firmware_txt.close()
    segments=[]
    firmware_bin=open(firmware_bin,'rb')
    if(strr.find("MRVL") != -1):
        return "Marvell"
        firmware_bin.close()
    elif(strr.find("81958711")!=-1):
        segment_header1=firmware_bin.read(0x20)
        if("81958711" in segment_header1[0:8]):
            return "RTL8711B"
        else:
            return "RTL8195A"
    elif(strr.find("HF-MC3000 Image")!=-1):
        return "HF-MC3000"
    elif(strr.find("LPB100")!=-1):
        return "HF-MC101"
    elif(strr.find("STM32F4")!=-1):
        return "STM32F4XX"

def classify_fw():
    file_dir='/home/yaoyao/light_firmware'
    num_size_file=open('num_size_results.csv','r')
    for line in num_size_file.readlines():
        new_line = line.split(',')
        fw_name=new_line[0]
        chip_vendor=getChipVender(file_dir+'/'+fw_name[:-3]+"txt",file_dir+'/'+fw_name)
        if "upd_" in fw_name:
            print chip_vendor+",mijia,"+line[:-2]
        elif "alink" in fw_name or "ALINK" in fw_name or "ota" in fw_name:
            print chip_vendor+",alink,"+line[:-2]
        elif "marconiv" in fw_name:
            print  chip_vendor+",irobot,"+line[:-2]
        else:
            print chip_vendor+",joylink,"+line[:-2]

def classify_results():
    classify_lib_file=open('libs_classify.csv','r')
    chip_dict=dict()
    vendor_dict_1=dict()
    vendor_dict_2=dict()
    vendor_dict_3=dict()
    vendor_dict_4=dict()
    vendor_dict_5=dict()
    vendor_dict_6=dict()
    chip_dict.update({'HF-MC101':vendor_dict_1})
    chip_dict.update({'HF-MC3000':vendor_dict_2})
    chip_dict.update({'Marvell':vendor_dict_3})
    chip_dict.update({'RTL8195A':vendor_dict_4})
    chip_dict.update({'RTL8711B':vendor_dict_5})
    chip_dict.update({'STM32F4XX':vendor_dict_6})
    for line in classify_lib_file.readlines():
        line_array=line.split(',')
        chip=line_array[0]
        vendor=line_array[1]
        func_num=float(line_array[3][1:])
        func_rate=float(line_array[7])
        func_size_rate=float(line_array[8])
        if chip=='HF-MC101':
            vendor_dict=chip_dict[chip]
            if vendor not in vendor_dict.keys():
                vendor_dict.update({vendor:(1,func_rate,func_rate,func_num,func_num)})
            else:
                value=vendor_dict[vendor]
                count=value[0]
                all_func_rate=value[1]+func_rate
                all_func_num=value[3]+func_num
                count=count+1
                avg_func_rate=all_func_rate/count
                avg_func_num=all_func_num/count
                vendor_dict.update({vendor:(count,all_func_rate,avg_func_rate,all_func_num,avg_func_num)})
            chip_dict.update({'HF-MC101':vendor_dict})
        elif chip=='HF-MC3000':
            vendor_dict=chip_dict[chip]
            if vendor not in vendor_dict.keys():
                vendor_dict.update({vendor:(1,func_rate,func_rate,func_num,func_num)})
            else:
                value=vendor_dict[vendor]
                count=value[0]
                all_func_rate=value[1]+func_rate
                all_func_num=value[3]+func_num
                count=count+1
                avg_func_rate=all_func_rate/count
                avg_func_num=all_func_num/count
                vendor_dict.update({vendor:(count,all_func_rate,avg_func_rate,all_func_num,avg_func_num)})
            chip_dict.update({'HF-MC3000':vendor_dict})
        elif chip=='Marvell':
            vendor_dict=chip_dict[chip]
            if vendor not in vendor_dict.keys():
                vendor_dict.update({vendor:(1,func_rate,func_rate,func_num,func_num)})
            else:
                value=vendor_dict[vendor]
                count=value[0]
                all_func_rate=value[1]+func_rate
                all_func_num=value[3]+func_num
                count=count+1
                avg_func_rate=all_func_rate/count
                avg_func_num=all_func_num/count
                vendor_dict.update({vendor:(count,all_func_rate,avg_func_rate,all_func_num,avg_func_num)})
            chip_dict.update({'Marvell':vendor_dict})
        elif chip=='RTL8195A':
            vendor_dict=chip_dict[chip]
            if vendor not in vendor_dict.keys():
                vendor_dict.update({vendor:(1,func_rate,func_rate,func_num,func_num)})
            else:
                value=vendor_dict[vendor]
                count=value[0]
                all_func_rate=value[1]+func_rate
                all_func_num=value[3]+func_num
                count=count+1
                avg_func_rate=all_func_rate/count
                avg_func_num=all_func_num/count
                vendor_dict.update({vendor:(count,all_func_rate,avg_func_rate,all_func_num,avg_func_num)})
            chip_dict.update({'RTL8195A':vendor_dict})
        elif chip=='RTL8711B':
            vendor_dict=chip_dict[chip]
            if vendor not in vendor_dict.keys():
                vendor_dict.update({vendor:(1,func_rate,func_rate,func_num,func_num)})
            else:
                value=vendor_dict[vendor]
                count=value[0]
                all_func_rate=value[1]+func_rate
                all_func_num=value[3]+func_num
                count=count+1
                avg_func_rate=all_func_rate/count
                avg_func_num=all_func_num/count
                vendor_dict.update({vendor:(count,all_func_rate,avg_func_rate,all_func_num,avg_func_num)})
            chip_dict.update({'RTL8711B':vendor_dict})
        elif chip=='STM32F4XX':
            vendor_dict=chip_dict[chip]
            if vendor not in vendor_dict.keys():
                vendor_dict.update({vendor:(1,func_rate,func_rate,func_num,func_num)})
            else:
                value=vendor_dict[vendor]
                count=value[0]
                all_func_rate=value[1]+func_rate
                all_func_num=value[3]+func_num
                count=count+1
                avg_func_rate=all_func_rate/count
                avg_func_num=all_func_num/count
                vendor_dict.update({vendor:(count,all_func_rate,avg_func_rate,all_func_num,avg_func_num)})
            chip_dict.update({'STM32F4XX':vendor_dict})
    print chip_dict

classify_results()
            
