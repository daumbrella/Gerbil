# -*- coding: utf-8 -*-
"""
Created on Fri Mar  8 10:40:00 2019

@author: yayao
"""


import time
import logging
import binascii
import os
import string


def convertBE(hexstr):
    return hexstr.decode('hex')[::-1].encode('hex_codec') 

def getLoadingrules(firmware_txt_name,firmware_bin):
    all_len=os.path.getsize(firmware_bin)
    firmware_txt=open(firmware_txt_name,'r')
    strr=firmware_txt.read()
    firmware_txt.close()
    segments=[]
    #print(firmware_bin)
    firmware_bin=open(firmware_bin,'rb')
    if(strr.find("MRVL") != -1):
        #print("Marvell Chip Firmware")
        segment_header=firmware_bin.read(0xc8)
        segment_header= segment_header.encode('hex')
        num_segment=int(convertBE(segment_header[24:28]))
        for i in range(num_segment):
            offset=int(convertBE(segment_header[40*(i+1)+8:40*(i+1)+16]),16)
            length=int(convertBE(segment_header[40*(i+1)+16:40*(i+1)+24]),16)
            base_addr=int(convertBE(segment_header[40*(i+1)+24:40*(i+1)+32]),16)
            segment_each=(offset,base_addr,length)
            segments.append(segment_each)
        firmware_bin.close()
    elif(strr.find("81958711")!=-1):
        segment_header1=firmware_bin.read(0x20)
        if("81958711" in segment_header1[0:8]):
            #print("RTL8711B Chip Firmware")
            #print(firmware_txt_name)
            segment_header1= segment_header1.encode('hex')
            offset1=0x20
            len1=int(convertBE(segment_header1[16:24]),16)
            base_addr1=int(convertBE(segment_header1[24:32]),16)
            segment1=(offset1,base_addr1,len1)
            segments.append(segment1)
            offset2=offset1+len1
            firmware_bin.seek(len1, 1)
            segment_header2=firmware_bin.read(0x20)
            segment_header2= segment_header2.encode('hex')
            len2=int(convertBE(segment_header2[16:24]),16)
            base_addr2=int(convertBE(segment_header2[24:32]),16)
            segment2=(offset2,base_addr2,len2)
            segments.append(segment2)
        else:
            #print("RTL8195A Chip Firmware")
            segment_header1=segment_header1.encode('hex')
            len1=int(convertBE(segment_header1[0:8]),16)
            base_addr1=int(convertBE(segment_header1[8:16]),16)
            segments.append((0,base_addr1,len1))
            firmware_bin.seek(len1-0x20,1)
            segment_header2=firmware_bin.read(0x30)
            segment_header2=segment_header2.encode('hex')
            if (len(segment_header2)>=96):
                offset2=len1+0x20
                len2=int(convertBE(segment_header2[32:40]),16)
                base_addr2=int(convertBE(segment_header2[40:48]),16)
                if(base_addr2!=0xffffffff):
                    segments.append((offset2,base_addr2,len2))
    elif(strr.find("HF-MC3000 Image")!=-1):
        #print("HF-MC3000 Chip Firmware")
        offset1=0x80
        base_addr1=0x3000000
        firmware_bin.seek(0x4080,1)
        segment_headern=firmware_bin.read(0x20)
        segment_headern=segment_headern.encode('hex')
        seg_end1=int(convertBE(segment_headern[0:8]),16)
        len1=seg_end1-0x3000000
        base_addr2=int(convertBE(segment_headern[8:16]),16)
        offset2=len1
        len2=all_len-len1
        segments.append((offset1,base_addr1,len1))
        segments.append((offset2,base_addr2,len2))
    elif(strr.find("LPB100")!=-1):
        #print("HF-MC101 Chip Firmware")
        offset1=0
        base_addr1=0x400000
        len1=all_len
        segments.append((offset1,base_addr1,len1))
    elif(strr.find("STM32F4")!=-1):
        #print("STM32F4XX Chip Firmware")
        print(firmware_txt_name)
        offset1=0
        base_addr1=0x800C000
        len1=all_len
        segments.append((offset1,base_addr1,len1))       
    return segments


file_dir='/home/yaoyao/light_firmware'
for root,dirs,files in os.walk(file_dir):
    for fw in files:
        if("bin" in fw):
            segments=getLoadingrules(file_dir+'/'+fw[:-3]+"txt",file_dir+'/'+fw)
            print(segments)
