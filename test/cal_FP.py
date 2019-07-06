# -*- coding: utf-8 -*-
"""
Created on Fri Mar  8 10:40:00 2019

@author: yayao
"""

import angr
import claripy
import re
from angr.state_plugins.sim_action import SimAction, SimActionConstraint
from cle.address_translator import AT
import cPickle as pickle
import time
import logging
import binascii
import os
import string
from collections import OrderedDict

def pickle_load_cfg_fast(filename):
    f_cfg=file(filename,'rb')
    cfg_fast=pickle.load(f_cfg)
    f_cfg.close()
    return cfg_fast

def pickle_dump_cfg_fast(filename,cfg):
    f_cfg=file(filename,'wb')
    cfg_fast=pickle.dump(cfg,f_cfg,-1)
    f_cfg.close()

def pickle_load_callgraph(start_addr):
    f_cfg=file('callgraph_'+hex(start_addr), 'rb')
    callgraph=pickle.load(f_cfg)
    f_cfg.close()
    return callgraph

def pickle_dump_fm_fast(filename,fm):
    f_fm=file(filename,'wb')
    pickle.dump(fm,f_fm,-1)
    f_fm.close()

def pickle_load_fm_fast(filename):
    f_fm=file(filename,'rb')
    fm=pickle.load(f_fm)
    f_fm.close()
    return fm

def pickle_dump_fm_accurate(filename,fm):
    f_fm=file(filename,'wb')
    pickle.dump(fm,f_fm,-1)
    f_fm.close()

def pickle_load_fm_accurate(filename):
    f_fm=file(filename,'rb')
    fm=pickle.load(f_fm)
    f_fm.close()
    return fm

def get_sym_variables(state,key):
    variables=list(state.solver.get_variables(key))
    symbol_vars=list()
    for var in variables:
        symbol_vars.append(var[1])
    return symbol_vars

def convertBE(hexstr):
    return hexstr.decode('hex')[::-1].encode('hex_codec') 

def getSegments(firmware_txt,firmware_bin):
    all_len=os.path.getsize(firmware_bin)
    firmware_txt=open(firmware_txt,'r')
    strr=firmware_txt.read()
    firmware_txt.close()
    segments=[]
    print(firmware_bin)
    firmware_bin=open(firmware_bin,'rb')
    if(strr.find("MRVL") != -1):
        print("Marvell Chip Firmware")
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
            print("RTL8711B Chip Firmware")
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
            print("RTL8195A Chip Firmware")
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
        print("HF-MC3000 Chip Firmware")
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
        print("HF-MC101 Chip Firmware")
        offset1=0
        base_addr1=0x400000
        len1=all_len
        segments.append((offset1,base_addr1,len1))
    elif(strr.find("STM32F4")!=-1):
        print("STM32F4XX Chip Firmware")
        offset1=0
        base_addr1=0x800C000
        len1=all_len
        segments.append((offset1,base_addr1,len1))       
    return segments


      
gerbil_cfg_path='/home/yaoyao/gerbil_results2'
angr_cfg_path='/home/yaoyao/angr_results' 
cfg_gerbil=dict()
cfg_angr=dict()             
'''for root, dirname, files in os.walk(filepath):
    for firmware in files:
        if 'cfg' in firmware:
            print firmware
            cfg=pickle_load_cfg_fast(os.path.join(root,firmware))
            cfg_gerbil.update({firmware:cfg})'''
'''for root, dirname, files in os.walk(filepath2):
    for firmware in files:
        cfg=pickle_load_cfg_fast(os.path.join(root,firmware))
        cfg_angr.update({firmware:cfg})  '''

file_dir='/home/yaoyao/light_firmware'
for root,dirs,files in os.walk(file_dir):
    for fw in files:
        if 'upd_aux.aircondition.hc1.bin' == fw:
            continue
        if 'mico_ota.bin' in fw:
            continue
        if "bin" in fw:
            print fw
            count=0
            total_num=0
            wrong_num=0
            intervel=5
            segments=getSegments(file_dir+'/'+fw[:-3]+"txt",file_dir+'/'+fw)
            print(segments)
            i=0
            for segment in segments:
                i=i+1
                base_addr=segment[1]
                main_segments=[]
                main_segments.append(segment)
                proj = angr.Project(file_dir+'/'+fw,load_options={'auto_load_libs':False},main_opts={'backend':'blob','custom_base_addr':base_addr,'custom_entry_point':base_addr,'custom_arch':'arm','segments':main_segments})
                cfg_fast=None
                cfg_file="cfg_all_"+str(i)+"_"+fw
                for cfg_root, dirname, files in os.walk(angr_cfg_path):
                    for cfg_name in files:
                        if cfg_file == cfg_name:
                            print cfg_name
                            cfg_g=pickle_load_cfg_fast(os.path.join(cfg_root,cfg_name))
                            memory=proj.loader.memory
                            for node_g in cfg_g.graph.nodes():
                                if total_num==2000:
                                    break
                                node_addr=node_g.addr
                                if node_addr%2==0:
                                    node_addr=node_addr
                                count=count+1
                                if count%intervel==0:
                                    total_num=total_num+1
                                    block = proj.factory.block(node_addr)
                                    #print "----block----"
                                    #block.pp()
                                    if block.size == 0:
                                        wrong_num=wrong_num+1
                                    strings = []
                                    stn = ""
                                    offset = 0
                                    addr=node_addr-1
                                    if addr+offset in memory:
                                        current_char = memory[addr + offset]
                                        while current_char in string.printable:
                                            stn += current_char
                                            offset += 1
                                            current_char = memory[addr + offset]
                                            if current_char == "\x00" and len(stn) >= 2:
                                                strings.append((addr, stn))
                                        #print strings
                                        if len(strings)>0:
                                            wrong_num=wrong_num+1
                                    else:
                                         wrong_num=wrong_num+1
            print "total num  ",total_num
            print "wrong num ", wrong_num
