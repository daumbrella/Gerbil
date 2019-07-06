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
    arch=None
    all_len=os.path.getsize(firmware_bin)
    firmware_txt=open(firmware_txt,'r')
    strr=firmware_txt.read()
    firmware_txt.close()
    segments=[]
    print(firmware_bin)
    firmware_bin=open(firmware_bin,'rb')
    if(strr.find("MRVL") != -1):
        print("Marvell Chip Firmware")
        arch='thumb'
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
        arch='thumb'
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
            arch='thumb'
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
        arch='arm'
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
        arch='thumb'
        offset1=0
        base_addr1=0x400000
        len1=all_len
        segments.append((offset1,base_addr1,len1))
    elif(strr.find("STM32F4")!=-1):
        print("STM32F4XX Chip Firmware")
        arch='thumb'
        offset1=0
        base_addr1=0x800C000
        len1=all_len
        segments.append((offset1,base_addr1,len1))       
    return (arch,segments)
def get_fw_libs_num(file_dir,fw):
    loading_rules=getSegments(file_dir+'/'+fw[:-3]+"txt",file_dir+'/'+fw)
    arch=loading_rules[0]
    arm_mode_thumb=None
    if arch == 'thumb':
        arm_mode_thumb=True
    segments=loading_rules[1]
    if not arm_mode_thumb:
        print(segments)
        i=0
        for segment in segments:
            i=i+1
            base_addr=segment[1]
            main_segments=[]
            main_segments.append(segment)
            proj = angr.Project(file_dir+'/'+fw,load_options={'auto_load_libs':False},main_opts={'backend':'blob','custom_base_addr':base_addr,'custom_entry_point':base_addr,'custom_arch':'arm','segments':main_segments})
            cfg_fast=None
            fm_fast=None
            fm_accurate=None
            cfg_file="cfg_all_"+str(i)+"_"+fw
            fm_fast_file="fm_fast_"+str(i)+"_"+fw
            if not os.path.exists(cfg_file):
                print "The cfg_file not exists, construct it..."
                cfg_start_time=time.time()
                cfg_fast= proj.analyses.CFG(force_complete_scan=True,arm_mode_thumb=arm_mode_thumb)
                print str(i)+"_"+fw+",nodes,"+str(len(cfg_fast.graph.nodes()))
                print str(i)+"_"+fw+",edges,"+str(len(cfg_fast.graph.edges()))
                fm_fast=cfg_fast.kb.functions
                print(len(fm_fast))
                pickle_dump_cfg_fast(cfg_file,cfg_fast)
                pickle_dump_fm_fast(fm_fast_file,fm_fast)
                cfg_end_time=time.time()
                print "Construct the cfg all costs ",cfg_end_time-cfg_start_time

for root, dirs,files in os.walk('/home/yaoyao/light_firmware'):
    for fw_name in files:
        if 'bin' in fw_name:
            get_fw_libs_num('/home/yaoyao/light_firmware',fw_name)
                
                
                
                
   
