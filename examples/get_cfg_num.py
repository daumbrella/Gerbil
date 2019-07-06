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

def get_cfg_fm(file_dir):
    for root,dirs,files in os.walk(file_dir):
        for fw in files:
            if("bin" in fw):
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
                    fm_fast=None
                    fm_accurate=None
                    cfg_file="cfg_all_"+str(i)+"_"+fw
                    fm_fast_file="fm_fast_"+str(i)+"_"+fw
                    if not os.path.exists(cfg_file):
                        print "The cfg_file not exists, construct it..."
                        cfg_start_time=time.time()
                        cfg_fast= proj.analyses.CFG(force_complete_scan=True)
                        fm_fast=cfg_fast.kb.functions
                        pickle_dump_cfg_fast(cfg_file,cfg_fast)
                        pickle_dump_fm_fast(fm_fast_file,fm_fast)
                        cfg_end_time=time.time()
                        print "Construct the cfg all costs ",cfg_end_time-cfg_start_time

def get_fun_num(file_dir):
    for root,dirs,files in os.walk(file_dir):
        for file in files:
            if (file.find("cfg")!=-1):
                cfg_fast=pickle_load_cfg_fast(file)
                print file[8:]+",nodes,"+str(len(cfg_fast.graph.nodes()))
                print file[8:]+",edges,"+str(len(cfg_fast.graph.edges()))
get_fun_num('/home/yaoyao/gerbil_results')
                
                
                
                
   
