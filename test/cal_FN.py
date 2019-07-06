import os 
import angr
import claripy
import re
from angr.state_plugins.sim_action import SimAction, SimActionConstraint
from cle.address_translator import AT
import cPickle as pickle
import time
import logging
import binascii
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

effective_node_file=open('effective_nodes.txt','r')
gerbil_cfg_path='/home/yaoyao/gerbil_results2'
angr_cfg_path='/home/yaoyao/angr_results' 
node_addrs=list()
count=0
FNR=0
num=0
already_fw=dict()
already_gerbil_nodes=open('gerbil_FN1.txt')
already_angr_nodes=open('angr_FN.txt')
angr_cfg_dict=dict()
gerbil_cfg_dict=dict()

for root, dirs, cfg_file in os.walk(angr_cfg_path):
    for cfg_name in cfg_file:
        angr_cfg_dict.update({cfg_name:os.path.join(root,cfg_name)})
#print angr_cfg_dict

for root, dirs, cfg_file in os.walk(gerbil_cfg_path):
    for cfg_name in cfg_file:
        gerbil_cfg_dict.update({cfg_name:os.path.join(root,cfg_name)})
#print gerbil_cfg_dict
for line in already_angr_nodes.readlines(): #modify
    line=line[:-1]
    if '.bin' in line:
        fw_name=line
    elif 'cfg' not in line and len(line)>0:
        #print(line)
        fn=int(line)
        fnr=(fn/2000.0)
        already_fw.update({fw_name:fnr})
#print already_fw
cal=True
for line in effective_node_file.readlines():
    if 'bin' in line and 'cfg' not in line:
        line=line[:-1]
        if line in already_fw.keys():
            FNR=FNR+already_fw[line]
            flag=False
            cal=False
        elif "cfg_all_1_"+line not in angr_cfg_dict.keys():
            print FNR
            cal=False
            flag=False
        else:
            num=num+1
            print 2000-count
            print line        
            if cal:
                FNR=FNR+(float)(2000-count)/2000
            print FNR    
            count=0
            flag=True
            cal=True
    elif flag:
        if 'cfg' in line:
            cfg=pickle_load_cfg_fast(angr_cfg_dict[line[:-1]])
            for node_g in cfg.graph.nodes():
                node_addrs.append(node_g.addr)
        else:
            effect_node=int(line,16)
            if effect_node in node_addrs or effect_node+1 in node_addrs or effect_node-1 in node_addrs:
                count=count+1
print FNR/100    
effective_node_file.close()
already_gerbil_nodes.close()    

   
