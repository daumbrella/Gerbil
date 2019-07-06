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
import nampa

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


def get_funcs(filename,fm_fast,lib_sig):
    total_func=0
    lib_func=0
    total_func_size=0
    lib_func_size=0
    for function_addr in fm_fast:
        total_func=total_func+1
        function=fm_fast.function(function_addr)
        function_size=function.size
        func_buf=function.byteStr32
        total_func_size=total_func_size+function_size
        match_result=nampa.match_function(lib_sig,func_buf)
        if match_result[0]:
            lib_func=lib_func+1
            lib_func_size=lib_func_size+function_size
    print filename,total_func,lib_func,total_func_size,lib_func_size

def test_lib_num():
    fw_path='/home/yaoyao/angr_results3'
    fpath='/home/yaoyao/test/angr_pat/marvel (copy).err'
    #fpath='/home/yaoyao/test/angr_pat/all_lib_sig.err'
    fm_fast=None
    lib_sig=None
    if fpath.endswith('.err'):
        lib_sig=nampa.parse_flirt_pat_file(open(fpath,'r'))
    elif fpath.endswith('.sig'):
        lib_sig = nampa.parse_flirt_sig_file(open(fpath, 'r'))
    for root,dirs,file in os.walk(fw_path):
        for filename in file:
            if 'fm_fast' in filename:
                fm_path=os.path.join(root,filename)
                fm_fast=pickle_load_fm_fast(fm_path)
                get_funcs(filename,fm_fast,lib_sig)

test_lib_num()
