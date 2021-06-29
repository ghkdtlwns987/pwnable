# python2.7
# path : /usr/lib/python2.7

from pwn import*
import argparse
import inspect
import os
import subprocess

log.info("Made My ghdktlwns987")
log.info("Must install Tmux, python2.7, pwntools, argparse, vtable")
log.info('ex : python exploit.py -r  ~>  remote version')
log.info('ex : python exploit.py -p  ~>  process execution')
log.info('ex : python exploit.py     ~>  attach version')

print("========================")
print("Use Info")
print("import tools")
print("...")
print("if tools.args.remote:")
print("\tr = remote(host,port)")
print("elif tools.args.process:")
print("\tr = process('./note')")
print("else:")
print("\tr = process('./note')")
print("\tgdb.attach(r)")
print("...")
print("========================")

pause()

parser = argparse.ArgumentParser()
parser.add_argument('-r','--remote', action = 'store_true', help='-r = remote connection')
parser.add_argument('-p','--process', action = 'store_true', help='-p = process execution')
args = parser.parse_args()
