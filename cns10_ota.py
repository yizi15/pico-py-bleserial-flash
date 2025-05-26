

import bleak
import threading
import json
import asyncio
import main
import sys
import os
import bleak
import queue
import serial
import time
import re
import functools
from serial import SerialException,SerialTimeoutException
import asyncio
from bleak import BleakClient, BleakScanner
from bleak.backends.characteristic import BleakGATTCharacteristic
import threading

msg_wait_l = []
class ThreadSafeList:  
    def __init__(self, max_len):  
        self.lock = threading.Lock()  
        self.data = []  
        self.max_len = max_len 
  
    def size(self):
        with self.lock:  
            return len(self.data)
    def empty(self):
        return len(self.data) == 0
    
    def front_pop(self, count):  
        with self.lock:  
            ret = self.data[:count]
            del self.data[:count]
        return ret
    
    def puch_back(self, items):  
        with self.lock:  
            if len(self.data) + len(items) <= self.max_len:
                self.data += list(items)
                
def CalCRC16(data, length):
    data = list(data)
    crc=0xFFFF
    j = 0
    while length != 0:
        crc ^= list.__getitem__(data, j)
        for i in range(0,8):
            if crc & 1:
                crc >>= 1
                crc ^= 0xA001
            else:
                crc >>= 1
        length -= 1
        j += 1

    return crc&0xFFFF

# 获取消息的CRC
def get_msg_crc(msg, msg_len=None):
    if msg_len is None:
        msg_len = len(msg)
    crc = CalCRC16(msg, msg_len)
    crc = int.to_bytes(crc, 2, byteorder='big', signed=False)
    return crc

g_list = ThreadSafeList(5000)
bytes_buffer = bytearray()

def print_hex(l):
    i = 0
    while i < len(l):
        addr = hex(i)[2:].rjust(8, '0')
        print(f'0x{addr}', end=':')
        for j in range(16):
            if i + j == len(l):
                break
            v = hex(l[i + j])[2:].rjust(2, '0')
            print(' ', v, end='')
        print('',bytes(l[i:i+16]))
        i += 16
        
def notify(data:bytearray):
    global g_list, bytes_buffer

    while len(data) > 0 and data[0] == 170:
        data = data[1:]
    if len(data) == 0:
        return
    if len(data) > 14 and data[0] == 0x5A and data[1] == 0xA5:
        if len(bytes_buffer) != 0:
            print('warning lost')

    g_list.puch_back(data)
    def parser_msg(in_bytes:bytes):
        cmd_type = int.from_bytes(in_bytes[12:14], byteorder = 'little', signed = False)
        res = int.from_bytes(in_bytes[16:20], byteorder = 'little', signed = False)
        return cmd_type, res, in_bytes[28:-2]
    err_flag = False
    def read_msg(length):
        r_l =  bytes(g_list.front_pop(length)) 
        return r_l if len(r_l) > 0 else None

    def get_msg_len(msg):
        length = int.from_bytes(msg[8:12], byteorder = 'little', signed = False)
        if length > 50000:
            return -1
        return length

    head = b'\x5A\xA5'
    head_len = 14
    while err_flag == False:

        # 查找消息头
        while len(bytes_buffer) < len(head) and err_flag == False:
            read_data = read_msg(1)
            if read_data is None:
                return
            if read_data[0] == head[len(bytes_buffer)]:
                bytes_buffer.append(read_data[0])
            else:
                bytes_buffer.clear()
                break
                    
        if len(bytes_buffer) < len(head):
            continue
        
        # 判断消息头
        while len(bytes_buffer) < head_len and err_flag == False:
            read_data = read_msg(head_len - len(bytes_buffer))
            if read_data is None:
                return
            bytes_buffer += read_data
        msg_all_len = get_msg_len(bytes_buffer)

        if msg_all_len < head_len:
            bytes_buffer.clear()
            continue
        
        # 读取消息体
        while len(bytes_buffer) < msg_all_len and err_flag == False:
            read_data = read_msg(msg_all_len - len(bytes_buffer))
            if read_data is None:
                return
            bytes_buffer += read_data
        msg_crc = bytes_buffer[-2:]
        cal_crc = get_msg_crc(bytes_buffer, len(bytes_buffer) - 2)
        if cal_crc != msg_crc:
            print(f'crc fail {cal_crc} {msg_crc}')
        else:
            cmd, res, data = parser_msg(bytes_buffer)
            try:
                msg_wait_l.remove(cmd)
            except:
                pass
            print(f'cmd {hex(cmd)},{cmd} res {res}, all:len{msg_all_len}, datalen:{len(data)}')
            print_hex(data)
                    
        bytes_buffer.clear()


async def send(client, data):
    char = bleak.uuids.normalize_uuid_16(0xfff2)
    chunk_size = client.mtu_size - 3
    while len(data) > 0:
        await client.write_gatt_char(char, data[:chunk_size])
        data = data[chunk_size:]
  
async def msg_send(client, msg:bytes, cmd_type):
    byte_data = bytearray()
    byte_data += b'\x5A\xA5'
    byte_data += bytearray([1,37,0,0,0,0])
    byte_data += ((16 if cmd_type != 0x9999 else 14)+ len(msg)).to_bytes(4, byteorder='little', signed=False)
    byte_data += int(cmd_type).to_bytes(2, byteorder='little', signed=False)
    byte_data += msg
    crc = CalCRC16(byte_data, len(byte_data))
    crc = int.to_bytes(crc, 2, byteorder='big', signed=False)
    if cmd_type != 0x9999:
        byte_data += crc
    await asyncio.sleep(0.15)
    return await send(client,byte_data)

def enter_bootloader():
    return b'\x00', 0x9999
 
    

#监听回调函数，此处为打印消息
def notification_handler(characteristic: BleakGATTCharacteristic, data: bytearray):
    pass
    
class CNS10:
    def __init__(self):
        self.root = asyncio.get_event_loop()
        asyncio.set_event_loop(self.root)
        self.t = threading.Thread(target = lambda loop: loop.run_forever(), args=(self.root,))
        self.t.start()
    
    @staticmethod
    def device_str_re(name):
        return re.search(r'([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}):\s+(.+)', name)

    
    def connect(self,name):
        res = self.device_str_re(name)
        print('start scan', name)
        if res is not None:
            name = res.group(2)
            mac = res.group(1)
            self.device = asyncio.run_coroutine_threadsafe(BleakScanner.find_device_by_address(mac), self.root).result()
        else:
            self.device = asyncio.run_coroutine_threadsafe(BleakScanner.find_device_by_name(name), self.root).result()

        print('scan find', self.device)
        self.c_name = self.device.name
        self.c_mac = self.device.address
        
        self.client = BleakClient(self.device)
        asyncio.run_coroutine_threadsafe(self.client.connect(), self.root).result()
        asyncio.run_coroutine_threadsafe(asyncio.sleep(1), self.root).result()
        asyncio.run_coroutine_threadsafe(self.client.start_notify(bleak.uuids.normalize_uuid_16(0xfff1), notification_handler), self.root).result()
       
        self.chunk_size = self.client.mtu_size - 3
        print('mtu_size', self.client.mtu_size)
    
    def devices(self):
        devices = asyncio.run_coroutine_threadsafe(BleakScanner.discover(), self.root).result()
        rets = []
        for d in devices[:]:
            if d.name is None:
                continue
            if d.name.startswith('CNS10-'):
                rets.append(d)
            if d.name.startswith('C10S-'):
                rets.append(d)
            if d.name == 'C8S_BLELOADER':
                rets.append(d)
        return rets
    
    def __del__(self):
        asyncio.run_coroutine_threadsafe(self.client.disconnect(), self.root).result()
        del self.client

import tkinter as tk
import tkinter.ttk as ttk
from tkinter import filedialog
# UI 层
class MyApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("通信测试 1.0.0")
        self.c = CNS10()
        self.devices = self.c.devices()
        self.input_box = ttk.Combobox(values=self.devices,width=40)
        self.input_box.insert(0, self.devices[0])
        self.input_box.grid(column=0, row=0)
        tk.Button(self, text="连接", command=self.on_button1_click).grid(column=0, row=1)
        tk.Button(self, text="执行", command=self.on_button2_click).grid()
        entry_var = tk.StringVar()
        entry_var.set("r'D:\Downloads\C10S(1).elf'")
        self.input_box_firm = tk.Entry(self, textvariable=entry_var, width=40)
        self.input_box_firm.grid()
        
    def on_button1_click(self):
        input_text = self.input_box.get()
        res = CNS10.device_str_re(input_text)
        if res is not None:
            self.c_name = res.group(2)
        else:
            self.c_name = input_text
        
        if self.c_name != 'C8S_BLELOADER':
            try:
                self.c.connect(self.c_name)
            except Exception as e:
                print(repr(e))
        else:
            print('already in bootloader')

    def on_button2_click(self):
        input_path = self.input_box_firm.get()
        if len(input_path) == 0:
            input_path = filedialog.askopenfilename(title="选择固件", initialdir='/',
                                                    filetypes=(("elf", "*.elf"), ("所有文件", "*.*")))
            # 再插入新内容
            self.input_box_firm.delete(0,'end')
            self.input_box_firm.insert(0, input_path)
        if not os.path.isfile(input_path):
            print(f'文件 {input_path} 不存在')
            return
        
        start_time = time.time()
        print(f'start_time', start_time)
        if self.c_name != 'C8S_BLELOADER':
            async def exec_cmd():
                await msg_send(self.c.client, *enter_bootloader())
            asyncio.run_coroutine_threadsafe(exec_cmd(), self.c.root).result()
            time.sleep(1)
            try:
                del self.c
            except Exception as e:
                pass
                self.c = None
                
            time.sleep(10)

        sys.argv = [sys.argv[0], 'C8S_BLELOADER', input_path]
        main.main()
        use_time = int(time.time() - start_time)
        print(f'use time {use_time}')


if __name__ == "__main__":
    app = MyApp()
    app.mainloop()
    del app

   
    