# -*- coding: utf-8 -*-
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


#监听回调函数，此处为打印消息
def notification_handler(event_q2:queue.Queue, res_list:list, client, characteristic: BleakGATTCharacteristic, data: bytearray):
    res_list.puch_back(data)
    print('notify', data)
    event_q2.put(("notify", client, characteristic, data))
    
async def ble_main(event_q1:queue.Queue, event_q2:queue.Queue):
    print("starting scan...")
    map_list:dict[str,ThreadSafeList] = {}
    while True:
        try:
            item = event_q1.get_nowait()
        except:
            await asyncio.sleep(0.001)
            continue
        if(item[0] == 'scan'):
            if item[1] is None:     
            #基于MAC地址查找设备
                device = await BleakScanner.find_device_by_address(
                    item[2])
            else:
                device = await BleakScanner.find_device_by_name(item[1])
            event_q2.put((item[0], device))
        elif item[0] == 'connect':
            device = item[1]
            client = BleakClient(device)
            await client.connect()
            map_list[client] = ThreadSafeList(100000)
            print("Connected")
            await client.start_notify(item[2], functools.partial(notification_handler, event_q2,map_list[client], client))        
            event_q2.put((item[0], client))
        elif item[0] == 'write':
            client:BleakClient = item[1]
            data = item[3]
            chunk_size = client.mtu_size - 3
            while len(data) > 0:
                await client.write_gatt_char(item[2], data[:chunk_size])
                data = data[chunk_size:]
            event_q2.put((item[0], None))
            
        elif item[0] == 'inWaiting':
            client:BleakClient = item[1]
            msg_l = map_list[client]
            event_q2.put((item[0], msg_l.size()))
        elif item[0] == 'read':
            client:BleakClient = item[1]
            read_len = item[2]
            timeout = item[3]
            msg_l = map_list[client]
            dst_time = time.time() + timeout
            while msg_l.empty() and time.time() < dst_time:
                await asyncio.sleep(0.001)
            res = msg_l.front_pop(read_len)
            event_q2.put((item[0], bytes(res) if res is not None else None))
        elif item[0] == 'disconnect':
            client:BleakClient = item[1]
            await client.disconnect()
            event_q2.put((item[0], client))
            
def ble_task(event_queue:queue.Queue, event_q2:queue.Queue):
    asyncio.run(ble_main(event_queue, event_q2))



class Serial:
    def __init__(self, bd_addr, baudrate = None, inter_byte_timeout = None, timeout = None):
        self.bd_addr = bd_addr
        self.bd_name = None
        if (len(bd_addr) != 17 and len(bd_addr) != 12) or re.search(r'[^0-9a-fA-F:-]', bd_addr) is not None:
            self.bd_name, self.bd_addr = self.bd_addr, self.bd_name
            
        self.port = 1
        self.inter_byte_timeout = inter_byte_timeout
        self._timeout = timeout
        self.sock = None
        self.q1 = queue.Queue()
        self.q2 = queue.Queue()
        self.t = threading.Thread(target=ble_task, args=(self.q1, self.q2))
        self.t.setDaemon(True)
        self.t.start()
        self.open()
    
    def ble_run(self, name, args, timeout):
        self.q1.put((name, *args))
        dst_time = time.time() + timeout
        while True:
            try:
                item = self.q2.get(timeout=dst_time-time.time())
            except Exception as e:
                raise e
            else:
                if item[0] != name:
                    continue
                return item[1]
        
    @property
    def timeout(self):
        """获取超时时间"""
        return self._timeout

    @timeout.setter
    def timeout(self, value):
        """设置超时时间"""
        self._timeout = value
    
    def open(self):
        """打开蓝牙连接"""        
        try:
            self.ble_addr = self.ble_run('scan', (self.bd_name, self.bd_addr), 10)
            self.sock = self.ble_run('connect', (self.ble_addr, "fff1"), 10)
        except queue.Empty:
            raise SerialException(f"addr {self.bd_addr} connect fail")
        else:
            if self.sock is None:
                raise SerialException(f"addr {self.bd_addr} connect fail")

    def close(self):
        """关闭蓝牙连接"""
        if self.sock:
            self.ble_run('disconnect', (self.sock,), 10)
            print(f"Disconnected from {self.ble_addr}")

    def write(self, data):
        """向蓝牙设备发送数据"""
        try:
            self.ble_run('write', (self.sock, 'fff2' ,data), 2 + 10 * len(data)/1024)
        except queue.Empty:
            raise SerialTimeoutException(f"addr {self.ble_addr} write timeout")

    def inWaiting(self):
        """获取缓冲区中的数据长度"""
        return self.ble_run('inWaiting', (self.sock,), 10)
    
    def read(self, size=1024):
        """从蓝牙设备接收数据"""
        try:
            res = self.ble_run('read', (self.sock, size, self._timeout), max(10, self._timeout))
        except queue.Empty:
            raise SerialTimeoutException(f"addr {self.ble_addr} read timeout")
        else:
            if len(res) == 0:
                raise SerialTimeoutException(f"addr {self.ble_addr} read timeout")
            return res
        


    def flush(self):
        """清空缓冲区"""
        pass  # 蓝牙通信可能不需要这个方法
    
if __name__ == "__main__":
    
    bd_addr = "testble"  # 替换为你的蓝牙设备地址

    # 创建 BluetoothSerial 实例
    bt_serial = Serial(bd_addr)
    time.sleep(10)
    # 设置超时时间为 5 秒
    bt_serial.timeout = 5.0

    try:
        # 发送数据
        bt_serial.write(b'Hello, Bluetooth!')

        # 接收数据
        data = bt_serial.read()
        print(data)
    except SerialTimeoutException as e:
        print(e)

    # 动态修改超时时间为 10 秒
    bt_serial.timeout = 10.0

    try:
        # 再次接收数据
        data = bt_serial.read()
        print(data)

    except SerialTimeoutException as e:
        print(e)

    # 关闭蓝牙连接
    bt_serial.close()
