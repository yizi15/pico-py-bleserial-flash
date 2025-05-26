import bleak
import threading
import json
import asyncio

g_docter = "test1"
g_serial_id = "690025200010"
g_patient = '2951234567890'
def get_ble_name():
    return "CNS10-" + g_serial_id[4:]

msg_test_count = 0
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

def get_register_code(sid:str):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.backends import default_backend
    import os
    cipher = Cipher(algorithms.AES(bytes([132,137,108,241,90,6,39,157,218,123,43,134,27,191,114,16])), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    text = sid.ljust(16, '\x00').encode()
    encrypted_data = encryptor.update(text)
    tmp = []
    for i in range(8):
        v = int(encrypted_data[i]) ^ int(encrypted_data[i + 8])
        tmp.append(hex(v>>4)[2:])
        tmp.append(hex(v&0xF)[2:])
    return ''.join(tmp).lower()
    
def register_doctor(doctor_info):
    register_p = get_register_code(g_serial_id).ljust(128, '\x00').encode('utf-8')
    import math
    patient_s = json.dumps(doctor_info).encode('utf-8') + b'\x00'
    patient_s_len = len(patient_s).to_bytes(4, byteorder='little', signed=False)
    patient_s = patient_s.ljust(math.ceil(len(patient_s) / 16) * 16, b'\x00')
    return b''.join([register_p, patient_s_len, patient_s]), 0x110


def login_doctor(name:str, passw:str):
    name = name.encode('utf-8')
    passw = passw.encode('utf-8')
    name = name.ljust(128, b'\x00')
    passw = passw.ljust(128, b'\x00')
    return b''.join([name, passw]), 3


def modify_doctor_p(name:str, passw:str):
    register_p = get_register_code(g_serial_id).ljust(128, '\x00').encode('utf-8')
    name = name.encode('utf-8').ljust(128, b'\x00')
    passw = passw.encode('utf-8').ljust(128, b'\x00')

    return b''.join([register_p, name, passw, passw]), 4

def login_patient(patient_id:str, name:str):
    id = patient_id.encode().ljust(32, b'\x00')
    name = name.encode().ljust(64, b'\x00')
    return id + name, 2


def add_patient(patient_info):
    import math
    patient_s = json.dumps(patient_info).encode('utf-8') + b'\x00'
    patient_s_len = len(patient_s).to_bytes(4, byteorder='little', signed=False)
    patient_s = patient_s.ljust(math.ceil(len(patient_s) / 16) * 16, b'\x00')
    return patient_s_len + patient_s, 6

def query_patients():
    id_start = int.to_bytes(-1, 4, byteorder='little', signed=True)
    id_end = int.to_bytes(-1, 4, byteorder='little', signed=True)
    return b''.join([id_start, id_end]), 9


def modify_doctor(doctor_info):
    import math
    patient_s = json.dumps(doctor_info).encode('utf-8') + b'\x00'
    patient_s_len = len(patient_s).to_bytes(4, byteorder='little', signed=False)
    patient_s = patient_s.ljust(math.ceil(len(patient_s) / 16) * 16, b'\x00')
    return b''.join([patient_s_len, patient_s]), 0x111

def modify_patient(patient_info):
    import math
    patient_s = json.dumps(patient_info).encode('utf-8') + b'\x00'
    patient_s_len = len(patient_s).to_bytes(4, byteorder='little', signed=False)
    patient_s = patient_s.ljust(math.ceil(len(patient_s) / 16) * 16, b'\x00')
    return b''.join([patient_s_len, patient_s]), 0x112

def query_doctors():
    register_p = get_register_code(g_serial_id).ljust(128, '\x00').encode('utf-8')
    id_start = int.to_bytes(-1, 4, byteorder='little', signed=True)
    id_end = int.to_bytes(-1, 4, byteorder='little', signed=True)
    return b''.join([id_start, id_end,register_p]), 8

def query_params():
    id_start = int.to_bytes(-1, 4, byteorder='little', signed=True)
    id_end = int.to_bytes(-1, 4, byteorder='little', signed=True)
    p = g_patient.encode().ljust(32, b'\x00')
    return b''.join([id_start, id_end, p]), 0xf

def add_param():
    param = {
"version":0,
"expert_param":0,
"patientID":g_patient,
"doctor": "test1",
"mode": 1,#int, 0:tDCS, 1:tPCS, 2：tACS,4: 对称CES, 5， 非对称CES， 6 tODCS
"current": 2,#int, 单位 uA
"freq":21, #//double Hz
"direction": 0,#int, 0双向，1单向
"duration":10,# //double 单位s
"ramp_up":10,#, //double 单位s
"ramp_down": 10,# //double 单位s
"electrode": 1,#0x1:普通电极，0x2:高精度电极, 0x4:耳夹电极， 0x3, 普通电极&高精度电极,
"positive_channel":1,#, //1:1阳2阴，2：2阴1阳，两通道电极使用， 若无则默认1阳2阴
"center_direction":1, # //1 阳极，2：阴极 高精度电极使用
"scheme":"41234",# 值任意， 但ascii码长度需<64, utf8 最坏情况下16个中文 
"indication":"2",#//值任意，但ascii码长度需<64, utf8 最坏情况下16个中文 
"anode_position":"fpz",#//最长3字符， 如果需要展示中文名称，app做映射
"cathode_position": "o2",#//最长3字符
"center_position":"F1",#//最长3字符
"center_peripheral":"F3,FPZ,O2,O1",#// 最长15字符 "F3,FPZ,O2,O1"
}
    r = b'\x00\x00'
    patient_s = json.dumps(param).encode('utf-8') + b'\x00'
    patient_s_len = len(patient_s).to_bytes(4, byteorder='little', signed=False)
    return b''.join([r, patient_s_len, patient_s]), 0xc

def select_param(para:int, elec, need_count, current):
    patientID = g_patient.encode().ljust(32, b'\x00')
    charact = int.to_bytes(para, 4, byteorder='little', signed=False)
    elec = int.to_bytes(elec, 4, byteorder = 'little', signed = False)
    need_count = int.to_bytes(need_count, 4, byteorder='little', signed=False)
    current = int.to_bytes(current, 4, byteorder = 'little', signed = False)
    return b''.join([patientID, charact, elec, need_count, current]), 0xe


def start_sti(para:int):
    r = b'\x00\x00'
    charact = int.to_bytes(para, 4, byteorder='little', signed=False)
    elec = int.to_bytes(1, 4, byteorder = 'little', signed = False)
    patientID = g_patient.encode().ljust(32, b'\x00')
    return b''.join([r, charact, elec, patientID]), 0x64

def pre_sti():
    param = {
"mode": 5,#int, 0:tDCS, 1:tPCS, 2：tACS,4: 对称CES, 5， 非对称CES， 6 tODCS
"tODCS_type":1,
"current": 300,#int, 单位 uA
"freq":10, #//double Hz
"direction": 1,#int, 0双向，1单向
"positive_channel":1,#, //1:1阳2阴，2：2阴1阳，两通道电极使用， 若无则默认1阳2阴
"center_direction":1, # //1 阳极，2：阴极 高精度电极使用
}
    r = b'\x00\x00'
    ele = int.to_bytes(1, 4, byteorder='little', signed=False)
    patient_s = json.dumps(param).encode('utf-8') + b'\x00'
    patient_s_len = len(patient_s).to_bytes(4, byteorder='little', signed=False)
    return b''.join([r, ele, patient_s_len, patient_s]), 0x74

def adjust_current(current:int):
    r = b'\x00\x00'
    
    current = current.to_bytes(4, byteorder='little', signed=True)
    return r + current, 0x75

def modify_param(param_char:int):
    param = {
"version":0,
"expert_param":0,
"doctor": "test1",
"mode": 1,#int, 0:tDCS, 1:tPCS, 2：tACS,4: 对称CES, 5， 非对称CES， 6 tODCS
"current": 1,#int, 单位 uA
"freq":10, #//double Hz
"direction": 0,#int, 0双向，1单向
"duration":10,# //double 单位s
"ramp_up":10,#, //double 单位s
"ramp_down": 10,# //double 单位s
"electrode": 1,#0x1:普通电极，0x2:高精度电极, 0x4:耳夹电极， 0x3, 普通电极&高精度电极,
"positive_channel":1,#, //1:1阳2阴，2：2阴1阳，两通道电极使用， 若无则默认1阳2阴
"center_direction":1, # //1 阳极，2：阴极 高精度电极使用
"scheme":"4",# 值任意， 但ascii码长度需<64, utf8 最坏情况下16个中文 
"indication":"1",#//值任意，但ascii码长度需<64, utf8 最坏情况下16个中文 
"anode_position":"fpz",#//最长3字符， 如果需要展示中文名称，app做映射
"cathode_position": "o2",#//最长3字符
"center_position":"F1",#//最长3字符
"center_peripheral":"F3,FPZ,O2,O1",#// 最长15字符 "F3,FPZ,O2,O1"
    }
    r = b'\x00\x00' + param_char.to_bytes(4, 'little', signed=False)
    patient_s = json.dumps(param).encode('utf-8') + b'\x00'
    patient_s_len = len(patient_s).to_bytes(4, byteorder='little', signed=False)
    return b''.join([r, patient_s_len, patient_s]), 0x113

def enter_bootloader():
    return b'\x00', 0x9999

def remove_patient(patientID:str):
    count = int.to_bytes(1, 4, byteorder='little', signed=False)
    patientID = patientID.encode().ljust(32, b'\x00')
    return b''.join([count, patientID]), 7

def remove_param(param_char:int):
    count = int.to_bytes(1, 4, byteorder='little', signed=False)
    patientID = int.to_bytes(param_char, 4, byteorder='little', signed=False)
    return b''.join([b'\x00\x00', count, patientID]), 13

def query_record():
    import time
    return int.to_bytes(0, 8, 'little', signed=True) +\
        int.to_bytes(int(time.time()), 8, byteorder='little', signed=True) + \
        int.to_bytes(-1, 8, 'little', signed=True) + b'', 0xa
    

async def test_ble_single(client:bleak.BleakClient):
    global msg_test_count
    while True:
        msg_wait_l.append(1)
        msg_test_count += 1
        await msg_send(client, b'', 1)
        await asyncio.sleep(1)
        print("test run lost", msg_test_count, len(msg_wait_l)/msg_test_count)

def shakehand():
    import time
    timsstamp = int.to_bytes(int(time.time())*1000, 8, byteorder='little', signed=True)
    tz = int.to_bytes(8, 4, byteorder='little', signed=True)
    pem = b''.ljust(128, b'\x00')
    return b''.join([timsstamp, tz, pem]), 1

async def main(client:bleak.BleakClient):
    await msg_send(client, *enter_bootloader())
    return
    await msg_send(client, *login_doctor('冯','111111'))
    await msg_send(client, *query_doctors())
    return
    await msg_send(client, *shakehand())
    # await msg_send(client, *register_doctor({'name':'test1', 'passw':'test3'}))
    await msg_send(client, *login_doctor('test1', 'test3'))
    # await msg_send(client, g_patient.encode().ljust(32, b'\x00'), 101)
    # await msg_send(client, *add_patient({
    #         "version":0,
    #         "doctor":"test1",
    #         "patientID": g_patient,
    #         "name": "中阿公共",
    #         "birthday": "1990-01-01",
    #         "gender": 0,
    #         "bednumber":"abcdefg"
    #     }))
    # await msg_send(client,*add_param())
    # await msg_send(client, *query_patients())
    # await msg_send(client, *query_params())
    await msg_send(client, *modify_param(0x1021c200))
    # await asyncio.sleep(0.2)
    # await msg_send(client, *select_param(0x1021c200, 1, 1000, 100))
    # await asyncio.sleep(0.2)

    # await msg_send(client, *login_patient(g_patient, '中阿公共'))
    # await msg_send(client, *login_doctor('test1', 'test3'))
    # # await msg_send(client,*add_param())
    # await msg_send(client, *query_patients())
    # await msg_send(client, *pre_sti())
    # await msg_send(client, *query_record()) 
    await msg_send(client, *select_param(0x1021c200, 1, 10, 1000))
    await msg_send(client, *start_sti(0x1021c200))
    await asyncio.sleep(10)
    await msg_send(client, b'', 113)
    return
    # await test_ble_single(client)
    # await msg_send(client, bytes([65,20,58,153,149,1,0,0,8,0,0,0,48,0]), 1)
    # return
    # await msg_send(client, *enter_bootloader())
    # return
    #await msg_send(client, *register_doctor({'name':'test1', 'passw':'test2'}))
    await msg_send(client, *login_doctor('test1', 'test3'))
    # await msg_send(client, *modify_param(0x1020a200))
    await msg_send(client, *query_params())
    # await msg_send(client, *modify_doctor_p('test1', 'test3'))
    # await msg_send(client, *remove_patient("751234567890"))
    await msg_send(client,*add_param())
    return await msg_send(client, *add_patient({
        "version":0,
        "doctor":"test1",
        "patientID": g_patient,
        "name": "中阿公共",
        "birthday": "1990-01-01",
        "gender": 0,
        "bednumber":"abcdefg"
    }))

if __name__ == '__main__':
    print(get_register_code('690025210008'))