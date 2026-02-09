# AdvHD WS2 脚本反汇编/汇编工具
#
# 使用方法:
# 1. 反汇编 (WS2 -> ASM):
#    python disasm_ws2.py <输入文件或目录> [输出目录]
#
# 2. 汇编 (ASM -> WS2):
#    python disasm_ws2.py --assemble <输入asm文件> <输出ws2文件> [加密模式]
#    加密模式: --encrypt (默认, 加密输出) 或 --no-encrypt (不加密输出)
#
# 3. 加密/解密工具:
#    python disasm_ws2.py --tool <encrypt|decrypt> <输入文件或目录> <输出目录>
#

import struct
import os
import sys
import json
import ast

OPCODE_NAMES = {
    0x01: "Condition",
    0x02: "Jump2",
    0x04: "RunFile",
    0x05: "Unk05",
    0x06: "Jump",
    0x07: "NextFile",
    0x08: "Unk08",
    0x09: "LayerConfig",
    0x0A: "Unk0A",
    0x0B: "SetFlag",
    0x0D: "Unk0D",
    0x0E: "Unk0E",
    0x0F: "ShowChoice",
    0x11: "SetTimer",
    0x12: "StartTimer",
    0x13: "Unk13",
    0x14: "DisplayMessage",
    0x15: "SetDisplayName",
    0x16: "Unk16",
    0x17: "Unk17",
    0x18: "AddMessageToLog",
    0x19: "Unk19",
    0x1A: "OpenTitle",
    0x1B: "Unk1B",
    0x1C: "ExecuteFunction",
    0x1D: "Unk1D",
    0x1E: "PlayMusic",
    0x1F: "StopMusic",
    0x20: "MusicUnk1",
    0x28: "SoundEffect",
    0x29: "SoundUnk1",
    0x2A: "SoundUnk2",
    0x2E: "CharMessageStart",
    0x32: "VariableUnk32",
    0x33: "SetBackground",
    0x34: "UsePnaPackage",
    0x35: "PlayMovie",
    0x36: "PrepareBackgroundArea",
    0x37: "ClearLayer",
    0x38: "VariableUnk3",
    0x39: "DisplayCharacterImage",
    0x3A: "UnkBackground2",
    0x3B: "BackgroundMessage",
    0x3D: "Unk3D",
    0x3E: "Unk3E",
    0x3F: "LayersList",
    0x40: "SetMask",
    0x41: "UnkBackground3",
    0x42: "Unk42",
    0x43: "Unk43",
    0x44: "Effect44",
    0x45: "DragBackground",
    0x46: "MoveBackground",
    0x47: "Effect1",
    0x48: "Effect2",
    0x4A: "Unk4A",
    0x51: "VariableUnk51",
    0x52: "VariableUnk2",
    0x53: "VariableUnk4",
    0x56: "RainStart",
    0x57: "UnkBackground1",
    0x58: "Effect3",
    0x5B: "InitKeyName",
    0x5C: "RainEnd",
    0x64: "Unk64",
    0x65: "C65",
    0x67: "Unk67",
    0x68: "Unk68",
    0x6E: "SetVariable",
    0x6F: "VariableUnk",
    0x73: "SetPnaFile",
    0x75: "Unk75",
    0x78: "Unk78",
    0x7A: "Unk7A",
    0x7B: "Unk7B",
    0x84: "Unk84",
    0x97: "Unk97",
    0xFB: "UnkFB",
    0xFC: "UnkFC",
    0xFD: "UnkFD",
    0xFF: "FileEnd"
}

OPCODES = {
    "0": [-1],
    "1": [0, 1, 5, 4, 4, -1],
    "2": [4, -1],
    "4": [10, 8, -1],
    "5": [-1],
    "6": [4, -1],
    "7": [10, 8, -1],
    "8": [0, -1],
    "9": [0, 1, 5, -1],
    "10": [1, 5, -1],
    "11": [1, 0, -1],
    "12": [1, 0, 7, 1, -1],
    "13": [1, 1, 5, -1],
    "14": [1, 1, 0, -1],
    "15": [0, -1],
    "17": [6, 8, 0, 5, -1],
    "18": [6, 8, 0, 10, 8, -1],
    "19": [-1],
    "20": [4, 6, 8, 6, 8, 0, -1],
    "21": [6, 8, 0, -1],
    "22": [0, 0, -1],
    "23": [-1],
    "24": [0, 6, 8, -1],
    "25": [-1],
    "26": [6, 8, -1],
    "27": [0, -1],
    "28": [6, 8, 6, 8, 1, 0, -1],
    "29": [1, -1],
    "30": [6, 8, 10, 8, 5, 5, 1, 1, 0, 5, -1],
    "31": [6, 8, 5, -1],
    "32": [6, 8, 5, 1, -1],
    "33": [6, 8, 1, 1, 1, -1],
    "34": [6, 8, 0, -1],
    "40": [6, 8, 10, 8, 5, 5, 1, 1, 0, 1, 1, 0, 5, -1],
    "41": [6, 8, 5, -1],
    "42": [6, 8, 5, 1, -1],
    "43": [6, 8, -1],
    "44": [6, 8, -1],
    "45": [6, 8, 0, -1],
    "46": [-1],
    "47": [6, 8, 1, 5, -1],
    "48": [6, 8, 5, -1],
    "50": [10, 8, -1],
    "51": [6, 8, 10, 8, 0, 0, -1],
    "52": [6, 8, 10, 8, 0, 0, -1],
    "53": [6, 8, 10, 8, 0, 0, 0, -1],
    "54": [6, 8, 5, 5, 5, 5, 5, 5, 5, 0, 0, -1],
    "55": [6, 8, -1],
    "56": [6, 8, 0, -1],
    "57": [6, 8, 0, 0, 7, 1, -1],
    "58": [6, 8, 0, 0, -1],
    "59": [6, 8, 6, 8, 1, 1, 1, 5, 5, 5, 5, 5, 5, 5, 5, -1],
    "60": [6, 8, -1],
    "61": [1, -1],
    "62": [-1],
    "63": [7, 6, -1],
    "64": [6, 8, 10, 8, 0, -1],
    "65": [6, 8, 0, -1],
    "66": [6, 8, 1, -1],
    "67": [6, 8, -1],
    "68": [6, 8, 6, 8, 0, -1],
    "69": [6, 8, 1, 5, 5, 5, 5, -1],
    "70": [6, 8, 1, 0, 5, 5, 5, 5, -1],
    "71": [6, 8, 6, 8, 1, 0, 0, 5, 5, 5, 5, 5, 1, 5, -1],
    "72": [6, 8, 6, 8, 1, 0, 0, 10, 8, -1],
    "73": [6, 8, 6, 8, 10, 8, -1],
    "74": [6, 8, 6, 8, -1],
    "75": [6, 8, 1, 1, 5, 5, 5, 5, -1],
    "76": [6, 8, 1, 1, 0, 5, 5, 5, 5, -1],
    "77": [6, 8, 6, 8, 1, 1, 0, 0, 5, 5, 5, 5, 5, 1, 5, -1],
    "78": [6, 8, 6, 8, 1, 1, 0, 0, 10, 8, -1],
    "79": [6, 8, 6, 8, 1, 10, 8, -1],
    "80": [6, 8, 6, 8, 1, -1],
    "81": [6, 8, 6, 8, 1, 5, 0, -1],
    "82": [6, 8, 6, 8, 5, 1, 5, 0, 10, 8, -1],
    "83": [6, 8, 6, 8, -1],
    "84": [6, 8, 6, 8, 10, 8, -1],
    "85": [6, 8, 6, 8, -1],
    "86": [6, 8, 0, 1, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 0, 5, 5, 5, 5, 0, 1, 6, 8, 1, 6, 8, 10, 8, 5, -1],
    "87": [6, 8, 1, -1],
    "88": [6, 8, 6, 8, -1],
    "89": [6, 8, 6, 8, 1, -1],
    "90": [6, 8, 7, 1, -1],
    "91": [6, 8, 1, 0, -1],
    "92": [6, 8, -1],
    "93": [6, 8, 6, 8, 0, -1],
    "94": [6, 8, 5, 5, -1],
    "95": [10, 8, -1],
    "96": [1, 1, 1, 1, -1],
    "97": [0, 5, 5, 5, 5, -1],
    "98": [6, 8, -1],
    "99": [6, 8, 0, -1],
    "100": [0, -1],
    "101": [1, 0, 5, 5, 0, 10, 8, -1],
    "102": [10, 8, -1],
    "103": [0, 0, 1, 5, 5, 5, 5, 5, 0, -1],
    "104": [0, -1],
    "105": [6, 8, 0, 0, 5, 5, 5, 5, 5, 1, 5, -1],
    "106": [6, 8, 1, 0, 0, 10, 8, -1],
    "107": [6, 8, 6, 8, -1],
    "108": [6, 8, 5, 5, -1],
    "109": [6, 8, 5, 5, 0, 0, 0, -1],
    "110": [9, 8, 6, 8, -1],
    "111": [9, 8, -1],
    "112": [9, 8, 1, -1],
    "113": [-1],
    "114": [9, 8, 1, 1, 9, 8, -1],
    "115": [9, 8, 9, 8, 1, -1],
    "116": [9, 8, 9, 8, -1],
    "117": [9, 8, 6, 8, -1],
    "120": [6, 8, 10, 8, 0, 0, 0, -1],
    "121": [6, 8, 6, 8, 5, -1],
    "122": [6, 8, 10, 8, 5, 0, 0, 10, 8, -1],
    "123": [6, 8, 10, 8, -1],
    "124": [6, 8, 6, 8, 5, -1],
    "125": [6, 8, 5, -1],
    "126": [6, 8, -1],
    "127": [6, 8, 5, 5, 5, 5, 5, -1],
    "128": [6, 8, -1],
    "129": [6, 8, 0, 10, 8, 5, 5, 0, -1],
    "130": [6, 8, 10, 8, 5, -1],
    "131": [6, 8, 6, 8, 5, 5, -1],
    "132": [6, 8, 6, 8, 6, 8, 5, 1, 5, -1],
    "133": [6, 8, 6, 8, 0, 5, -1],
    "134": [6, 8, 5, 5, 5, -1],
    "135": [6, 8, 5, -1],
    "136": [6, 8, 6, 8, 6, 8, 5, 1, 5, -1],
    "137": [6, 8, 5, 5, -1],
    "138": [6, 8, 6, 8, 0, 0, 0, -1],
    "140": [6, 8, 10, 8, 6, 8, 0, 0, 6, 8, 10, 8, -1],
    "141": [4, 6, 8, 6, 8, 0, 0, 1, 10, 8, -1],
    "142": [4, 6, 8, 6, 8, 0, 0, 1, 10, 8, -1],
    "143": [6, 8, 10, 8, -1],
    "144": [6, 8, -1],
    "145": [-1],
    "150": [1, 5, 5, 5, 5, -1],
    "151": [1, 0, 5, 5, 5, 5, -1],
    "152": [6, 8, 1, 0, 0, 5, 5, 5, 5, 5, 1, 5, -1],
    "153": [6, 8, 1, 0, 0, 10, 8, -1],
    "154": [-1],
    "155": [6, 8, -1],
    "156": [6, 8, 10, 8, -1],
    "157": [6, 8, -1],
    "158": [6, 8, 0, -1],
    "159": [6, 8, 0, -1],
    "160": [5, 5, 5, 5, -1],
    "161": [-1],
    "165": [6, 8, 5, 5, 10, 8, 10, 8, 5, 0, 0, -1],
    "166": [6, 8, 1, 1, 0, 0, 5, 5, 5, 5, 5, 1, 5, -1],
    "167": [6, 8, 1, 1, 0, 0, 10, 8, -1],
    "168": [6, 8, 6, 8, 1, 1, 0, 0, 5, 5, 5, 5, 5, 1, 5, -1],
    "169": [6, 8, 6, 8, 1, 1, 0, 0, 10, 8, -1],
    "170": [1, 0, 0, 5, 5, 5, 5, 5, 1, 5, -1],
    "171": [1, 0, 0, -1],
    "172": [-1],
    "173": [1, -1],
    "174": [6, 8, 1, -1],
    "175": [1, 1, 5, 5, 5, 5, -1],
    "176": [6, 8, 1, 1, 5, 5, 5, 5, -1],
    "180": [6, 8, 10, 8, 0, 0, -1],
    "181": [6, 8, 6, 8, 0, 0, 5, 5, 5, 0, 0, 10, 8, -1],
    "182": [6, 8, 5, -1],
    "183": [6, 8, 5, -1],
    "184": [6, 8, -1],
    "185": [6, 8, 6, 8, -1],
    "186": [6, 8, 6, 8, 6, 8, -1],
    "187": [6, 8, 0, -1],
    "190": [6, 8, 10, 8, 0, 0, -1],
    "191": [6, 8, 6, 8, -1],
    "192": [6, 8, 6, 8, 0, 0, 0, 0, 10, 8, -1],
    "193": [6, 8, -1],
    "194": [6, 8, 6, 8, 1, 1, 0, 0, 0, -1],
    "195": [6, 8, 1, 1, 6, 8, -1],
    "200": [-1],
    "201": [6, 8, 6, 8, 1, 1, 1, 1, -1],
    "202": [6, 8, 6, 8, -1],
    "203": [6, 8, 0, 0, -1],
    "204": [-1],
    "205": [6, 8, 6, 8, 6, 8, 6, 8, 6, 8, 5, 0, -1],
    "206": [0, -1],
    "207": [6, 8, 6, 8, 5, -1],
    "208": [6, 8, 1, -1],
    "209": [6, 8, 1, -1],
    "210": [6, 8, -1],
    "211": [6, 8, -1],
    "212": [10, 8, 1, 1, -1],
    "213": [6, 8, 5, -1],
    "214": [6, 8, 10, 8, -1],
    "220": [6, 8, 10, 8, 0, 0, 5, 5, 5, 0, -1],
    "221": [6, 8, 5, 5, 5, 0, 5, 0, 10, 8, -1],
    "222": [6, 8, 1, 5, 5, 5, 0, 5, 0, 10, 8, -1],
    "223": [6, 8, -1],
    "224": [6, 8, 1, -1],
    "230": [4, 4, -1],
    "231": [-1],
    "232": [-1],
    "233": [0, -1],
    "240": [0, -1],
    "248": [-1],
    "249": [0, 10, 8, -1],
    "250": [-1],
    "251": [0, -1],
    "252": [1, -1],
    "253": [-1],
    "254": [6, 8, -1],
}

def ror2(byte_val):
    return ((byte_val >> 2) | (byte_val << 6)) & 0xFF

def decrypt_ws2(data):
    return bytes([ror2(b) for b in data])

def rol2(byte_val):
    return ((byte_val << 2) | (byte_val >> 6)) & 0xFF

def encrypt_ws2(data):
    return bytes([rol2(b) for b in data])

def detect_ws2_type(data):
    if not data:
        return 'unknown'
        
    # 辅助函数：检查数据的合法性（通过Opcode判断）
    def check_validity(test_data, limit=20):
        try:
            reader = BinaryReader(test_data)
            valid_opcodes = 0
            instructions_checked = 0
            
            while instructions_checked < limit:
                if reader.offset >= len(test_data):
                    break
                opcode = reader.read_byte()
                opcode_str = str(opcode)
                if opcode_str not in OPCODES:
                    return -1 # 发现非法Opcode
                
                # 有效的Opcode，增加计数
                valid_opcodes += 1
                instructions_checked += 1
                
                # 简单的跳过参数逻辑，仅根据签名表跳过字节
                signature = OPCODES[opcode_str]
                for type_code in signature:
                    if type_code == -1: break
                    if type_code == 7:
                         count = reader.read_byte()
                         # 遇到变长数组，难以简单跳过，暂时停止深入检查
                         return valid_opcodes 
                    
                    # 尝试跳过参数值
                    if type_code in [0]: reader.offset += 1
                    elif type_code in [1, 2]: reader.offset += 2
                    elif type_code in [3, 4, 5]: reader.offset += 4
                    elif type_code in [6, 9, 10]: 
                        # 跳过字符串
                        while reader.offset + 1 < len(test_data):
                            if test_data[reader.offset] == 0 and test_data[reader.offset+1] == 0:
                                reader.offset += 2
                                break
                            reader.offset += 2
                    elif type_code == 8: pass
            return valid_opcodes
        except:
            return 0

    # 初始检查（前20条指令）
    score_plain = check_validity(data, limit=20)
    
    # 检查加密版本（采样前1000字节解密后检查）
    decrypted_sample = decrypt_ws2(data[:2000]) # 增加采样大小以支持更多指令检查
    score_encrypted = check_validity(decrypted_sample, limit=20)
    
    # 如果得分相同且都大于0，尝试深入检查（增加检查指令数）
    if score_plain == score_encrypted and score_plain > 0:
        score_plain = check_validity(data, limit=100)
        score_encrypted = check_validity(decrypted_sample, limit=100)
        
    # 再次平局，尝试完整解密（如果文件不大）或更深入检查
    if score_plain == score_encrypted and score_plain > 0:
        # 极端情况：继续增加深度
         score_plain = check_validity(data, limit=500)
         # 此时需要更多解密数据
         decrypted_sample_large = decrypt_ws2(data[:10000])
         score_encrypted = check_validity(decrypted_sample_large, limit=500)

    if score_encrypted > score_plain:
        return 'encrypted'
    else:
        # 默认为解密状态（或者无法判断时当作普通文件）
        return 'decrypted'

class BinaryReader:
    def __init__(self, data):
        self.data = data
        self.offset = 0
        
    def read_byte(self):
        if self.offset >= len(self.data):
            raise EOFError("文件结束")
        b = self.data[self.offset]
        self.offset += 1
        return b
        
    def peek_byte(self):
        if self.offset >= len(self.data):
            return None
        return self.data[self.offset]

    def read_word(self):
        if self.offset + 2 > len(self.data):
            raise EOFError("文件结束")
        v = struct.unpack('<H', self.data[self.offset:self.offset+2])[0]
        self.offset += 2
        return v
        
    def read_int(self):
        if self.offset + 4 > len(self.data):
            raise EOFError("文件结束")
        v = struct.unpack('<I', self.data[self.offset:self.offset+4])[0]
        self.offset += 4
        return v
        
    def read_float(self):
        if self.offset + 4 > len(self.data):
            raise EOFError("文件结束")
        v = struct.unpack('<f', self.data[self.offset:self.offset+4])[0]
        self.offset += 4
        return v
        
    def read_string(self):
        raw, _, _, _ = self.read_string_bytes()
        return raw.decode("utf-16le", errors="surrogatepass")

    def read_raw_string(self):
        raw, _, _, _ = self.read_string_bytes()
        return raw

    def read_string_bytes(self):
        start = self.offset
        terminated = False
        while self.offset + 1 < len(self.data):
            if self.data[self.offset] == 0 and self.data[self.offset + 1] == 0:
                terminated = True
                break
            self.offset += 2
        end = self.offset
        if not terminated and self.offset < len(self.data):
            if self.offset + 1 == len(self.data):
                end = len(self.data)
                self.offset = len(self.data)
        raw = self.data[start:end]
        if terminated:
            self.offset += 2
        return raw, start, end, terminated

def _decode_string_for_disasm(raw, terminated):
    if not terminated:
        return {"raw": raw.hex().upper(), "terminated": False}
    try:
        text = raw.decode("utf-16le")
    except UnicodeDecodeError:
        return {"raw": raw.hex().upper(), "terminated": True}
    if any(0xD800 <= ord(ch) <= 0xDFFF for ch in text):
        return {"raw": raw.hex().upper(), "terminated": True}
    return text

def disassemble(file_path, encryption_mode='auto'):
    lines = []
    with open(file_path, 'rb') as f:
        raw_data = f.read()
        
    if encryption_mode == 'auto':
        encryption_mode = detect_ws2_type(raw_data)
        lines.append(f"; 检测模式: {encryption_mode}")
        
    if encryption_mode == 'encrypted':
        data = decrypt_ws2(raw_data)
        lines.append("; 来源: 已加密 (Encrypted)")
    else:
        data = raw_data
        lines.append("; 来源: 未加密 (Decrypted)")
        
    reader = BinaryReader(data)
    
    lines.append(f"解密后大小: {len(data)}")
    
    while reader.offset < len(data):
        start_offset = reader.offset
        try:
            opcode = reader.read_byte()
        except EOFError:
            break
            
        opcode_str = str(opcode)
        opcode_name = OPCODE_NAMES.get(opcode, f"Unk{opcode:02X}")
        
        args = []
        eof_hit = False

        # 特殊 Opcode 处理
        if opcode == 0x01: # Condition
            try:
                val = reader.read_byte()
                args.append(val)
                peek_val = reader.peek_byte()
                if val in [2, 128, 129, 130, 192] or (val == 3 and peek_val in [50, 51, 127, 128]):
                    args.append(read_value_for_disasm(reader, 1)) # Word
                    args.append(read_value_for_disasm(reader, 5)) # Float
                    
                    ptr1 = read_value_for_disasm(reader, 4) # Int (Pointer)
                    if ptr1 != 0:
                        ptr1 = f"loc_{ptr1:08X}"
                    args.append(ptr1)
                    
                    ptr2 = read_value_for_disasm(reader, 4) # Int (Pointer)
                    if ptr2 != 0:
                        ptr2 = f"loc_{ptr2:08X}"
                    args.append(ptr2)
            except EOFError:
                eof_hit = True

        elif opcode == 0x02: # Jump2
            try:
                ptr = read_value_for_disasm(reader, 4)
                if ptr != 0:
                    ptr = f"loc_{ptr:08X}"
                args.append(ptr)
            except EOFError:
                eof_hit = True

        elif opcode == 0x06: # Jump
            try:
                ptr = read_value_for_disasm(reader, 4)
                if ptr != 0:
                    ptr = f"loc_{ptr:08X}"
                args.append(ptr)
            except EOFError:
                eof_hit = True
                
        elif opcode == 0x0F: # ShowChoice
            try:
                count = reader.read_byte()
                args.append(count) # Choice Amount
                choices = []
                for _ in range(count):
                    choice_item = {}
                    choice_item["id"] = read_value_for_disasm(reader, 1) # Word
                    choice_item["text"] = read_value_for_disasm(reader, 6) # String
                    
                    choice_item["op1"] = reader.read_byte()
                    choice_item["op2"] = reader.read_byte()
                    choice_item["op3"] = reader.read_byte()
                    opJump = reader.read_byte()
                    choice_item["opJump"] = opJump
                    
                    if opJump == 6:
                        ptr = read_value_for_disasm(reader, 4) # Int
                        if ptr != 0:
                            ptr = f"loc_{ptr:08X}"
                        choice_item["pointer"] = ptr
                    elif opJump == 7:
                        choice_item["file"] = read_value_for_disasm(reader, 6) # String
                    else:
                        choice_item["error"] = f"Unknown opJump {opJump}"
                        
                    choices.append(choice_item)
                args.append(choices)
            except EOFError:
                eof_hit = True

        elif opcode == 0xE6: # ConditionalJump
            try:
                ptr1 = read_value_for_disasm(reader, 4)
                if ptr1 != 0:
                    ptr1 = f"loc_{ptr1:08X}"
                args.append(ptr1)
                
                ptr2 = read_value_for_disasm(reader, 4)
                if ptr2 != 0:
                    ptr2 = f"loc_{ptr2:08X}"
                args.append(ptr2)
            except EOFError:
                eof_hit = True

        elif opcode == 0xFF: # FileEnd
            try:
                args.append(read_value_for_disasm(reader, 4)) # Int
                args.append(reader.read_byte())
                args.append(reader.read_byte())
                args.append(reader.read_byte())
                args.append(reader.read_byte())
            except EOFError:
                eof_hit = True

        elif opcode_str not in OPCODES:
            remaining = data[start_offset:]
            lines.append(f"loc_{start_offset:08X}: RAW {remaining.hex()}")
            break
            
        else:
            signature = OPCODES[opcode_str]
            i = 0
                
            while i < len(signature):
                type_code = signature[i]
                if type_code == -1:
                    break
                if type_code == 7:
                    try:
                        count = reader.read_byte()
                    except EOFError:
                        remaining = data[start_offset:]
                        lines.append(f"loc_{start_offset:08X}: RAW {remaining.hex()}")
                        eof_hit = True
                        break
                    next_type = signature[i + 1] if i + 1 < len(signature) else None
                    items = []
                    if next_type is not None:
                        for _ in range(count):
                            try:
                                val = read_value_for_disasm(reader, next_type)
                            except EOFError:
                                remaining = data[start_offset:]
                                lines.append(f"loc_{start_offset:08X}: RAW {remaining.hex()}")
                                eof_hit = True
                                break
                            items.append(val)
                    args.append({"count": count, "items": items})
                    if eof_hit:
                        break
                    i += 2
                    continue
                try:
                    val = read_value_for_disasm(reader, type_code)
                except EOFError:
                    remaining = data[start_offset:]
                    lines.append(f"loc_{start_offset:08X}: RAW {remaining.hex()}")
                    eof_hit = True
                    break
                if val is not None:
                    args.append(val)
                i += 1
                
        if eof_hit:
            lines.append(f"loc_{start_offset:08X}: 在Opcode {opcode:02X} 处遇到EOF")
            break
            
        args_json = json.dumps(args, ensure_ascii=False)
        lines.append(f"loc_{start_offset:08X}: {opcode:02X} ({opcode_name}) {args_json}")
    return lines

def read_value(reader, type_code):
    if type_code == 0:
        return reader.read_byte()
    if type_code == 1 or type_code == 2:
        return reader.read_word()
    if type_code == 3 or type_code == 4:
        return reader.read_int()
    if type_code == 5:
        return reader.read_float()
    if type_code == 6 or type_code == 9 or type_code == 10:
        return reader.read_string()
    if type_code == 8:
        return "<M8>"
    return f"<Unknown Type {type_code}>"

def read_value_for_disasm(reader, type_code):
    if type_code == 6 or type_code == 9 or type_code == 10:
        raw, _, _, terminated = reader.read_string_bytes()
        return _decode_string_for_disasm(raw, terminated)
    return read_value(reader, type_code)

def encode_value(type_code, value):
    if type_code == 0:
        return struct.pack("<B", int(value))
    if type_code == 1 or type_code == 2:
        return struct.pack("<H", int(value))
    if type_code == 3 or type_code == 4:
        return struct.pack("<I", int(value))
    if type_code == 5:
        return struct.pack("<f", float(value))
    if type_code == 6 or type_code == 9 or type_code == 10:
        if isinstance(value, dict) and "raw" in value:
            raw_bytes = bytes.fromhex(str(value["raw"]))
            terminated = value.get("terminated", True)
            return raw_bytes + (b"\x00\x00" if terminated else b"")
        return str(value).encode("utf-16le", errors="surrogatepass") + b"\x00\x00"
    if type_code == 8:
        return b""
    raise ValueError(f"Unknown type code {type_code}")



def parse_args(args_part):
    args_part = args_part.strip()
    if not args_part or args_part == "(End)":
        return []
    try:
        return json.loads(args_part)
    except json.JSONDecodeError:
        return ast.literal_eval(args_part)

def assemble_from_asm(asm_path):
    # 第一遍扫描: 收集标签并计算大小
    out_buffer = bytearray()
    labels = {} # name -> offset
    temp_instructions = [] # (opcode, args, offset)
    
    with open(asm_path, "r", encoding="utf-8") as f:
        current_offset = 0
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            
            # 解析独立的标签定义
            if line.endswith(":") and not " " in line:
                 label_name = line[:-1]
                 labels[label_name] = current_offset
                 continue
                 
            if ":" not in line:
                continue
            
            # 处理行首可能的标签 "loc_XXXX: 00 ..."
            prefix, rest = line.split(":", 1)
            prefix = prefix.strip()
            # 如果前缀看起来像标签 (以 loc_ 开头)，记录它
            if prefix.startswith("loc_"):
                labels[prefix] = current_offset
            
            # 继续解析指令
            rest = rest.strip()
            if not rest:
                continue
                
            parts = rest.split(" ", 1)
            op_hex = parts[0].strip()
            
            if op_hex == "RAW":
                if len(parts) > 1:
                    raw_bytes = bytes.fromhex(parts[1].strip())
                    out_buffer.extend(raw_bytes)
                    current_offset += len(raw_bytes)
                    temp_instructions.append(("RAW", raw_bytes, current_offset - len(raw_bytes)))
                continue
                
            if len(op_hex) != 2 or any(c not in "0123456789ABCDEFabcdef" for c in op_hex):
                continue
                
            opcode = int(op_hex, 16)
            
            # 移除 (OpcodeName)
            args_str = ""
            if len(parts) > 1:
                args_str = parts[1].strip()
                if args_str.startswith("("):
                     end_paren = args_str.find(")")
                     if end_paren != -1:
                         args_str = args_str[end_paren+1:].strip()
            
            args = []
            if args_str:
                try:
                    args = parse_args(args_str)
                except Exception as e:
                    print(f"Error parsing line: {line}")
                    raise e
            
            # 计算大小
            instr_bytes = bytearray()
            instr_bytes.append(opcode)
            
            start_instr_offset = current_offset
            
            # ... 特殊情况 ...
            if opcode == 0xFF:
                 instr_bytes.extend(encode_value(4, args[0]))
                 instr_bytes.append(int(args[1]))
                 instr_bytes.append(int(args[2]))
                 instr_bytes.append(int(args[3]))
                 instr_bytes.append(int(args[4]))
            
            elif opcode == 0x01:
                 val = args[0]
                 instr_bytes.append(int(val))
                 if val in [2, 128, 129, 130, 192] or (val == 3 and len(args) > 1):
                     instr_bytes.extend(encode_value(1, args[1]))
                     instr_bytes.extend(encode_value(5, args[2]))
                     # 指针 (可能是标签)
                     instr_bytes.extend(b"\x00\x00\x00\x00") # 占位符
                     instr_bytes.extend(b"\x00\x00\x00\x00") # 占位符
            
            elif opcode == 0x02 or opcode == 0x06:
                 # 指针 (可能是标签)
                 instr_bytes.extend(b"\x00\x00\x00\x00") # 占位符
                 
            elif opcode == 0xE6:
                 # 指针
                 instr_bytes.extend(b"\x00\x00\x00\x00") # 占位符
                 instr_bytes.extend(b"\x00\x00\x00\x00") # 占位符

            elif opcode == 0x0F:
                 count = int(args[0])
                 instr_bytes.append(count)
                 for choice in args[1]:
                     instr_bytes.extend(encode_value(1, choice["id"]))
                     instr_bytes.extend(encode_value(6, choice["text"]))
                     instr_bytes.append(int(choice["op1"]))
                     instr_bytes.append(int(choice["op2"]))
                     instr_bytes.append(int(choice["op3"]))
                     instr_bytes.append(int(choice["opJump"]))
                     if choice["opJump"] == 6:
                          instr_bytes.extend(b"\x00\x00\x00\x00") # 占位符
                     elif choice["opJump"] == 7:
                          instr_bytes.extend(encode_value(6, choice["file"]))
            
            else:
                signature = OPCODES.get(str(opcode))
                if signature is None:
                    raise ValueError(f"Unknown opcode {opcode:02X}")
                
                arg_index = 0
                i = 0
                while i < len(signature):
                    type_code = signature[i]
                    if type_code == -1:
                        break
                    if type_code == 7:
                        arr = args[arg_index]
                        count = int(arr.get("count", 0))
                        items = arr.get("items", [])
                        instr_bytes.append(count)
                        next_type = signature[i + 1]
                        for idx in range(count):
                            instr_bytes.extend(encode_value(next_type, items[idx]))
                        arg_index += 1
                        i += 2
                        continue
                    
                    value = args[arg_index]
                    instr_bytes.extend(encode_value(type_code, value))
                    arg_index += 1
                    i += 1

            current_offset += len(instr_bytes)
            temp_instructions.append({
                "opcode": opcode,
                "args": args,
                "offset": start_instr_offset,
                "size": len(instr_bytes)
            })

    # 第二遍扫描: 使用解析后的标签进行编码
    final_buffer = bytearray()
    
    for instr in temp_instructions:
        if instr["opcode"] == "RAW":
            final_buffer.extend(instr["args"]) # args 此时是 bytes
            continue
            
        opcode = instr["opcode"]
        args = instr["args"]
        
        final_buffer.append(opcode)
        
        if opcode == 0xFF:
             final_buffer.extend(encode_value(4, args[0]))
             final_buffer.append(int(args[1]))
             final_buffer.append(int(args[2]))
             final_buffer.append(int(args[3]))
             final_buffer.append(int(args[4]))
        
        elif opcode == 0x01:
             val = args[0]
             final_buffer.append(int(val))
             if val in [2, 128, 129, 130, 192] or (val == 3 and len(args) > 1):
                 final_buffer.extend(encode_value(1, args[1]))
                 final_buffer.extend(encode_value(5, args[2]))
                 final_buffer.extend(encode_pointer(args[3], labels))
                 final_buffer.extend(encode_pointer(args[4], labels))
        
        elif opcode == 0x02 or opcode == 0x06:
             final_buffer.extend(encode_pointer(args[0], labels))
             
        elif opcode == 0xE6:
             final_buffer.extend(encode_pointer(args[0], labels))
             final_buffer.extend(encode_pointer(args[1], labels))

        elif opcode == 0x0F:
             count = int(args[0])
             final_buffer.append(count)
             for choice in args[1]:
                 final_buffer.extend(encode_value(1, choice["id"]))
                 final_buffer.extend(encode_value(6, choice["text"]))
                 final_buffer.append(int(choice["op1"]))
                 final_buffer.append(int(choice["op2"]))
                 final_buffer.append(int(choice["op3"]))
                 final_buffer.append(int(choice["opJump"]))
                 if choice["opJump"] == 6:
                      final_buffer.extend(encode_pointer(choice["pointer"], labels))
                 elif choice["opJump"] == 7:
                      final_buffer.extend(encode_value(6, choice["file"]))
        
        else:
            # 标准编码
            signature = OPCODES.get(str(opcode))
            arg_index = 0
            i = 0
            while i < len(signature):
                type_code = signature[i]
                if type_code == -1:
                    break
                if type_code == 7:
                    arr = args[arg_index]
                    count = int(arr.get("count", 0))
                    items = arr.get("items", [])
                    final_buffer.append(count)
                    next_type = signature[i + 1]
                    for idx in range(count):
                        final_buffer.extend(encode_value(next_type, items[idx]))
                    arg_index += 1
                    i += 2
                    continue
                
                value = args[arg_index]
                final_buffer.extend(encode_value(type_code, value))
                arg_index += 1
                i += 1
                
    return bytes(final_buffer)

def encode_pointer(val, labels):
    if isinstance(val, str):
        if val in labels:
            return struct.pack("<I", labels[val])
        if val.startswith("loc_"):
            # 如果标签未找到，发出警告
            print(f"Warning: Label {val} not found, using 0")
            return b"\x00\x00\x00\x00"
    try:
        return struct.pack("<I", int(val))
    except:
        return b"\x00\x00\x00\x00"





def find_ws2_files(input_path):
    if os.path.isfile(input_path):
        return [input_path]
    ws2_files = []
    for root, _, files in os.walk(input_path):
        for name in files:
            if name.lower().endswith(".ws2"):
                ws2_files.append(os.path.join(root, name))
    return ws2_files

def write_disasm(output_dir, file_path, lines):
    os.makedirs(output_dir, exist_ok=True)
    base = os.path.basename(file_path)
    out_path = os.path.join(output_dir, base + ".asm.txt")
    with open(out_path, "w", encoding="utf-8") as f:
        for line in lines:
            f.write(line + "\n")
    return out_path

def process_file_encryption(file_path, output_dir, mode):
    """
    mode: 'encrypt' or 'decrypt'
    """
    os.makedirs(output_dir, exist_ok=True)
    
    with open(file_path, 'rb') as f:
        data = f.read()
        
    if mode == 'encrypt':
        out_data = encrypt_ws2(data)
    else: # decrypt
        out_data = decrypt_ws2(data)
        
    base_name = os.path.basename(file_path)
    # 确保后缀为 .ws2
    if not base_name.lower().endswith(".ws2"):
        out_name = base_name + ".ws2"
    else:
        out_name = base_name
        
    out_path = os.path.join(output_dir, out_name)
    with open(out_path, 'wb') as f:
        f.write(out_data)
        
    return out_path

def print_usage():
    print("AdvHD WS2 Toolkit CLI")
    print("---------------------")
    print("使用方法:")
    print("1. 反汇编 (WS2 -> ASM):")
    print("   python disasm_ws2.py <输入文件或目录> [输出目录]")
    print("")
    print("2. 汇编 (ASM -> WS2):")
    print("   python disasm_ws2.py --assemble <输入asm文件> <输出ws2文件> [--no-encrypt]")
    print("")
    print("3. 加密/解密工具:")
    print("   python disasm_ws2.py --tool <encrypt|decrypt> <输入文件或目录> <输出目录>")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print_usage()
        sys.exit(1)

    if sys.argv[1] == "--assemble":
        if len(sys.argv) < 4:
            print("错误: 参数不足")
            print("用法: python disasm_ws2.py --assemble <输入.asm.txt> <输出.ws2> [--no-encrypt]")
            sys.exit(1)
            
        asm_path = sys.argv[2]
        output_ws2 = sys.argv[3]
        
        should_encrypt = True
        if len(sys.argv) > 4 and sys.argv[4] == "--no-encrypt":
            should_encrypt = False
            
        try:
            assembled = assemble_from_asm(asm_path)
            
            if should_encrypt:
                final_data = encrypt_ws2(assembled)
                print("模式: 加密输出")
            else:
                final_data = assembled
                print("模式: 不加密输出")
                
            with open(output_ws2, "wb") as f:
                f.write(final_data)
            print(f"成功生成: {output_ws2}")
        except Exception as e:
            print(f"错误: {str(e)}")
            sys.exit(1)
            
    elif sys.argv[1] == "--tool":
        if len(sys.argv) < 5:
            print("错误: 参数不足")
            print("用法: python disasm_ws2.py --tool <encrypt|decrypt> <输入文件或目录> <输出目录>")
            sys.exit(1)
            
        mode = sys.argv[2]
        if mode not in ['encrypt', 'decrypt']:
            print(f"错误: 未知模式 '{mode}'，请使用 'encrypt' 或 'decrypt'")
            sys.exit(1)
            
        input_path = sys.argv[3]
        output_dir = sys.argv[4]
        
        if not os.path.exists(input_path):
            print(f"错误: 输入路径不存在: {input_path}")
            sys.exit(1)
            
        files = find_ws2_files(input_path)
        if not files:
            print(f"在 {input_path} 未找到 .ws2 文件")
            sys.exit(1)
            
        print(f"开始{mode}任务，共 {len(files)} 个文件...")
        for file_path in files:
            try:
                out = process_file_encryption(file_path, output_dir, mode)
                print(f"处理: {os.path.basename(file_path)} -> {out}")
            except Exception as e:
                print(f"失败 {file_path}: {str(e)}")
                
    else:
        # 默认反汇编模式
        input_path = sys.argv[1]
        output_dir = sys.argv[2] if len(sys.argv) >= 3 else "ws2_disasm"
        
        if not os.path.exists(input_path):
            print(f"错误: 输入路径不存在: {input_path}")
            sys.exit(1)
            
        ws2_files = find_ws2_files(input_path)
        if not ws2_files:
            print(f"在 {input_path} 未找到 .ws2 文件")
            sys.exit(1)
            
        print(f"找到 {len(ws2_files)} 个 .ws2 文件，开始反汇编...")
        for file_path in ws2_files:
            try:
                lines = disassemble(file_path, encryption_mode='auto')
                out_path = write_disasm(output_dir, file_path, lines)
                print(f"输出: {out_path}")
            except Exception as e:
                print(f"失败 {file_path}: {str(e)}")
