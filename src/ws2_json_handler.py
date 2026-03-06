import json
import re
import os
import disasm_ws2

# 匹配消息末尾的控制符 (%K, %P 等)，提取时需去除
RE_CONTROL_CODES = re.compile(r'(%(?:K|P))+$')

def extract_text_from_ws2(file_path, encryption_mode='auto'):
    """从 .ws2 提取文本到 JSON"""
    try:
        # 反汇编获取指令
        lines = disasm_ws2.disassemble(file_path, encryption_mode=encryption_mode)
    except Exception as e:
        raise RuntimeError(f"反汇编失败: {str(e)}")

    entries = []
    current_name_raw = None # 保留原始名字 (含 %LC)
    current_name_clean = None # 纯名字

    for line in lines:
        line = line.strip()
        if not line.startswith("loc_"):
            continue
            
        try:
            # 解析指令: loc_XXXX: Opcode (Name) [Args...]
            args_start = line.find('[')
            if args_start == -1:
                continue
                
            opcode_part = line[:args_start].split()
            if len(opcode_part) < 2:
                continue
                
            opcode = int(opcode_part[1], 16)
            args = disasm_ws2.parse_args(line[args_start:])
            
            # SetDisplayName (0x15)
            if opcode == 0x15:
                if len(args) > 0 and isinstance(args[0], str):
                    raw_name = args[0]
                    if not raw_name:
                        current_name_raw = None
                        current_name_clean = None
                    else:
                        current_name_raw = raw_name
                        current_name_clean = raw_name[3:] if raw_name.startswith("%LC") else raw_name
                continue
                
            # DisplayMessage (0x14)
            elif opcode == 0x14:
                if len(args) >= 4 and isinstance(args[3], str):
                    raw_msg = args[3]
                    
                    # 分离消息和后缀
                    msg_text = raw_msg
                    suffix = ""
                    match = RE_CONTROL_CODES.search(raw_msg)
                    if match:
                        suffix = match.group(0)
                        msg_text = raw_msg[:-len(suffix)]
                        
                    if not msg_text:
                        continue

                    entry = {
                        "message": msg_text,
                        "suffix": suffix # 内部保留后缀状态
                    }
                    
                    if current_name_clean:
                        entry["name"] = current_name_clean
                        if current_name_raw and current_name_raw.startswith("%LC"):
                            entry["name_prefix"] = "%LC"
                    
                    # 输出条目
                    out_entry = {}
                    if "name" in entry:
                        out_entry["name"] = entry["name"]
                    out_entry["message"] = entry["message"]
                    
                    entries.append(out_entry)
                continue
                
            # ShowChoice (0x0F)
            elif opcode == 0x0F:
                if len(args) >= 2 and isinstance(args[1], list):
                    for choice in args[1]:
                        if isinstance(choice, dict) and "text" in choice:
                            entries.append({"message": choice["text"]})
                continue
                
        except Exception:
            continue
            
    return entries

def import_text_to_ws2(ws2_path, json_path, output_path, encryption_mode='auto', output_encrypt_mode='auto'):
    """
    将 JSON 文本导回 WS2。
    ws2_path: 原始 WS2 模板
    encryption_mode: 读取模板的解密模式 (auto/encrypted/decrypted)
    output_encrypt_mode: 输出文件的加密模式 (auto/encrypted/decrypted)，auto 则跟随原文件
    """
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            json_entries = json.load(f)
            
        # 1. 检测原文件加密状态 (用于 auto 模式)
        original_is_encrypted = False
        if encryption_mode == 'encrypted':
            original_is_encrypted = True
        elif encryption_mode == 'decrypted':
            original_is_encrypted = False
        else:
            # Auto detect
            with open(ws2_path, 'rb') as f:
                header = f.read(16)
                original_is_encrypted = disasm_ws2.detect_ws2_type(header) == 'encrypted'

        # 2. 反汇编模板
        # 读取时始终建议用 auto 或正确匹配的模式，否则反汇编会乱码
        lines = disasm_ws2.disassemble(ws2_path, encryption_mode=encryption_mode)
        
    except Exception as e:
        raise RuntimeError(f"准备导回数据失败: {str(e)}")

    # 3. 替换文本
    lines_to_process = lines
    processed_lines = [None] * len(lines)
    
    current_json_idx = 0
    last_set_name_line_idx = -1
    current_name_raw = None
    
    for i, line in enumerate(lines_to_process):
        line_stripped = line.strip()
        if not line_stripped.startswith("loc_"):
            processed_lines[i] = line
            continue
            
        try:
            args_start = line.find('[')
            if args_start == -1:
                processed_lines[i] = line
                continue
                
            opcode_part = line[:args_start].split()
            opcode = int(opcode_part[1], 16)
            args_str = line[args_start:]
            args = disasm_ws2.parse_args(args_str)
            
            if opcode == 0x15: # SetDisplayName
                if len(args) > 0 and isinstance(args[0], str) and args[0]:
                    last_set_name_line_idx = i
                    current_name_raw = args[0]
                elif len(args) > 0 and args[0] == "":
                    last_set_name_line_idx = i
                    current_name_raw = ""
                processed_lines[i] = line
                
            elif opcode == 0x14: # DisplayMessage
                orig_msg = args[3]
                orig_text = orig_msg
                orig_match = RE_CONTROL_CODES.search(orig_msg)
                if orig_match:
                    orig_text = orig_msg[:-len(orig_match.group(0))]
                
                if not orig_text:
                    processed_lines[i] = line
                    continue

                if current_json_idx < len(json_entries):
                    json_entry = json_entries[current_json_idx]
                    
                    # 替换 Message
                    if "message" in json_entry:
                        new_msg = json_entry["message"]
                        suffix = ""
                        match = RE_CONTROL_CODES.search(orig_msg)
                        if match: suffix = match.group(0)
                        args[3] = new_msg + suffix
                        
                    # 检查 Name 并回溯
                    if "name" in json_entry and last_set_name_line_idx != -1:
                        target_name = json_entry["name"]
                        prefix = "%LC" if current_name_raw.startswith("%LC") else ""
                        curr_clean = current_name_raw[3:] if prefix else current_name_raw
                            
                        if target_name != curr_clean:
                            set_name_line = lines_to_process[last_set_name_line_idx]
                            sn_start = set_name_line.find('[')
                            sn_args = disasm_ws2.parse_args(set_name_line[sn_start:])
                            
                            new_raw_name = prefix + target_name
                            sn_args[0] = new_raw_name
                            current_name_raw = new_raw_name
                            
                            new_sn_line = set_name_line[:sn_start] + json.dumps(sn_args, ensure_ascii=False)
                            processed_lines[last_set_name_line_idx] = new_sn_line
                            
                    new_line = line[:args_start] + json.dumps(args, ensure_ascii=False)
                    processed_lines[i] = new_line
                    current_json_idx += 1
                else:
                    processed_lines[i] = line
                    
            elif opcode == 0x0F: # ShowChoice
                if len(args) >= 2:
                    for choice in args[1]:
                        if "text" in choice and current_json_idx < len(json_entries):
                            choice["text"] = json_entries[current_json_idx]["message"]
                            current_json_idx += 1
                    new_line = line[:args_start] + f"[{args[0]}, {json.dumps(args[1], ensure_ascii=False)}]"
                    processed_lines[i] = new_line
                else:
                    processed_lines[i] = line
            
            else:
                processed_lines[i] = line
                
        except Exception:
            processed_lines[i] = line

    # 4. 重新汇编
    temp_asm = output_path + ".temp.asm"
    with open(temp_asm, 'w', encoding='utf-8') as f:
        for l in processed_lines:
            if l is not None:
                f.write(l + "\n")
        
    try:
        assembled_data = disasm_ws2.assemble_from_asm(temp_asm)
        
        # 决定输出加密
        should_encrypt = original_is_encrypted # Default to original
        
        if output_encrypt_mode == 'encrypted':
            should_encrypt = True
        elif output_encrypt_mode == 'decrypted':
            should_encrypt = False
        # else auto: keep original
            
        final_data = assembled_data
        if should_encrypt:
            final_data = disasm_ws2.encrypt_ws2(assembled_data)
            
        with open(output_path, 'wb') as f:
            f.write(final_data)
            
    finally:
        if os.path.exists(temp_asm):
            os.remove(temp_asm)

if __name__ == "__main__":
    import argparse
    import sys
    
    def main():
        parser = argparse.ArgumentParser(description="WS2 JSON 工具")
        subparsers = parser.add_subparsers(dest="command", help="命令")
        
        # Extract
        p_ext = subparsers.add_parser("extract", help="提取 WS2 到 JSON")
        p_ext.add_argument("input", help="输入 WS2")
        p_ext.add_argument("output", help="输出 JSON")
        
        # Import
        p_imp = subparsers.add_parser("import", help="导入 JSON 到 WS2")
        p_imp.add_argument("ws2_input", help="原始 WS2 (模板)")
        p_imp.add_argument("json_input", help="输入 JSON")
        p_imp.add_argument("output", help="输出 WS2")
        p_imp.add_argument("--encrypt", choices=['auto', 'encrypted', 'decrypted'], default='auto', help="读取解密模式")
        p_imp.add_argument("--output-encrypt", choices=['auto', 'encrypted', 'decrypted'], default='auto', help="输出加密模式")
        
        args = parser.parse_args()
        
        if args.command == "extract":
            try:
                entries = extract_text_from_ws2(args.input)
                with open(args.output, 'w', encoding='utf-8') as f:
                    json.dump(entries, f, ensure_ascii=False, indent=2)
                print(f"Extracted to {args.output}")
            except Exception as e:
                print(f"Error: {e}")
                
        elif args.command == "import":
            try:
                import_text_to_ws2(args.ws2_input, args.json_input, args.output, encryption_mode=args.encrypt, output_encrypt_mode=args.output_encrypt)
                print(f"Imported to {args.output}")
            except Exception as e:
                print(f"Error: {e}")
                
        else:
            parser.print_help()
            
    main()
