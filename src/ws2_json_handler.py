import json
import re
import os
import disasm_ws2

# 编译正则表达式，用于匹配消息末尾的控制符
# 匹配末尾连续的 %K, %P 等控制符
# 用户要求：message后面的%K和%P不要提取
RE_CONTROL_CODES = re.compile(r'(%(?:K|P))+$')

def extract_text_from_ws2(file_path, encryption_mode='auto'):
    """
    从 .ws2 文件直接提取文本到 JSON 列表。
    无需中间 ASM 文件。
    """
    try:
        # 1. 反汇编获取指令列表 (内存中)
        lines = disasm_ws2.disassemble(file_path, encryption_mode=encryption_mode)
    except Exception as e:
        raise RuntimeError(f"反汇编失败: {str(e)}")

    entries = []
    current_name_raw = None # 保留原始名字字符串（含 %LC 等）
    current_name_clean = None # 提取出的纯名字

    # 解析反汇编后的行
    for line in lines:
        line = line.strip()
        if not line.startswith("loc_"):
            continue
            
        # 解析指令部分
        # 格式: loc_XXXX: Opcode (Name) [Args...]
        try:
            # 找到参数列表的起始位置
            args_start = line.find('[')
            if args_start == -1:
                continue
                
            opcode_part = line[:args_start].split()
            if len(opcode_part) < 2:
                continue
                
            opcode_hex = opcode_part[1]
            opcode = int(opcode_hex, 16)
            
            # 解析参数
            args_str = line[args_start:]
            args = disasm_ws2.parse_args(args_str)
            
            # 处理 SetDisplayName (0x15)
            if opcode == 0x15:
                if len(args) > 0 and isinstance(args[0], str):
                    raw_name = args[0]
                    if not raw_name: # 空名字，清除当前状态
                        current_name_raw = None
                        current_name_clean = None
                    else:
                        current_name_raw = raw_name
                        # 提取纯名字：去掉 %LC 前缀
                        if raw_name.startswith("%LC"):
                            current_name_clean = raw_name[3:]
                        else:
                            current_name_clean = raw_name
                continue
                
            # 处理 DisplayMessage (0x14)
            elif opcode == 0x14:
                if len(args) >= 4 and isinstance(args[3], str):
                    raw_msg = args[3]
                    
                    # 分离消息文本和末尾控制符
                    msg_text = raw_msg
                    suffix = ""
                    
                    match = RE_CONTROL_CODES.search(raw_msg)
                    if match:
                        suffix = match.group(0)
                        msg_text = raw_msg[:-len(suffix)]
                        
                    # 如果去除控制符后文本为空，则跳过提取
                    if not msg_text:
                        continue

                    entry = {
                        "message": msg_text,
                        "suffix": suffix # 保存后缀以便导回时使用（虽然用户要求不提取，但内部需要保存状态）
                    }
                    
                    # 用户要求 JSON 输出不含后缀，但为了导回我们需要知道后缀
                    # 方案：JSON 中只放纯文本，后缀我们暂时不放入 JSON（或者放入隐藏字段？）
                    # 用户的要求是“message后面的%K和%P不要提取”，意思是 JSON 里不要看到这些。
                    # 为了能正确导回，我们需要在 JSON 里存一下，或者假设用户不会改后缀？
                    # 既然用户说“导回只要求导回修改前面的文本”，那意味着后缀应该保持原样。
                    # 我们可以在 JSON 中增加一个不用于显示的字段，或者就完全不输出，
                    # 导回时利用原始文件做对照？
                    # 既然要求“直接从ws2导出json，并且能从json直接导回到ws2文件”，
                    # 如果不保留后缀信息，导回时就丢失了。
                    # 
                    # 策略：
                    # 导出时：message 字段只包含纯文本。
                    # 导回时：读取 JSON，同时再次反汇编原始 WS2，
                    # 将 JSON 中的 message 与原始的后缀拼接，再写入。
                    
                    if current_name_clean:
                        entry["name"] = current_name_clean
                        # 同理，保存原始名字前缀以便导回
                        if current_name_raw and current_name_raw.startswith("%LC"):
                            entry["name_prefix"] = "%LC"
                    
                    # 最终输出给用户的条目（去掉内部使用的辅助字段，避免用户困惑）
                    # 但为了导回方便，我们还是需要一种机制。
                    # 既然要求是写个模块负责，那我们可以把这个逻辑封装在 Import 函数里：
                    # Import 函数接受 (原始WS2, JSON) -> 新WS2
                    # 这样就可以从原始 WS2 获取后缀了。
                    
                    # 这里只输出用户需要的字段
                    out_entry = {}
                    if "name" in entry:
                        out_entry["name"] = entry["name"]
                    out_entry["message"] = entry["message"]
                    
                    entries.append(out_entry)
                continue
                
            # 处理 ShowChoice (0x0F)
            elif opcode == 0x0F:
                if len(args) >= 2 and isinstance(args[1], list):
                    for choice in args[1]:
                        if isinstance(choice, dict) and "text" in choice:
                            # 选项通常没有复杂的控制符后缀，如果有也照常处理
                            raw_text = choice["text"]
                            # 选项也可能包含控制符？通常较少，但以防万一
                            # 假设选项纯文本
                            entries.append({"message": raw_text})
                continue
                
        except Exception:
            # 忽略解析错误的行
            continue
            
    return entries

def import_text_to_ws2(ws2_path, json_path, output_path, encryption_mode='auto'):
    """
    将 JSON 文本导回 WS2 文件。
    需要原始 WS2 文件作为模板来恢复控制符和结构。
    """
    try:
        # 1. 读取 JSON
        with open(json_path, 'r', encoding='utf-8') as f:
            json_entries = json.load(f)
            
        # 2. 反汇编原始 WS2 得到 ASM 结构
        # 强制解密以便处理，最终再根据需要加密回去
        # 我们先检测原始文件的加密状态，以便最后恢复
        if encryption_mode != 'auto':
            enc_mode = encryption_mode
        else:
            enc_mode = disasm_ws2.detect_ws2_type(open(ws2_path, 'rb').read())
        
        # 获取 ASM 行列表
        lines = disasm_ws2.disassemble(ws2_path, encryption_mode=encryption_mode)
        
    except Exception as e:
        raise RuntimeError(f"准备导回数据失败: {str(e)}")

    # 3. 遍历 ASM 行并替换文本
    # 我们采用“双指针”策略：遍历 ASM 行的同时，维护 JSON 数据的索引。
    # 遇到 SetDisplayName 记录位置；遇到 DisplayMessage/ShowChoice 从 JSON 取值并替换。
    # 如果 DisplayMessage 对应的名字改变了，回溯修改 SetDisplayName。
    
    lines_to_process = lines # 原始 ASM 行
    processed_lines = [None] * len(lines) # 结果行列表
    
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
            opcode_hex = opcode_part[1]
            opcode = int(opcode_hex, 16)
            args_str = line[args_start:]
            args = disasm_ws2.parse_args(args_str)
            
            if opcode == 0x15: # SetDisplayName
                if len(args) > 0 and isinstance(args[0], str) and args[0]:
                    last_set_name_line_idx = i
                    current_name_raw = args[0]
                elif len(args) > 0 and args[0] == "":
                    # 清空名字，但也记录位置，以便后续如果有名字需要写入时可以回溯修改
                    last_set_name_line_idx = i
                    current_name_raw = ""
                processed_lines[i] = line # 先保持原样，稍后可能回溯修改
                
            elif opcode == 0x14: # DisplayMessage
                # 检查原始消息是否为空（如果为空，说明导出时跳过了，这里也跳过 JSON 消耗）
                orig_msg = args[3]
                orig_text = orig_msg
                orig_match = RE_CONTROL_CODES.search(orig_msg)
                if orig_match:
                    orig_text = orig_msg[:-len(orig_match.group(0))]
                
                if not orig_text:
                    # 原始文本为空，跳过处理，保持原样
                    processed_lines[i] = line
                    continue

                if current_json_idx < len(json_entries):
                    json_entry = json_entries[current_json_idx]
                    
                    # 1. 替换 Message (同上)
                    if "message" in json_entry:
                        new_msg = json_entry["message"]
                        # orig_msg = args[3] # 已在上文获取
                        suffix = ""
                        match = RE_CONTROL_CODES.search(orig_msg)
                        if match: suffix = match.group(0)
                        args[3] = new_msg + suffix
                        
                    # 2. 检查 Name 并回溯修改
                    if "name" in json_entry and last_set_name_line_idx != -1:
                        target_name = json_entry["name"]
                        
                        # 检查前缀
                        prefix = ""
                        if current_name_raw.startswith("%LC"):
                            prefix = "%LC"
                            curr_clean = current_name_raw[3:]
                        else:
                            curr_clean = current_name_raw
                            
                        if target_name != curr_clean:
                            # 需要修改之前的 SetDisplayName 行
                            # 获取那一行
                            set_name_line = lines_to_process[last_set_name_line_idx]
                            # 解析它
                            sn_start = set_name_line.find('[')
                            sn_args = disasm_ws2.parse_args(set_name_line[sn_start:])
                            # 修改它
                            new_raw_name = prefix + target_name
                            sn_args[0] = new_raw_name
                            # 更新 current_name_raw 以免重复修改
                            current_name_raw = new_raw_name
                            
                            # 重建行
                            new_sn_line = set_name_line[:sn_start] + json.dumps(sn_args, ensure_ascii=False)
                            processed_lines[last_set_name_line_idx] = new_sn_line
                            
                    # 保存修改后的 DisplayMessage
                    new_line = line[:args_start] + json.dumps(args, ensure_ascii=False)
                    processed_lines[i] = new_line
                    current_json_idx += 1
                else:
                    processed_lines[i] = line
                    
            elif opcode == 0x0F: # ShowChoice
                # 同上处理 ShowChoice
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

    # 4. 将 ASM 编译回 WS2 二进制
    # 先写入临时文件
    temp_asm = output_path + ".temp.asm"
    with open(temp_asm, 'w', encoding='utf-8') as f:
        for l in processed_lines:
            if l is not None:
                f.write(l + "\n")
        
    try:
        # 调用汇编器
        assembled_data = disasm_ws2.assemble_from_asm(temp_asm)
        
        # 根据原始加密状态决定是否加密
        final_data = assembled_data
        if enc_mode == 'encrypted':
            final_data = disasm_ws2.encrypt_ws2(assembled_data)
            
        with open(output_path, 'wb') as f:
            f.write(final_data)
            
    finally:
        # 清理临时文件
        if os.path.exists(temp_asm):
            os.remove(temp_asm)

if __name__ == "__main__":
    import argparse
    import sys
    
    def main():
        parser = argparse.ArgumentParser(description="WS2 JSON Extraction/Import Tool")
        subparsers = parser.add_subparsers(dest="command", help="Commands")
        
        # Extract
        p_ext = subparsers.add_parser("extract", help="Extract text from WS2 to JSON")
        p_ext.add_argument("input", help="Input WS2 file")
        p_ext.add_argument("output", help="Output JSON file")
        
        # Import
        p_imp = subparsers.add_parser("import", help="Import text from JSON to WS2")
        p_imp.add_argument("ws2_input", help="Original WS2 file (template)")
        p_imp.add_argument("json_input", help="Input JSON file")
        p_imp.add_argument("output", help="Output WS2 file")
        p_imp.add_argument("--encrypt", choices=['auto', 'encrypted', 'decrypted'], default='auto', help="Encryption mode")
        
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
                import_text_to_ws2(args.ws2_input, args.json_input, args.output, encryption_mode=args.encrypt)
                print(f"Imported to {args.output}")
            except Exception as e:
                print(f"Error: {e}")
                
        else:
            parser.print_help()
            
    main()

