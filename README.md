# AdvHD2.1 WS2 Toolkit

这是一个用于处理 AdvHD 2.1 版本引擎 .ws2 脚本文件的工具集。
由于 AdvHD 2.1 更改了 .ws2 脚本文件中的字符串编码（从 sjis 改成了 utf-16le），故重新写了此工具。
它支持反汇编、汇编、文本提取（导出为 JSON）、文本导入（从 JSON 导入）以及加密/解密操作。

## 功能特性

- **反汇编 (Disassemble)**: 将 `.ws2` 二进制文件转换为可阅读的 `.asm.txt` 汇编代码。
- **构建 (Build)**:
  - **从 ASM 构建**: 将 `.asm.txt` 汇编回 `.ws2` 文件。
  - **从 JSON 导入**: 将修改后的 JSON 文本直接导入回原始 `.ws2` 文件（无需中间 ASM）。
- **文本处理**:
  - **提取文本**: 从 `.ws2` 文件提取对话和选项文本到 JSON 文件。
  - **导入文本**: 将 JSON 中的文本导回 `.ws2` 文件，自动处理控制符和名字回溯修改。
- **加密工具**: 单独对 `.ws2` 文件进行加密或解密。
- **GUI 界面**: 提供现代化的图形用户界面，支持深色模式。

## 环境要求

- Python 3.8+
- 依赖库: PyQt6, darkdetect

## 安装与运行

### 方式一：运行 EXE

   直接运行 `AdvHD_WS2_Toolkit.exe`。

### 方式二：直接运行 Python 脚本

1. 安装依赖:
   ```bat
   install_requirements.bat
   ```
   或者:
   ```bash
   pip install -r requirements.txt
   ```

2. 启动 GUI:
   ```bat
   run_gui.bat
   ```
   或者:
   ```bash
   python GUI_ws2.py
   ```

## 使用说明

### 提取/反汇编 (Extract / Disasm)
1. 在 **Extract / Disasm** 标签页中，选择输入 `.ws2` 文件或目录。
2. 设置输出目录。
3. 点击 **提取文本 (To JSON)** 导出文本，或点击 **反汇编 (To ASM)** 生成汇编代码。

### 构建/导出 (Build / Import)
1. 在 **Build / Import** 标签页中，选择 **构建模式**:
   - **从 ASM 构建**: 输入 `.asm.txt` 文件，输出 `.ws2`。
   - **从 JSON 导入**: 需要提供 **原始 `.ws2` 文件** (作为模板) 和 **JSON 文件**，输出新的 `.ws2`。
2. 设置 **输出加密设置**: 选择生成的文件是否加密。
3. 点击对应按钮开始处理。

### WS2加解密 (WS2 Crypto)
- 提供简单的加密/解密功能，用于批量处理 `.ws2` 文件。

## 文件结构

- `AdvHD_WS2_Toolkit.exe`: 编译后的可执行文件。
- `GUI_ws2.py`: 主程序 GUI 入口。
- `disasm_ws2.py`: 核心反汇编/汇编/加密逻辑。
- `ws2_json_handler.py`: JSON 提取与导入逻辑。
- `requirements.txt`: 项目依赖列表。

## 测试游戏
ensemble SWEET 《ラブラブお痴験バイト性活 -怪しいクスリでフル勃〇！モテまくりヤリまくりで人生大逆転-》


