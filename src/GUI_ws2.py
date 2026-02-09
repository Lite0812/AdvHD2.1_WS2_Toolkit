import sys
import json
import re
import os
import threading
import traceback
from PyQt6.QtWidgets import (QApplication, QWidget, QVBoxLayout, QHBoxLayout, 
                             QLabel, QLineEdit, QPushButton, QTextEdit, 
                             QFileDialog, QProgressBar, QMessageBox, QFrame,
                             QComboBox, QTabWidget, QRadioButton, QButtonGroup, QStackedWidget)
from PyQt6.QtCore import Qt, pyqtSignal, QObject
from PyQt6.QtGui import QDropEvent

# Try to import darkdetect for system theme detection
try:
    import darkdetect
    HAS_DARKDETECT = True
except ImportError:
    HAS_DARKDETECT = False

# 尝试导入 disasm_ws2
try:
    import disasm_ws2
except ImportError:
    disasm_ws2 = None

# 尝试导入 ws2_json_handler
try:
    import ws2_json_handler
except ImportError:
    ws2_json_handler = None

class Logger(QObject):
    log_signal = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.terminal = sys.stdout

    def write(self, message):
        # self.terminal.write(message)
        self.log_signal.emit(message)

    def flush(self):
        # self.terminal.flush()
        pass

class WorkerThread(QObject):
    finished = pyqtSignal()
    log_signal = pyqtSignal(str)
    
    def __init__(self, mode, input_path, output_path, **kwargs):
        super().__init__()
        self.mode = mode
        self.input_path = input_path
        self.output_path = output_path
        self.kwargs = kwargs
        
    def run(self):
        try:
            if not disasm_ws2:
                raise ImportError("找不到 disasm_ws2 模块")
                
            if self.mode == 'disasm':
                self.run_disasm()
            elif self.mode == 'build':
                self.run_build()
            elif self.mode == 'tool':
                self.run_tool()
            elif self.mode == 'json_extract':
                self.run_json_extract()
            elif self.mode == 'json_import':
                self.run_json_import()
        except Exception as e:
            msg = f"发生异常: {str(e)}"
            self.log_signal.emit(msg)
            self.log_signal.emit(traceback.format_exc())
        finally:
            self.finished.emit()
            
    def run_disasm(self):
        enc_mode = self.kwargs.get('disasm_mode', 'auto')
        mode_map = {'auto': '自动识别', 'encrypted': '强制解密', 'decrypted': '强制跳过解密'}
        display_mode = mode_map.get(enc_mode, enc_mode)
        
        ws2_files = disasm_ws2.find_ws2_files(self.input_path)
        if not ws2_files:
            self.log_signal.emit(f"在 {self.input_path} 未找到 .ws2 文件")
            return
            
        total = len(ws2_files)
        self.log_signal.emit(f"找到 {total} 个 .ws2 文件，开始反汇编 (模式: {display_mode})...")
        
        for i, file_path in enumerate(ws2_files):
            self.log_signal.emit(f"[{i+1}/{total}] 处理: {os.path.basename(file_path)}")
            try:
                lines = disasm_ws2.disassemble(file_path, encryption_mode=enc_mode)
                out_path = disasm_ws2.write_disasm(self.output_path, file_path, lines)
                self.log_signal.emit(f"  -> 输出: {out_path}")
            except Exception as e:
                self.log_signal.emit(f"  -> 失败: {str(e)}")
                self.log_signal.emit(traceback.format_exc())
                
        self.log_signal.emit("反汇编任务完成！")

    def run_build(self):
        build_mode = self.kwargs.get('build_mode', 'encrypted')
        display_mode = "加密输出" if build_mode == 'encrypted' else "不加密输出"
        
        if os.path.isfile(self.input_path):
            files = [self.input_path]
        else:
            files = []
            for root, _, filenames in os.walk(self.input_path):
                for name in filenames:
                    if name.lower().endswith(".asm.txt"):
                        files.append(os.path.join(root, name))
                        
        if not files:
            self.log_signal.emit(f"在 {self.input_path} 未找到 .asm.txt 文件")
            return
            
        total = len(files)
        self.log_signal.emit(f"找到 {total} 个 .asm.txt 文件，开始构建 (模式: {display_mode})...")
        
        os.makedirs(self.output_path, exist_ok=True)
        
        for i, asm_path in enumerate(files):
            base_name = os.path.basename(asm_path)
            self.log_signal.emit(f"[{i+1}/{total}] 构建: {base_name}")
            
            try:
                if base_name.lower().endswith(".asm.txt"):
                    out_name = base_name[:-8] # remove .asm.txt
                else:
                    out_name = base_name + ".ws2"
                    
                out_ws2_path = os.path.join(self.output_path, out_name)
                
                assembled_data = disasm_ws2.assemble_from_asm(asm_path)
                
                if build_mode == 'encrypted':
                    final_data = disasm_ws2.encrypt_ws2(assembled_data)
                else:
                    final_data = assembled_data
                
                with open(out_ws2_path, "wb") as f:
                    f.write(final_data)
                    
                self.log_signal.emit(f"  -> 生成: {out_ws2_path}")
            except Exception as e:
                self.log_signal.emit(f"  -> 失败: {str(e)}")
                # self.log_signal.emit(traceback.format_exc())
                
        self.log_signal.emit("构建任务完成！")

    def run_tool(self):
        tool_mode = self.kwargs.get('tool_mode', 'decrypt')
        display_mode = "解密" if tool_mode == 'decrypt' else "加密"
        
        if os.path.isfile(self.input_path):
            files = [self.input_path]
        else:
            files = disasm_ws2.find_ws2_files(self.input_path)
            
        if not files:
            self.log_signal.emit(f"在 {self.input_path} 未找到 .ws2 文件")
            return
            
        total = len(files)
        self.log_signal.emit(f"找到 {total} 个文件，开始{display_mode}...")
        
        for i, file_path in enumerate(files):
            self.log_signal.emit(f"[{i+1}/{total}] {display_mode}: {os.path.basename(file_path)}")
            try:
                out_path = disasm_ws2.process_file_encryption(file_path, self.output_path, tool_mode)
                self.log_signal.emit(f"  -> 输出: {out_path}")
            except Exception as e:
                self.log_signal.emit(f"  -> 失败: {str(e)}")
        
        self.log_signal.emit(f"{display_mode}任务完成！")

    def run_json_extract(self):
        if not ws2_json_handler:
            raise ImportError("找不到 ws2_json_handler 模块")

        if os.path.isfile(self.input_path):
            files = [self.input_path]
        else:
            files = disasm_ws2.find_ws2_files(self.input_path)
            
        if not files:
            self.log_signal.emit(f"在 {self.input_path} 未找到 .ws2 文件")
            return
            
        total = len(files)
        self.log_signal.emit(f"找到 {total} 个文件，开始提取 JSON...")
        
        # 如果输出路径是一个文件（当输入是单文件时可能发生），我们需要处理
        # 但通常 GUI 会给出一个目录作为输出，或者自动生成文件名
        # 这里假设 output_path 是目录，如果不是目录则当作文件名前缀
        
        is_output_dir = not self.output_path.lower().endswith(".json")
        if is_output_dir:
            os.makedirs(self.output_path, exist_ok=True)
            
        for i, file_path in enumerate(files):
            self.log_signal.emit(f"[{i+1}/{total}] 提取: {os.path.basename(file_path)}")
            try:
                entries = ws2_json_handler.extract_text_from_ws2(file_path)
                
                # 决定输出文件名
                if total == 1 and not is_output_dir:
                    out_json_path = self.output_path
                else:
                    base_name = os.path.basename(file_path)
                    # 如果文件名是 xxx.ws2，输出 xxx.json
                    if base_name.lower().endswith(".ws2"):
                        json_name = base_name[:-4] + ".json"
                    else:
                        json_name = base_name + ".json"
                    out_json_path = os.path.join(self.output_path, json_name)
                    
                with open(out_json_path, 'w', encoding='utf-8') as f:
                    json.dump(entries, f, ensure_ascii=False, indent=2)
                    
                self.log_signal.emit(f"  -> 生成: {out_json_path}")
            except Exception as e:
                self.log_signal.emit(f"  -> 失败: {str(e)}")
                self.log_signal.emit(traceback.format_exc())
                
        self.log_signal.emit("JSON 提取任务完成！")

    def run_json_import(self):
        if not ws2_json_handler:
            raise ImportError("找不到 ws2_json_handler 模块")

        # 输入应当是 WS2 文件或目录
        # 还需要 JSON 文件或目录
        # 这里设计稍微有点 tricky，因为我们需要成对的 (WS2, JSON)
        # 在 GUI 中，我们让用户选择 "原始 WS2 目录" 和 "JSON 目录"
        # 或者 "原始 WS2 文件" 和 "JSON 文件"
        
        ws2_input = self.input_path
        json_input = self.kwargs.get('json_input')
        
        if not json_input:
            self.log_signal.emit("错误: 未指定 JSON 输入路径")
            return
            
        # 收集任务对
        tasks = [] # (ws2_path, json_path, out_path)
        
        if os.path.isfile(ws2_input):
            if os.path.isfile(json_input):
                # 单文件模式
                # 输出路径如果是目录，则放入目录；如果是文件，则直接使用
                if os.path.isdir(self.output_path) or self.output_path.endswith("/") or self.output_path.endswith("\\"):
                    out_name = os.path.basename(ws2_input)
                    out_path = os.path.join(self.output_path, out_name)
                else:
                    out_path = self.output_path
                tasks.append((ws2_input, json_input, out_path))
            else:
                self.log_signal.emit("错误: WS2 是文件，但 JSON 是目录")
                return
        else:
            # 目录模式
            if not os.path.isdir(json_input):
                self.log_signal.emit("错误: WS2 是目录，但 JSON 是文件")
                return
                
            os.makedirs(self.output_path, exist_ok=True)
            ws2_files = disasm_ws2.find_ws2_files(ws2_input)
            
            for ws2_file in ws2_files:
                base_name = os.path.basename(ws2_file)
                # 寻找对应的 JSON
                # 假设命名规则: xxx.ws2 -> xxx.json
                json_name = None
                if base_name.lower().endswith(".ws2"):
                    json_name = base_name[:-4] + ".json"
                else:
                    json_name = base_name + ".json"
                    
                json_path = os.path.join(json_input, json_name)
                if not os.path.exists(json_path):
                    self.log_signal.emit(f"警告: 找不到对应的 JSON 文件: {json_name} (跳过)")
                    continue
                    
                out_path = os.path.join(self.output_path, base_name)
                tasks.append((ws2_file, json_path, out_path))
                
        total = len(tasks)
        if total == 0:
            self.log_signal.emit("未找到匹配的 WS2 和 JSON 文件对")
            return
            
        self.log_signal.emit(f"找到 {total} 个匹配任务，开始导入 JSON...")
        
        for i, (ws, js, out) in enumerate(tasks):
            self.log_signal.emit(f"[{i+1}/{total}] 导入: {os.path.basename(ws)} + {os.path.basename(js)}")
            try:
                ws2_json_handler.import_text_to_ws2(ws, js, out)
                self.log_signal.emit(f"  -> 生成: {out}")
            except Exception as e:
                self.log_signal.emit(f"  -> 失败: {str(e)}")
                self.log_signal.emit(traceback.format_exc())
                
        self.log_signal.emit("JSON 导入任务完成！")

class DragDropLineEdit(QLineEdit):
    file_dropped = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        
    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.accept()
        else:
            event.ignore()
            
    def dropEvent(self, event):
        urls = event.mimeData().urls()
        if urls:
            path = urls[0].toLocalFile()
            self.setText(path)
            self.file_dropped.emit(path)

class ModernButton(QPushButton):
    def __init__(self, text, is_primary=False):
        super().__init__(text)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setObjectName("PrimaryButton" if is_primary else "SecondaryButton")
        self.setMinimumHeight(35)

class WS2ToolkitGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AdvHD2.1 WS2 Toolkit GUI")
        self.resize(800, 750)
        self.setObjectName("MainBackground")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        
        self.init_ui()
        
        # Redirect stdout
        self.logger = Logger()
        self.logger.log_signal.connect(self.append_log)
        sys.stdout = self.logger
        sys.stderr = self.logger
        
        # Detect system theme on startup
        self.detect_system_theme()

    def init_ui(self):
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(15)
        self.setLayout(main_layout)
        
        # --- Header ---
        header_layout = QHBoxLayout()
        title_label = QLabel("AdvHD2.1 WS2 Toolkit")
        title_label.setObjectName("AppTitle") 
        title_label.setStyleSheet("font-size: 18pt; font-weight: bold;")
        header_layout.addWidget(title_label)
        header_layout.addStretch()
        
        # Theme Selector
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["跟随系统", "现代浅色", "现代深色", "赛博朋克"])
        self.theme_combo.currentTextChanged.connect(self.apply_theme)
        header_layout.addWidget(QLabel("主题:"))
        header_layout.addWidget(self.theme_combo)
        
        main_layout.addLayout(header_layout)
        
        # --- Tabs ---
        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)
        
        # --- Extract Tab (Merged) ---
        extract_tab = QWidget()
        self.setup_extract_tab(extract_tab)
        self.tabs.addTab(extract_tab, "提取 (Extract)")
        
        # --- Build Tab (Merged) ---
        build_tab = QWidget()
        self.setup_build_tab(build_tab)
        self.tabs.addTab(build_tab, "构建 (Build)")

        # --- Tools Tab ---
        tools_tab = QWidget()
        self.setup_tools_tab(tools_tab)
        self.tabs.addTab(tools_tab, "WS2加解密 (WS2 Crypto)")
        
        # --- Log ---
        log_label = QLabel("日志:")
        main_layout.addWidget(log_label)
        
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setObjectName("LogConsole")
        main_layout.addWidget(self.log_text)
        
        # Status
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0) # Indeterminate
        self.progress_bar.hide()
        main_layout.addWidget(self.progress_bar)

    def setup_extract_tab(self, tab):
        layout = QVBoxLayout()
        layout.setContentsMargins(15, 15, 15, 15)
        tab.setLayout(layout)
        
        # Input
        self.extract_input_edit = self.create_file_selector(
            layout, 
            "输入文件/目录 (.ws2):", 
            is_input=True,
            on_change=lambda: self.auto_fill_output('extract')
        )
        
        # Options
        opts_layout = QHBoxLayout()
        opts_layout.addWidget(QLabel("解密模式:"))
        self.extract_mode_combo = QComboBox()
        self.extract_mode_combo.addItems(["自动识别 (Auto)", "已加密 (Encrypted)", "未加密 (Decrypted)"])
        opts_layout.addWidget(self.extract_mode_combo)
        opts_layout.addStretch()
        layout.addLayout(opts_layout)

        # Output
        self.extract_output_edit = self.create_file_selector(layout, "输出目录:", is_input=False)
        
        layout.addSpacing(20)
        
        # Action Buttons Area
        actions_group = QFrame()
        actions_group.setFrameShape(QFrame.Shape.StyledPanel)
        actions_layout = QHBoxLayout(actions_group)
        
        # Disasm Button
        self.btn_disasm = ModernButton("反汇编 (To ASM)", is_primary=True)
        self.btn_disasm.clicked.connect(self.run_disasm)
        actions_layout.addWidget(self.btn_disasm)
        
        actions_layout.addSpacing(20)
        
        # JSON Extract Button
        self.btn_json_extract = ModernButton("提取文本 (To JSON)", is_primary=True)
        self.btn_json_extract.clicked.connect(self.run_json_extract)
        actions_layout.addWidget(self.btn_json_extract)
        
        layout.addWidget(actions_group)
        layout.addStretch()

    def setup_build_tab(self, tab):
        layout = QVBoxLayout()
        layout.setContentsMargins(15, 15, 15, 15)
        tab.setLayout(layout)
        
        # 1. Mode Selector
        mode_layout = QHBoxLayout()
        mode_layout.addWidget(QLabel("构建模式:"))
        self.build_type_combo = QComboBox()
        self.build_type_combo.addItems([
            "从 ASM 构建 (ASM -> WS2)", 
            "从 JSON 导入 (Original WS2 + JSON -> New WS2)"
        ])
        mode_layout.addWidget(self.build_type_combo)
        mode_layout.addStretch()
        layout.addLayout(mode_layout)

        # 2. Common Options (Encryption) - Moved up as requested
        common_group = QFrame()
        common_group.setFrameShape(QFrame.Shape.NoFrame)
        common_layout = QHBoxLayout(common_group)
        common_layout.setContentsMargins(0, 5, 0, 5) # Slightly adjust margins
        
        common_layout.addWidget(QLabel("输出加密设置 (通用):"))
        self.build_mode_combo = QComboBox()
        self.build_mode_combo.addItems(["加密输出 (Encrypted)", "不加密 (Decrypted)"])
        common_layout.addWidget(self.build_mode_combo)
        common_layout.addStretch()
        
        layout.addWidget(common_group)
        
        # 3. Description Label
        self.build_desc_label = QLabel("说明: ...")
        self.build_desc_label.setStyleSheet("color: #666; font-style: italic; margin-bottom: 10px;")
        self.build_desc_label.setWordWrap(True)
        layout.addWidget(self.build_desc_label)
        
        # 4. Stacked Widget for Modes
        self.build_stack = QStackedWidget()
        
        # --- Page 1: ASM Build ---
        page_asm = QWidget()
        asm_layout = QVBoxLayout(page_asm)
        asm_layout.setContentsMargins(0, 0, 0, 0)
        
        asm_group = QFrame()
        asm_group.setFrameShape(QFrame.Shape.StyledPanel)
        asm_inner = QVBoxLayout(asm_group)
        
        self.build_asm_input_edit = self.create_file_selector(
            asm_inner, 
            "输入 ASM 文件/目录:", 
            is_input=True,
            on_change=lambda: self.auto_fill_output('build_asm')
        )
        self.build_asm_output_edit = self.create_file_selector(asm_inner, "输出目录:", is_input=False)
        
        asm_btn_layout = QHBoxLayout()
        self.btn_build_asm = ModernButton("执行构建 (ASM)", is_primary=True)
        self.btn_build_asm.clicked.connect(self.run_build_asm)
        asm_btn_layout.addWidget(self.btn_build_asm)
        asm_btn_layout.addStretch()
        asm_inner.addLayout(asm_btn_layout)
        
        asm_layout.addWidget(asm_group)
        asm_layout.addStretch()
        self.build_stack.addWidget(page_asm)
        
        # --- Page 2: JSON Import ---
        page_json = QWidget()
        json_layout = QVBoxLayout(page_json)
        json_layout.setContentsMargins(0, 0, 0, 0)
        
        json_group = QFrame()
        json_group.setFrameShape(QFrame.Shape.StyledPanel)
        json_inner = QVBoxLayout(json_group)
        
        self.json_imp_ws2_edit = self.create_file_selector(
            json_inner, 
            "原始 WS2 文件/目录 (模板):", 
            is_input=True,
            on_change=lambda: self.auto_fill_output('json_import')
        )
        self.json_imp_json_edit = self.create_file_selector(
            json_inner, 
            "输入 JSON 文件/目录:", 
            is_input=True
        )
        self.json_imp_output_edit = self.create_file_selector(json_inner, "输出目录:", is_input=False)
        
        json_btn_layout = QHBoxLayout()
        self.btn_json_import = ModernButton("执行导入 (JSON)", is_primary=True)
        self.btn_json_import.clicked.connect(self.run_json_import)
        json_btn_layout.addWidget(self.btn_json_import)
        json_btn_layout.addStretch()
        json_inner.addLayout(json_btn_layout)
        
        json_layout.addWidget(json_group)
        json_layout.addStretch()
        self.build_stack.addWidget(page_json)
        
        layout.addWidget(self.build_stack)
        
        # Logic connection
        self.build_type_combo.currentIndexChanged.connect(self.on_build_mode_changed)
        
        # Initial state
        self.on_build_mode_changed(0)

    def on_build_mode_changed(self, index):
        self.build_stack.setCurrentIndex(index)
        if index == 0:
            self.build_desc_label.setText("说明: 将修改后的 .asm.txt 汇编文件重新编译为 .ws2 脚本文件。适用于高级修改。")
        else:
            self.build_desc_label.setText("说明: 使用原始 .ws2 文件作为模板，将 JSON 文本导回并生成新的 .ws2 文件。自动处理控制符恢复和名字回溯修改。")

    def setup_tools_tab(self, tab):
        layout = QVBoxLayout()
        layout.setContentsMargins(15, 15, 15, 15)
        tab.setLayout(layout)
        
        # Input
        self.tool_input_edit = self.create_file_selector(
            layout, 
            "输入文件/目录 (.ws2):", 
            is_input=True,
            on_change=lambda: self.auto_fill_output('tool')
        )
        
        # Mode Selection
        mode_group_layout = QHBoxLayout()
        mode_group_layout.addWidget(QLabel("操作模式:"))
        self.tool_radio_decrypt = QRadioButton("解密 (Decrypt)")
        self.tool_radio_encrypt = QRadioButton("加密 (Encrypt)")
        self.tool_radio_decrypt.setChecked(True)
        mode_group_layout.addWidget(self.tool_radio_decrypt)
        mode_group_layout.addWidget(self.tool_radio_encrypt)
        mode_group_layout.addStretch()
        layout.addLayout(mode_group_layout)
        
        # Output
        self.tool_output_edit = self.create_file_selector(layout, "输出目录:", is_input=False)
        
        layout.addSpacing(10)
        
        # Button
        self.btn_tool = ModernButton("执行操作", is_primary=True)
        self.btn_tool.clicked.connect(self.run_tool)
        layout.addWidget(self.btn_tool)
        layout.addStretch()

    def setup_json_tab(self, tab):
        # This function is deprecated as we merged its content into Extract/Build tabs.
        # But we must remove it or keep it empty to avoid errors if referenced.
        # It's better to remove it from the code, but if I just remove it, I must ensure it's not called.
        # I already removed the call in init_ui, so I can just remove this method or leave it empty.
        pass

    def create_file_selector(self, parent_layout, label_text, is_input=True, on_change=None):
        # Vertical container for Label + Controls
        container = QVBoxLayout()
        container.setSpacing(5)
        
        label = QLabel(label_text)
        container.addWidget(label)
        
        # Horizontal row for Edit + Buttons
        row = QHBoxLayout()
        row.setSpacing(8)
        
        edit = DragDropLineEdit()
        edit.setPlaceholderText("拖拽文件/文件夹到此处...")
        if on_change:
            edit.file_dropped.connect(on_change)
        row.addWidget(edit)
        
        if is_input:
            btn_file = ModernButton("文件", is_primary=False)
            btn_file.clicked.connect(lambda: self.browse_file(edit, on_change))
            row.addWidget(btn_file)
            
            btn_folder = ModernButton("目录", is_primary=False)
            btn_folder.clicked.connect(lambda: self.browse_folder(edit, on_change))
            row.addWidget(btn_folder)
        else:
            # Output is typically a directory
            btn_folder = ModernButton("目录", is_primary=False)
            btn_folder.clicked.connect(lambda: self.browse_folder(edit))
            row.addWidget(btn_folder)
            
        container.addLayout(row)
        parent_layout.addLayout(container)
        return edit

    def browse_folder(self, line_edit, on_change=None):
        path = QFileDialog.getExistingDirectory(self, "选择目录")
        if path:
            line_edit.setText(os.path.normpath(path))
            if on_change:
                on_change()

    def browse_file(self, line_edit, on_change=None):
        path, _ = QFileDialog.getOpenFileName(self, "选择文件")
        if path:
            line_edit.setText(os.path.normpath(path))
            if on_change:
                on_change()

    def auto_fill_output(self, mode):
        if mode == 'extract':
            input_path = self.extract_input_edit.text().strip()
            if input_path:
                base_path = os.path.splitext(input_path)[0]
                self.extract_output_edit.setText(f"{base_path}_out")
        elif mode == 'build_asm':
            input_path = self.build_asm_input_edit.text().strip()
            if input_path:
                base_path = os.path.splitext(input_path)[0]
                if base_path.endswith("_disasm"):
                    base_path = base_path[:-7]
                self.build_asm_output_edit.setText(f"{base_path}_build")
        elif mode == 'tool':
            input_path = self.tool_input_edit.text().strip()
            if input_path:
                base_path = os.path.splitext(input_path)[0]
                self.tool_output_edit.setText(f"{base_path}_out")
        elif mode == 'json_import':
            input_path = self.json_imp_ws2_edit.text().strip()
            if input_path:
                base_path = os.path.splitext(input_path)[0]
                self.json_imp_output_edit.setText(f"{base_path}_new")

    def run_disasm(self):
        input_path = self.extract_input_edit.text().strip()
        output_path = self.extract_output_edit.text().strip()
        
        if not input_path or not output_path:
            QMessageBox.warning(self, "提示", "请选择输入和输出路径")
            return
            
        mode_idx = self.extract_mode_combo.currentIndex()
        mode_key = ['auto', 'encrypted', 'decrypted'][mode_idx]
        
        self.start_worker('disasm', input_path, output_path, disasm_mode=mode_key)
        
    def run_build_asm(self):
        input_path = self.build_asm_input_edit.text().strip()
        output_path = self.build_asm_output_edit.text().strip()
        
        if not input_path or not output_path:
            QMessageBox.warning(self, "提示", "请选择输入和输出路径")
            return

        mode_idx = self.build_mode_combo.currentIndex()
        mode_key = ['encrypted', 'decrypted'][mode_idx]
            
        self.start_worker('build', input_path, output_path, build_mode=mode_key)

    def run_tool(self):
        input_path = self.tool_input_edit.text().strip()
        output_path = self.tool_output_edit.text().strip()
        
        if not input_path or not output_path:
            QMessageBox.warning(self, "提示", "请选择输入和输出路径")
            return
            
        mode_key = 'decrypt' if self.tool_radio_decrypt.isChecked() else 'encrypt'
        self.start_worker('tool', input_path, output_path, tool_mode=mode_key)

    def run_json_extract(self):
        input_path = self.extract_input_edit.text().strip()
        output_path = self.extract_output_edit.text().strip()
        
        if not input_path or not output_path:
            QMessageBox.warning(self, "提示", "请选择输入和输出路径")
            return
            
        mode_idx = self.extract_mode_combo.currentIndex()
        mode_key = ['auto', 'encrypted', 'decrypted'][mode_idx]
        
        self.start_worker('json_extract', input_path, output_path, disasm_mode=mode_key)

    def run_json_import(self):
        ws2_input = self.json_imp_ws2_edit.text().strip()
        json_input = self.json_imp_json_edit.text().strip()
        output_path = self.json_imp_output_edit.text().strip()
        
        if not ws2_input or not json_input or not output_path:
            QMessageBox.warning(self, "提示", "请完整选择路径")
            return

        mode_idx = self.build_mode_combo.currentIndex()
        mode_key = ['encrypted', 'decrypted'][mode_idx]
            
        self.start_worker('json_import', ws2_input, output_path, json_input=json_input, build_mode=mode_key)

    def start_worker(self, mode, input_path, output_path, **kwargs):
        self.set_ui_enabled(False)
        self.progress_bar.show()
        self.log_text.clear()
        
        self.thread = threading.Thread(target=self.worker_target, args=(mode, input_path, output_path), kwargs=kwargs)
        self.thread.daemon = True
        self.thread.start()
        
    def worker_target(self, mode, input_path, output_path, **kwargs):
        worker = WorkerThread(mode, input_path, output_path, **kwargs)
        worker.log_signal.connect(self.append_log)
        worker.finished.connect(self.on_finished)
        worker.run()

    def on_finished(self):
        self.progress_bar.hide()
        self.set_ui_enabled(True)
        QMessageBox.information(self, "完成", "任务已完成")

    def set_ui_enabled(self, enabled):
        self.btn_disasm.setEnabled(enabled)
        self.btn_build_asm.setEnabled(enabled)
        self.btn_tool.setEnabled(enabled)
        self.btn_json_extract.setEnabled(enabled)
        self.btn_json_import.setEnabled(enabled)
        self.extract_input_edit.setEnabled(enabled)
        self.build_asm_input_edit.setEnabled(enabled)
        self.tool_input_edit.setEnabled(enabled)
        self.json_imp_ws2_edit.setEnabled(enabled)
        self.json_imp_json_edit.setEnabled(enabled)

    def append_log(self, text):
        self.log_text.append(text)
        
    def detect_system_theme(self):
        self.theme_combo.setCurrentText("跟随系统")
        self.apply_theme("跟随系统")

    def apply_theme(self, theme_name):
        real_theme = theme_name
        if theme_name == "跟随系统":
            if HAS_DARKDETECT and darkdetect.isDark():
                real_theme = "现代深色"
            else:
                real_theme = "现代浅色"
        
        # Styles from majiro_gui.py
        light_qss = """
        QWidget { font-family: 'Segoe UI', 'Microsoft YaHei', sans-serif; font-size: 10pt; color: #333333; }
        QWidget#MainBackground { background-color: #f5f7fa; }
        QFrame#CardFrame { background-color: #ffffff; border: 1px solid #e1e4e8; border-radius: 8px; }
        QLabel#AppTitle { font-size: 18pt; font-weight: bold; color: #2c3e50; }
        QLineEdit { padding: 8px; border: 1px solid #ced4da; border-radius: 4px; background: #ffffff; color: #333; }
        QLineEdit:focus { border: 1px solid #3498db; }
        QPushButton#SecondaryButton { background-color: #ffffff; border: 1px solid #dcdfe6; border-radius: 4px; color: #606266; padding: 6px 12px; }
        QPushButton#SecondaryButton:hover { border-color: #c6e2ff; color: #409eff; background-color: #ecf5ff; }
        QPushButton#PrimaryButton { background-color: #3498db; border: 1px solid #3498db; border-radius: 4px; color: #ffffff; font-weight: bold; padding: 8px 16px; }
        QPushButton#PrimaryButton:hover { background-color: #5dade2; border-color: #5dade2; }
        QTabWidget::pane { border: 1px solid #e1e4e8; background: #fff; border-radius: 5px; }
        QTabBar::tab { background: #e8ebf0; color: #666; padding: 10px 20px; margin-right: 2px; border-top-left-radius: 4px; border-top-right-radius: 4px; }
        QTabBar::tab:selected { background: #ffffff; color: #3498db; font-weight: bold; }
        QTextEdit#LogConsole { background-color: #fcfcfc; color: #333333; border: 1px solid #e1e4e8; font-family: 'Consolas', monospace; font-size: 9pt; }
        QWidget#LogHeader { background-color: #f1f1f1; border-bottom: 1px solid #ddd; }
        QComboBox { padding: 4px; color: #333; background: #fff; border: 1px solid #ced4da; border-radius: 4px; }
        """
        
        dark_qss = """
        QWidget { font-family: 'Segoe UI', 'Microsoft YaHei', sans-serif; font-size: 10pt; color: #e0e0e0; }
        QWidget#MainBackground { background-color: #1e1e1e; }
        QFrame#CardFrame { background-color: #2d2d2d; border: 1px solid #444; border-radius: 8px; }
        QLabel { color: #e0e0e0; }
        QLabel#AppTitle { color: #ffffff; font-size: 18pt; font-weight: bold; }
        QLineEdit { background: #1a1a1a; border: 1px solid #555; border-radius: 4px; color: #ffffff; padding: 8px; }
        QLineEdit:focus { border: 1px solid #bb86fc; }
        QPushButton#SecondaryButton { background: #333; border: 1px solid #555; color: #ddd; border-radius: 4px; }
        QPushButton#SecondaryButton:hover { background: #444; border-color: #777; }
        QPushButton#PrimaryButton { background: #bb86fc; border: 1px solid #bb86fc; color: #121212; border-radius: 4px; font-weight:bold; }
        QPushButton#PrimaryButton:hover { background: #d0aaff; }
        QTabWidget::pane { border: 1px solid #444; background: #2d2d2d; }
        QTabBar::tab { background: #1e1e1e; color: #999; padding: 10px 20px; border-top-left-radius: 4px; border-top-right-radius: 4px; margin-right:2px;}
        QTabBar::tab:selected { background: #2d2d2d; color: #bb86fc; font-weight:bold; }
        QTextEdit#LogConsole { background-color: #1a1a1a; color: #e0e0e0; border: 1px solid #444; font-family: 'Consolas', monospace; font-size: 9pt; }
        QWidget#LogHeader { background-color: #252525; border-bottom: 1px solid #444; }
        QComboBox { padding: 4px; color: #e0e0e0; background: #333; border: 1px solid #555; border-radius: 4px; }
        QComboBox QAbstractItemView { background-color: #2d2d2d; color: #e0e0e0; selection-background-color: #bb86fc; selection-color: #121212; }
        """

        cyber_qss = """
        QWidget { font-family: 'Segoe UI', 'Microsoft YaHei', sans-serif; font-size: 10pt; color: #00ffcc; }
        QWidget#MainBackground { background-color: #0d0d15; }
        QFrame#CardFrame { background-color: #1a1a2e; border: 1px solid #00ffcc; border-radius: 8px; }
        QLabel { color: #00ffcc; }
        QLabel#AppTitle { color: #ff00ff; font-size: 18pt; font-weight: bold; }
        QLineEdit { background: #0f0f1a; border: 1px solid #ff00ff; border-radius: 4px; color: #00ffcc; padding: 8px; }
        QPushButton#SecondaryButton { background: #0b0b19; border: 1px solid #00ffcc; color: #00ffcc; }
        QPushButton#PrimaryButton { background: #ff0055; border: 1px solid #ff0055; color: #ffffff; font-weight: bold; }
        QTabWidget::pane { border: 1px solid #00ffcc; background: #0d0d15; }
        QTabBar::tab { background: #0d0d15; color: #008888; border: 1px solid #004444; padding: 10px; }
        QTabBar::tab:selected { color: #00ffcc; border: 1px solid #00ffcc; }
        QTextEdit#LogConsole { background-color: #0f0f1f; color: #00ffcc; border: 1px solid #00ffcc; }
        QWidget#LogHeader { background-color: #121225; border-bottom: 1px solid #00ffcc; }
        QComboBox { background: #0d0d15; color: #00ffcc; border: 1px solid #00ffcc; }
        QComboBox QAbstractItemView { background-color: #0d0d15; color: #00ffcc; selection-background-color: #ff0055; }
        """
        
        if real_theme == "现代深色":
            self.setStyleSheet(dark_qss)
        elif real_theme == "赛博朋克":
            self.setStyleSheet(cyber_qss)
        else:
            self.setStyleSheet(light_qss)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = WS2ToolkitGUI()
    window.show()
    sys.exit(app.exec())
