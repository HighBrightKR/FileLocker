import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from ttkbootstrap import Style
from cipher import Cipher, Login
from tkinter import filedialog
import shutil
ttk.localization.initialize_localities = bool

class FileManagerApp(ttk.Window):
    def __init__(self):
        super().__init__(title="파일 관리자", themename="litera")
        self.geometry("900x600")
        self.minsize(600, 400)
        self.output_path = ""

        style = Style()
        style.configure('.', font=('Noto Sans KR', 10))
        style.configure('Treeview.Heading', font=('Noto Sans KR', 10, 'bold'))
        style.map('Treeview', rowheight=[("!disabled", 20)])
        style.configure('TButton', font=('Noto Sans KR', 10, 'bold'))

        top_frame = ttk.Frame(self, padding=(10, 10))
        top_frame.pack(fill=X, side=TOP)

        settings_button = ttk.Menubutton(top_frame, text="설정")
        settings_button.pack(side=LEFT, padx=(0, 5))

        setting_menu = ttk.Menu(settings_button, tearoff=False)
        setting_menu.add_command(label="비밀번호 변경", command= lambda o='pw': self.on_settings_click(o))
        setting_menu.add_command(label="출력 폴더 변경", command=lambda o='output': self.on_settings_click(o))

        settings_button.config(menu=setting_menu)

        load_button = ttk.Button(top_frame, text="데이터 로드", command=self.on_load_click)
        load_button.pack(side=LEFT, padx=5)

        dec_button = ttk.Button(top_frame, text="목록에 없는 파일 복호화", command=self.on_notinlist_dec_click)
        dec_button.pack(side=LEFT, padx=5)

        self.use_key = ttk.BooleanVar()
        self.use_key_check = ttk.Checkbutton(top_frame, text="키 사용자 지정", variable=self.use_key, command=self.on_usekey_check)
        self.use_key_check.pack(side=LEFT, padx=5)

        style.configure('KeyEntry.TEntry')
        style.map('KeyEntry.TEntry', foreground=[("disabled", "gray")], fieldbackground=[("disabled", "#e0e0e0")])
        self.key_entry = ttk.Entry(top_frame, style="KeyEntry.TEntry", show="*")
        self.key_entry.config(state="disabled")
        self.key_entry.pack(side=LEFT, padx=5)

        add_button = ttk.Button(top_frame, text="추가", bootstyle="success", command=self.on_add_click)
        add_button.pack(side=RIGHT, padx=5)

        separator = ttk.Separator(self)
        separator.pack(fill=X, padx=10, pady=5)
        
        table_frame = ttk.Frame(self, padding=(10, 0, 10, 10))
        table_frame.pack(expand=YES, fill=BOTH)

        columns = ("file_path", "suffix", "time", "size")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", bootstyle="primary")

        self.tree.heading("file_path", text="파일 경로")
        self.tree.heading("suffix", text="원본 확장자")
        self.tree.heading("time", text="시간")
        self.tree.heading("size", text="원본 크기")
        
        self.tree.column("file_path", width=500)
        self.tree.column("suffix", width=50, anchor=CENTER)
        self.tree.column("time", width=150, anchor=CENTER)
        self.tree.column("size", width=50, anchor=CENTER)
        
        scrollbar = ttk.Scrollbar(table_frame, orient=VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side=LEFT, expand=YES, fill=BOTH)
        scrollbar.pack(side=RIGHT, fill=Y)
        self.tree.bind("<<TreeviewSelect>>", self.on_item_select)

        bottom_frame = ttk.Frame(self, padding=(10, 10))
        bottom_frame.pack(fill=X, side=BOTTOM)

        self.status_label = ttk.Label(bottom_frame, text="준비 완료")
        self.status_label.pack(side=LEFT, fill=X, expand=True)

        self.decrypt_button = ttk.Button(
            bottom_frame,
            text="선택 항목 복호화",
            command=self.on_decrypt_click,
            state="disabled"
        )
        self.decrypt_button.pack(side=RIGHT)


    def set_pw(self, pw):
        self.pw = pw
        self.cipher = Cipher(self.pw)
        self.load_data()

    def load_data(self, log_path="./data.bin"):
        for item in self.tree.get_children():
            self.tree.delete(item)
        data = self.cipher.log_load(log_path)
        cols = ("file", "suffix", "date", "size")
        if data:
            for item in data["files"]:
                self.tree.insert("", END, values=[item[col] for col in cols])
            return True
        else:
            self.status_label.config(text="파일 목록을 불러오는데 실패했습니다.")
            return False

    def on_settings_click(self, option):
        if option == "pw":
            screen = ttk.Toplevel(self.master)
            screen.title("비밀번호 변경")
            screen.geometry("400x250")
            screen.grab_set()

            ttk.Label(screen, text="비밀번호 입력").pack(pady=10)
            pw1_entry = ttk.Entry(screen, show="*", width=30)
            pw1_entry.pack()
            ttk.Label(screen, text="비밀번호 재입력").pack(pady=10)
            pw2_entry = ttk.Entry(screen, show="*", width=30)
            pw2_entry.pack()
            pw_status = ttk.Label(screen, text="비밀번호 변경시 기존 암호화된 파일을 복구할 수 없습니다.", bootstyle=WARNING)
            pw_status.pack()

            def check_pw():
                pw1, pw2 = pw1_entry.get(), pw2_entry.get()
                if not pw1 or not pw2:
                    pw_status.config(text="비밀번호를 입력하세요.")
                elif pw1 != pw2:
                    pw_status.config(text="비밀번호가 일치하지 않습니다. 입력하세요.")
                else:
                    l = Login()
                    l.save(pw1)
                    screen.destroy()
                    self.status_label.config(text="비밀번호가 변경되었습니다.")
                    self.set_pw(pw1)

            ttk.Button(screen, text="확인", command=check_pw, bootstyle="success", width=30).pack(pady=20)

        elif option == "output":
            screen = ttk.Toplevel(self.master)
            screen.title("출력 폴더 변경")
            screen.geometry("400x250")
            screen.grab_set()

            ttk.Label(screen, text="출력 폴더 설정").pack(pady=10)
            sel_dir_btn = ttk.Button(screen, text="폴더 선택", bootstyle="info")
            sel_dir_btn.pack(pady=10)
            output_label = ttk.Label(screen, text="출력 폴더를 선택하세요.")
            output_label.pack(pady=10)
            save_btn = ttk.Button(screen, text="저장", bootstyle="success", width=30)
            save_btn.pack(pady=10)

            def on_sel_dir_click():
                output = filedialog.askdirectory(title="출력 폴더 선택", initialdir="./")
                if output:
                    output_label.config(text=output)

            def on_save_click():
                output = output_label.cget("text")
                if output == "출력 폴더를 선택하세요." or output == "":
                    self.status_label.config(text="출력 폴더가 선택되지 않았습니다.")
                else:
                    self.status_label.config(text=f"출력 폴더가 {output}으로 변경되었습니다.")
                    self.output_path = output
                screen.destroy()

            sel_dir_btn.config(command=on_sel_dir_click)
            save_btn.config(command=on_save_click)


    def on_load_click(self):
        log_path = filedialog.askopenfilename(title="파일 선택", filetypes=(("데이터 파일", "*.bin"),))
        if not log_path: return
        try:
            if self.load_data(log_path):
                shutil.copy(log_path, "./data.bin")
        except Exception as e:
            pass

    def on_add_click(self):
        file_path = filedialog.askopenfilename(title="파일 선택", filetypes=(("모든 파일", "*.*"),))
        if not file_path: return
        self.status_label.config(text=f"'{file_path}' 암호화를 시작합니다.")
        self.cipher.enc(file_path)
        self.status_label.config(text=f"'{file_path}' 암호화가 완료되었습니다.")
        self.load_data()

    def on_decrypt_click(self):
        try:
            sel = self.tree.selection()[0]
            item_details = self.tree.item(sel)
            file_path = item_details.get('values')[0] # str임
            self.status_label.config(text=f"'{file_path}' 복호화를 시작합니다.")
            self.cipher.dec(file_path, out_path=self.output_path)
            self.load_data()
            self.status_label.config(text=f"'{file_path}' 복호화가 완료되었습니다.")

        except FileNotFoundError:
            self.cipher.log_del(file_path, is_filename=True)
            self.load_data()
            self.status_label.config(text=f"'{file_path}'를 찾을 수 없어 목록에서 삭제했습니다.")

        except Exception as e:
            self.status_label.config(text=f"오류: {e}")


    def on_notinlist_dec_click(self):
        try:
            file_path = filedialog.askopenfilename(title="파일 선택", filetypes=(("암호화된 파일", "*.enc"),))
            if file_path:
                self.status_label.config(text=f"'{file_path}' 복호화를 시작합니다.")
            if self.use_key.get():
                key = self.key_entry.get()
                if not key:
                    self.status_label.config(text=f"키가 입력되지 않았습니다.")
                    return
                temp_cipher = Cipher(key)
                temp_cipher.dec(file_path, no_log=True, out_path=self.output_path)
            else:
                self.cipher.dec(file_path, no_log=True, out_path=self.output_path)
                self.status_label.config(text=f"'{file_path}' 복호화가 완료되었습니다.")
        except Exception as e:
            self.status_label.config(text=f"복호화 오류: {e}")

    def on_item_select(self, event):
        if self.tree.selection():
            self.decrypt_button.config(state="normal")
        else:
            self.decrypt_button.config(state="disabled")

    def on_usekey_check(self):
        if self.use_key.get():
            self.key_entry.config(state="normal")
        else:
            self.key_entry.config(state="disabled")


class LoginApp(ttk.Toplevel):
    def __init__(self, parent, on_login_success):  
        super().__init__(parent)  
        self.geometry("400x500")
        self.title = "인증"
        self.resizable(False, False)
        self.on_login_success = on_login_success

        main_frame = ttk.Frame(self, padding=40)
        main_frame.pack(expand=True, fill=BOTH)

        style = Style()
        style.configure('.', font=('Noto Sans KR', 10))
        
        title_label = ttk.Label(
            main_frame,
            text="파일 관리자",
            font=("Noto Sans KR", 24, "bold"),
            bootstyle=PRIMARY
        )
        title_label.pack(pady=(0, 10))

        
        subtitle_label = ttk.Label(
            main_frame,
            text="서비스를 이용하기 위해 본인인증이 필요합니다.",
            font=("Noto Sans KR", 12),
            bootstyle=SECONDARY
        )
        subtitle_label.pack(pady=(0, 30))
        
        password_frame = ttk.Frame(main_frame)
        password_frame.pack(fill=X, pady=(0, 25))

        password_label = ttk.Label(password_frame, text="비밀번호")
        password_label.pack(anchor=W)

        self.password_entry = ttk.Entry(password_frame, show="*", bootstyle=PRIMARY)
        self.password_entry.pack(fill=X, ipady=5)
        self.password_entry.focus_set()  
        self.password_entry.bind("<Return>", self.on_login)  

        self.status_label = ttk.Label(
            password_frame,
            text="",
            font=("Noto Sans KR", 11),
            bootstyle=DANGER,
        )
        self.status_label.pack(pady=5)

        
        self.login_button = ttk.Button(
            main_frame,
            text="로그인",
            command=self.on_login,
            bootstyle=PRIMARY,
            padding=(10)
        )
        self.login_button.pack(fill=X)

        signup_frame = ttk.Frame(main_frame)
        signup_frame.pack(pady=(30, 0))

        freshman_label = ttk.Label(
            signup_frame,
            text="초기 비밀번호는 1234입니다. \n로그인 후 반드시 '설정 > 비밀번호 변경'을 통해 \n비밀번호를 변경하세요.",
            bootstyle=SECONDARY
        )
        freshman_label.pack(padx=(0, 5))

    def on_login(self, event=None):
        password = self.password_entry.get()
        l = Login()
        if l.verify(password):
            self.destroy()
            self.on_login_success(password)
        else:
            self.status_label.config(text="비밀번호가 올바르지 않습니다.")
            self.password_entry.delete(0, END)