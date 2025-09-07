import os
from argon2.low_level import hash_secret_raw, Type
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from pathlib import Path
from datetime import datetime
import json
import shutil
from os import urandom, path

class Cipher:
    def __init__(self, password: str):
        self.password = password.encode()

    def get_key(self, salt: bytes):
        return hash_secret_raw(
            secret=self.password,
            salt=salt,
            time_cost=3,
            memory_cost=64*1024,
            parallelism=4,
            hash_len=32,
            type=Type.ID
        )
    
    def enc(self, in_file, is_str=False):
        salt = urandom(16)
        key = self.get_key(salt)
        encryptor = AES.new(key, AES.MODE_GCM)
        iv = encryptor.nonce

        if is_str:
            enc_data, tag = encryptor.encrypt_and_digest(in_file.encode())
            return salt + iv + tag + enc_data
        else:
            in_file = Path(in_file)
            with open(in_file.resolve(), 'rb') as f:
                data = f.read()

            meta_dict = {
                "file": str(in_file.with_suffix('.enc').resolve()),
                "suffix": in_file.suffix,
                "date": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "size": path.getsize(in_file.resolve())
            }

            meta_bytes = json.dumps(meta_dict, ensure_ascii=False).encode()
            meta_size = len(meta_bytes).to_bytes(4, "big")

            enc_data, tag = encryptor.encrypt_and_digest(meta_size + meta_bytes + data)

            with open(in_file.with_suffix('.enc'), 'wb') as f:
                f.write(salt + iv + tag + enc_data)

            in_file.unlink()
            self.log_add(meta_dict)
    
    def dec(self, in_file, is_str=False, no_log=False, out_path=""):
        if is_str:
            salt = in_file[:16]
            iv = in_file[16:32]
            tag = in_file[32:48]
            enc_data = in_file[48:]
            key = self.get_key(salt)
        else:
            in_file = Path(in_file)
            with open(in_file.resolve(), 'rb') as f:
                salt = f.read(16)
                iv = f.read(16)
                tag = f.read(16)
                enc_data = f.read()
            key = self.get_key(salt)

        decryptor = AES.new(key, AES.MODE_GCM, nonce=iv)
        dec_data = decryptor.decrypt_and_verify(enc_data, tag)

        if is_str:
            return dec_data
        else:
            meta_size = int.from_bytes(dec_data[:4], "big")
            meta_json = json.loads(dec_data[4:4 + meta_size].decode())
            data = dec_data[4 + meta_size:]
            meta_path = Path(meta_json["file"])
            if out_path == "" or not out_path:
                origin_path = meta_path.with_suffix(meta_json["suffix"])
            else:
                out_path = Path(out_path)
                origin_path = out_path / meta_path.name
            with open(origin_path, 'wb') as f:
                f.write(data)
            in_file.unlink()
            if not no_log: self.log_del(meta_json)

    def log_add(self, meta_dict):
        try:
            if os.path.exists('./data.bin'):
                dec_data_dic = self.log_load()
                dec_data_dic["files"].append(meta_dict)
            else:
                dec_data_dic = {"files": [meta_dict]}

            with open('./data.bin', 'wb') as f:
                f.write(self.enc(json.dumps(dec_data_dic, ensure_ascii=False), True))
        except Exception as e:
            print(f"로그 추가 - {e}")

    def log_del(self, meta_dict, is_filename=False):
        try:
            dec_data_dic = self.log_load()
            if is_filename:
                dec_data_dic["files"] = [i for i in dec_data_dic["files"] if i.get("file") != meta_dict.get("file")]
            else:
                dec_data_dic["files"] = [i for i in dec_data_dic["files"] if i.get("file") != meta_dict] # gui에서 meta_dict가 file_path고 str임
            with open('./data.bin', 'wb') as f:
                f.write(self.enc(json.dumps(dec_data_dic, ensure_ascii=False), True))
        except Exception as e:
            print(f"로그 삭제 - {e}")

    def log_load(self, log_path='./data.bin'):
        try:
            with open(log_path, 'rb') as f:
                data = f.read()
            dec_data = self.dec(data, True)
            dec_data_dic = json.loads(dec_data.decode())
            return dec_data_dic
        except ValueError:
            os.remove(log_path)

        except Exception as e:
            print(f"로그 로드 - {e}")
            return {"files": []}

class Login:
    def save(self, password:str):
        ph = PasswordHasher()
        with open('password.bin', 'w') as f:
            f.write(ph.hash(password))

    def verify(self, password:str):
        ph = PasswordHasher()
        try:
            with open('password.bin', 'r') as f:
                hashed_password = f.read()
                ph.verify(hashed_password, password)
                return True
        except VerifyMismatchError:
            return False
        except FileNotFoundError:
            if password == "1234":
                return True
            else:
                return False
