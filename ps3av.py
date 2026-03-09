import os
import struct
import json
import pathlib
from Crypto.Cipher import AES

NP_KLIC_FREE = b'\x72\xF9\x90\x78\x8F\x9C\xFF\x74\x57\x25\xF0\x8E\x4C\x12\x83\x87'
NP_OMAC_KEY_2 = b'\x6B\xA5\x29\x76\xEF\xDA\x16\xEF\x3C\x33\x9F\xB2\x97\x1E\x25\x6B'
NP_OMAC_KEY_3 = b'\x9B\x51\x5F\xEA\xCF\x75\x06\x49\x81\xAA\x60\x4D\x91\xA5\x4E\x97'

EDAT_KEY_0 = b'\xBE\x95\x9C\xA8\x30\x8D\xEF\xA2\xE5\xE1\x80\xC6\x37\x12\xA9\xAE'
EDAT_KEY_1 = b'\x4C\xA9\xC1\x4B\x01\xC9\x53\x09\x96\x9B\xEC\x68\xAA\x0B\xC0\x81'
EDAT_IV = b'\x00' * 16

class PS3Crypto:
    @staticmethod
    def rap_to_rif(rap_data):
        RAP_KEY = b'\x86\x9F\x77\x45\xC1\x3F\xD8\x90\xCC\xF2\x91\x88\xE3\xCC\x3E\xDF'
        RAP_PBOX = [0x0C, 0x03, 0x06, 0x04, 0x01, 0x0B, 0x0F, 0x08, 0x02, 0x07, 0x00, 0x05, 0x0A, 0x0E, 0x0D, 0x09]
        RAP_E1 = [0xA9, 0x3E, 0x1F, 0xD6, 0x7C, 0x55, 0xA3, 0x29, 0xB7, 0x5F, 0xDD, 0xA6, 0x2A, 0x95, 0xC7, 0xA5]
        RAP_E2 = [0x67, 0xD4, 0x5D, 0xA3, 0x29, 0x6D, 0x00, 0x6A, 0x4E, 0x7C, 0x53, 0x7B, 0xF5, 0x53, 0x8C, 0x74]

        if len(rap_data) < 16:
            return None

        key = bytearray(16)
        iv = bytearray(16)
        cipher = AES.new(RAP_KEY, AES.MODE_CBC, iv)
        key[:] = cipher.decrypt(rap_data[:16])

        for round_num in range(5):
            for i in range(16):
                p = RAP_PBOX[i]
                key[p] ^= RAP_E1[p]

            for i in range(15, 0, -1):
                p = RAP_PBOX[i]
                pp = RAP_PBOX[i - 1]
                key[p] ^= key[pp]

            o = 0
            for i in range(16):
                p = RAP_PBOX[i]
                kc = key[p] - o
                ec2 = RAP_E2[p]
                if o != 1 or kc != 0xFF:
                    o = 1 if kc < ec2 else 0
                    key[p] = (kc - ec2) & 0xFF
                else:
                    key[p] = kc & 0xFF

        return bytes(key)

class PS3EdatDecryptor:
    def __init__(self, filepath, klic_map):
        self.filepath = filepath
        self.klic_map = klic_map
        self.png_header = b'\x89PNG\r\n\x1a\n'

    def dec_section(self, metadata):
        dec = bytearray(16)
        dec[0] = metadata[0xC] ^ metadata[0x8] ^ metadata[0x10]
        dec[1] = metadata[0xD] ^ metadata[0x9] ^ metadata[0x11]
        dec[2] = metadata[0xE] ^ metadata[0xA] ^ metadata[0x12]
        dec[3] = metadata[0xF] ^ metadata[0xB] ^ metadata[0x13]
        dec[4] = metadata[0x4] ^ metadata[0x8] ^ metadata[0x14]
        dec[5] = metadata[0x5] ^ metadata[0x9] ^ metadata[0x15]
        dec[6] = metadata[0x6] ^ metadata[0xA] ^ metadata[0x16]
        dec[7] = metadata[0x7] ^ metadata[0xB] ^ metadata[0x17]
        dec[8] = metadata[0xC] ^ metadata[0x0] ^ metadata[0x18]
        dec[9] = metadata[0xD] ^ metadata[0x1] ^ metadata[0x19]
        dec[10] = metadata[0xE] ^ metadata[0x2] ^ metadata[0x1A]
        dec[11] = metadata[0xF] ^ metadata[0x3] ^ metadata[0x1B]
        dec[12] = metadata[0x4] ^ metadata[0x0] ^ metadata[0x1C]
        dec[13] = metadata[0x5] ^ metadata[0x1] ^ metadata[0x1D]
        dec[14] = metadata[0x6] ^ metadata[0x2] ^ metadata[0x1E]
        dec[15] = metadata[0x7] ^ metadata[0x3] ^ metadata[0x1F]

        offset = struct.unpack(">Q", dec[0:8])[0]
        length = struct.unpack(">I", dec[8:12])[0] & 0xFFFFFFFF
        comp_end = struct.unpack(">I", dec[12:16])[0] & 0xFFFFFFFF
        return offset, length, comp_end

    def get_block_key(self, block, dev_hash, version):
        key = bytearray(16)
        if version <= 1:
            key[:12] = b'\x00' * 12
        else:
            key[:12] = dev_hash[:12]
        key[12:] = struct.pack(">I", block)
        return bytes(key)

    def decrypt_to_png(self):
        try:
            with open(self.filepath, 'rb') as f:
                data = f.read()
        except Exception as e:
            print(f"[*] Error reading: {e}")
            return None

        if len(data) < 4 or not data.startswith(b'NPD'):
            return self.extract_png_from_buffer(data)

        version = struct.unpack(">I", data[4:8])[0]
        license_type = struct.unpack(">I", data[8:12])[0]
        content_id = data[16:64].decode('ascii', errors='ignore').strip('\x00')
        digest = data[64:80]
        dev_hash = data[96:112]

        flags = struct.unpack('>I', data[128:132])[0]
        block_size = struct.unpack('>I', data[132:136])[0]
        file_size = struct.unpack('>Q', data[136:144])[0]

        EDAT_COMPRESSED_FLAG = 0x00000001
        EDAT_FLAG_0x02 = 0x00000002
        EDAT_ENCRYPTED_KEY_FLAG = 0x00000008
        EDAT_FLAG_0x20 = 0x00000020
        SDAT_FLAG = 0x01000000

        is_compressed = bool(flags & EDAT_COMPRESSED_FLAG)
        is_payload_encrypted = not bool(flags & EDAT_FLAG_0x02)
        is_encrypted_key = bool(flags & EDAT_ENCRYPTED_KEY_FLAG)
        has_0x20_flag = bool(flags & EDAT_FLAG_0x20)
        is_sdat = bool(flags & SDAT_FLAG)

        if is_sdat:
            SDAT_KEY = b'\x0D\x65\x5E\xF8\xE6\x74\xA9\x8A\xB8\x50\x5C\xFA\x7D\x01\x29\x33'
            key_input = bytes(a ^ b for a, b in zip(dev_hash, SDAT_KEY))
        else:
            license_mask = license_type & 0x3
            if license_mask == 0x3:
                key_input = self.klic_map.get(content_id, NP_KLIC_FREE)
            else:
                rap_data = self.klic_map.get(content_id)
                if rap_data:
                    key_input = PS3Crypto.rap_to_rif(rap_data)
                else:
                    key_input = NP_KLIC_FREE

        num_blocks = (file_size + block_size - 1) // block_size
        meta_size = 32 if (is_compressed or has_0x20_flag) else 16
        metadata_offset = 0x100

        png_start_markers = [b'\x89PNG\r\n\x1a\n', b'PSNA', b'IHDR']
        png_data = bytearray()
        found_png = False

        for i in range(num_blocks):
            if is_compressed:
                meta_pos = metadata_offset + (i * meta_size)
                if meta_pos + meta_size > len(data): break
                metadata = data[meta_pos:meta_pos + meta_size]
                if version <= 1:
                    offset = struct.unpack(">Q", metadata[0x10:0x18])[0]
                    chunk_len = struct.unpack(">I", metadata[0x18:0x1C])[0]
                else:
                    offset, chunk_len, _ = self.dec_section(metadata)
                data_offset = offset
            elif has_0x20_flag:
                meta_pos = metadata_offset + (i * (meta_size + block_size))
                data_offset = meta_pos + meta_size
                chunk_len = min(block_size, file_size - (i * block_size))
            else:
                data_offset = metadata_offset + (num_blocks * meta_size) + (i * block_size)
                chunk_len = min(block_size, file_size - (i * block_size))

            b_key_input = self.get_block_key(i, dev_hash, version)
            key_result = AES.new(key_input, AES.MODE_ECB).encrypt(b_key_input)

            if is_encrypted_key:
                edat_key = EDAT_KEY_1 if version == 4 else EDAT_KEY_0
                cipher_key = AES.new(edat_key, AES.MODE_CBC, iv=EDAT_IV)
                key_final = cipher_key.decrypt(key_result)
            else:
                key_final = key_result

            read_len = (chunk_len + 15) & ~15
            if data_offset + read_len > len(data): break
            block_enc = data[data_offset:data_offset + read_len]

            if is_payload_encrypted:
                iv_payload = b'\x00' * 16 if version <= 1 else digest
                cipher_payload = AES.new(key_final, AES.MODE_CBC, iv=iv_payload)
                dec_block = cipher_payload.decrypt(block_enc)[:chunk_len]
            else:
                dec_block = block_enc[:chunk_len]

            if not found_png:
                for marker in png_start_markers:
                    pos = dec_block.find(marker)
                    if pos != -1:
                        png_data.extend(dec_block[pos:])
                        found_png = True
                        break
            else:
                png_data.extend(dec_block)

        if png_data:
            return self.extract_png_from_buffer(bytes(png_data))
        return None

    def extract_png_from_buffer(self, buffer):
        if buffer.startswith(b'\x89PNG\r\n\x1a\n'):
            end = buffer.find(b'IEND')
            return buffer[:end+8] if end != -1 else buffer

        ihdr_pos = buffer.find(b'IHDR')
        if ihdr_pos != -1:
            png_header = b'\x89PNG\r\n\x1a\n\x00\x00\x00\r'
            reconstructed = png_header + buffer[ihdr_pos:]
            end = reconstructed.find(b'IEND')
            return reconstructed[:end+8] if end != -1 else reconstructed
        return None

class AvatarApp:
    def __init__(self):
        self.base_dir = os.path.dirname(os.path.abspath(__file__))

        self.default_avatar_path = os.path.join(self.base_dir, "avatar")
        self.default_extract_path = os.path.join(self.base_dir, "avatars")

        self.config_file = os.path.join(self.base_dir, "config.json")
        self.config = self.load_config()
        self.available_klics = {}

        for p in [self.config['avatar_path'], self.config['extract_path']]:
            if not os.path.exists(p):
                os.makedirs(p)

    def load_config(self):
        if os.path.exists(self.config_file):
            with open(self.config_file, 'r') as f:
                cfg = json.load(f)
                if 'extract_path' not in cfg:
                    cfg['extract_path'] = self.default_extract_path
                return cfg
        return {
            "avatar_path": self.default_avatar_path,
            "exdata_path": "",
            "extract_path": self.default_extract_path
        }

    def save_config(self):
        with open(self.config_file, 'w') as f:
            json.dump(self.config, f, indent=4)

    def sanitize_path(self, path):
        return path.strip().strip("'\"")

    def load_rap_keys(self):
        path = self.config.get("exdata_path")
        if path and os.path.exists(path):
            print(f"[*] Loading RAPs from: {path}")
            count = 0
            for file in os.listdir(path):
                if file.lower().endswith(".rap"):
                    cid = os.path.splitext(file)[0]
                    try:
                        with open(os.path.join(path, file), 'rb') as f:
                            self.available_klics[cid] = f.read(16)
                            count += 1
                    except Exception as e:
                        print(f"    Error loading {file}: {e}")
            print(f"[*] Loaded {count} RAP files.")

    def process_all(self):
        root = self.config.get("avatar_path")
        out_root = self.config.get("extract_path")
        if not root or not os.path.exists(root):
            print(f"[*] Path not found: {root}")
            return

        success_count = 0
        fail_count = 0

        for r, d, files in os.walk(root):
            for f in files:
                if f.lower().endswith(('.edat', '.unedat')):
                    file_path = os.path.join(r, f)
                    print(f"\n[*] Processing: {file_path}")

                    png_data = PS3EdatDecryptor(file_path, self.available_klics).decrypt_to_png()

                    if png_data:
                        subfolder_name = os.path.basename(r)
                        target_dir = os.path.join(out_root, subfolder_name)

                        if not os.path.exists(target_dir):
                            os.makedirs(target_dir)

                        png_name = f.rsplit('.', 1)[0] + ".png"
                        png_path = os.path.join(target_dir, png_name)

                        with open(png_path, 'wb') as png_file:
                            png_file.write(png_data)
                        print(f"    Saved PNG to: {png_path}")
                        success_count += 1
                    else:
                        print(f"    No PNG found in {f}")
                        fail_count += 1
        print(f"\n[*] Done! Success: {success_count}, Failed: {fail_count}")

    def choose_and_extract(self):
        root = self.config.get("avatar_path")
        out_root = self.config.get("extract_path")
        if not root or not os.path.exists(root):
            print(f"[*] Path not found: {root}")
            return

        subdirs = sorted([d for d in os.listdir(root) if os.path.isdir(os.path.join(root, d))])
        if not subdirs:
            print("[*] No subdirectories found in avatar folder.")
            return

        for i, d in enumerate(subdirs): print(f"{i}. {d}")
        try:
            f_idx = int(input("\nFolder index: "))
            sel_f = subdirs[f_idx]
            folder_path = os.path.join(root, sel_f)
            files = sorted([f for f in os.listdir(folder_path) if f.lower().endswith(('.edat', '.unedat'))])

            if not files:
                print("[*] No EDAT files in this folder.")
                return

            for i, f in enumerate(files): print(f"{i}. {f}")
            file_idx = int(input("\nFile index: "))
            sel_file = files[file_idx]

            print(f"\n[*] Processing: {sel_file}")
            png_data = PS3EdatDecryptor(os.path.join(folder_path, sel_file), self.available_klics).decrypt_to_png()
            if png_data:
                target_dir = os.path.join(out_root, sel_f)
                if not os.path.exists(target_dir):
                    os.makedirs(target_dir)

                png_name = sel_file.rsplit('.', 1)[0] + ".png"
                png_path = os.path.join(target_dir, png_name)
                with open(png_path, 'wb') as png_file: png_file.write(png_data)
                print(f"    Saved PNG to: {png_path}")
            else: print(f"    No PNG found")
        except Exception as e: print(f"[*] Error: {e}")

    def change_paths_menu(self):
        while True:
            print("\n" + "-"*30)
            print("1. Change psn_avatar path")
            print("2. Change exdata path")
            print("3. Change extract path")
            print("0. Back")
            print("-"*30)
            sub_c = input("\nChoice: ").strip()

            if sub_c == '1':
                path = self.sanitize_path(input("New PSN Avatar Path: "))
                if path:
                    self.config['avatar_path'] = path
                    self.save_config()
            elif sub_c == '2':
                path = self.sanitize_path(input("New Exdata Path: "))
                if path:
                    self.config['exdata_path'] = path
                    self.save_config()
                    self.load_rap_keys()
            elif sub_c == '3':
                path = self.sanitize_path(input("New Extract Path: "))
                if path:
                    self.config['extract_path'] = path
                    self.save_config()
            elif sub_c == '0':
                break

    def menu(self):
        self.load_rap_keys()
        while True:
            print("\n" + "="*50)
            print(f"1. Change paths")
            print("2. Choose avatar to extract")
            print("3. Extract all from avatar folder")
            print("0. Exit")
            print("="*50)
            c = input("\nChoice: ").strip()

            if c == '1':
                self.change_paths_menu()
            elif c == '2':
                self.choose_and_extract()
            elif c == '3':
                self.process_all()
            elif c == '0':
                break

if __name__ == "__main__":
    AvatarApp().menu()