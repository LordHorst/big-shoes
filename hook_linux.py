import os
import re
import threading
import time
import errno
import psutil
from typing import List, Tuple

import constants

def read_process_memory(pid: int, address: int, size: int) -> bytes:
    """Liest Speicher aus einem Prozess über /proc/pid/mem."""
    try:
        mem_path = f'/proc/{pid}/mem'
        # O_RDONLY: read only
        mem_handle = os.open(mem_path, os.O_RDONLY) 
        
        # jump to target address
        os.lseek(mem_handle, address, os.SEEK_SET)
        
        # read byttes
        data = os.read(mem_handle, size)
        os.close(mem_handle)
        return data
    except FileNotFoundError:
        raise constants.BadHookException(f"Prozess {pid} nicht gefunden oder Zugriff auf /proc/mem verweigert.")
    except PermissionError:
        raise constants.BadHookException(f"Zugriff auf /proc/{pid}/mem verweigert. Bitte versuchen Sie es mit 'sudo'.")
    except OSError as e:
        # EIO (Input/Output Error)
        if e.errno == errno.EIO:
             return b'\x00' * size
        raise e

def find_module_base_address(pid: int, module_name_regex: str) -> int or None:
    maps_path = f'/proc/{pid}/maps'
    try:
        with open(maps_path, 'r') as maps_file:
            for line in maps_file:
                parts = line.strip().split()
                if len(parts) >= 6 and re.search(module_name_regex, parts[-1], re.IGNORECASE):
                    start_addr_str = parts[0].split('-')[0]
                    return int(start_addr_str, 16)
        return None
    except:
        return None

# --- replace win32process and Toolhelp32) ---

def get_emu_process_ids():
    pids = {}
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            exe_path = proc.exe()
            filename = os.path.basename(exe_path)
            for emu_name in Hook.EMULATOR_MAP.keys():
                if re.search(Hook.EMULATOR_MAP[emu_name][0], filename, re.IGNORECASE):
                    if emu_name in pids:
                        pids[emu_name].append(proc.pid)
                    else:
                        pids[emu_name] = [proc.pid]
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    for emu_name in pids:
        pids[emu_name].sort()
    return pids

TARGET_SUBSTRING = "EmuHawk"

def get_emu_process_ids_linux(target_substring: str = "EmuHawk"):
    pids = {}
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            pid = proc.info['pid']
            process_name = proc.info['name']
            cmdline = proc.info['cmdline']
            cmdline_str = " ".join(cmdline or [])

            is_match = (
                re.search(target_substring, process_name, re.IGNORECASE) or
                re.search(target_substring, cmdline_str, re.IGNORECASE)
            )

            if is_match:
                pids[process_name].append(pid)

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        except Exception:
            continue
            
    # return sorted(found_processes, key=lambda x: x[0])
    for emu_name in pids:
        pids[emu_name].sort()
    return pids


def get_pc_process_id():
    target_exe = "ff7_en.exe" 
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'].casefold() == target_exe.casefold():
            return proc.pid
    return None

class Address:
    def __init__(self, psx_address: int, pc_address: int, size: int, name: str):
        self.psx_address = psx_address
        self.pc_address = pc_address
        self.size = size
        self.name = name

class HookablePlatform:
    def __init__(self, name, is_psx, version, address_func):
        self.name = name
        self.is_psx = is_psx
        self.version = version
        self._address_func = address_func

    def read_int(self, hook, address: Address):
        try:
            a = self._address_func(hook, address, self.version) 
            data = read_process_memory(hook.hooked_process_id, a, address.size // 8)
            if len(data) != address.size // 8:
                 return 0
                 
            return int.from_bytes(data, byteorder='little')
        except constants.BadHookException as e:
            raise e
        except Exception as e:
            raise RuntimeError("Memory read error")

    def read_bytes(self, hook, address: Address, size: int):
        a = self._address_func(hook, address, self.version)
        return read_process_memory(hook.hooked_process_id, a, size)

def psxfin_address_func(hook, address: Address, version: str):
    if hook.base_cache is None:
        psxfin_base = find_module_base_address(hook.hooked_process_id, r'psxfin\.exe')
        
        if psxfin_base:
             try:
                 base1_addr = psxfin_base + 0x1899BC
                 base1_value = int.from_bytes(read_process_memory(hook.hooked_process_id, base1_addr, 4), byteorder='little')
                 
                 base2_addr = base1_value + 0x30
                 hook.base_cache = int.from_bytes(read_process_memory(hook.hooked_process_id, base2_addr, 4), byteorder='little')
             except Exception:
                 hook.base_cache = None

        if hook.base_cache is None:
             raise constants.BadHookException("Couldn't find PSXFin.")
             
    return hook.base_cache + address.psx_address


def bizhawk_address_func(hook, address: Address, version: str):
    if hook.base_cache is None:
        module_base = find_module_base_address(hook.hooked_process_id, r'octoshock\.dll')
        
        _BIZHAWK_ADDRESS_MAP = {
            "2.9.1": 0x124b30, "2.7": 0x317F80, "2.6.2": 0x30DF80, "2.5.2": 0x310F80,
            "2.4.1": 0x30DF90, "2.3.2": 0x11D880,
        }
        
        if module_base and version in _BIZHAWK_ADDRESS_MAP:
            hook.base_cache = module_base + _BIZHAWK_ADDRESS_MAP[version]
        
        if hook.base_cache is None:
            raise constants.BadHookException("Couldn't find BizHawk")
            
    return hook.base_cache + address.psx_address


def retroduck_address_func(hook, address: Address, version: str):
    if hook.base_cache is None:
        module_base = find_module_base_address(hook.hooked_process_id, r'duckstation_libretro\.dll')
        
        if module_base:
            try:
                base1_addr = module_base + 0x40E078 
                pointer_value = int.from_bytes(read_process_memory(hook.hooked_process_id, base1_addr, 8), byteorder='little')
                hook.base_cache = pointer_value
            except Exception:
                 hook.base_cache = None
        
        if hook.base_cache is None:
            raise constants.BadHookException("Couldn't find RetroDuck")
            
    return hook.base_cache + address.psx_address


def manual_address_func(hook, address: Address, version: str):
    if hook.manual_address is None:
        raise Exception("No manual address")
    return hook.manual_address + address.psx_address


def pc_address_func(hook, address: Address, version: str):
    if hook.base_cache is None:
        module_base = find_module_base_address(hook.hooked_process_id, r'ff7_en\.exe')
        if module_base:
             hook.base_cache = module_base
        
        if hook.base_cache is None:
            raise constants.BadHookException("Couldn't find FF7 PC Executable")
            
    return hook.base_cache + address.pc_address


def find_base_address_candidates(b: bytes):
    i = 0
    while i < len(b):
        i = b.find(constants.RNG_BYTES, i)
        if i < 0:
            return

        if sum(b[i - 0xD0638:i - 0xD0638 + 128]) == 9178: 
            yield i - 0xE0638
        i += len(constants.RNG_BYTES)


def manual_search(process_id):
    try:
        mem_path = f'/proc/{process_id}/mem'
        mem_handle = os.open(mem_path, os.O_RDONLY)
    except Exception as e:
        print(f"Konnte /proc/pid/mem nicht öffnen: {e}. Eventuell fehlen sudo-Rechte.")
        return 

    maps_path = f'/proc/{process_id}/maps'
    try:
        with open(maps_path, 'r') as maps_file:
            for line in maps_file:
                parts = line.strip().split()
                if len(parts) < 5: continue
                
                permission = parts[1]
                if 'r' not in permission: continue
                
                address_range = parts[0]
                start_addr_str, end_addr_str = address_range.split('-')
                start_addr = int(start_addr_str, 16)
                end_addr = int(end_addr_str, 16)
                region_size = end_addr - start_addr
                
                file_name = parts[-1] if len(parts) >= 6 and parts[-1].startswith('/') else "anonymous"

                try:
                    os.lseek(mem_handle, start_addr, os.SEEK_SET)
                    b = os.read(mem_handle, region_size)
                    
                    for base in find_base_address_candidates(b):
                        yield file_name, start_addr + base
                        
                except OSError as e:
                    # ignore
                    continue
                except Exception:
                    continue
    finally:
        os.close(mem_handle)

# --- Hook Class ---

class Hook:
    def read(self, address: Address):
        return self.hooked_platform.read_int(self, address)

    _BIZHAWK_ADDRESS_MAP = {
        "2.9.1": 0x124b30, "2.7": 0x317F80, "2.6.2": 0x30DF80, "2.5.2": 0x310F80,
        "2.4.1": 0x30DF90, "2.3.2": 0x11D880,
    }

    EMULATOR_MAP = {
        "PSXFin": (
            "[Pp][Ss][Xx][Ff][Ii][Nn]",
            [
                HookablePlatform("PSXfin v1.13", True, "1.13", psxfin_address_func)
            ]
        ),
        "BizHawk": (
            "mono", # <---- maybe needs to be changed, depending on how you run bizhawk!
            [
                HookablePlatform("BizHawk Manual", True, "__MANUAL__", manual_address_func)
            ]
        ),
        "Retroarch": (
            "[Rr]etro[Aa]rch",
            [
                HookablePlatform("Retroarch (Manual)", True, "__MANUAL__", manual_address_func),
            ]
        ),
        "DuckStation": (
            "[Dd][Uu][Cc][Kk][Ss][Tt][Aa][Tt][Ii][Oo][Nn]",
            [
                HookablePlatform("DuckStation (Manual)", True, "__MANUAL__", manual_address_func)
            ]
        )
    }

    PC_PLATFORM = HookablePlatform("PC", False, "", pc_address_func)

    def start(self):
        self.thread = threading.Thread(target=self.main)
        self.thread.start()

    def stop(self):
        with self.running_lock:
            self.running = False

    def is_running(self):
        with self.running_lock:
            return self.running

    def read_key(self, key):
        with self.address_state_lock:
            if key not in self.state or key not in self.addresses:
                raise ValueError("Key not present")
            return self.state[key]

    def register_address(self, address, default_value=None):
        with self.address_state_lock:
            new_key = self.next_key
            self.next_key += 1

            self.addresses[new_key] = address
            self.state[new_key] = default_value

            return new_key, self.state[new_key]

    def deregister_address(self, key):
        with self.address_state_lock:
            if key in self.addresses:
                del self.addresses[key]
            if key in self.state:
                del self.state[key]

    def main(self):
        self.base_cache = None

        try:
             read_process_memory(self.hooked_process_id, 0x0, 1) 
        except constants.BadHookException:
             self.parent_app.update_title(self.parent_app.settings.DISCONNECTED_TEXT)
             return

        self.parent_app.update_title(self.parent_app.settings.CONNECTED_TO_TEXT + self.hooked_platform.name)

        with self.running_lock:
            self.running = True

        while self.is_running():
            try:
                with self.address_state_lock:
                    for key in self.addresses:
                        self.state[key] = self.read(self.addresses[key])

            except Exception as e:
                if isinstance(e, constants.BadHookException) or isinstance(e, RuntimeError):
                    self.running = False
                    break
                
                raise e
                
            time.sleep(1 / self.parent_app.settings.UPDATES_PER_SECOND)
        
        try:
            self.hooked_process_id = None
            self.hooked_platform = None
            self.parent_app.update_title(self.parent_app.settings.DISCONNECTED_TEXT)

        except RuntimeError as err:
            print("uh oh", err)

    def __init__(self, parent_app):
        self.parent_app = parent_app
        self.base_cache = None
        self.manual_address = None
        self.thread = threading.Thread(target=self.main)
        self.running = False
        self.running_lock = threading.Lock()

        self.addresses = {}
        self.state = {}
        self.next_key = 0
        self.address_state_lock = threading.Lock()

        self.hooked_platform = None
        self.hooked_process_id = None
        self.hooked_process_handle = None # Not used in Linux, but we'll keep it here