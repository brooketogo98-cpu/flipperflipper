#!/usr/bin/env python3
"""
Stitch C2 Framework Setup Script
Advanced Command and Control Framework
"""

from setuptools import setup, find_packages
import os

# Read requirements from requirements.txt
def read_requirements():
    with open('requirements.txt', 'r') as f:
        return [line.strip() for line in f if line.strip() and not line.startswith('#')]

# Read README for long description
def read_readme():
    if os.path.exists('README.md'):
        with open('README.md', 'r') as f:
            return f.read()
    return "Advanced Command and Control Framework"

setup(
    name="stitch-c2",
    version="2.0.0",
    author="Stitch Development Team",
    author_email="dev@stitch-c2.com",
    description="Advanced Command and Control Framework with Elite Features",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/oranolio956/flipperflipper",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Topic :: Security",
        "Topic :: System :: Networking",
    ],
    python_requires=">=3.8",
    install_requires=read_requirements(),
    extras_require={
        'dev': [
            'pytest>=7.0.0',
            'pytest-cov>=4.0.0',
            'black>=23.0.0',
            'flake8>=6.0.0',
            'mypy>=1.0.0',
        ],
    },
    entry_points={
        'console_scripts': [
            'stitch-server=main:main',
            'stitch-start=START_SYSTEM:main',
        ],
    },
    include_package_data=True,
    zip_safe=False,
)