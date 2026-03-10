"""
SentinelX – Setup Configuration
"""

from setuptools import setup, find_packages

setup(
    name="sentinelx",
    version="1.0.0",
    description="SentinelX – Windows Defensive Cybersecurity Monitoring Suite",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    author="SentinelX Team",
    url="https://github.com/sentinelx/sentinelx",
    license="Proprietary",
    packages=find_packages(),
    python_requires=">=3.11",
    install_requires=[
        "PySide6>=6.6.0",
        "scapy>=2.5.0",
        "psutil>=5.9.0",
        "pywin32>=306",
        "watchdog>=3.0.0",
        "SQLAlchemy>=2.0.0",
        "bcrypt>=4.1.0",
        "cryptography>=41.0.0",
        "matplotlib>=3.8.0",
        "reportlab>=4.0.0",
    ],
    entry_points={
        "console_scripts": [
            "sentinelx=sentinelx.main:main",
            "sentinelx-service=sentinelx.service:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Win32 (MS Windows)",
        "Intended Audience :: System Administrators",
        "Operating System :: Microsoft :: Windows",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
    ],
)
