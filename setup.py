#!/usr/bin/env python3

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

with open("requirements.txt") as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith("#")]

setup(
    name="cypherx",
    version="1.0.0",
    author="CypherX",
    description="Cyber Intelligence Suite — OSINT, Recon, Scanner, Vuln, Forensics",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/sarkashi/cypherx",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "cypherx=cypherx:cli",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: System :: Networking",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
    ],
    keywords="osint recon security pentest cybersecurity forensics scanner",
)
