"""Setup configuration for OpenEASD."""

from setuptools import setup, find_packages
from pathlib import Path

# Read README file
readme_path = Path(__file__).parent / "README.md"
long_description = readme_path.read_text(encoding="utf-8") if readme_path.exists() else ""

# Read requirements
requirements_path = Path(__file__).parent / "requirements.txt"
if requirements_path.exists():
    with open(requirements_path) as f:
        requirements = [
            line.strip() 
            for line in f.readlines() 
            if line.strip() and not line.startswith("#")
        ]
else:
    requirements = []

setup(
    name="openeasd",
    version="1.0.0",
    author="Rathnakara G N",
    author_email="rathnakara@amnic.com",
    description="Automated External Attack Surface Detection for Startups with Lean Security Resources",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/rathnakara/OpenEASD",
    
    # Package configuration
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    
    # Include additional files
    include_package_data=True,
    package_data={
        "": ["*.yaml", "*.yml", "*.json", "*.txt", "*.md"],
    },
    
    # Python version requirement
    python_requires=">=3.11",
    
    # Dependencies
    install_requires=requirements,
    
    # Optional dependencies
    extras_require={
        "dev": [
            "pytest>=7.4.3",
            "pytest-asyncio>=0.21.1",
            "pytest-cov>=4.1.0",
            "pytest-mock>=3.12.0",
            "black>=23.11.0",
            "flake8>=6.1.0",
            "mypy>=1.7.1",
            "isort>=5.12.0",
        ],
        "docker": [
            "docker>=6.1.3",
        ],
        "reporting": [
            "reportlab>=4.0.7",
            "weasyprint>=61.2",
            "pillow>=10.1.0",
        ],
        "monitoring": [
            "prometheus-client>=0.19.0",
            "structlog>=23.2.0",
        ]
    },
    
    # Entry points for CLI
    entry_points={
        "console_scripts": [
            "openeasd=main:main",
            "openeasd-scan=prefect_flows.daily_scan_flow:main",
            "openeasd-weekly=prefect_flows.weekly_scan_flow:main",
        ],
    },
    
    # Classifiers
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Topic :: System :: Monitoring",
        "Topic :: System :: Systems Administration",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
        "Environment :: Console",
        "Framework :: Prefect",
    ],
    
    # Keywords
    keywords=[
        "security", 
        "vulnerability-scanner", 
        "attack-surface", 
        "penetration-testing",
        "cybersecurity", 
        "automation", 
        "prefect", 
        "docker",
        "dns", 
        "ssl", 
        "subdomain-enumeration",
        "port-scanning",
        "mitre-attack"
    ],
    
    # Project URLs
    project_urls={
        "Documentation": "https://github.com/rathnakara/OpenEASD/wiki",
        "Source": "https://github.com/rathnakara/OpenEASD",
        "Tracker": "https://github.com/rathnakara/OpenEASD/issues",
    },
    
    # Zip safe
    zip_safe=False,
)