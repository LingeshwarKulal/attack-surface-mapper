"""
Setup configuration for the Attack Surface Reconnaissance tool.
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README for long description
try:
    this_directory = Path(__file__).parent
    long_description = (this_directory / "README.md").read_text(encoding='utf-8')
except:
    long_description = "Google-Powered Attack Surface Reconnaissance & GitHub Leak Correlator"

setup(
    name='google-powered-attack-surface-recon',
    version='1.0.0',
    author='Security Research Team',
    author_email='security@example.com',
    description='A security intelligence platform for attack surface reconnaissance and GitHub leak correlation.',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/yourusername/google-powered-attack-surface-recon',
    packages=find_packages(where='src'),
    package_dir={'': 'src'},
    install_requires=[
        'requests>=2.31.0',
        'aiohttp>=3.9.0',
        'python-dotenv>=1.0.0',
        'pydantic>=2.5.0',
    ],
    extras_require={
        'dev': [
            'pytest>=7.4.0',
            'pytest-asyncio>=0.21.0',
            'pytest-cov>=4.1.0',
            'black>=23.0.0',
            'flake8>=6.1.0',
            'mypy>=1.7.0',
        ],
        'reports': [
            'jinja2>=3.1.2',
        ],
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Information Technology',
        'Topic :: Security',
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
    ],
    python_requires='>=3.8',
    entry_points={
        'console_scripts': [
            'attack-surface-recon=src.main:main',
        ],
    },
)