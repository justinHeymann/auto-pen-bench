from pathlib import Path

from setuptools import find_packages, setup

README = Path(__file__).resolve().parent / 'README.md'

setup(
    name='autopenbench',
    version='0.1',
    description=(
        'Benchmark for Generative Agents in automated penetration testing'
    ),
    long_description=README.read_text(encoding='utf-8') if README.exists() else '',
    long_description_content_type='text/markdown',
    packages=find_packages(),
    # scripts/randomize_flags.py and the test suite use PEP 604 unions
    # (`Path | None`), which need 3.10+.
    python_requires='>=3.10',
    install_requires=[
        'python-dotenv>=1.0.1',
        'paramiko>=3.5.0',
        'termcolor>=2.4.0',
        'chardet>=5.2.0',
        'pydantic>=2.10.0',
        'ipykernel>=6.29.5',
        'pyyaml>=6.0.2',
        'openai>=1.51.0',
        'instructor>=1.15.0',
        'httpx>=0.27.2',
        'mcp>=1.1.0'
    ],
    extras_require={
        'test': ['pytest>=8.0'],
        'lint': ['ruff>=0.6'],
    },
    include_package_data=True,
)
