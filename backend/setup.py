"""Setup script for SovaScan backend package."""

import pathlib

from setuptools import find_packages, setup

HERE = pathlib.Path(__file__).parent


def read_requirements() -> list[str]:
    """Read requirements from requirements.txt."""
    req_file = HERE / "requirements.txt"
    if req_file.exists():
        return [
            line.strip()
            for line in req_file.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        ]
    return []


setup(
    name="sovascan",
    version="0.1.0",
    description="SovaScan - Security vulnerability scanner and compliance checker",
    long_description=(HERE / "README.md").read_text(encoding="utf-8")
    if (HERE / "README.md").exists()
    else "",
    long_description_content_type="text/markdown",
    author="SovaScan Contributors",
    license="MIT",
    python_requires=">=3.11",
    packages=find_packages(exclude=["tests", "tests.*"]),
    install_requires=read_requirements(),
    entry_points={
        "console_scripts": [
            "sovascan = sovascan.cli.main:cli",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
    ],
)
