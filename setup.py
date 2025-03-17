from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = fh.read().splitlines()

setup(
    name="mitre_sig_converter",
    version="0.1.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="Convert MITRE ATT&CK techniques to common signature formats",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/mitre-sig-converter",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.7",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "mitre-sig-converter=mitre_sig_converter.__main__:main",
        ],
    },
    include_package_data=True,
)
