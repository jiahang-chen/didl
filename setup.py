from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="didl",
    version="0.0.1",
    author="Jiahang Chen",  # Please change this
    author_email="your.email@example.com",  # Please change this
    description="A Python library for DIDL and Linked Data Proofs.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/didl",  # Please change this
    packages=find_packages(),
    install_requires=[
        "requests",
        "pydantic",
        "cryptography",
        "python-jose",
        "pyld",
        "base58",
        "ecdsa",
        "rsa",
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",  # Or choose another license
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.9',
)
