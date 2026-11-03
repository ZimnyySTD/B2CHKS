from setuptools import setup, find_packages

setup(
    name="b2chks",
    version="1.0.0",
    description="B2CHKS: High-performance file packaging, chunking, compression, and secure distribution protocol",
    packages=find_packages(),
    py_modules=["b2chks", "core", "b3chks"],
    python_requires=">=3.8",
    extras_require={
        "fast": ["cryptography", "zstandard"],
    },
    entry_points={
        "console_scripts": [
            "b2chks=cli.main:main",
            "core=cli.main:main",
            "chunkcore=cli.main:main",
            "b3chks=cli.main:main",
        ],
    },
)
