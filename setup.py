from setuptools import setup

setup(
    name="b2chks",
    version="1.0.0",
    description="B2CHKS: High-performance file packaging, chunking, compression, and distribution tool",
    py_modules=["b2chks", "core", "b3chks"],
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "b2chks=b2chks:main",
            "core=b2chks:main",
            "chunkcore=b2chks:main",
            "b3chks=b2chks:main",
        ],
    },
)
