from setuptools import setup, Extension
from Cython.Build import cythonize

ext_modules = [
    Extension(
        "syscalls",
        ["syscalls.pyx"],
        libraries=["crypt32"],   
    )
]

setup(
    name="syscalls",
    ext_modules=cythonize(
        ext_modules,
        compiler_directives={"language_level": "3"}
    ),
)
