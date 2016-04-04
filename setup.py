from cx_Freeze import setup, Executable
import sys
import requests.certs
base=None
target = Executable(
    script="rknscan.py",
    base=base,
    icon="icon.ico"
    )
build_exe_options = {
    "include_msvcr": True,
    "include_files":[(requests.certs.where(),'cacert.pem')]
    }

setup(
    name = "Rknscan",
    version = "1.7",
    author = "Nechay Anton",
    description = "Rknscan",
    options = {"build_exe": build_exe_options},
    executables = [target]
)
