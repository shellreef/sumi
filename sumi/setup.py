# Setup SUMI using distutils
# $Id$

# 20040712 notes: USAGE: python setup.py py2exe (run on a Windows machine)

# If you get "error: Permission denied", stop editing the Python in vi

# the exe will be in dist, named sumiserv.exe, sumiget.exe, sumigetw.exe
# any errors will be saved in dist/*.log

# UPDATE 20040719(pm):
#  If wxObjectPtr is not found, delete the "build" directory.

from distutils.core import setup
import py2exe
import glob
import os
import compileall
import py_compile

def without_hidden(dir_name):
    """List a directory without hidden directories (most importantly .svn)."""
    a = os.listdir(dir_name)
    b = []
    for x in a:
        if not x.startswith("."): 
            b.append(dir_name + os.path.sep + x)
    return b

if not compileall.compile_dir("transport"):
    print "Compiling transports failed!"
    raise SystemExit

py_compile.compile("socks5.py", doraise=True)

opts = {"py2exe": #{}
# While it may seem like a good idea to include these WinPcap DLLs, it is not.
# Instead, let the user install (the correct version) of WinPcap for their OS
# and use those DLLs. (XP version of WinPcap depends on mfc42u.dll, Me version
# doesn't--and cannot use Unicode versions of MFC, resulting in cryptic error
# about one of the DLLs missing when importing pcapy.)
    {"dll_excludes": 
        ["NPPTools.dll", "packet.dll", "wpcap.dll", "WanPacket.dll"],
        # "The application has failed to start because wpcap.dll could
        # not be found"
        # So much for *dynamic* DLLs; having pcapy requires wpcap even if
        # pcapy isn't imported or used yet. Excluding it doesn't help
      #"excludes": ["pcapy"],
    "compressed": 1,
    },
}

setup(options=opts, console=["sumiget.py"])
setup(options=opts, windows=[
	{"script": "sumigetw.py",
	"icon_resources": [(1, "sumi.ico")]}  # Icon from Keith Oakley 2004-08-11
	], data_files=[
	("transport", glob.glob("transport/*.pyc")),
    ("client-side", without_hidden("client-side")),
    (".", ["socks5.pyc", "SUMI Home.url", "LICENSE", "share/lptest",
        "rawproxd"]),
    # Don't include docs; on Wiki now  (todo: convert from wiki)
    #("doc", without_hidden("doc")),
	(".", ["sumi.ico"])])
setup(options=opts, console=["sumiserv.py"])

# Now package using NSIS installer
os.startfile("sumi.nsi")
