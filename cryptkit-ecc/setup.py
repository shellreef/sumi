#! /usr/bin/env python
from distutils.core import setup,Extension
from distutils.sysconfig import get_python_inc

SOURCES = ["src/bigint.c",
			"src/ecc_wrap.c",
			"src/eliptic.c",
			"src/int_functions.c",
			"src/onb_integer.c",
			"src/onb.c",
			"src/protocols1.c",
			"src/sha.c"]

setup(name="ecc",
		version="0.9",
		description="Elliptic Curve Crypto",
		author="Bryan Mongeau",
		author_email="bryan@eevolved.com",
		url="http://cryptkit.sourceforge.net",

		packages = ["ecc"],
		package_dir = { "ecc":"src" },
		ext_modules = [Extension("ellipticc",
						sources=SOURCES,
						include_dirs=[get_python_inc(plat_specific=1)] )]

)
