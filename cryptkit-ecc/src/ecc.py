"""
**Elliptic Curve Class**
"""
#====================================================================
# Elliptic Curve module
#
# Copyright (c) 2001, Bryan Mongeau <bryan@eevolved.com>
# All rights reserved.
#
# This code is hereby placed in the public domain.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1- Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
#
# 2- Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# 3- The names of its contributors may not be used to endorse or promote
#    products derived from this software without specific prior written
#    permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
# EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
# PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
#  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#====================================================================

from elliptic import *

# Initialize global components only once
init()
base=EC_PARAMETER()
makeBaseCurve(base)


class ecc:
	"""
	This is the Elliptic Curve Cryptography base class.
	Used for generating and receiving Diffie-Hellman
	values, along with Nyberg-Rueppel signature and
	verification.

	**Sample usage**::

		>>> from ecc.ecc import ecc
		>>> e,f=ecc(1),ecc(2)
		>>> e_pub_key, f_pub_key = e.publicKey(), f.publicKey()

		>>> # Key Exchange
		>>> secret1 = e.DH_recv(f_pub_key)
		>>> secret2 = f.DH_recv(e_pub_key)
		>>> secret1 == secret2
		1

		>>> # Signing / Verification
		>>> msg = "Hello World!"
		>>> sig = e.sign(msg)
		>>> f.verify(msg,e_pub_key,sig)
		1

		>>> # Tamper with the message
		>>> msg += 'a'
		>>> f.verify(msg,e_pub_key,sig)
		0

	This class implements Public Key algorithms whose security
	draws from the intractability of the Elliptic Curve Discrete
	Logarithm Problem (ECDLP).  This particular implementation
	uses a 113 bit curve of type II with an optimal normal basis
	and the form::

		E: y^2 + xy = x^3 + x^2 + 1

	This module, concepts, and underlying C code relies heavily
	on the work of Michael Rosing, and his book, *Implementing
	Elliptic Curve Cryptography*.
	"""

	# Conservative estimate of max size of a pickled public key
	pubKeySize=50

	def __init__(self,entropy=None,mode='DH'):
		"""
		Constructor. Provide an arbitrary integer of cryptographically
		secure *entropy* to be used in generating a random secret
		key. Examples of good sources include CSPRNGs and /dev/random.
		*mode* determines how the public key is generated. Possible
		values are 'DH' for Diffie-Hellman and 'ECKGP' for the Elliptic
		Curve Key Generation Protocol.  'ECKGP' mode cannot be used
		for any of the Diffie-Hellman routines.
		"""
		self.keypair=None
		if entropy:
			self.makeKeypair(entropy,mode)


	def makeKeypair(self,entropy,mode='DH'):
		"""
		Makes a keypair for use as descibed for the constructor.
		"""
		if type(entropy) == type(1):
			cvar.random_seed = entropy
			self.keypair=EC_KEYPAIR()
			self.mode=mode
			if mode=='DH':
				makeSecretKey(base,self.keypair)
				DH_gen(base,self.keypair)
			elif mode=='ECKGP':
				makeKeypair(base,self.keypair)
			else:
				raise TypeError("mode must be either DH or ECKGP")
		else:
			raise TypeError("entropy must be an integer")


	def publicKey(self):
		"""
		Returns a two element tuple containing the values to be
		exchanged during the Diffie-Hellman Key Agreement protocol or
		used in verification. Essentially this is a small binary
		representation of your public key, which constitutes a
		given point (x,y) on the public curve.
		"""
		if self.keypair:
			return ( field2bin(self.keypair.pblc_key.x),
					field2bin(self.keypair.pblc_key.y) )
		else:
			raise RuntimeError("No keypair has yet been created.")


	def DH_recv(self,inVal):
		"""
		Returns the mutually shared secret when provided with
		*inVal*, the other party's two-element tuple containing
		the binary representation of their public key. The key
		derivation scheme is Diffie-Hellman.
		"""
		if (type(inVal) == type(())) :
			if self.mode == 'DH':
				p=POINT()
				msg=FIELD2N()
				p.x,p.y=bin2field(inVal[0]),bin2field(inVal[1])
				DH_recv(base,self.keypair,p,msg)
				return field2bin(msg)
			else:
				raise RuntimeError("Cannot call DH_recv on a non-DH keypair")
		else:
			raise TypeError("inVal is not a tuple of size 2")


	def sign(self,message):
		"""
		This method will cryptographically sign the string *message*
		to prevent it from being tampered with. Signing scheme
		is Nyberg-Rueppel.  The method returns a two element
		tuple of binary values representing the signature.
		"""
		if (type(message) == type("")) and ( len(message) > 0 ):
			s=SIGNATURE()
			NR_Signature(message,len(message),base,self.keypair.prvt_key,s)
			return ( field2bin(s.c), field2bin(s.d) )
		else:
			raise TypeError("message must be a non-zero length string")


	def verify(self,message,public_key,signature):
		"""
		This method will verify that the string *message* has not been
		tampered with. Returns true or false. *signature* is
		the tuple produced by the original signing of *message*.
		"""
		if (type(message) == type("")) and ( len(message) > 0 ):
			if type(signature) == type(()):
				if type(public_key) == type(()):
					s,p=SIGNATURE(),POINT()
					s.c,s.d=bin2field(signature[0]),bin2field(signature[1])
					p.x,p.y=bin2field(public_key[0]),bin2field(public_key[1])
					return NR_Verify(message,len(message),base,p,s)
				else:
					raise TypeError("public_key is not a tuple")
			else:
				raise TypeError("signature is not a tuple")
		else:
			raise TypeError("message must be a non-zero length string")




