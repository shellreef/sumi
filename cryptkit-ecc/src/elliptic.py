# This file was created automatically by SWIG.
import ellipticc
class FIELD2N:
    def __init__(self,*args):
        self.this = apply(ellipticc.new_FIELD2N,args)
        self.thisown = 1

    def __del__(self,ellipticc=ellipticc):
        if self.thisown == 1 :
            ellipticc.delete_FIELD2N(self)
    __setmethods__ = {
    }
    def __setattr__(self,name,value):
        if (name == "this") or (name == "thisown"): self.__dict__[name] = value; return
        method = FIELD2N.__setmethods__.get(name,None)
        if method: return method(self,value)
        self.__dict__[name] = value
    __getmethods__ = {
        "e" : ellipticc.FIELD2N_e_get,
    }
    def __getattr__(self,name):
        method = FIELD2N.__getmethods__.get(name,None)
        if method: return method(self)
        raise AttributeError,name
    def __repr__(self):
        return "<C FIELD2N instance at %s>" % (self.this,)
class FIELD2NPtr(FIELD2N):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = FIELD2N



class EC_PARAMETER:
    def __init__(self,*args):
        self.this = apply(ellipticc.new_EC_PARAMETER,args)
        self.thisown = 1

    def __del__(self,ellipticc=ellipticc):
        if self.thisown == 1 :
            ellipticc.delete_EC_PARAMETER(self)
    __setmethods__ = {
        "crv" : ellipticc.EC_PARAMETER_crv_set,
        "pnt" : ellipticc.EC_PARAMETER_pnt_set,
        "pnt_order" : ellipticc.EC_PARAMETER_pnt_order_set,
        "cofactor" : ellipticc.EC_PARAMETER_cofactor_set,
    }
    def __setattr__(self,name,value):
        if (name == "this") or (name == "thisown"): self.__dict__[name] = value; return
        method = EC_PARAMETER.__setmethods__.get(name,None)
        if method: return method(self,value)
        self.__dict__[name] = value
    __getmethods__ = {
        "crv" : ellipticc.EC_PARAMETER_crv_get,
        "pnt" : lambda x : POINTPtr(ellipticc.EC_PARAMETER_pnt_get(x)),
        "pnt_order" : lambda x : FIELD2NPtr(ellipticc.EC_PARAMETER_pnt_order_get(x)),
        "cofactor" : lambda x : FIELD2NPtr(ellipticc.EC_PARAMETER_cofactor_get(x)),
    }
    def __getattr__(self,name):
        method = EC_PARAMETER.__getmethods__.get(name,None)
        if method: return method(self)
        raise AttributeError,name
    def __repr__(self):
        return "<C EC_PARAMETER instance at %s>" % (self.this,)
class EC_PARAMETERPtr(EC_PARAMETER):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = EC_PARAMETER



class EC_KEYPAIR:
    def __init__(self,*args):
        self.this = apply(ellipticc.new_EC_KEYPAIR,args)
        self.thisown = 1

    def __del__(self,ellipticc=ellipticc):
        if self.thisown == 1 :
            ellipticc.delete_EC_KEYPAIR(self)
    __setmethods__ = {
        "prvt_key" : ellipticc.EC_KEYPAIR_prvt_key_set,
        "pblc_key" : ellipticc.EC_KEYPAIR_pblc_key_set,
    }
    def __setattr__(self,name,value):
        if (name == "this") or (name == "thisown"): self.__dict__[name] = value; return
        method = EC_KEYPAIR.__setmethods__.get(name,None)
        if method: return method(self,value)
        self.__dict__[name] = value
    __getmethods__ = {
        "prvt_key" : lambda x : FIELD2NPtr(ellipticc.EC_KEYPAIR_prvt_key_get(x)),
        "pblc_key" : lambda x : POINTPtr(ellipticc.EC_KEYPAIR_pblc_key_get(x)),
    }
    def __getattr__(self,name):
        method = EC_KEYPAIR.__getmethods__.get(name,None)
        if method: return method(self)
        raise AttributeError,name
    def __repr__(self):
        return "<C EC_KEYPAIR instance at %s>" % (self.this,)
class EC_KEYPAIRPtr(EC_KEYPAIR):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = EC_KEYPAIR



class SIGNATURE:
    def __init__(self,*args):
        self.this = apply(ellipticc.new_SIGNATURE,args)
        self.thisown = 1

    def __del__(self,ellipticc=ellipticc):
        if self.thisown == 1 :
            ellipticc.delete_SIGNATURE(self)
    __setmethods__ = {
        "c" : ellipticc.SIGNATURE_c_set,
        "d" : ellipticc.SIGNATURE_d_set,
    }
    def __setattr__(self,name,value):
        if (name == "this") or (name == "thisown"): self.__dict__[name] = value; return
        method = SIGNATURE.__setmethods__.get(name,None)
        if method: return method(self,value)
        self.__dict__[name] = value
    __getmethods__ = {
        "c" : lambda x : FIELD2NPtr(ellipticc.SIGNATURE_c_get(x)),
        "d" : lambda x : FIELD2NPtr(ellipticc.SIGNATURE_d_get(x)),
    }
    def __getattr__(self,name):
        method = SIGNATURE.__getmethods__.get(name,None)
        if method: return method(self)
        raise AttributeError,name
    def __repr__(self):
        return "<C SIGNATURE instance at %s>" % (self.this,)
class SIGNATUREPtr(SIGNATURE):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = SIGNATURE



class POINT:
    def __init__(self,*args):
        self.this = apply(ellipticc.new_POINT,args)
        self.thisown = 1

    def __del__(self,ellipticc=ellipticc):
        if self.thisown == 1 :
            ellipticc.delete_POINT(self)
    __setmethods__ = {
        "x" : ellipticc.POINT_x_set,
        "y" : ellipticc.POINT_y_set,
    }
    def __setattr__(self,name,value):
        if (name == "this") or (name == "thisown"): self.__dict__[name] = value; return
        method = POINT.__setmethods__.get(name,None)
        if method: return method(self,value)
        self.__dict__[name] = value
    __getmethods__ = {
        "x" : lambda x : FIELD2NPtr(ellipticc.POINT_x_get(x)),
        "y" : lambda x : FIELD2NPtr(ellipticc.POINT_y_get(x)),
    }
    def __getattr__(self,name):
        method = POINT.__getmethods__.get(name,None)
        if method: return method(self)
        raise AttributeError,name
    def __repr__(self):
        return "<C POINT instance at %s>" % (self.this,)
class POINTPtr(POINT):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = POINT



class safeString:
    def __init__(self,this):
        self.this = this

    __setmethods__ = {
        "sz" : ellipticc.safeString_sz_set,
        "bytes" : ellipticc.safeString_bytes_set,
    }
    def __setattr__(self,name,value):
        if (name == "this") or (name == "thisown"): self.__dict__[name] = value; return
        method = safeString.__setmethods__.get(name,None)
        if method: return method(self,value)
        self.__dict__[name] = value
    __getmethods__ = {
        "sz" : ellipticc.safeString_sz_get,
        "bytes" : ellipticc.safeString_bytes_get,
    }
    def __getattr__(self,name):
        method = safeString.__getmethods__.get(name,None)
        if method: return method(self)
        raise AttributeError,name
    def __repr__(self):
        return "<C safeString instance at %s>" % (self.this,)
class safeStringPtr(safeString):
    def __init__(self,this):
        self.this = this
        self.thisown = 0
        self.__class__ = safeString





#-------------- FUNCTION WRAPPERS ------------------

ptrvalue = ellipticc.ptrvalue

ptrset = ellipticc.ptrset

ptrcreate = ellipticc.ptrcreate

ptrfree = ellipticc.ptrfree

ptradd = ellipticc.ptradd

makeSecretKey = ellipticc.makeSecretKey

makeKeypair = ellipticc.makeKeypair

makeBaseCurve = ellipticc.makeBaseCurve

init = ellipticc.init

def field2bin(*args, **kwargs):
    val = apply(ellipticc.field2bin,args,kwargs)
    return val

def bin2field(*args, **kwargs):
    val = apply(ellipticc.bin2field,args,kwargs)
    if val: val = FIELD2NPtr(val)
    return val

DH_gen = ellipticc.DH_gen

DH_recv = ellipticc.DH_recv

NR_Signature = ellipticc.NR_Signature

NR_Verify = ellipticc.NR_Verify



#-------------- VARIABLE WRAPPERS ------------------

cvar = ellipticc.cvar
