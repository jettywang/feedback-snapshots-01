from __future__ import annotations
import json, sys, types

EVENTS=[]
def rec(kind, **kw): EVENTS.append({"kind":kind, **kw})

def mod(name, **attrs):
    m=types.ModuleType(name)
    for k,v in attrs.items(): setattr(m,k,v)
    sys.modules[name]=m
    return m

# ---- azure.core.exceptions
core=mod("azure.core"); core.__path__=[]
core_exc=mod("azure.core.exceptions")
class ResourceExistsError(Exception): pass
class AzureError(Exception): pass
core_exc.ResourceExistsError=ResourceExistsError
core_exc.AzureError=AzureError
core.exceptions=core_exc
sys.modules["azure"]=mod("azure"); sys.modules["azure"].__path__=[]
sys.modules["azure"].core=core
sys.modules["azure.core"]=core

# ---- azure.identity
identity=mod("azure.identity")
class _Cred:
    kind="credential"
    def __init__(self,*args,**kwargs):
        self.args=args; self.kwargs=kwargs
        rec("credential", cls=type(self).__name__, args=args, kwargs=kwargs)
    def get_token(self,*scopes,**kw):
        rec("get_token", cls=type(self).__name__, scopes=scopes)
        return {"token":"opaque"}
class DefaultAzureCredential(_Cred):
    pass
class ManagedIdentityCredential(_Cred):
    pass
identity.DefaultAzureCredential=DefaultAzureCredential
identity.ManagedIdentityCredential=ManagedIdentityCredential
sys.modules["azure.identity"]=identity

# ---- azure.servicebus
servicebus=mod("azure.servicebus")
servicebus.__path__=[]
class ServiceBusMessage:
    def __init__(self, body): self.body=body
class ServiceBusReceiveMode:
    PEEK_LOCK="peek_lock"; RECEIVE_AND_DELETE="receive_and_delete"
class ServiceBusClient:
    def __init__(self, namespace, credential, **kw):
        rec("ServiceBusClient", namespace=namespace, credential=type(credential).__name__ if not isinstance(credential,str) else credential, kwargs=kw)
        self.namespace=namespace; self.credential=credential
    @classmethod
    def from_connection_string(cls, cs, **kw):
        rec("ServiceBusClient.from_connection_string", connection_string=cs, kwargs=kw)
        return cls("from-cs", None)
    def get_queue_sender(self,*a,**k): return types.SimpleNamespace(send_messages=lambda m: None)
    def get_queue_receiver(self,*a,**k): return types.SimpleNamespace(receive_messages=lambda **kw: [])
class ServiceBusReceiver: pass
class ServiceBusSender: pass
class AutoLockRenewer: pass
servicebus.ServiceBusClient=ServiceBusClient
servicebus.ServiceBusMessage=ServiceBusMessage
servicebus.ServiceBusReceiveMode=ServiceBusReceiveMode
servicebus.ServiceBusReceiver=ServiceBusReceiver
servicebus.ServiceBusSender=ServiceBusSender
servicebus.AutoLockRenewer=AutoLockRenewer
sys.modules["azure.servicebus"]=servicebus

sb_exc=mod("azure.servicebus.exceptions")
class OperationTimeoutError(Exception): pass
class ServiceBusCommunicationError(Exception): pass
class ServiceBusConnectionError(Exception): pass
class ServiceBusServerBusyError(Exception): pass
class MessageAlreadySettled(Exception): pass
class MessageLockLostError(Exception): pass
for n in ("OperationTimeoutError","ServiceBusCommunicationError","ServiceBusConnectionError",
          "ServiceBusServerBusyError","MessageAlreadySettled","MessageLockLostError"):
    setattr(sb_exc,n,locals()[n])
servicebus.exceptions=sb_exc

pyamqp=mod("azure.servicebus._pyamqp"); pyamqp.__path__=[]
pyamqp_err=mod("azure.servicebus._pyamqp.error")
class AMQPConnectionError(Exception): pass
class AMQPLinkError(Exception): pass
class AMQPSessionError(Exception): pass
pyamqp_err.AMQPConnectionError=AMQPConnectionError
pyamqp_err.AMQPLinkError=AMQPLinkError
pyamqp_err.AMQPSessionError=AMQPSessionError

mgmt=mod("azure.servicebus.management")
class ServiceBusAdministrationClient:
    def __init__(self, namespace, credential):
        rec("ServiceBusAdministrationClient", namespace=namespace,
            credential=type(credential).__name__ if not isinstance(credential,str) else credential)
    @classmethod
    def from_connection_string(cls, cs): 
        rec("ServiceBusAdministrationClient.from_connection_string", connection_string=cs)
        return cls("from-cs", None)
    def create_queue(self,**kw): pass
mgmt.ServiceBusAdministrationClient=ServiceBusAdministrationClient
servicebus.management=mgmt

# ---- isodate
isodate=mod("isodate")
class Duration:
    def __init__(self, seconds=0): self.seconds=seconds
isodate.Duration=Duration
isodate.duration_isoformat=lambda d: f"PT{d.seconds}S"

# ---- azure.storage.queue
storage=mod("azure.storage"); storage.__path__=[]
sq=mod("azure.storage.queue")
class QueueServiceClient:
    def __init__(self, account_url=None, credential=None, **kw):
        rec("QueueServiceClient", account_url=account_url,
            credential=type(credential).__name__ if not isinstance(credential,(str,dict)) else credential,
            kwargs=kw)
        self.account_url=account_url; self.credential=credential
    def list_queues(self): return []
    def get_queue_client(self, queue=None): return types.SimpleNamespace()
    def create_queue(self, queue): return types.SimpleNamespace(get_queue_properties=lambda: None)
sq.QueueServiceClient=QueueServiceClient
storage.queue=sq
sys.modules["azure.storage"]=storage
sys.modules["azure.storage.queue"]=sq

# ---- real kombu
from kombu import Connection
from kombu.transport import azureservicebus as ASB
from kombu.transport import azurestoragequeues as ASQ

def dump(t):
    print(f"\n=== {t} ===")
    for e in EVENTS: print(json.dumps(e, default=str, sort_keys=True))
    EVENTS.clear()

def credinfo(cred):
    if isinstance(cred,str): return {"credential":"sas/policy-string"}
    return {"credential":type(cred).__name__, "args":getattr(cred,"args",None),
            "kwargs":getattr(cred,"kwargs",None)}

for label, url in [
    ("ServiceBus managed identity", "azureservicebus://ManagedIdentityCredential@alerts-sb"),
    ("ServiceBus default chain", "azureservicebus://DefaultAzureCredential@alerts-sb"),
    ("ServiceBus SAS policy", "azureservicebus://alerts-policy:abc/def=@alerts-sb"),
]:
    conn=Connection(url, transport=ASB.Transport)
    ch=conn.channel()
    print("\n##",label,"| uri:",conn.as_uri(),"| credential:",credinfo(ch._credential))
    _=ch.queue_service
    _=ch.queue_mgmt_service
    dump(label)

for label, url in [
    ("Storage managed identity", "azurestoragequeues://ManagedIdentityCredential@https://alerts.queue.core.windows.net/"),
    ("Storage default chain", "azurestoragequeues://DefaultAzureCredential@https://alerts.queue.core.windows.net/"),
    ("Storage SAS", "azurestoragequeues://sas/token%3D@https://alerts.queue.core.windows.net/"),
]:
    conn=Connection(url, transport=ASQ.Transport)
    ch=conn.channel()
    print("\n##",label,"| uri:",conn.as_uri(),"| credential:",credinfo(ch._credential))
    _=ch.queue_service
    dump(label)

# GCP: no runtime SDK; show what the transport passes to the SDK constructors from source surface
