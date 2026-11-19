import runpy, sys, types
# reuse the stub setup from redis_probe.py up to the kombu imports
src = open('/tmp/claude-501/redis_probe.py').read()
cut = src.index('from kombu import Connection as KConnection')
exec(compile(src[:cut], 'stubs', 'exec'), {'__name__': '__main__'})
sys.argv = ['x']

from kombu.transport import redis as rt

class Dummy:
    """Only what _connparams() touches before _process_credential_provider."""
    _process_credential_provider = rt.Channel._process_credential_provider
    _prepare_virtual_host = rt.Channel._prepare_virtual_host
    connection = None
    max_connections = 10
    socket_timeout = None
    socket_connect_timeout = None
    socket_keepalive = False
    socket_keepalive_options = None
    health_check_interval = 25
    retry_on_timeout = False
    client_name = None
    connection_class = rt.redis.Connection
    connection_class_ssl = rt.redis.SSLConnection

class ConnInfo:
    def __init__(self, **kw): self.__dict__.update(kw)

def params_for(transport_options, credential_provider=None, hostname="localhost", userid=None, password=None, query=None):
    d = Dummy()
    d.connection = types.SimpleNamespace(
        client=ConnInfo(hostname=hostname, port=None, virtual_host=0,
                        userid=userid, password=password,
                        transport_options=transport_options,
                        credential_provider=credential_provider,
                        ssl=None),
        default_port=6379,
    )
    return rt.Channel._connparams(d)

provider = rt.CredentialProvider()

print("1) transport_options={'credential_provider': provider}  (broker_transport_options style)")
p = params_for({"credential_provider": provider})
print("   credential_provider in connparams:", "credential_provider" in p,
      "| username/password still present:", "username" in p, "password" in p)

print("2) Connection(..., credential_provider=provider)")
p = params_for({}, credential_provider=provider)
print("   credential_provider in connparams:", "credential_provider" in p,
      "| username/password dropped:", "username" not in p, "password" not in p)

print("3) URL query credential_provider")
p = params_for({}, hostname="redis://foo:bar@localhost:6379/0",
               query=None)
print("   (URL query is parsed inside _connparams only when hostname has '://'; see source line 2120)")
print("   with plain hostname, credential_provider in connparams:", "credential_provider" in p)

print("4) plain URL userinfo, no provider")
p = params_for({}, hostname="redis://foo:bar@localhost:6379/0")
print("   username/password from URL:", p.get("username"), p.get("password"),
      "| provider present:", "credential_provider" in p)

print("5) URL query credential_provider, what Connection keeps")
_c = KConnection("redis://foo:bar@localhost:6379/0?credential_provider=builtins.object",
                 transport=rt.Transport)
print("   hostname:", _c.hostname, "| credential_provider:", _c.credential_provider,
      "| userid/password:", _c.userid, _c.password)
print("   -> Connection exports the query value as a kwarg, so it arrives via path 2")

print("6) provider class that is not a redis.CredentialProvider")
try:
    params_for({}, credential_provider="builtins.object")
except ValueError as exc:
    print("   raises ValueError as expected:", exc)
