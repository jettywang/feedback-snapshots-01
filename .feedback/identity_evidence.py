from __future__ import annotations

import datetime
import json
import sys
import types

EVENTS = []

def rec(kind, **kw):
    EVENTS.append({"call": kind, **kw})

# ---------------------------------------------------------------- stub botocore
botocore = types.ModuleType("botocore")
client_mod = types.ModuleType("botocore.client")

class BaseClient: pass

class Config:
    def __init__(self, **kw): self.kw = dict(kw)
    def merge(self, other):
        merged = Config(**self.kw)
        merged.kw.update(getattr(other, "kw", {}) or {})
        return merged

client_mod.BaseClient = BaseClient
client_mod.Config = Config
botocore.client = client_mod

exc_mod = types.ModuleType("botocore.exceptions")
class BotoCoreError(Exception): pass
class ClientError(Exception): pass
class EndpointConnectionError(BotoCoreError):
    def __init__(self, endpoint_url=""):
        self.endpoint_url = endpoint_url
        super().__init__(f"Could not connect to the endpoint URL: {endpoint_url}")
class ConnectTimeoutError(BotoCoreError): pass
class ReadTimeoutError(BotoCoreError): pass
for _name in ("BotoCoreError", "ClientError", "EndpointConnectionError",
              "ConnectTimeoutError", "ReadTimeoutError"):
    setattr(exc_mod, _name, locals()[_name])
botocore.exceptions = exc_mod

serialize_mod = types.ModuleType("botocore.serialize")
class Serializer: DEFAULT_METHOD = "POST"
serialize_mod.Serializer = Serializer
botocore.serialize = serialize_mod

awsrequest_mod = types.ModuleType("botocore.awsrequest")
class AWSRequest:
    def __init__(self, *a, **k): pass
    def prepare(self): return self
awsrequest_mod.AWSRequest = AWSRequest
botocore.awsrequest = awsrequest_mod

httpsession_mod = types.ModuleType("botocore.httpsession")
httpsession_mod.get_cert_path = lambda *a, **k: None
botocore.httpsession = httpsession_mod

response_mod = types.ModuleType("botocore.response")
response_mod.get_response = lambda *a, **k: (None, {})
botocore.response = response_mod

sys.modules.update({
    "botocore": botocore,
    "botocore.client": client_mod,
    "botocore.exceptions": exc_mod,
    "botocore.serialize": serialize_mod,
    "botocore.awsrequest": awsrequest_mod,
    "botocore.httpsession": httpsession_mod,
    "botocore.response": response_mod,
})

# ---------------------------------------------------------------- stub boto3
DEFAULT_CHAIN = {
    "access_key": "ASIA_DEFAULT_CHAIN",
    "secret": "default-chain-secret",
    "token": "default-chain-token",
    "name": "env/shared-config/container/metadata chain",
}

boto3_mod = types.ModuleType("boto3")

class FakeMeta:
    def __init__(self, region): self.region_name = region

class FakeClient(BaseClient):
    def __init__(self, service, region, key, secret, token, endpoint, source):
        self.service = service
        self.meta = FakeMeta(region)
        self.identity = {
            "service": service,
            "region": region,
            "endpoint": endpoint,
            "access_key": key,
            "session_token": token,
            "secret": secret,
            "credential_source": source,
        }

    def _record(self, op, **kw):
        rec("api", operation=f"{self.service}.{op}", **self.identity)

    @property
    def _request_signer(self):
        """Minimal stand-in for the botocore signer used by _new_release_client()."""
        identity = self.identity
        class _Frozen:
            access_key = identity["access_key"]
            secret_key = identity["secret"]
            token = identity["session_token"]
        class _Credentials:
            def get_frozen_credentials(self):
                return _Frozen()
        return types.SimpleNamespace(_credentials=_Credentials())

    def list_queues(self, QueueNamePrefix=None, **kw):
        self._record("ListQueues")
        if self.identity["endpoint"] and "host1" in self.identity["endpoint"]:
            raise EndpointConnectionError(self.identity["endpoint"])
        return {"QueueUrls": []}
    def create_queue(self, **kw):
        self._record("CreateQueue"); return {"QueueUrl": "https://sqs.example/1/q"}
    def send_message(self, **kw):
        self._record("SendMessage"); return {"MessageId": "m"}
    def receive_message(self, **kw):
        self._record("ReceiveMessage"); return {}
    def delete_message(self, **kw):
        self._record("DeleteMessage"); return {}
    def get_queue_attributes(self, **kw):
        self._record("GetQueueAttributes")
        return {"Attributes": {"ApproximateNumberOfMessages": "0",
                               "QueueArn": "arn:aws:sqs:us-east-1:1:q"},
                "ResponseMetadata": {"HTTPStatusCode": 200}}
    def change_message_visibility(self, **kw):
        self._record("ChangeMessageVisibility"); return {}
    def purge_queue(self, **kw):
        self._record("PurgeQueue"); return {}
    def get_queue_url(self, QueueName=None, **kw):
        self._record("GetQueueUrl"); return {"QueueUrl": "https://sqs.example/1/q"}
    def set_queue_attributes(self, **kw):
        self._record("SetQueueAttributes"); return {}
    def publish(self, **kw):
        self._record("Publish"); return {"ResponseMetadata": {"HTTPStatusCode": 200}}
    def create_topic(self, **kw):
        self._record("CreateTopic")
        return {"TopicArn": "arn:aws:sns:us-east-1:1:t",
                "ResponseMetadata": {"HTTPStatusCode": 200}}
    def subscribe(self, **kw):
        self._record("Subscribe")
        return {"SubscriptionArn": "arn:aws:sns:us-east-1:1:t:s",
                "ResponseMetadata": {"HTTPStatusCode": 200}}
    def get_paginator(self, *a, **k):
        self._record("GetPaginator")
        return types.SimpleNamespace(paginate=lambda **kw: [])

class FakeSession:
    def __init__(self, region_name=None, aws_access_key_id=None,
                 aws_secret_access_key=None, aws_session_token=None):
        self.region_name = region_name or "us-east-1"
        self.explicit = aws_access_key_id is not None
        self.key = aws_access_key_id
        self.secret = aws_secret_access_key
        self.token = aws_session_token
        rec("session", region=region_name, explicit_access_key=aws_access_key_id)
    def client(self, service, config=None, **kw):
        if self.explicit:
            key, secret, token = self.key, self.secret, self.token
            source = "explicit key in URL/queue dict"
        else:
            key = DEFAULT_CHAIN["access_key"]
            secret = DEFAULT_CHAIN["secret"]
            token = DEFAULT_CHAIN["token"]
            source = DEFAULT_CHAIN["name"]
        endpoint = kw.get("endpoint_url")
        rec("client", service=service, credential_source=source,
            access_key=key, secret=secret, session_token=token,
            endpoint=endpoint)
        return FakeClient(service, self.region_name, key, secret, token,
                          endpoint, source)

class FakeSts:
    def assume_role(self, RoleArn, RoleSessionName, DurationSeconds, **kw):
        rec("sts.AssumeRole", RoleArn=RoleArn, RoleSessionName=RoleSessionName,
            DurationSeconds=DurationSeconds)
        return {"Credentials": {
            "AccessKeyId": "ASIA_STS_SESSION",
            "SecretAccessKey": "sts-secret",
            "SessionToken": "sts-token",
            "Expiration": datetime.datetime.now(datetime.timezone.utc)
                          + datetime.timedelta(seconds=DurationSeconds)}}

boto3_mod.Session = FakeSession
def _boto3_client(service, **kw):
    rec("boto3.client", service=service, arguments=kw)
    if service == "sts":
        return FakeSts()
    return FakeClient(service, "us-east-1", "BOTO3_CLIENT", "x", None,
                      kw.get("endpoint_url"), "boto3.client")
boto3_mod.client = _boto3_client
sys.modules["boto3"] = boto3_mod

# ---------------------------------------------------------------- real kombu
from kombu import Connection, Exchange  # noqa: E402
from kombu import pools  # noqa: E402
from kombu.transport import SQS  # noqa: E402

PRE = {
    "q-exp": {
        "url": "https://sqs.us-east-1.amazonaws.com/111122223333/q-exp",
        "access_key_id": "EXPLICIT_QUEUE_KEY",
        "secret_access_key": "explicit-queue-secret",
    },
    "q-url": {
        "url": "https://sqs.us-east-1.amazonaws.com/111122223333/q-url",
    },
}

def show(title):
    print(f"\n--- {title}")
    for event in EVENTS:
        print(json.dumps(event, default=str, sort_keys=True))
    EVENTS.clear()

def who(client):
    return json.dumps(client.identity, sort_keys=True)

print("=" * 78)
print("A. FIRST CONNECT")
print("=" * 78)

# A1: URL userinfo
print("\n[A1] sqs://URL_KEY:URL_SECRET@  (no predefined queues)")
conn = Connection("sqs://URL_KEY:URL_SECRET@", transport=SQS.Transport)
ch = conn.channel()
print("client seen by transport:", who(ch.sqs()))
show("A1 first connect")

# A2: no userinfo
print("\n[A2] sqs://  (no userinfo, no predefined queues)")
conn = Connection("sqs://", transport=SQS.Transport)
ch = conn.channel()
print("client seen by transport:", who(ch.sqs()))
show("A2 first connect")

# A3: predefined queue, only URL creds; connect() should make no AWS call
print("\n[A3] predefined queue without keys; URL has no userinfo")
conn = Connection("sqs://", transport=SQS.Transport,
                  transport_options={"predefined_queues": PRE})
conn.connect()
print("events after connect():", EVENTS)
ch = conn.channel()
print("events after channel():", EVENTS)
print("q-exp client:", who(ch.sqs(queue="q-exp")))
print("q-url client:", who(ch.sqs(queue="q-url")))
show("A3 first connect / first queue call")

# A4: partial pair: key from queue, secret from URL
print("\n[A4] queue provides access_key_id only; URL provides password")
conn = Connection("sqs://URL_KEY:URL_SECRET@", transport=SQS.Transport,
                  transport_options={"predefined_queues": {
                      "q-half": {"url": "https://sqs.us-east-1.amazonaws.com/1/q-half",
                                 "access_key_id": "QUEUE_KEY"}}})
ch = conn.channel()
print("q-half client:", who(ch.sqs(queue="q-half")))
show("A4 field-by-field fallback")

print("\n" + "=" * 78)
print("B. POOL REUSE")
print("=" * 78)

print("\n[B1] one ConnectionPool(limit=1), two acquires")
conn = Connection("sqs://", transport=SQS.Transport,
                  transport_options={"predefined_queues": {"q-exp": PRE["q-exp"]}})
pool = conn.Pool(limit=1)
with pool.acquire() as c1:
    ch1 = c1.channel(); cli1 = ch1.sqs(queue="q-exp")
    ids1 = (id(c1), id(c1.transport), id(cli1))
with pool.acquire() as c2:
    ch2 = c2.channel(); cli2 = ch2.sqs(queue="q-exp")
    ids2 = (id(c2), id(c2.transport), id(cli2))
print("acquire#1 ids (connection, transport, client):", ids1)
print("acquire#2 ids (connection, transport, client):", ids2)
print("same connection:", c1 is c2, "same transport:", c1.transport is c2.transport,
      "same channel:", ch1 is ch2, "same client:", cli1 is cli2)
show("B1 pool reuse calls")

print("\n[B2] pool key ignores credential_provider")
base = dict(transport=SQS.Transport,
            transport_options={"predefined_queues": {"q-exp": PRE["q-exp"]}})
a = Connection("sqs://URL_KEY:URL_SECRET@", **base)
b = Connection("sqs://URL_KEY:URL_SECRET@", credential_provider=object(), **base)
print("__eqhash__ equal:", a.__eqhash__() == b.__eqhash__())
pa = pools.connections[a]; pb = pools.connections[b]
print("same pool object:", pa is pb)
print("pool.connection is first connection:", pa.connection is a)
print("pool.connection.credential_provider:", pa.connection.credential_provider)
pools.reset()
show("B2 pool key")

print("\n[B3] pool key ignores alternates")
a = Connection("sqs://URL_KEY:URL_SECRET@host1", transport=SQS.Transport)
b = Connection("sqs://URL_KEY:URL_SECRET@host1",
               alternates=["sqs://ALT_KEY:ALT_SECRET@host2"],
               transport=SQS.Transport)
print("__eqhash__ equal:", a.__eqhash__() == b.__eqhash__())
pa = pools.connections[a]; pb = pools.connections[b]
print("same pool object:", pa is pb, "pool.connection is first:", pa.connection is a)
print("pool.connection.alt:", pa.connection.alt)
pools.reset()
show("B3 pool key alternates")

print("\n" + "=" * 78)
print("C. EXPLICIT OVERRIDE")
print("=" * 78)

print("\n[C1] per-queue keys beat URL keys; queue without keys inherits URL")
conn = Connection("sqs://URL_KEY:URL_SECRET@", transport=SQS.Transport,
                  transport_options={"predefined_queues": PRE})
ch = conn.channel()
print("q-exp:", who(ch.sqs(queue="q-exp")))
print("q-url:", who(ch.sqs(queue="q-url")))
show("C1 per-queue override")

print("\n[C2] sts_role_arn beats per-queue keys; STS call uses default chain")
conn = Connection("sqs://URL_KEY:URL_SECRET@", transport=SQS.Transport,
                  transport_options={"predefined_queues": PRE,
                                     "sts_role_arn": "arn:aws:iam::111122223333:role/AlertSender",
                                     "sts_token_timeout": 900})
ch = conn.channel()
print("q-exp:", who(ch.sqs(queue="q-exp")))
show("C2 STS override")

print("\n[C3] sts_role_arn without predefined_queues is ignored")
conn = Connection("sqs://URL_KEY:URL_SECRET@", transport=SQS.Transport,
                  transport_options={"sts_role_arn": "arn:aws:iam::111122223333:role/AlertSender"})
ch = conn.channel()
print("default client:", who(ch.sqs()))
show("C3 STS ignored")

print("\n[C4] a new Channel assumes the role again and replaces the Connection-wide client")
conn = Connection("sqs://URL_KEY:URL_SECRET@", transport=SQS.Transport,
                  transport_options={"predefined_queues": PRE,
                                     "sts_role_arn": "arn:aws:iam::111122223333:role/AlertSender"})
ch1 = conn.channel(); cli1 = ch1.sqs(queue="q-exp")
ch2 = conn.channel(); cli2 = ch2.sqs(queue="q-exp")
print("same client object:", cli1 is cli2)
print("transport cache now points at ch2 client:",
      conn.transport._predefined_queue_clients["q-exp"] is cli2)
show("C4 two channels, two AssumeRole calls")

print("\n[C5] SNS: predefined exchange can use another identity than the default SNS client")
EX = {"ex": {"arn": "arn:aws:sns:us-east-1:1:ex",
             "access_key_id": "EXPLICIT_EXCHANGE_KEY",
             "secret_access_key": "explicit-exchange-secret"}}
conn = Connection("sqs://URL_KEY:URL_SECRET@", transport=SQS.Transport,
                  transport_options={"predefined_exchanges": EX})
ch = conn.channel()
print("predefined exchange client:", who(ch.fanout.get_client("ex")))
print("default SNS client:       ", who(ch.fanout.get_client()))
show("C5 SNS predefined vs default")

conn = Connection("sqs://URL_KEY:URL_SECRET@", transport=SQS.Transport,
                  transport_options={"predefined_exchanges": EX,
                                     "sts_role_arn": "arn:aws:iam::111122223333:role/AlertSender"})
ch = conn.channel()
print("predefined exchange + sts:", who(ch.fanout.get_client("ex")))
print("default SNS + sts:        ", who(ch.fanout.get_client()))
show("C5b SNS with STS")

print("\n" + "=" * 78)
print("D. FALLBACK CONNECTION")
print("=" * 78)

def fallback(label, url, **kwargs):
    print(f"\n[D] {label}: {url!r}")
    conn = Connection(url, transport=SQS.Transport, **kwargs)
    try:
        conn.connect()
    except Exception as exc:
        print("connect raised:", type(exc).__name__, exc)
    print("after switch host/userid/password:", conn.hostname, conn.userid, conn.password)
    ch = conn.channel()
    print("client:", who(ch.sqs()))
    show(label)

fallback("D1 alternate URL without userinfo", "sqs://URL_KEY:URL_SECRET@host1;sqs://host2")
fallback("D2 alternate schemeless host", "sqs://URL_KEY:URL_SECRET@host1;host2")
fallback("D3 alternates list without userinfo", "sqs://URL_KEY:URL_SECRET@host1",
         alternates=["sqs://host2"])
fallback("D4 alternate URL with userinfo", "sqs://URL_KEY:URL_SECRET@host1;sqs://ALT_KEY:ALT_SECRET@host2")

print("\n[D5] per-queue explicit key survives switch; only the endpoint changes")
conn = Connection("sqs://URL_KEY:URL_SECRET@host1;sqs://host2", transport=SQS.Transport,
                  transport_options={"predefined_queues": {"q-exp": PRE["q-exp"]}})
conn.connect()
ch = conn.channel()
print("before ensure host/userid/password:", conn.hostname, conn.userid, conn.password)
print("client before ensure:", who(ch.sqs(queue="q-exp")))
print("queue URL still points at account 111122223333:",
      conn.transport_options["predefined_queues"]["q-exp"]["url"])
class Target:
    def revive(self, channel): self.channel = channel
def operation():
    return conn.channel().sqs(queue="q-exp").list_queues()
conn.ensure(Target(), operation, max_retries=1, interval_start=0,
            interval_step=0, interval_max=0)()
print("after ensure host/userid/password:", conn.hostname, conn.userid, conn.password)
print("client after ensure:", who(conn.channel().sqs(queue="q-exp")))
show("D5 explicit key vs endpoint after failover")


print("\n" + "=" * 78)
print("E. ONE CONNECTION, TWO IDENTITIES IN THE SAME OPERATION")
print("=" * 78)
print("\n[E1] SNS fanout subscribe: SNS call vs SQS queue-policy call")
EX2 = {"ex": {"arn": "arn:aws:sns:us-east-1:1:ex",
              "access_key_id": "EXPLICIT_EXCHANGE_KEY",
              "secret_access_key": "explicit-exchange-secret"}}
conn = Connection("sqs://URL_KEY:URL_SECRET@", transport=SQS.Transport,
                  transport_options={"predefined_queues": PRE,
                                     "predefined_exchanges": EX2})
ch = conn.channel()
arn = ch.fanout.subscriptions.subscribe_queue("q-exp", "ex")
print("subscription:", arn)
show("E1 fanout subscribe identity split")

print("\n[E2] same, with sts_role_arn")
conn = Connection("sqs://URL_KEY:URL_SECRET@", transport=SQS.Transport,
                  transport_options={"predefined_queues": PRE,
                                     "predefined_exchanges": EX2,
                                     "sts_role_arn": "arn:aws:iam::111122223333:role/AlertSender"})
ch = conn.channel()
arn = ch.fanout.subscriptions.subscribe_queue("q-exp", "ex")
print("subscription:", arn)
show("E2 fanout subscribe with STS")

print("\n" + "=" * 78)
print("F. CANCELLED CONSUMER: short-timeout release client keeps the queue identity")
print("=" * 78)
conn = Connection("sqs://", transport=SQS.Transport,
                  transport_options={"predefined_queues": {
                      "q-exp": {"url": "https://sqs.us-east-1.amazonaws.com/1/q-exp",
                                "access_key_id": "EXPLICIT_QUEUE_KEY",
                                "secret_access_key": "explicit-queue-secret"}}})
ch = conn.channel()
source = ch.sqs(queue="q-exp")
release = ch._new_release_client(source)
print("source client key: ", source.identity["access_key"])
print("release client key:", release.identity["access_key"],
      "| same object:", release is source)
show("F release client identity")
