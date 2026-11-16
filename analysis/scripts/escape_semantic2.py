from dissect.cobaltstrike.c2profile import C2Profile

# literal file content, using normal python strings:
# REQUEST branch output for b'a"b\\c' ->  "a\"b\c"
request_like = 'http-get { client { metadata { prepend "a\\"b\\c"; } } }\n'
# POSTREQ branch output for same arg   ->  "a\"b\\c"
postreq_like = 'http-post { client { output { prepend "a\\"b\\\\c"; } } }\n'

print("REQUEST-like text:", request_like.strip())
try:
    p = C2Profile.from_text(request_like)
    got = p.properties["http-get.client.metadata"][0][1]
    print("  decoded =", got, got.hex(), " equal=", got == b'a"b\\c')
except Exception as e:
    print("  PARSE FAILURE:", type(e).__name__, str(e).splitlines()[0])

print("POSTREQ-like text:", postreq_like.strip())
p2 = C2Profile.from_text(postreq_like)
got2 = p2.properties["http-post.client.output"][0][1]
print("  decoded =", got2, got2.hex(), " equal=", got2 == b'a"b\\c')
