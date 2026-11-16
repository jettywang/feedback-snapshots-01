from dissect.cobaltstrike.c2profile import C2Profile

# what the REQUEST (latin-1) branch emits for arg b'a"b\\c'
profile_text = r'''http-get {
    client {
        metadata {
            prepend "a\"b\c";
        }
    }
}
'''
p = C2Profile.from_text(profile_text)   # parses fine: syntax is valid
got = p.properties["http-get.client.metadata"][0][1]
print("parsed without syntax error; decoded bytes =", got, "hex =", got.hex())
print("original beacon arg            =", b'a"b\\c', "hex =", b'a"b\\c'.hex())
print("semantic round-trip equal      =", got == b'a"b\\c', " -> backslash silently DROPPED")

# contrast: repr-style (POSTREQ) output is semantically preserved
profile_text2 = r'''http-post {
    client {
        output {
            prepend "a\"b\\c";
        }
    }
}
'''
p2 = C2Profile.from_text(profile_text2)
got2 = p2.properties["http-post.client.output"][0][1]
print("\nPOSTREQ repr-style decoded    =", got2, "equal =", got2 == b'a"b\\c')
