"""Plugin entry target."""


class Probe:
    name = "evidence-probe"

    def inspect(self):
        return {"probe": self.name, "ok": True}


def build_probe():
    return Probe()
