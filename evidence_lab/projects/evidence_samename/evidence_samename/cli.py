"""Console entry target. Source-only callable semantics by design."""


def main(argv=None):
    print("evidence-probe console entry says hello")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
