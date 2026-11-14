"""命令行入口：analyze / generate-demo 两个子命令。"""

from __future__ import annotations

import argparse
import json
import sys

from .analyzer import analyze
from .models import SampleFormatError, parse_records
from .reporting import render_text, report_to_dict
from .sampler import build_demo_sample


def _load_payload(path: str) -> dict:
    if path == "-":
        return json.load(sys.stdin)
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def cmd_analyze(args: argparse.Namespace) -> int:
    try:
        payload = _load_payload(args.input)
        records = parse_records(payload)
    except (
        OSError,
        json.JSONDecodeError,
        SampleFormatError,
        ValueError,
    ) as exc:
        print(f"输入错误: {exc}", file=sys.stderr)
        return 64

    report = analyze(records)
    if args.format == "json":
        output = report_to_dict(report, reveal_secrets=args.reveal_secrets)
        print(json.dumps(output, ensure_ascii=False, indent=2))
    else:
        print(render_text(report, reveal_secrets=args.reveal_secrets), end="")

    if args.fail_on_confirmed and report.confirmed_groups:
        return 2
    return 0


def cmd_generate_demo(args: argparse.Namespace) -> int:
    payload, private_notes = build_demo_sample(rng_seed=args.seed)
    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    print(f"已写入合成样本: {args.output}（{len(payload['records'])} 条记录）")
    if args.emit_private:
        key_path = args.output + ".priv.json"
        with open(key_path, "w", encoding="utf-8") as handle:
            json.dump(
                {
                    "warning": "敏感材料，仅限本地交叉验证，请勿随日志分发",
                    "private_scalars": {
                        name: format(value, "x")
                        for name, value in private_notes.items()
                    },
                },
                handle,
                ensure_ascii=False,
                indent=2,
            )
            handle.write("\n")
        print(f"已写入私钥对照（敏感）: {key_path}")
    else:
        print("未写出私钥；需要本地交叉验证时加 --emit-private")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nonce-audit",
        description="离线 ECDSA nonce 重用审计（仅处理调用方提供的授权/合成样本）",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    analyze_p = sub.add_parser("analyze", help="分析样本 JSON")
    analyze_p.add_argument("input", help="样本文件路径，- 表示标准输入")
    analyze_p.add_argument(
        "--format", choices=["text", "json"], default="text", help="报告格式"
    )
    analyze_p.add_argument(
        "--reveal-secrets",
        action="store_true",
        help="输出恢复出的私钥与 nonce（默认隐藏）",
    )
    analyze_p.add_argument(
        "--fail-on-confirmed",
        action="store_true",
        help="确认 nonce 重用时以退出码 2 结束，便于接入 CI",
    )
    analyze_p.set_defaults(func=cmd_analyze)

    demo_p = sub.add_parser("generate-demo", help="生成合成故障样本")
    demo_p.add_argument("output", help="样本输出路径")
    demo_p.add_argument("--seed", type=int, default=20261115)
    demo_p.add_argument(
        "--emit-private",
        action="store_true",
        help="同时写出私钥对照文件（敏感，仅限本地验证）",
    )
    demo_p.set_defaults(func=cmd_generate_demo)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
