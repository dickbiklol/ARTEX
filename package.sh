#!/usr/bin/env bash
# 把当前源码目录打成可上传服务器的归档。
#
# 默认 tar.gz（Linux 服务器原生 `tar -xzf` 即可，不依赖 unzip）；加 --zip 则出 .zip。
#
# 排除：构建产物、依赖、运行期数据、以及【任何可能含密钥的文件】
#   - web/node_modules  (数百 MB)
#   - web/.next web/out server/webui/dist  (构建产物，Dockerfile.source 会重建)
#   - data/ transcripts/  (运行期数据，含 jwt.key；新机器上不能覆盖)
#   - .env config.json  (*含数据库密码 / API key，绝不能打进分发包*)
#   - .git bench/ *.db *.log dist/
#
# 用法：
#   ./package.sh              → dist/artex-<版本>-<日期>.tar.gz
#   ./package.sh --zip        → dist/artex-<版本>-<日期>.zip
#   OUT_DIR=/tmp ./package.sh → 指定输出目录
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

info(){ printf '\033[36m[*]\033[0m %s\n' "$*"; }
ok(){   printf '\033[32m[+]\033[0m %s\n' "$*"; }
warn(){ printf '\033[33m[!]\033[0m %s\n' "$*"; }
die(){  printf '\033[31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

FORMAT=tar
case "${1:-}" in
  "")        ;;
  --tar)     FORMAT=tar ;;
  --zip)     FORMAT=zip ;;
  -h|--help) sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
  *)         die "未知参数：$1（可用：--zip / --tar / --help）" ;;
esac

VER="$(git describe --tags --always --dirty 2>/dev/null || echo dev)"
VER="${VER//\//-}" # 标签里可能带斜杠，不能出现在文件名里
STAMP="$(date +%Y%m%d-%H%M%S)"
TOP="artex-${VER}" # 解压后得到的目录名（不带时间戳，服务器上好操作）
OUT_DIR="${OUT_DIR:-$SCRIPT_DIR/dist}"
mkdir -p "$OUT_DIR"
OUT="$OUT_DIR/${TOP}-${STAMP}.${FORMAT/tar/tar.gz}"

# 与 .dockerignore 保持同样的排除口径，另加「密钥」与「运行期数据」。
EXCLUDES=(
  ./.git
  ./dist
  ./web/node_modules
  ./web/.next
  ./web/out
  ./web/tsconfig.tsbuildinfo
  ./server/webui/dist
  ./data
  ./transcripts
  ./bench
  ./.env
  ./config.json
  ./*.db
  ./*.log
  ./artex
)

STAGE="$(mktemp -d)"
cleanup(){ rm -rf "$STAGE"; }
trap cleanup EXIT
DEST="$STAGE/$TOP"
mkdir -p "$DEST"

info "收集文件…"
# 用 tar 做「过滤复制」：先解到暂存目录，这样归档里天然带一层 $TOP/ 目录，
# 服务器上解压即得一个干净的文件夹，不会把文件撒到当前目录。
TAR_ARGS=()
for e in "${EXCLUDES[@]}"; do TAR_ARGS+=("--exclude=$e"); done
tar -cf - "${TAR_ARGS[@]}" . | tar -xf - -C "$DEST"

# ── 安全自检：分发包里绝不能出现密钥/数据 ────────────────
forbidden="$(find "$DEST" \
  \( -name '.env' -o -name 'config.json' -o -name 'node_modules' \
     -o -name '.git' -o -name '*.db' -o -name 'jwt.key' \) -print -quit)"
if [ -n "$forbidden" ]; then
  die "打包结果里出现了不该发布的文件：${forbidden#"$DEST"/}（已中止）"
fi

# ── 脚本换行自检：CRLF 的 .sh 在 Linux 上会报 `$'\r': command not found` ──
crlf_fixed=0
while IFS= read -r -d '' f; do
  if grep -qU $'\r' "$f" 2>/dev/null; then
    sed -i 's/\r$//' "$f"
    crlf_fixed=$((crlf_fixed+1))
  fi
done < <(find "$DEST" -name '*.sh' -print0)
[ "$crlf_fixed" -gt 0 ] && warn "已把 $crlf_fixed 个 .sh 文件转成 LF（CRLF 会让服务器上执行失败）"

# ── 必备文件自检 ──────────────────────────────────────
for need in go.mod go.sum Dockerfile.source docker-compose.yml install.sh start.sh \
            web/package.json web/package-lock.json db/schema.sql skills; do
  [ -e "$DEST/$need" ] || die "缺少必需文件：$need"
done

info "生成 $OUT …"
if [ "$FORMAT" = zip ]; then
  command -v zip >/dev/null 2>&1 || die "未安装 zip：请改用 ./package.sh --tar，或先装 zip"
  ( cd "$STAGE" && zip -qr "$OUT" "$TOP" )
else
  tar -czf "$OUT" -C "$STAGE" "$TOP"
fi

SIZE="$(du -h "$OUT" | cut -f1)"
COUNT="$(find "$DEST" -type f | wc -l | tr -d ' ')"
ok "完成：$OUT"
echo "    大小 $SIZE · $COUNT 个文件 · 顶层目录 $TOP/"
echo ""
echo "上传后在服务器上："
echo "    tar -xzf $(basename "$OUT")        # zip 则用 unzip"
echo "    cd $TOP"
echo "    ./install.sh                        # 选 Docker 模式，会问端口"
echo ""
echo "注意：.env / config.json / data/ 都【不在】包里——密码与密钥请在服务器上重新生成。"
