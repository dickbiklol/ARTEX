#!/usr/bin/env bash
# 安装扫描器工具链——【下载官方预编译二进制】，不从源码编译。
#
# 为什么不用 `go install`：go install 会把整个依赖树拉下来并现场编译。nuclei 一家就带
# 进来 envoy/go-control-plane、cncf/xds、go-jose 等两百多个模块，实测单这一层 18 分钟。
# 而这些项目在 GitHub Releases 上都有 linux-amd64/arm64 的成品二进制，下载只要几十秒。
#
# 用法（由 Dockerfile 调用）：
#   TARGETARCH=amd64 GOBIN=/out NUCLEI_VER=latest ./install-scanners.sh
#
# 版本策略：
#   <TOOL>_VER=latest   → 解析 GitHub 的 /releases/latest 重定向拿到 tag（不走 API，无速率限制）
#   <TOOL>_VER=v3.4.10  → 直接使用该 tag（可复现构建）
#
# 单个工具装不上只记 WARN 不中断：一个改名的 asset 不该让整次构建白跑。
set -uo pipefail

# 这个脚本只该在【Docker 构建过程】里跑（那才是要往镜像里塞扫描器的地方）。
# 用显式开关而不是探测 /.dockerenv：那个文件只在「运行中的容器」里存在，
# BuildKit 构建期间并没有它，用它判断会把构建本身拦下来。
if [ "${ARTEX_INSTALL_SCANNERS:-}" != "1" ]; then
  echo "[x] 这是给 Docker 构建用的脚本（镜像里由 Dockerfile 调用，会用 ARTEX_INSTALL_SCANNERS=1 开启）。" >&2
  echo "    确实想在当前机器上装扫描器，执行：ARTEX_INSTALL_SCANNERS=1 ./scripts/install-scanners.sh" >&2
  exit 1
fi

arch="${TARGETARCH:-amd64}"
case "$arch" in
  amd64) garch=x86_64 ;;
  arm64) garch=arm64 ;;
  *) echo "[x] 不支持的架构: $arch" >&2; exit 1 ;;
esac

out="${GOBIN:-/out}"
mkdir -p "$out"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

missing=()
note(){ printf '  %-14s %s\n' "$1" "$2"; }

# tag_of <owner/repo> <latest|tag>
# 用 /releases/latest 的 302 目标解析 tag，比 api.github.com 省心（无 60 次/小时限制）。
tag_of(){
  local repo="$1" want="$2" url
  if [ "$want" != "latest" ]; then printf '%s' "$want"; return 0; fi
  url="$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/${repo}/releases/latest" 2>/dev/null)"
  case "$url" in
    */tag/*) printf '%s' "${url##*/tag/}" ;;
    *) return 1 ;;
  esac
}

# fetch <url> <解压目录>：按扩展名解压
fetch(){
  local url="$1" dest="$2" f
  f="$tmp/$(basename "$url")"
  curl -fsSL --retry 3 --retry-delay 2 -o "$f" "$url" || return 1
  mkdir -p "$dest"
  case "$f" in
    *.zip) unzip -oq "$f" -d "$dest" ;;
    *.tar.gz|*.tgz) tar -xzf "$f" -C "$dest" ;;
    *) return 1 ;;
  esac
}

# install_bin <源文件> <目标名>
install_bin(){
  [ -f "$1" ] || return 1
  install -m 0755 "$1" "$out/$2"
}

# pd <name> <ver>：projectdiscovery 系列，asset 形如 nuclei_3.4.10_linux_amd64.zip
pd(){
  local name="$1" want="$2" tag v dir
  tag="$(tag_of "projectdiscovery/$name" "$want")" || { missing+=("$name(tag)"); return; }
  v="${tag#v}"
  dir="$tmp/$name"
  if ! fetch "https://github.com/projectdiscovery/${name}/releases/download/${tag}/${name}_${v}_linux_${arch}.zip" "$dir"; then
    missing+=("$name(download $tag)"); return
  fi
  install_bin "$dir/$name" "$name" || missing+=("$name(unpack)")
  note "$name" "$tag"
}

# rel <name> <owner/repo> <ver> <asset 模板> [备选模板 …]
#
# 模板占位符：
#   {tag}   完整 tag（含 v，例如 v3.2.4）
#   {v}     去掉 v 的版本号（例如 3.2.4）
#   {arch}  Go 的叫法 amd64 / arm64
#   {garch} 发布包里常见的叫法 x86_64 / arm64
#
# 各项目的资产命名并不统一（有的带版本号、有的不带；dalfox 用连字符 + x86_64，
# gobuster 干脆用 gobuster_Linux_x86_64.tar.gz 完全不带版本）——所以允许给多个候选，
# 按顺序试到第一个能下载的为止，命名再变也不会整块失败。
rel(){
  local name="$1" repo="$2" want="$3"
  shift 3
  local tag v dir tmpl asset got found
  tag="$(tag_of "$repo" "$want")" || { missing+=("$name(tag)"); return; }
  v="${tag#v}"
  dir="$tmp/$name"
  got=""
  for tmpl in "$@"; do
    asset="${tmpl//\{tag\}/$tag}"
    asset="${asset//\{v\}/$v}"
    asset="${asset//\{arch\}/$arch}"
    asset="${asset//\{garch\}/$garch}"
    rm -rf "$dir"; mkdir -p "$dir"
    if fetch "https://github.com/${repo}/releases/download/${tag}/${asset}" "$dir"; then
      got="$asset"
      break
    fi
  done
  if [ -z "$got" ]; then
    missing+=("$name(没有匹配的资产 @${tag})")
    return
  fi
  # 归档里可能是裸二进制，也可能在子目录里
  found="$(find "$dir" -maxdepth 2 -type f -name "$name" -print -quit)"
  if install_bin "$found" "$name"; then
    note "$name" "$tag"
  else
    missing+=("$name(解包失败 $got)")
  fi
}

echo "[*] 安装扫描器二进制 (arch=$arch → $out) …"

pd nuclei     "${NUCLEI_VER:-latest}"
pd subfinder  "${SUBFINDER_VER:-latest}"
pd katana     "${KATANA_VER:-latest}"
pd httpx      "${HTTPX_VER:-latest}"
pd naabu      "${NAABU_VER:-latest}"
pd dnsx       "${DNSX_VER:-latest}"

# 下面几个命名都经 GitHub Release 实际核对过（2026-10）：
#   ffuf      ffuf_2.3.0_linux_amd64.tar.gz
#   dalfox    dalfox-v3.2.4-linux-x86_64.tar.gz     ← 连字符 + x86_64 + 带 v
#   gau       gau_2.2.4_linux_amd64.tar.gz
#   gobuster  gobuster_Linux_x86_64.tar.gz          ← 完全不带版本号
rel ffuf      "ffuf/ffuf"     "${FFUF_VER:-latest}" \
  "ffuf_{v}_linux_{arch}.tar.gz" "ffuf_{v}_linux_{garch}.tar.gz"
rel dalfox    "hahwul/dalfox" "${DALFOX_VER:-latest}" \
  "dalfox-{tag}-linux-{garch}.tar.gz" "dalfox_{v}_linux_{arch}.tar.gz" "dalfox-{tag}-linux-{arch}.tar.gz"
rel gau       "lc/gau"        "${GAU_VER:-latest}" \
  "gau_{v}_linux_{arch}.tar.gz"
rel gobuster  "OJ/gobuster"   "${GOBUSTER_VER:-latest}" \
  "gobuster_Linux_{garch}.tar.gz" "gobuster_{v}_Linux_{garch}.tar.gz"

# waybackurls 没有发布二进制 → 只能 go install，但它只有一个极小模块，几秒完成。
if command -v go >/dev/null 2>&1; then
  if go install "github.com/tomnomnom/waybackurls@${WAYBACKURLS_VER:-latest}" 2>/dev/null; then
    note waybackurls "go install"
  else
    missing+=("waybackurls(go install)")
  fi
else
  missing+=("waybackurls(no go)")
fi

echo ""
echo "[+] 已安装："
ls -1 "$out" | sed 's/^/    /'
if [ ${#missing[@]} -gt 0 ]; then
  echo ""
  echo "[!] 以下工具没装成功（其余照常可用；如需可手动 --build-arg 指定版本）：" >&2
  printf '    %s\n' "${missing[@]}" >&2
fi
exit 0
