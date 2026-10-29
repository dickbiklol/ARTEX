#!/usr/bin/env bash
# ARTEX 安装脚本：① 全部 Docker  ② 本地编译运行
set -euo pipefail
# 源码目录（compose 的 build context 指向它，因此必须先解析成绝对路径再 cd）。
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

info(){ printf '\033[36m[*]\033[0m %s\n' "$*"; }
ok(){   printf '\033[32m[+]\033[0m %s\n' "$*"; }
warn(){ printf '\033[33m[!]\033[0m %s\n' "$*"; }
die(){  printf '\033[31m[x]\033[0m %s\n' "$*" >&2; exit 1; }
ask(){  local p="$1" d="${2:-}" a; read -rp "$p${d:+ [$d]}: " a; echo "${a:-$d}"; }
rand(){ head -c 18 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 24; }
rand8(){ head -c 24 /dev/urandom | base64 | tr -dc 'a-z0-9' | head -c 8; }

# ── 端口可用性 ──────────────────────────────────
# 尽力检测：没装 ss/netstat 就跳过，不因检测不到而阻断安装。
port_busy(){
  local p="$1"
  if command -v ss >/dev/null 2>&1; then
    ss -ltn 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${p}$"
    return
  fi
  if command -v netstat >/dev/null 2>&1; then
    netstat -ltn 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${p}$"
    return
  fi
  return 1
}

# ask_port <标题> <默认值> [已被占用的端口]
ask_port(){
  local title="$1" def="$2" taken="${3:-}" taken2="${4:-}" p
  while :; do
    p="$(ask "$title" "$def")"
    if ! [[ "$p" =~ ^[0-9]+$ ]] || [ "$p" -lt 1 ] || [ "$p" -gt 65535 ]; then
      warn "端口必须是 1-65535 的整数"; continue
    fi
    if [ -n "$taken" ] && [ "$p" = "$taken" ]; then
      warn "不能与另一个端口相同"; continue
    fi
    if [ -n "$taken2" ] && [ "$p" = "$taken2" ]; then
      warn "不能与另一个端口相同"; continue
    fi
    if port_busy "$p"; then
      warn "端口 $p 已被占用，换一个"; def=""; continue
    fi
    echo "$p"; return
  done
}

# ── 安装目录：当前 / 自定义 / 随机 ──────────────
choose_dir(){
  local choice custom
  echo "" >&2
  echo "安装目录：" >&2
  echo "  1) 当前目录（$SCRIPT_DIR）" >&2
  echo "  2) 自定义路径" >&2
  echo "  3) 随机路径（\$HOME/artex-xxxxxxxx）" >&2
  choice="$(ask '选择' 1)"
  case "$choice" in
    2)
      custom="$(ask '安装路径（支持 ~）' "$HOME/artex")"
      case "$custom" in "~"|"~/"*) custom="${HOME}${custom#\~}" ;; esac
      ;;
    3)
      custom="$HOME/artex-$(rand8)"
      info "随机目录：$custom" >&2
      ;;
    *) custom="$SCRIPT_DIR" ;;
  esac
  mkdir -p "$custom" || die "无法创建目录 $custom"
  [ -w "$custom" ] || die "目录不可写：$custom"
  ( cd "$custom" && pwd -P )
}

# ── docker 环境检测 / 自动安装 ───────────────────
ensure_docker(){
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    ok "已检测到 docker 与 docker compose"; return
  fi
  warn "未检测到 docker / docker compose"
  case "$(uname -s)" in
    Linux)
      if [ "$(ask '自动安装 Docker? (y/n)' y)" = y ]; then
        curl -fsSL https://get.docker.com | sh
        sudo usermod -aG docker "$USER" || true
        ok "Docker 安装完成（用户组变更需重新登录后免 sudo）"
      else
        die "请自行安装 docker 后重试"
      fi ;;
    Darwin) die "macOS 请安装 Docker Desktop：https://www.docker.com/products/docker-desktop/" ;;
    *)      die "请自行安装 docker 后重试" ;;
  esac
}

# ── ① 全部 Docker ───────────────────────────────
install_docker(){
  ensure_docker
  local dir port pport pgport
  dir="$(choose_dir)"
  echo ""
  # 默认端口从 8787 开始找第一个空闲的，省得用户自己去查
  local def=8787
  while [ "$def" -lt 9000 ] && port_busy "$def"; do def=$((def+1)); done
  port="$(ask_port '面板端口' "$def")"
  pport="$(ask_port '录制代理端口（只绑 127.0.0.1）' "$((port+1))" "$port")"
  # Postgres 只绑回环；同机第二套 ARTEX 必须各用各的宿主机端口（5433/5434/…）。
  local pgdef=5433
  while [ "$pgdef" -lt 5600 ] && port_busy "$pgdef"; do pgdef=$((pgdef+1)); done
  pgport="$(ask_port 'Postgres 宿主机端口（只绑 127.0.0.1）' "$pgdef" "$port" "$pport")"

  # compose 文件与 skills 必须落到安装目录：compose 把 ./skills 挂进容器，
  # 目录为空时会把镜像自带的 skills 整个盖掉。
  if [ "$dir" != "$SCRIPT_DIR" ]; then
    info "复制 compose 文件与 skills 到 $dir …"
    cp docker-compose.yml "$dir/"
    cp .env.example "$dir/.env.example" 2>/dev/null || true
    mkdir -p "$dir/skills" "$dir/data"
    cp -R skills/. "$dir/skills/" 2>/dev/null || true
  fi
  mkdir -p "$dir/data"

  if [ ! -f "$dir/.env" ]; then
    local pw key
    pw="$(ask 'Postgres 密码（回车随机生成）' "$(rand)")"
    key="$(ask 'ANTHROPIC_API_KEY（可留空，后续在 UI 配）' '')"
    cat > "$dir/.env" <<ENV
ARTEX_TAG=${ARTEX_TAG:-local}
POSTGRES_USER=artex
POSTGRES_PASSWORD=${pw}
POSTGRES_DB=artex
# 宿主机侧 Postgres 端口（只绑 127.0.0.1）。同机多套实例时改这里即可。
POSTGRES_HOST_PORT=${pgport}
ARTEX_PORT=${port}
ARTEX_PROXY_PORT=${pport}
# 预构建镜像拉不到时，compose 用这份源码从源码构建；context 必须是源码目录。
ARTEX_BUILD_CONTEXT=${SCRIPT_DIR}
ARTEX_DOCKERFILE=Dockerfile.source
ARTEX_VERSION=${ARTEX_VERSION:-$( (cd "$SCRIPT_DIR" && git describe --tags --always 2>/dev/null) || echo dev )}
ANTHROPIC_API_KEY=${key}
OPENAI_API_KEY=
ARTEX_UPDATE_GITHUB_TOKEN=
ARTEX_LLM_PROVIDER=
ARTEX_LLM_MODEL=
ARTEX_LLM_BASE_URL=
ARTEX_LLM_PROXY=
ENV
    chmod 600 "$dir/.env"
    ok "已生成 $dir/.env（POSTGRES_PASSWORD 已设置，权限 600）"
  else
    info "沿用已存在的 .env（端口取其中的 ARTEX_PORT / ARTEX_PROXY_PORT）"
    port="$(grep -E '^ARTEX_PORT=' "$dir/.env" | tail -1 | cut -d= -f2 || true)"
    pport="$(grep -E '^ARTEX_PROXY_PORT=' "$dir/.env" | tail -1 | cut -d= -f2 || true)"
    pgport="$(grep -E '^POSTGRES_HOST_PORT=' "$dir/.env" | tail -1 | cut -d= -f2 || true)"
    port="${port:-8787}"; pport="${pport:-8788}"; pgport="${pgport:-5433}"
  fi

  # 始终从本地源码构建，不碰 registry（上游预构建镜像已不再发布）。
  # postgres 仍然会正常拉取——它是标准镜像，且不该自己编译。
  [ -f "$SCRIPT_DIR/Dockerfile.source" ] || die "找不到 $SCRIPT_DIR/Dockerfile.source，无法构建"
  info "从源码构建镜像（首次需联网下载依赖，约 5–15 分钟，占 2–3 GB 磁盘）…"
  ( cd "$dir" && docker compose build ) || die "镜像构建失败，请查看上方日志"
  ( cd "$dir" && docker compose up -d ) || die "启动失败，请查看上方日志"
  ok "启动完成 → http://localhost:${port}"
  info "安装目录：$dir"
  info "代码有更新后重建：cd $dir && docker compose up -d --build"
  info "查看日志：cd $dir && docker compose logs -f artex"
}

# ── ② 本地编译运行 ──────────────────────────────
install_local(){
  local dir port pport
  dir="$(choose_dir)"
  echo ""
  local def=8787
  while [ "$def" -lt 9000 ] && port_busy "$def"; do def=$((def+1)); done
  port="$(ask_port '面板端口' "$def")"
  pport="$(ask_port '录制代理端口（只绑 127.0.0.1）' "$((port+1))" "$port")"

  echo ""
  echo "数据库安装方式："
  echo "  1) 连接已有 PostgreSQL"
  echo "  2) 用 Docker 起一个 PostgreSQL（需要 docker）"
  case "$(ask '选择' 1)" in
    2)
      ensure_docker
      local pw; pw="$(ask 'Postgres 密码（回车随机）' "$(rand)")"
      docker run -d --name artex-pg -p 5432:5432 \
        -e POSTGRES_USER=artex -e POSTGRES_PASSWORD="$pw" -e POSTGRES_DB=artex \
        -v artex-pg:/var/lib/postgresql/data postgres:16-alpine
      DB_HOST=127.0.0.1 DB_PORT=5432 DB_USER=artex DB_PASS="$pw" DB_NAME=artex DB_SSL=disable ;;
    *)
      DB_HOST="$(ask '数据库地址' 127.0.0.1)"
      DB_PORT="$(ask '端口' 5432)"
      DB_USER="$(ask '账号' artex)"
      DB_PASS="$(ask '密码' '')"
      DB_NAME="$(ask '数据库名' artex)"
      DB_SSL="$(ask 'sslmode (disable/require)' disable)" ;;
  esac

  # 生成 config.json（放进安装目录，由 ARTEX_CONFIG 指定）
  mkdir -p "$dir/data"
  cat > "$dir/config.json" <<JSON
{
  "database": {
    "host": "${DB_HOST}",
    "port": ${DB_PORT},
    "user": "${DB_USER}",
    "password": "${DB_PASS}",
    "dbname": "${DB_NAME}",
    "sslmode": "${DB_SSL}"
  }
}
JSON
  chmod 600 "$dir/config.json"
  ok "已生成 $dir/config.json"

  # go 环境检查
  command -v go >/dev/null 2>&1 || die "未检测到 Go，请先安装 Go（>=1.26）：https://go.dev/dl/"
  ok "Go: $(go version)"

  # 编译始终在源码目录做，产物装到目标目录
  if command -v npm >/dev/null 2>&1; then
    info "构建前端静态产物…"
    ( cd "$SCRIPT_DIR/web" && npm ci && npm run build:static )
    rm -rf "$SCRIPT_DIR/server/webui/dist" && cp -R "$SCRIPT_DIR/web/out" "$SCRIPT_DIR/server/webui/dist"
    info "编译内嵌单二进制…"
    ( cd "$SCRIPT_DIR" && CGO_ENABLED=0 go build -tags embedui -trimpath -o "$dir/artex" ./cmd/artex )
  else
    warn "未检测到 npm：将编译**不内嵌前端**的后端（前端需另跑 npm run dev）"
    ( cd "$SCRIPT_DIR" && CGO_ENABLED=0 go build -o "$dir/artex" ./cmd/artex )
  fi
  [ -x "$dir/artex" ] || die "编译产物不存在：$dir/artex"
  ok "编译完成 → $dir/artex"

  # skills 必须跟着二进制走：SkillDir 默认是 <BaseDir>/skills
  if [ "$dir" != "$SCRIPT_DIR" ]; then
    mkdir -p "$dir/skills"
    cp -R "$SCRIPT_DIR/skills/." "$dir/skills/" 2>/dev/null || true
  fi

  # 写个启动脚本，省得每次记参数；改端口就改这里
  cat > "$dir/start-artex.sh" <<SH
#!/usr/bin/env bash
set -euo pipefail
cd "\$(cd "\$(dirname "\$0")" && pwd)"
exec env ARTEX_CONFIG="$dir/config.json" ARTEX_SKILL_DIR="$dir/skills" \\
  "$dir/artex" -addr ":$port" -proxy "127.0.0.1:$pport" -data "$dir/data" "\$@"
SH
  chmod +x "$dir/start-artex.sh"

  ok "面板地址：http://localhost:${port}"
  info "启动：$dir/start-artex.sh"
}

echo "=============================="
echo "  ARTEX 安装"
echo "  1) 全部 Docker 安装"
echo "  2) 本地运行（go 编译）"
echo "=============================="
case "$(ask '选择' 1)" in
  1) install_docker ;;
  2) install_local ;;
  *) die "无效选择" ;;
esac
