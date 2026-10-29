# syntax=docker/dockerfile:1
#
# 运行镜像（不在镜像里编译）：只装常用工具，放入**预编译好的 Linux 单二进制**。
# 二进制由 CI 的 binaries job 交叉编译（纯 Go、无 QEMU），按目标架构放在
# 构建上下文的 dist/<TARGETARCH>/artex。这样多架构构建时 arm64 只需模拟 apt 层，
# 不再模拟 Next/Go 编译，速度快得多。
#
# 本地手动构建镜像时，先自行准备二进制：
#   cd web && npm run build:static && cd ..
#   cp -r web/out server/webui/dist
#   CGO_ENABLED=0 GOARCH=amd64 go build -tags embedui -o dist/amd64/artex ./cmd/artex
#   docker build -t artex:local .
#
# ─────────────────────────────────────────────────────────────────────────────
# 扫描器工具链
# ─────────────────────────────────────────────────────────────────────────────
# 平台内置了 65 个命令配方（db/toolrecipes.json），其中 nuclei / ffuf / subfinder /
# katana / dalfox / gau / httpx / naabu / gobuster / waybackurls 等都是【外部二进制】。
# 配方只是「怎么调用」的接线；二进制不在镜像里时，模型会看到工具却收到 command not found。
# 所以这里加一层专门的 scanners stage：纯 Go 工具先编好，再 COPY 进运行镜像——
# 运行镜像本身依然不带 Go 工具链。
#
# 只想要面板、不要扫描器：
#   docker build --build-arg WITH_SCANNERS=false -t artex:panel-only .
#
# 注意：arm64 构建时这一层走 QEMU（比 amd64 慢），但它是缓存层，只有改版本号才重建。

FROM golang:1.26-bookworm AS scanners
ARG TARGETOS=linux
ARG TARGETARCH
ARG WITH_SCANNERS=true
# 版本可用 --build-arg 覆盖；默认 @latest，避免钉死一个不存在的补丁号导致构建失败。
# 需要可复现构建时全部钉成具体版本（例如 --build-arg NUCLEI_VER=v3.3.9）。
ARG NUCLEI_VER=latest
ARG SUBFINDER_VER=latest
ARG KATANA_VER=latest
ARG HTTPX_VER=latest
ARG NAABU_VER=latest
ARG FFUF_VER=latest
ARG DALFOX_VER=latest
ARG DNSX_VER=latest
ARG GAU_VER=latest
ARG GOBUSTER_VER=latest
ARG WAYBACKURLS_VER=latest

ENV CGO_ENABLED=0 GOBIN=/out GOFLAGS=-trimpath
# 与 Dockerfile.source 的 scanners stage 保持一致：下载官方预编译二进制，
# 不用 go install 现场编译（nuclei 的依赖树全量编译实测要 18 分钟）。
# 细节见 scripts/install-scanners.sh。
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends curl unzip ca-certificates; \
    rm -rf /var/lib/apt/lists/*
COPY scripts/install-scanners.sh /usr/local/bin/install-scanners.sh
RUN chmod +x /usr/local/bin/install-scanners.sh && \
    mkdir -p /out && \
    if [ "$WITH_SCANNERS" = "true" ]; then \
      ARTEX_INSTALL_SCANNERS=1 TARGETARCH="$TARGETARCH" GOBIN=/out \
        NUCLEI_VER="$NUCLEI_VER" SUBFINDER_VER="$SUBFINDER_VER" KATANA_VER="$KATANA_VER" \
        HTTPX_VER="$HTTPX_VER" NAABU_VER="$NAABU_VER" FFUF_VER="$FFUF_VER" \
        DALFOX_VER="$DALFOX_VER" DNSX_VER="$DNSX_VER" GAU_VER="$GAU_VER" \
        GOBUSTER_VER="$GOBUSTER_VER" WAYBACKURLS_VER="$WAYBACKURLS_VER" \
        /usr/local/bin/install-scanners.sh; \
    else \
      echo "WITH_SCANNERS=false → 跳过扫描器"; \
    fi && \
    ls -l /out

# ─────────────────────────────────────────────────────────────────────────────
# 运行镜像
# ─────────────────────────────────────────────────────────────────────────────
FROM python:3.12-slim-bookworm
ARG TARGETARCH
ARG WITH_SCANNERS=true
# nuclei 模板体积不小（数百 MB），默认不装：没有模板时 nuclei 跑不出任何结果。
# 要开箱即用的 nuclei：--build-arg INSTALL_NUCLEI_TEMPLATES=true
ARG INSTALL_NUCLEI_TEMPLATES=false
# SecLists 词表（ffuf / gobuster 的 -w 来源），体积大，默认不装。
ARG INSTALL_SECLISTS=false
# exploitdb（提供 searchsploit）—— component-vuln-intel 第 1 步就用它，但库很大（数百 MB）。
ARG INSTALL_EXPLOITDB=false

# 常用工具：ripgrep / curl / vim，加一批 recon 常备件（按需增删）。
# 扫描器（sqlmap / nikto / whatweb）逐个装、装不上就跳过：不同 Debian 版本的打包
# 情况不一致（bookworm 已移除 nikto 包），可选工具不该让构建失败。perl 给 nikto 兜底。
# Node 从 NodeSource 装 20.x：bookworm 自带的 apt nodejs 是 18，Playwright 要求 >=20。
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
      ca-certificates ripgrep curl wget vim git jq unzip perl \
      dnsutils iputils-ping netcat-openbsd inetutils-telnet whois nmap; \
    for p in sqlmap nikto whatweb; do \
      apt-get install -y --no-install-recommends "$p" \
        || echo "WARN: apt 源里没有 $p，跳过"; \
    done; \
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash -; \
    apt-get install -y --no-install-recommends nodejs; \
    rm -rf /var/lib/apt/lists/*

# nikto 在 bookworm 及之后的 apt 源里已不存在 → 用官方 Perl 脚本兜底。
RUN if ! command -v nikto >/dev/null 2>&1; then \
      git clone --depth 1 https://github.com/sullo/nikto /opt/nikto && \
      rm -rf /opt/nikto/.git && \
      printf '#!/bin/sh\nexec perl /opt/nikto/program/nikto.pl "$@"\n' > /usr/local/bin/nikto && \
      chmod +x /usr/local/bin/nikto ; \
    fi

# Python 侧的扫描器（arjun 参数枚举、dirsearch 目录扫描、wafw00f 指纹识别）。
# 官方 python 镜像没有 EXTERNALLY-MANAGED 限制，可以直接 pip install。
RUN pip install --no-cache-dir --disable-pip-version-check arjun dirsearch wafw00f

# Go 侧扫描器：从 scanners stage 拷入（该 stage 失败会先报错，不会静默产出空镜像）。
COPY --from=scanners /out/ /usr/local/bin/

# nuclei 模板（可选）。装在 /root/nuclei-templates —— nuclei 的默认查找路径，
# 所以配方不传 template 参数时也能直接命中。
RUN if [ "$INSTALL_NUCLEI_TEMPLATES" = "true" ]; then \
      git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates /root/nuclei-templates && \
      rm -rf /root/nuclei-templates/.git ; \
    fi

# SecLists（可选）。给 ffuf / gobuster 一个可用的默认词表路径。
RUN if [ "$INSTALL_SECLISTS" = "true" ]; then \
      git clone --depth 1 https://github.com/danielmiessler/SecLists /opt/seclists && \
      rm -rf /opt/seclists/.git ; \
    fi

# exploitdb / searchsploit（可选）。skill component-vuln-intel 第 1 步直接调它。
RUN if [ "$INSTALL_EXPLOITDB" = "true" ]; then \
      apt-get update && apt-get install -y --no-install-recommends exploitdb && \
      rm -rf /var/lib/apt/lists/* ; \
    fi
# 预装 Playwright MCP 与 CLI（全局），运行时不再 npx 联网下载。
# @playwright/mcp：browser MCP 直接 `npx @playwright/mcp`（已全局装好，无需 -y/@latest）。
# @playwright/cli：提供 playwright-cli，装完顺带 --help 验证可执行。
# 再装 playwright（提供浏览器管理），装完用 --with-deps 预置 chromium 及其系统依赖，
# 这样容器内 MCP/CLI 首次启动即可用，不再联网下载浏览器。
RUN npm install -g @playwright/mcp@latest @playwright/cli@latest playwright@latest \
    && playwright-cli --help \
    && playwright install --with-deps chromium \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
# 预编译好的对应架构二进制（dist/amd64/artex 或 dist/arm64/artex）
COPY dist/${TARGETARCH}/artex /app/artex
# 守护启动脚本：进程退出后按退出码决定是否重新拉起，页面一键更新靠它完成换装。
# 它同时负责把 SIGTERM 转发给 artex —— docker stop 只把信号发给 PID 1，
# 不转发的话 artex 收不到、做不了优雅关闭，10 秒后被 SIGKILL 硬杀。
COPY start.sh /app/start.sh
RUN chmod +x /app/artex /app/start.sh
COPY skills/ /app/skills/
# data/（SQLite + jwt.key）持久化点
VOLUME ["/app/data"]
EXPOSE 8787 8788
ENTRYPOINT ["/app/start.sh"]
CMD ["-addr", ":8787", "-proxy", ":8788"]
