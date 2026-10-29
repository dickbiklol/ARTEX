"use client";

import * as React from "react";

import {
  AlertCircleIcon,
  CheckCircle2Icon,
  GlobeIcon,
  PlayIcon,
  RefreshCwIcon,
  SearchIcon,
  SparklesIcon,
  Trash2Icon,
  XCircleIcon,
} from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { DiscoveryCandidate, DiscoveryRun, DiscoveryRunDetail } from "@/lib/types";

// 目标发现页。
//
// 设计前提（和后端一致）：候选永远不等于授权。这一页只做两件事——把 AI 找到的站点摆出来，
// 以及在你批准之后才建任务。所以「开始测试」按钮只在有 approved 候选时才亮，
// 并且点了只消费 approved 行。

const IN_FLIGHT: DiscoveryRun["status"][] = ["queued", "keywords", "searching", "filtering"];

const STATUS_LABEL: Record<DiscoveryRun["status"], string> = {
  queued: "已排队",
  keywords: "生成关键词",
  searching: "搜索中",
  filtering: "过滤中",
  ready: "待审批",
  started: "已建任务",
  failed: "失败",
};

const STATUS_STYLE: Record<DiscoveryRun["status"], string> = {
  queued: "bg-muted text-muted-foreground",
  keywords: "bg-blue-500/15 text-blue-600 dark:text-blue-400",
  searching: "bg-blue-500/15 text-blue-600 dark:text-blue-400",
  filtering: "bg-blue-500/15 text-blue-600 dark:text-blue-400",
  ready: "bg-amber-500/15 text-amber-600 dark:text-amber-400",
  started: "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400",
  failed: "bg-destructive/15 text-destructive",
};

const CAND_FILTERS = [
  { value: "pending", label: "待审批" },
  { value: "approved", label: "已批准" },
  { value: "rejected", label: "已拒绝" },
  { value: "used", label: "已进任务" },
  { value: "skipped", label: "被过滤" },
] as const;

function fmtTime(s?: string): string {
  if (!s) return "—";
  const d = new Date(s);
  return Number.isNaN(d.getTime()) ? s : d.toLocaleString();
}

export default function DiscoveryPage() {
  const [runs, setRuns] = React.useState<DiscoveryRun[]>([]);
  const [selectedId, setSelectedId] = React.useState<number | null>(null);
  const [detail, setDetail] = React.useState<DiscoveryRunDetail | null>(null);
  const [candidates, setCandidates] = React.useState<DiscoveryCandidate[]>([]);
  const [total, setTotal] = React.useState(0);
  const [filter, setFilter] = React.useState<string>("pending");
  const [checked, setChecked] = React.useState<Set<number>>(new Set());
  const [busy, setBusy] = React.useState(false);
  const [err, setErr] = React.useState<string>("");

  // form
  const [query, setQuery] = React.useState("");
  const [targetCount, setTargetCount] = React.useState(100);
  const [queries, setQueries] = React.useState(8);
  const [maxRounds, setMaxRounds] = React.useState(3);
  const [shape, setShape] = React.useState<"single" | "per_domain" | "batches">("single");
  const [batchSize, setBatchSize] = React.useState(25);
  const [exclude, setExclude] = React.useState("");
  const [liveness, setLiveness] = React.useState(true);
  const [minRelevance, setMinRelevance] = React.useState(40);
  // 测试目标：建任务后真正要测什么，和上面的搜索意图完全是两回事。
  const [testGoal, setTestGoal] = React.useState("");
  // 启动前可再改一次的版本（从 run.params.test_goal 回填）。
  const [startGoal, setStartGoal] = React.useState("");

  const loadRuns = React.useCallback(async () => {
    try {
      const list = await api.discoveryRuns(30);
      setRuns(list);
      setSelectedId((cur) => cur ?? list[0]?.id ?? null);
    } catch (e) {
      setErr(String(e));
    }
  }, []);

  const loadDetail = React.useCallback(async (id: number) => {
    try {
      setDetail(await api.discoveryRun(id));
    } catch (e) {
      setErr(String(e));
    }
  }, []);

  const loadCandidates = React.useCallback(
    async (id: number, status: string) => {
      try {
        const r = await api.discoveryCandidates(id, { status, limit: 500 });
        setCandidates(r.candidates);
        setTotal(r.total);
        setChecked(new Set());
      } catch (e) {
        setErr(String(e));
      }
    },
    [],
  );

  React.useEffect(() => {
    void loadRuns();
  }, [loadRuns]);

  React.useEffect(() => {
    if (selectedId == null) return;
    void loadDetail(selectedId);
    void loadCandidates(selectedId, filter);
  }, [selectedId, filter, loadDetail, loadCandidates]);

  // 切到某个 run 时把它的测试目标回填到启动框。只依赖 id：
  // 轮询会让 detail 对象不断变化，若依赖整个 detail 就会把用户正在改的字冲掉。
  const goalSeededFor = React.useRef<number | null>(null);
  React.useEffect(() => {
    if (!detail || goalSeededFor.current === detail.run.id) return;
    goalSeededFor.current = detail.run.id;
    const g = detail.run.params?.test_goal;
    setStartGoal(typeof g === "string" ? g : "");
  }, [detail]);

  // 流水线在跑时轮询（后端每阶段都会写 status，所以轮询能看到进展）。
  const inFlight = detail ? IN_FLIGHT.includes(detail.run.status) : false;
  React.useEffect(() => {
    if (!inFlight || selectedId == null) return;
    const t = setInterval(() => {
      void loadDetail(selectedId);
      void loadRuns();
    }, 2500);
    return () => clearInterval(t);
  }, [inFlight, selectedId, loadDetail, loadRuns]);

  // 从「生成中」变成「待审批」时自动刷新候选列表。
  const prevStatus = React.useRef<string>("");
  React.useEffect(() => {
    if (!detail) return;
    const now = detail.run.status;
    if (prevStatus.current !== now) {
      if (now === "ready" || now === "failed") {
        if (selectedId != null) void loadCandidates(selectedId, filter);
      }
      prevStatus.current = now;
    }
  }, [detail, filter, selectedId, loadCandidates]);

  async function createRun() {
    if (!query.trim()) {
      toast.error("先写清你要找什么样的站点");
      return;
    }
    setBusy(true);
    setErr("");
    try {
      const run = await api.discoveryCreateRun({
        query: query.trim(),
        target_count: targetCount,
        queries,
        max_rounds: maxRounds,
        shape,
        batch_size: batchSize,
        exclude: exclude
          .split(/[,，\s]+/)
          .map((s) => s.trim())
          .filter(Boolean),
        liveness,
        min_relevance: minRelevance,
        test_goal: testGoal.trim(),
      });
      toast.success("已开始搜索：关键词由模型自行生成");
      setSelectedId(run.id);
      await loadRuns();
    } catch (e) {
      setErr(String(e));
      toast.error("创建失败");
    } finally {
      setBusy(false);
    }
  }

  async function setStatus(ids: number[], status: "approved" | "rejected") {
    if (!selectedId || ids.length === 0) return;
    setBusy(true);
    try {
      if (ids.length === 1) await api.discoverySetCandidate(ids[0], status);
      else await api.discoveryBulkStatus(selectedId, ids, status);
      await loadCandidates(selectedId, filter);
      await loadDetail(selectedId);
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function startTests() {
    if (!selectedId) return;
    const approved = detail?.counts?.approved ?? 0;
    if (approved === 0) {
      toast.error("没有已批准的候选");
      return;
    }
    setBusy(true);
    try {
      const r = await api.discoveryStart(selectedId, {
        shape,
        batch_size: batchSize,
        goal: startGoal.trim(),
      });
      toast.success(`已创建 ${r.created} 个任务`);
      await loadDetail(selectedId);
      await loadRuns();
    } catch (e) {
      setErr(String(e));
      toast.error("启动失败");
    } finally {
      setBusy(false);
    }
  }

  async function deleteRun(id: number) {
    setBusy(true);
    try {
      await api.discoveryDeleteRun(id);
      if (selectedId === id) {
        setSelectedId(null);
        setDetail(null);
        setCandidates([]);
      }
      await loadRuns();
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  const stats = (detail?.run.stats ?? {}) as Record<string, unknown>;
  const keywords = Array.isArray(detail?.run.keywords) ? (detail?.run.keywords as string[]) : [];
  const approvedCount = detail?.counts?.approved ?? 0;
  const allChecked = candidates.length > 0 && checked.size === candidates.length;

  return (
    <div className="flex flex-col gap-4 p-4">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold">目标发现</h1>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            说一句你要找什么样的站点，模型自己生成搜索词、跑搜索、抓域名并过滤。候选通过后才会变成任务范围——
            <span className="font-medium">搜索到不等于获授权</span>，所以这里不会自动开扫。
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={() => void loadRuns()} disabled={busy}>
          <RefreshCwIcon className="size-4" /> 刷新
        </Button>
      </div>

      {err && (
        <div className="flex items-start gap-2 rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
          <AlertCircleIcon className="mt-0.5 size-4 shrink-0" />
          <span className="break-all">{err}</span>
        </div>
      )}

      <div className="grid gap-4 lg:grid-cols-[380px_1fr]">
        {/* ── 左：新建 + 历史 ── */}
        <div className="flex flex-col gap-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base">
                <SparklesIcon className="size-4" /> 新建发现
              </CardTitle>
            </CardHeader>
            <CardContent className="flex flex-col gap-3">
              <div className="flex flex-col gap-1.5">
                <Label htmlFor="dq">你要找什么站点</Label>
                <Textarea
                  id="dq"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder="例：找 100 个国内的在线教育平台官网，排除新闻和大厂"
                  rows={3}
                />
              </div>

              <div className="flex flex-col gap-1.5">
                <Label htmlFor="dgoal">测试目标（建任务后真正要测什么）</Label>
                <Textarea
                  id="dgoal"
                  value={testGoal}
                  onChange={(e) => setTestGoal(e.target.value)}
                  placeholder="例：对这批站点做授权渗透测试，重点找未授权访问、任意文件上传、SQL 注入，每个洞给出可复现 PoC"
                  rows={3}
                />
                <p className="text-xs text-muted-foreground">
                  上面那栏只用来「找站点」，跑完就作废；这里会写进任务的目标，规划者按它拆子目标。留空则用通用渗透目标。
                </p>
              </div>

              <div className="grid grid-cols-3 gap-3">
                <div className="flex flex-col gap-1.5">
                  <Label htmlFor="dc">目标数量</Label>
                  <Input
                    id="dc"
                    type="number"
                    min={1}
                    max={500}
                    value={targetCount}
                    onChange={(e) => setTargetCount(Number(e.target.value) || 100)}
                  />
                </div>
                <div className="flex flex-col gap-1.5">
                  <Label htmlFor="dqy">搜索词/轮</Label>
                  <Input
                    id="dqy"
                    type="number"
                    min={1}
                    max={12}
                    value={queries}
                    onChange={(e) => setQueries(Number(e.target.value) || 8)}
                  />
                </div>
                <div className="flex flex-col gap-1.5">
                  <Label htmlFor="dmr2">补搜轮数</Label>
                  <Input
                    id="dmr2"
                    type="number"
                    min={1}
                    max={3}
                    value={maxRounds}
                    onChange={(e) => setMaxRounds(Number(e.target.value) || 3)}
                  />
                </div>
              </div>
              <p className="text-xs text-muted-foreground">
                一轮搜完后若还不够数量，会换角度再搜（最多 {maxRounds} 轮），已测过的域名会被跳过且不占名额。
              </p>

              <div className="flex flex-col gap-1.5">
                <Label htmlFor="dshape">任务形态</Label>
                <select
                  id="dshape"
                  className="h-9 rounded-md border border-input bg-background px-3 text-sm"
                  value={shape}
                  onChange={(e) => setShape(e.target.value as typeof shape)}
                >
                  <option value="single">单个任务（全部域名放一起）</option>
                  <option value="batches">分批任务（每 N 个一批）</option>
                  <option value="per_domain">每个域名一个任务</option>
                </select>
              </div>

              {shape !== "single" && shape !== "per_domain" && (
                <div className="flex flex-col gap-1.5">
                  <Label htmlFor="dbs">每批域名数</Label>
                  <Input
                    id="dbs"
                    type="number"
                    min={1}
                    max={200}
                    value={batchSize}
                    onChange={(e) => setBatchSize(Number(e.target.value) || 25)}
                  />
                </div>
              )}

              <div className="flex flex-col gap-1.5">
                <Label htmlFor="dex">排除词（逗号或空格分隔）</Label>
                <Input
                  id="dex"
                  value={exclude}
                  onChange={(e) => setExclude(e.target.value)}
                  placeholder="新闻, 百科, 招聘"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="flex flex-col gap-1.5">
                  <Label htmlFor="dmr">相关性阈值</Label>
                  <Input
                    id="dmr"
                    type="number"
                    min={0}
                    max={100}
                    value={minRelevance}
                    onChange={(e) => setMinRelevance(Number(e.target.value))}
                  />
                </div>
                <label className="flex items-end gap-2 pb-2 text-sm">
                  <Checkbox checked={liveness} onCheckedChange={() => setLiveness((v) => !v)} />
                  存活探测
                </label>
              </div>

              <Button onClick={() => void createRun()} disabled={busy}>
                <SearchIcon className="size-4" /> 开始搜索
              </Button>
              <p className="text-xs text-muted-foreground">
                搜索走 系统设置 → Web 搜索 里配置的出口（可填住宅代理）。被限流时会提示，不会静默返回半份结果。
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-base">历史发现</CardTitle>
            </CardHeader>
            <CardContent className="flex flex-col gap-1.5">
              {runs.length === 0 && <p className="text-sm text-muted-foreground">还没有记录</p>}
              {runs.map((r) => (
                <div
                  key={r.id}
                  className={`flex items-center gap-2 rounded-md border p-2 text-sm ${
                    selectedId === r.id ? "border-primary/60 bg-primary/5" : "border-transparent"
                  }`}
                >
                  <button
                    type="button"
                    className="min-w-0 flex-1 text-left"
                    onClick={() => setSelectedId(r.id)}
                  >
                    <div className="truncate font-medium">
                      #{r.id} {r.query}
                    </div>
                    <div className="text-xs text-muted-foreground">{fmtTime(r.created_at)}</div>
                  </button>
                  <span className={`rounded px-1.5 py-0.5 text-xs ${STATUS_STYLE[r.status]}`}>
                    {STATUS_LABEL[r.status]}
                  </span>
                  <Button
                    size="icon"
                    variant="ghost"
                    className="size-7"
                    onClick={() => void deleteRun(r.id)}
                    disabled={busy}
                  >
                    <Trash2Icon className="size-3.5" />
                  </Button>
                </div>
              ))}
            </CardContent>
          </Card>
        </div>

        {/* ── 右：详情 ── */}
        <div className="flex min-w-0 flex-col gap-4">
          {!detail && (
            <Card>
              <CardContent className="flex h-40 items-center justify-center text-sm text-muted-foreground">
                左侧新建一轮发现，或选一条历史记录
              </CardContent>
            </Card>
          )}

          {detail && (
            <>
              <Card>
                <CardHeader>
                  <CardTitle className="flex flex-wrap items-center gap-2 text-base">
                    <GlobeIcon className="size-4" />
                    <span className="min-w-0 flex-1 truncate">{detail.run.query}</span>
                    <span className={`rounded px-2 py-0.5 text-xs ${STATUS_STYLE[detail.run.status]}`}>
                      {STATUS_LABEL[detail.run.status]}
                    </span>
                  </CardTitle>
                </CardHeader>
                <CardContent className="flex flex-col gap-3 text-sm">
                  {detail.run.error && (
                    <div className="flex items-start gap-2 rounded-md border border-destructive/40 bg-destructive/10 p-2 text-destructive">
                      <XCircleIcon className="mt-0.5 size-4 shrink-0" />
                      <span className="break-all">{detail.run.error}</span>
                    </div>
                  )}

                  <div className="flex flex-wrap gap-x-5 gap-y-1 text-muted-foreground">
                    <span>查询 {String(stats.queries ?? keywords.length)} 个</span>
                    <span>命中 {String(stats.hits ?? 0)} 条</span>
                    <span>去重后主机 {String(stats.hosts_raw ?? 0)} 个</span>
                    <span className="text-amber-600 dark:text-amber-400">
                      待审批 {detail.counts.pending ?? 0}
                    </span>
                    <span className="text-emerald-600 dark:text-emerald-400">
                      已批准 {approvedCount}
                    </span>
                    <span>已进任务 {detail.counts.used ?? 0}</span>
                    <span>被过滤 {detail.counts.skipped ?? 0}</span>
                  </div>

                  {/* 实时进度：轮次 + 查询进度 + 当前搜索词。跑的时候每 2.5s 刷新一次。 */}
                  {inFlight && (
                    <div className="flex flex-col gap-1.5 rounded-md border border-border bg-muted/40 p-2">
                      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs">
                        <span>
                          第 {String(stats.round ?? 1)}/{String(stats.max_rounds ?? 1)} 轮
                        </span>
                        <span>
                          查询 {String(stats.queries_done ?? 0)}/{String(stats.queries_total ?? 0)}
                        </span>
                        <span>已发现新主机 {String(stats.new_hosts ?? 0)}</span>
                        <span>已收录 {String(stats.pending ?? 0)} 个</span>
                      </div>
                      {typeof stats.current_query === "string" && stats.current_query !== "" && (
                        <div className="truncate text-xs text-muted-foreground">
                          正在搜索：
                          <span className="ml-1 font-mono text-foreground">{stats.current_query}</span>
                        </div>
                      )}
                    </div>
                  )}

                  {typeof stats.stopped_reason === "string" && stats.stopped_reason !== "" && (
                    <div className="rounded-md border border-amber-500/40 bg-amber-500/10 p-2 text-xs text-amber-700 dark:text-amber-400">
                      {stats.stopped_reason}
                    </div>
                  )}

                  {keywords.length > 0 && (
                    <div className="flex flex-col gap-1.5">
                      <span className="text-xs text-muted-foreground">模型实际使用的搜索词</span>
                      <div className="flex flex-wrap gap-1.5">
                        {keywords.map((k) => (
                          <Badge key={k} variant="secondary" className="max-w-full truncate">
                            {k}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* 建任务前再确认/改写一次测试目标：这串文字就是 task.goal。 */}
                  <div className="flex flex-col gap-1.5 border-t border-border pt-3">
                    <Label htmlFor="sgoal">本次测试目标</Label>
                    <Textarea
                      id="sgoal"
                      value={startGoal}
                      onChange={(e) => setStartGoal(e.target.value)}
                      placeholder="例：对这批域名做授权渗透测试，重点找未授权访问与文件上传，产出可复现 PoC"
                      rows={3}
                    />
                    <p className="text-xs text-muted-foreground">
                      会写进任务的目标，规划者按它拆子目标；不是搜索站点用的那句话。
                    </p>
                  </div>

                  <div className="flex flex-wrap items-center gap-2 pt-1">
                    <Button
                      size="sm"
                      onClick={() => void startTests()}
                      disabled={busy || approvedCount === 0 || detail.run.status === "started"}
                    >
                      <PlayIcon className="size-4" /> 开始测试（{approvedCount} 个已批准）
                    </Button>
                    <span className="text-xs text-muted-foreground">
                      只把 approved 的域名写进任务范围；其余候选原样保留
                    </span>
                  </div>
                </CardContent>
              </Card>

              <Card className="min-w-0">
                <CardHeader className="flex flex-row flex-wrap items-center justify-between gap-2">
                  <CardTitle className="text-base">候选站点（{total}）</CardTitle>
                  <div className="flex flex-wrap items-center gap-2">
                    <select
                      className="h-8 rounded-md border border-input bg-background px-2 text-sm"
                      value={filter}
                      onChange={(e) => setFilter(e.target.value)}
                    >
                      {CAND_FILTERS.map((f) => (
                        <option key={f.value} value={f.value}>
                          {f.label}
                        </option>
                      ))}
                    </select>
                    <Button
                      size="sm"
                      variant="outline"
                      disabled={busy || checked.size === 0}
                      onClick={() => void setStatus([...checked], "approved")}
                    >
                      <CheckCircle2Icon className="size-4" /> 批准所选
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      disabled={busy || checked.size === 0}
                      onClick={() => void setStatus([...checked], "rejected")}
                    >
                      <XCircleIcon className="size-4" /> 拒绝所选
                    </Button>
                  </div>
                </CardHeader>
                <CardContent className="min-w-0 overflow-x-auto">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead className="w-8">
                          <Checkbox
                            checked={allChecked}
                            onCheckedChange={() =>
                              setChecked(
                                allChecked ? new Set() : new Set(candidates.map((c) => c.id)),
                              )
                            }
                          />
                        </TableHead>
                        <TableHead>域名</TableHead>
                        <TableHead className="w-16">相关性</TableHead>
                        <TableHead>标题 / 原因</TableHead>
                        <TableHead className="w-40">来源查询</TableHead>
                        <TableHead className="w-24" />
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {candidates.length === 0 && (
                        <TableRow>
                          <TableCell colSpan={6} className="text-center text-sm text-muted-foreground">
                            {filter === "pending" ? "没有待审批的候选" : "该状态下没有候选"}
                          </TableCell>
                        </TableRow>
                      )}
                      {candidates.map((c) => (
                        <TableRow key={c.id}>
                          <TableCell>
                            <Checkbox
                              checked={checked.has(c.id)}
                              onCheckedChange={() =>
                                setChecked((prev) => {
                                  const next = new Set(prev);
                                  if (next.has(c.id)) next.delete(c.id);
                                  else next.add(c.id);
                                  return next;
                                })
                              }
                            />
                          </TableCell>
                          <TableCell className="font-mono text-sm">{c.host}</TableCell>
                          <TableCell>
                            {c.relevance > 0 ? (
                              <Badge variant={c.relevance >= 60 ? "secondary" : "outline"}>
                                {c.relevance}
                              </Badge>
                            ) : (
                              <span className="text-muted-foreground">—</span>
                            )}
                          </TableCell>
                          <TableCell className="max-w-md">
                            <div className="truncate">{c.title || "—"}</div>
                            {c.skip_reason && (
                              <div className="truncate text-xs text-amber-600 dark:text-amber-400">
                                {c.skip_reason}
                              </div>
                            )}
                          </TableCell>
                          <TableCell className="max-w-40 truncate text-xs text-muted-foreground">
                            {c.source_query || "—"}
                          </TableCell>
                          <TableCell className="text-right">
                            <Button
                              size="sm"
                              variant="ghost"
                              disabled={busy}
                              onClick={() => void setStatus([c.id], "approved")}
                            >
                              批准
                            </Button>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </CardContent>
              </Card>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
