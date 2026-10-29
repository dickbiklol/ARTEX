"use client";

// 漏洞类覆盖台账 tab.
//
// 与「资产覆盖图」互补，而不是替代：资产覆盖图回答「哪些资产被人碰过」，这个 tab
// 回答「哪一类漏洞在哪个资产上还没试过」。后者才是漏报的直接来源——一个任务可以
// 资产覆盖 100%，却从来没有在任何地方试过 SSRF。
//
// 数据来自 /tasks/{id}/coverage-ledger，与规划者派工时看的是同一份 coverage_ledger。

import * as React from "react";

import { AlertTriangleIcon, CheckCircle2Icon, Loader2Icon, RefreshCwIcon } from "lucide-react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Empty, EmptyDescription, EmptyHeader, EmptyTitle } from "@/components/ui/empty";
import { Progress } from "@/components/ui/progress";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { Skeleton } from "@/components/ui/skeleton";
import { api } from "@/lib/api";
import type { CoverageClassStat, CoverageGap, CoverageLedgerData } from "@/lib/types";

const ALL = "__all__";
const GAP_LIMIT = 120;

// 缺口排序：有线索的（suspected）最值钱，其次是完全没碰的，最后是没探够的否定。
const GAP_ORDER: Record<string, number> = { suspected: 0, untested: 1, tried_negative: 2 };

function stateMeta(state: string): { label: string; className: string } {
  switch (state) {
    case "suspected":
      return { label: "有线索", className: "border-amber-500/50 text-amber-600 dark:text-amber-400" };
    case "untested":
      return { label: "未碰", className: "border-muted-foreground/40 text-muted-foreground" };
    case "tried_negative":
      return { label: "没探够", className: "border-orange-500/40 text-orange-600 dark:text-orange-400" };
    case "confirmed":
      return { label: "已确认", className: "border-emerald-500/50 text-emerald-600 dark:text-emerald-400" };
    case "na":
      return { label: "不适用", className: "border-muted-foreground/30 text-muted-foreground" };
    default:
      return { label: state || "—", className: "" };
  }
}

function pct1(part: number, whole: number): number {
  if (whole <= 0) return 0;
  return Math.round((part / whole) * 1000) / 10;
}

export function VulnClassTab({ taskId, coverageEnabled }: { taskId: string; coverageEnabled: boolean }) {
  const [data, setData] = React.useState<CoverageLedgerData | null>(null);
  const [error, setError] = React.useState("");
  const [loading, setLoading] = React.useState(true);
  const [filter, setFilter] = React.useState<string>(ALL);

  const load = React.useCallback(
    async (disposed?: () => boolean) => {
      try {
        const res = await api.taskCoverageLedger(taskId, {
          limit: GAP_LIMIT,
          vulnclass: filter === ALL ? undefined : filter,
        });
        if (disposed?.()) return;
        setData(res);
        setError("");
      } catch (e) {
        if (!disposed?.()) setError((e as Error).message);
      } finally {
        if (!disposed?.()) setLoading(false);
      }
    },
    [taskId, filter],
  );

  React.useEffect(() => {
    let cancelled = false;
    setLoading(true);
    void load(() => cancelled);
    // 台账由 worker 持续写入，慢轮询即可；这个 tab 不是实时监控面板。
    const timer = setInterval(() => void load(() => cancelled), 5000);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [load]);

  const labelFor = React.useMemo(() => {
    const map = new Map<string, string>();
    for (const c of data?.catalog ?? []) map.set(c.id, c.label);
    return (id: string) => map.get(id) ?? id;
  }, [data?.catalog]);

  if (!coverageEnabled) {
    return (
      <Alert>
        <AlertTriangleIcon />
        <AlertTitle>本任务未开启覆盖度功能</AlertTitle>
        <AlertDescription>漏洞类覆盖台账随覆盖度功能一起关闭，因此没有数据可展示。</AlertDescription>
      </Alert>
    );
  }

  if (loading && !data) {
    return (
      <div className="flex flex-col gap-3">
        <Skeleton className="h-24 w-full" />
        <Skeleton className="h-64 w-full" />
      </div>
    );
  }

  if (error && !data) {
    return (
      <Alert variant="destructive">
        <AlertTriangleIcon />
        <AlertTitle>读取覆盖台账失败</AlertTitle>
        <AlertDescription>{error}</AlertDescription>
      </Alert>
    );
  }

  const classes = data?.by_class ?? [];
  const gaps = data?.gaps ?? [];
  // 后端已按「有线索优先、尝试少优先」排序；这里再按状态分一层，纯前端展示需要。
  const sortedGaps = [...gaps].sort(
    (a, b) => (GAP_ORDER[a.state] ?? 9) - (GAP_ORDER[b.state] ?? 9) || a.attempts - b.attempts,
  );
  const cells = data?.cells ?? 0;
  const untouched = classes.reduce((sum, c) => sum + (c.total - c.touched), 0);
  const confirmed = data?.confirmed ?? 0;

  return (
    <div className="flex flex-col gap-4">
      {/* 概览 */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>台账格子总数</CardDescription>
            <CardTitle className="text-2xl">{cells}</CardTitle>
          </CardHeader>
          <CardContent className="text-muted-foreground text-xs">asset × param × vulnclass</CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>已碰过</CardDescription>
            <CardTitle className="text-2xl">{data?.touched ?? 0}</CardTitle>
          </CardHeader>
          <CardContent>
            <Progress value={pct1(data?.touched ?? 0, cells)} />
            <p className="text-muted-foreground mt-1.5 text-xs">碰过 ≠ 探够，见下方缺口</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>完全没碰</CardDescription>
            <CardTitle className="text-2xl">{untouched}</CardTitle>
          </CardHeader>
          <CardContent className="text-muted-foreground text-xs">
            {cells > 0 ? `${pct1(untouched, cells)}% 的格子还没人试过` : "台账尚未展开"}
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>已确认漏洞</CardDescription>
            <CardTitle className="text-2xl">{confirmed}</CardTitle>
          </CardHeader>
          <CardContent className="text-muted-foreground text-xs">带 finding 引用的格子</CardContent>
        </Card>
      </div>

      {cells === 0 && (
        <Alert>
          <AlertTriangleIcon />
          <AlertTitle>台账还没有数据</AlertTitle>
          <AlertDescription>
            覆盖台账在任务锚定测试范围后由系统展开。若范围为空，先确认本任务已有 scope
            （测试范围）与已识别资产。
          </AlertDescription>
        </Alert>
      )}

      {/* 分类统计 */}
      <Card>
        <CardHeader className="flex-row items-center justify-between gap-3 space-y-0">
          <div className="min-w-0">
            <CardTitle className="text-base">按漏洞类</CardTitle>
            <CardDescription>
              某一类整体 <span className="text-foreground font-mono">touched/total</span> 偏低，说明这一类整批没打——不是
              「打了没有」。
            </CardDescription>
          </div>
          <div className="flex shrink-0 items-center gap-2">
            <Select value={filter} onValueChange={setFilter}>
              <SelectTrigger className="w-40">
                <SelectValue placeholder="全部漏洞类" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value={ALL}>全部漏洞类</SelectItem>
                {classes.map((c) => (
                  <SelectItem key={c.vulnclass} value={c.vulnclass}>
                    {labelFor(c.vulnclass)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Button size="icon" variant="ghost" onClick={() => void load()} title="刷新">
              <RefreshCwIcon className="size-4" />
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {classes.length === 0 ? (
            <Empty>
              <EmptyHeader>
                <EmptyTitle>暂无分类数据</EmptyTitle>
                <EmptyDescription>台账展开后这里会按漏洞类显示总数、已碰、已确认。</EmptyDescription>
              </EmptyHeader>
            </Empty>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[640px] text-sm">
                <thead>
                  <tr className="text-muted-foreground border-border border-b text-left text-xs">
                    <th className="py-2 pr-3 font-medium">漏洞类</th>
                    <th className="py-2 pr-3 font-medium">已碰 / 总数</th>
                    <th className="py-2 pr-3 font-medium">已确认</th>
                    <th className="py-2 pr-3 font-medium">否定</th>
                    <th className="py-2 pr-3 font-medium">累计尝试</th>
                    <th className="py-2 font-medium">进度</th>
                  </tr>
                </thead>
                <tbody>
                  {classes.map((c: CoverageClassStat) => (
                    <tr key={c.vulnclass} className="border-border/60 border-b last:border-0">
                      <td className="py-2 pr-3">
                        <span className="text-foreground">{labelFor(c.vulnclass)}</span>
                        <span className="text-muted-foreground ml-1.5 font-mono text-[11px]">{c.vulnclass}</span>
                      </td>
                      <td className="py-2 pr-3 font-mono">
                        {c.touched} / {c.total}
                      </td>
                      <td className="py-2 pr-3">
                        {c.confirmed > 0 ? (
                          <Badge variant="outline" className="border-emerald-500/50 text-emerald-600">
                            <CheckCircle2Icon className="size-3" />
                            {c.confirmed}
                          </Badge>
                        ) : (
                          <span className="text-muted-foreground">0</span>
                        )}
                      </td>
                      <td className="py-2 pr-3 font-mono">{c.negative}</td>
                      <td className="py-2 pr-3 font-mono">{c.attempts}</td>
                      <td className="py-2">
                        <div className="flex items-center gap-2">
                          <Progress value={pct1(c.touched, c.total)} className="h-1.5 w-24" />
                          <span className="text-muted-foreground w-10 font-mono text-[11px]">
                            {pct1(c.touched, c.total)}%
                          </span>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* 缺口清单 */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">待打缺口</CardTitle>
          <CardDescription>
            共 <span className="text-foreground font-mono">{data?.gaps_total ?? 0}</span> 个，显示前 {sortedGaps.length} 个。
            「没探够」指试过但打法不足 3 种，被系统视作尚未排除。
          </CardDescription>
        </CardHeader>
        <CardContent>
          {sortedGaps.length === 0 ? (
            <Empty>
              <EmptyHeader>
                <EmptyTitle>没有待打缺口</EmptyTitle>
                <EmptyDescription>当前范围内的资产在已展开的漏洞类上都已经探够或已确认。</EmptyDescription>
              </EmptyHeader>
            </Empty>
          ) : (
            <ul className="flex flex-col">
              {sortedGaps.map((g: CoverageGap, i) => {
                const meta = stateMeta(g.state);
                return (
                  <li key={`${g.asset_id}-${g.param}-${g.vulnclass}-${i}`}>
                    {i > 0 && <Separator className="my-1" />}
                    <div className="flex flex-wrap items-center gap-2 py-1.5 text-sm">
                      <Badge variant="outline" className={meta.className}>
                        {meta.label}
                      </Badge>
                      <span className="text-muted-foreground shrink-0 font-mono text-[11px]">#{g.asset_id}</span>
                      <span className="text-foreground min-w-32 flex-1 truncate" title={g.label}>
                        {g.label || "—"}
                      </span>
                      <span className="text-muted-foreground shrink-0 text-xs">{labelFor(g.vulnclass)}</span>
                      {g.param ? (
                        <span className="text-muted-foreground shrink-0 font-mono text-[11px]">?{g.param}</span>
                      ) : null}
                      {g.attempts > 0 && (
                        <span className="text-muted-foreground shrink-0 font-mono text-[11px]">试 {g.attempts} 次</span>
                      )}
                    </div>
                  </li>
                );
              })}
            </ul>
          )}
        </CardContent>
      </Card>

      {loading && (
        <p className="text-muted-foreground flex items-center gap-1.5 text-xs">
          <Loader2Icon className="size-3 animate-spin" />
          刷新中
        </p>
      )}
    </div>
  );
}
