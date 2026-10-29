package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

// Coverage ledger tools.
//
// These are the only way agents touch coverage_ledger, and they exist so that
// "what is left to test" becomes a query instead of a guess:
//   - mark_coverage   — worker writes back what it actually tried (state + attempts)
//   - list_coverage_gaps — planner reads the worklist
//
// Neither tool expands the ledger; expansion happens server-side from task scope
// (db.ExpandCoverage), so an agent can never invent coverage rows for out-of-scope
// assets.

// covGuard is the shared precondition check: these tools need both a task and an
// asset store, and are meaningless when the coverage feature is off for the task.
func (t *ToolSet) covGuard(name string) error {
	if t.as == nil {
		return fmt.Errorf("%s 未启用：AssetStore 未初始化", name)
	}
	if t.taskID <= 0 {
		return fmt.Errorf("%s 需要任务上下文（当前没有 task_id）", name)
	}
	if t.coverageDisabled {
		return fmt.Errorf("%s 不可用：本任务已关闭资产覆盖度功能", name)
	}
	return nil
}

// coverageMarkItem is one cell write-back.
type coverageMarkItem struct {
	AssetID   json.RawMessage `json:"asset_id"`
	Param     string          `json:"param"`
	VulnClass string          `json:"vulnclass"`
	State     string          `json:"state"`
	Attempts  int             `json:"attempts"`
	IntentID  json.RawMessage `json:"intent_id"`
	FactID    json.RawMessage `json:"fact_id"`
	FindingID json.RawMessage `json:"finding_node_id"`
	Note      string          `json:"note"`
}

// normalized fills defaults so a caller can write the common case compactly.
func (c coverageMarkItem) normalized() coverageMarkItem {
	c.VulnClass = strings.TrimSpace(c.VulnClass)
	c.State = strings.TrimSpace(c.State)
	if c.State == "" {
		// A state-less write means "I tried and found nothing" — the most common
		// write-back. Requiring an explicit state here just produced noise.
		c.State = db.CovTriedNegative
	}
	c.Param = strings.TrimSpace(c.Param)
	return c
}

func (t *ToolSet) markCoverage() actool.CoreTool {
	return writeTool("mark_coverage",
		"把【这次实际测过的东西】写进覆盖台账：哪个资产的哪个参数、打了哪一类漏洞、结果如何。\n"+
			"**这是让规划者知道「哪类还没打」的唯一途径**——不写台账，你测过的东西下一次会被当成没测过（重复劳动），而你没测的东西也永远不会被派工。\n"+
			"参数：\n"+
			"  · vulnclass 必填，必须是 vulnclass-coverage 表里的标准 id（sqli/xss_reflected/idor/ssrf/file_upload/…）。\n"+
			"  · asset_id 必填，本意图目标资产的 id（来自 list_assets 或意图的 asset_ids）。\n"+
			"  · param：测的是哪个参数；资产级结论（端口/配置/指纹类）留空。\n"+
			"  · state：untested / tried_negative（试过没信号，默认）/ suspected（有线索未验证）/ confirmed（已确认）/ na（不适用，note 写理由）。\n"+
			"  · attempts：**tried_negative 必填**，本次试过几种【彼此不同】的打法。少于 "+
			strconv.Itoa(db.CoverageAttemptsBar)+" 次会被规划者当成「还没探够」重新派工——如实填，别凑数。\n"+
			"  · finding_node_id：**confirmed 必填**，用 report_finding 返回的 finding_node_id。\n"+
			"  · fact_id：本次结论对应的 fact 节点 id（record_fact 返回）。\n"+
			"多条一起写用 cells 数组。返回 {marked, errors}。",
		obj(map[string]any{
			"cells": map[string]any{
				"type":        "array",
				"description": "批量：元素字段同下方顶层字段。",
				"items":       map[string]any{"type": "object"},
			},
			"vulnclass":       str("标准漏洞类 id（见 vulnclass-coverage skill），如 sqli / idor / ssrf"),
			"asset_id":        idp("目标资产 id（必填）"),
			"param":           str("被测参数名；资产级结论（端口/配置/组件）留空"),
			"state":           str("tried_negative（默认）| suspected | confirmed | untested | na"),
			"attempts":        intp("tried_negative 必填：本次试过几种彼此不同的打法"),
			"intent_id":       idp("产生本次结论的意图 id（可选）"),
			"fact_id":         idp("对应 fact 节点 id（可选）"),
			"finding_node_id": idp("confirmed 必填：report_finding 返回的 finding_node_id"),
			"note":            str("补充说明（na 时必填理由；否定结论建议写试过哪几种打法）"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if err := t.covGuard("mark_coverage"); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			var a struct {
				Cells []coverageMarkItem `json:"cells"`
				coverageMarkItem
			}
			_ = json.Unmarshal(in, &a)
			items := a.Cells
			if len(items) == 0 {
				items = []coverageMarkItem{a.coverageMarkItem}
			}

			marked := 0
			errs := map[string]string{}
			for i, raw := range items {
				it := raw.normalized()
				assetID := pid(it.AssetID)
				if assetID <= 0 {
					errs[strconv.Itoa(i)] = "asset_id 必填"
					continue
				}
				m := db.CoverageMark{
					AssetID:   assetID,
					Param:     it.Param,
					VulnClass: it.VulnClass,
					State:     it.State,
					Attempts:  it.Attempts,
					IntentID:  pid(it.IntentID),
					FactID:    pid(it.FactID),
					FindingID: pid(it.FindingID),
					Note:      it.Note,
				}
				if m.IntentID == 0 {
					m.IntentID = t.ownerNodeID()
				}
				if err := t.as.MarkCoverage(t.taskID, m); err != nil {
					errs[strconv.Itoa(i)] = err.Error()
					continue
				}
				marked++
			}
			out := map[string]any{"marked": marked}
			if len(errs) > 0 {
				out["errors"] = errs
			}
			return jsonResult(out)
		})
}

// ownerNodeID returns the intent this ToolSet belongs to (0 when unknown). Workers
// set it to their intent; planner-side writes default to the task root.
func (t *ToolSet) ownerNodeID() int64 { return t.ownerNode }

func (t *ToolSet) listCoverageGaps() actool.CoreTool {
	return readTool("list_coverage_gaps",
		"查【本任务】还没打透的漏洞类单元格——这是你派工的工作清单。\n"+
			"包含三类：untested（完全没碰）、suspected（有线索没验证）、tried_negative 但 attempts < "+
			strconv.Itoa(db.CoverageAttemptsBar)+"（试过但没探够）。\n"+
			"返回 {gaps:[{asset_id,asset_type,label,param,vulnclass,state,attempts}], total}，按「有线索优先、尝试次数少的优先」排序。\n"+
			"用法：**先看缺口再想方向**。看到「某资产的 sqli attempts=1」就派「补齐手段」的意图；看到「untested 的 ssrf」就派新方向。\n"+
			"可选过滤：vulnclass 只看某一类；asset_id 只看某个资产；limit 默认 40（上限 200）。",
		obj(map[string]any{
			"vulnclass": str("只看某一类（可选），如 sqli"),
			"asset_id":  idp("只看某个资产（可选）"),
			"limit":     intp("返回条数，默认 40，上限 200"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if err := t.covGuard("list_coverage_gaps"); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			var a struct {
				VulnClass string          `json:"vulnclass"`
				AssetID   json.RawMessage `json:"asset_id"`
				Limit     int             `json:"limit"`
			}
			_ = json.Unmarshal(in, &a)
			gaps, total, err := t.as.ListCoverageGaps(t.taskID, strings.TrimSpace(a.VulnClass), pid(a.AssetID), a.Limit)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(map[string]any{"gaps": gaps, "total": total})
		})
}

// coverageRollup builds the compact per-class summary injected into the planner's
// situational overview. Deliberately small: the planner needs "which classes are
// untouched", not 20k rows.
func (t *ToolSet) coverageRollup() map[string]any {
	if t.as == nil || t.taskID <= 0 || t.coverageDisabled {
		return nil
	}
	sum, err := t.as.CoverageSummary(t.taskID)
	if err != nil || sum == nil || sum.Cells == 0 {
		return nil
	}
	type classLine struct {
		VulnClass string `json:"vulnclass"`
		Total     int    `json:"total"`
		Touched   int    `json:"touched"`
		Confirmed int    `json:"confirmed"`
		Attempts  int    `json:"attempts"`
	}
	lines := make([]classLine, 0, len(sum.ByClass))
	var untouched []string
	for _, c := range sum.ByClass {
		lines = append(lines, classLine{c.VulnClass, c.Total, c.Touched, c.Confirmed, c.Attempts})
		if c.Touched == 0 {
			untouched = append(untouched, c.VulnClass)
		}
	}
	out := map[string]any{
		"cells":     sum.Cells,
		"touched":   sum.Touched,
		"confirmed": sum.Confirmed,
		"by_class":  lines,
	}
	if sum.Pct != nil {
		out["pct"] = *sum.Pct
	}
	if len(untouched) > 0 {
		out["untouched_classes"] = untouched
	}
	out["note"] = "漏洞类覆盖台账（按 asset×param×vulnclass 单元格统计）。pct 是下限：tried_negative 会把 pct 拉高，但 attempts<" +
		strconv.Itoa(db.CoverageAttemptsBar) + " 的否定不算探透。要具体缺口用 list_coverage_gaps。"
	return out
}
