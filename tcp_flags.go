package main

import (
	"fmt"
	"strings"
)

// This is the operator's exact allowlist, not an exhaustive TCP validity test.
// In particular, flags alone cannot validate connection state, payload or ECN
// negotiation, and other standards/extensions may allow unlisted combinations.
type TCPFlagRule struct {
	Mask        uint32 `json:"mask"`
	Combination string `json:"combination"`
	Phase       string `json:"phase"`
	Description string `json:"description"`
}

var tcpFlagRules = []TCPFlagRule{
	{0x02, "SYN", "連線建立", "客戶端發起交握。"},
	{0x12, "SYN, ACK", "連線建立", "伺服器回應交握並確認 SYN。"},
	{0x10, "ACK", "所有階段", "確認收到資料；無法只靠旗標判斷目前連線階段。"},
	{0x18, "PSH, ACK", "資料傳輸", "確認資料並要求儘快交付應用層。"},
	{0x30, "URG, ACK", "資料傳輸", "含緊急指標的資料確認。"},
	{0x38, "URG, PSH, ACK", "資料傳輸", "含緊急資料並要求儘快交付。"},
	{0x11, "FIN, ACK", "連線終止", "正常關閉連線並確認資料。"},
	{0x19, "FIN, PSH, ACK", "連線終止", "交付最後資料並關閉連線。"},
	{0x04, "RST", "例外中斷", "拒絕或重設連線。"},
	{0x14, "RST, ACK", "例外中斷", "重設連線並確認收到的資料。"},
	{0xc2, "SYN, ECE, CWR", "ECN 協商", "客戶端表示支援並請求啟用傳統 ECN。"},
	{0x52, "SYN, ACK, ECE", "ECN 協商", "伺服器同意啟用傳統 ECN。"},
	{0x50, "ACK, ECE", "壅塞回報", "回報 ECN 壅塞訊號。"},
	{0x90, "ACK, CWR", "降速確認", "通知已回應壅塞訊號。"},
	{0x58, "PSH, ACK, ECE", "資料／壅塞回報", "交付資料並回報壅塞。"},
}

type TCPFlagObservation struct {
	Mask  uint32
	Known bool
}
type TCPFlagInfo struct {
	Combination string `json:"combination"`
	RuleMatch   string `json:"rule_match"`
	Verdict     string `json:"verdict"`
	Phase       string `json:"phase"`
}

func flagScope(source string) string {
	if source == "sflow" {
		return "packet"
	}
	return "flow"
}
func classifyTCPFlags(mask uint32, scope string, known bool) TCPFlagInfo {
	if !known || mask > 0xfff {
		return TCPFlagInfo{"UNKNOWN", "unknown", "資料不足", "無法判定"}
	}
	info := TCPFlagInfo{Combination: flagCombination(mask), RuleMatch: "unlisted", Verdict: "非法（依清單）", Phase: "未列入清單"}
	for _, r := range tcpFlagRules {
		if r.Mask == mask {
			info.Combination = r.Combination
			info.RuleMatch = "allowed"
			info.Verdict = "合法（依清單）"
			info.Phase = r.Phase
			break
		}
	}
	if scope != "packet" {
		info.Verdict = "不可判定單包"
		info.Phase = "不可由 Flow 推定"
	}
	return info
}
func flagCombination(mask uint32) string {
	if mask == 0 {
		return "NONE"
	}
	var names []string
	for _, f := range []struct {
		mask uint32
		name string
	}{{1, "FIN"}, {2, "SYN"}, {4, "RST"}, {8, "PSH"}, {16, "ACK"}, {32, "URG"}, {64, "ECE"}, {128, "CWR"}, {256, "AE"}} {
		if mask&f.mask != 0 {
			names = append(names, f.name)
		}
	}
	if reserved := mask & 0xe00; reserved != 0 {
		names = append(names, fmt.Sprintf("RESERVED(0x%03X)", reserved))
	}
	return strings.Join(names, ", ")
}
