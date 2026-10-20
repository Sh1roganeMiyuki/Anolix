// Package zygote 实现"母体预热 + 快拉隔离 worker"机制。
//
// 架构概览：
//
//	┌─────────────────────────────────────────────────────────┐
//	│  宿主                                                    │
//	│                                                          │
//	│  spawn client ──AF_UNIX──► zygote mother (常驻)          │
//	│                                │                         │
//	│                       clone(CLONE_NEW* 6 间房)           │
//	│                                │                         │
//	│                                ▼                         │
//	│                          worker: PID=1 in new PID ns     │
//	│                                  host PID 直传回 client   │
//	└─────────────────────────────────────────────────────────┘
//
// 核心设计点：
//   - 母体不在 PID namespace 中 → clone 返回值即宿主 PID（无需 /proc 扫描）
//   - 一句 clone 带 6 个 CLONE_NEW* → 每个 worker 拥有独立的 6 间房
//   - worker 是母体直接子进程 → 母体用后台 goroutine Wait 收尸
package zygote

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
)

// --- 协议常量 ---

const (
	// MagicBytes 是请求的 4 字节魔数（"ZYGO"），用于快速校验连接合法性。
	MagicBytes = "ZYGO"
	// MaxMsgSize 是单条 JSON 消息的最大字节数（防止恶意/错误的大包）。
	MaxMsgSize = 1 << 20 // 1 MiB
)

// SpawnRequest 是 client → mother 的 spawn 请求。
type SpawnRequest struct {
	// Binary 是 worker 要执行的程序路径（容器内绝对路径）。
	Binary string `json:"binary"`
	// Args 是命令行参数（不含 argv[0]）。
	Args []string `json:"args,omitempty"`
	// Env 是 worker 的环境变量；为空时继承母体环境。
	Env []string `json:"env,omitempty"`
	// Cwd 是 worker 的工作目录；为空时继承母体。
	Cwd string `json:"cwd,omitempty"`
	// WorkerID 是可选的标识符（用于日志/注册/cgroup 叶子名）。
	WorkerID string `json:"worker_id,omitempty"`
	// Limits 可选：本 worker 的资源围栏覆盖（nil = 用母体启动时的默认值）。
	// 让不同 worker 能有不同的 cgroup 限额（见 cgroup.go）。
	Limits *CgroupLimits `json:"limits,omitempty"`
	// T0NS 是客户端发请求前取的 CLOCK_MONOTONIC 纳秒，用于端到端计时。
	// 为 0 时由母体在 clone 前自己取——那样不含 socket 往返与排队，
	// 测“用户感知的启动延迟”时必须由客户端填。
	T0NS int64 `json:"t0_ns,omitempty"`
}

// SpawnResponse 是 mother → client 的 spawn 响应。
type SpawnResponse struct {
	// HostPID 是 worker 在宿主 PID namespace 中的进程号。
	// 这是整个 zygote 协议的核心产出：client 拿到它就能 kill/管理 worker。
	HostPID int `json:"host_pid"`
	// Error 非空时表示 spawn 失败，HostPID 无意义。
	Error string `json:"error,omitempty"`
}

// --- 编解码（长度前缀 + JSON） ---

// WriteRequest 将请求编码写入 conn。
// 格式：4 字节魔数 + 4 字节大端长度 + JSON payload。
func WriteRequest(conn net.Conn, req *SpawnRequest) error {
	payload, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("序列化请求失败: %w", err)
	}
	return writeFrame(conn, []byte(MagicBytes), payload)
}

// ReadRequest 从 conn 读取并解码请求。
func ReadRequest(conn net.Conn) (*SpawnRequest, error) {
	magic, payload, err := readFrame(conn)
	if err != nil {
		return nil, err
	}
	if string(magic) != MagicBytes {
		return nil, fmt.Errorf("魔数不匹配: got %q, want %q", magic, MagicBytes)
	}
	var req SpawnRequest
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, fmt.Errorf("解析请求 JSON 失败: %w", err)
	}
	return &req, nil
}

// WriteResponse 将响应编码写入 conn。
// 格式：4 字节大端长度 + JSON payload（响应不带魔数，简化解析）。
func WriteResponse(conn net.Conn, resp *SpawnResponse) error {
	payload, err := json.Marshal(resp)
	if err != nil {
		return fmt.Errorf("序列化响应失败: %w", err)
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(payload)))
	if _, err := conn.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err = conn.Write(payload)
	return err
}

// ReadResponse 从 conn 读取并解码响应。
func ReadResponse(conn net.Conn) (*SpawnResponse, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, fmt.Errorf("读取响应长度失败: %w", err)
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n > MaxMsgSize {
		return nil, fmt.Errorf("响应过大: %d bytes", n)
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, fmt.Errorf("读取响应体失败: %w", err)
	}
	var resp SpawnResponse
	if err := json.Unmarshal(payload, &resp); err != nil {
		return nil, fmt.Errorf("解析响应 JSON 失败: %w", err)
	}
	return &resp, nil
}

// --- 内部帧读写 ---

func writeFrame(w io.Writer, magic, payload []byte) error {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(payload)))
	// 魔数 + 长度 + 体
	buf := make([]byte, 0, 4+4+len(payload))
	buf = append(buf, magic...)
	buf = append(buf, lenBuf[:]...)
	buf = append(buf, payload...)
	_, err := w.Write(buf)
	return err
}

func readFrame(r io.Reader) (magic, payload []byte, err error) {
	magic = make([]byte, 4)
	if _, err = io.ReadFull(r, magic); err != nil {
		return nil, nil, fmt.Errorf("读取魔数失败: %w", err)
	}
	var lenBuf [4]byte
	if _, err = io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, nil, fmt.Errorf("读取长度失败: %w", err)
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n > MaxMsgSize {
		return nil, nil, fmt.Errorf("消息过大: %d bytes", n)
	}
	payload = make([]byte, n)
	if _, err = io.ReadFull(r, payload); err != nil {
		return nil, nil, fmt.Errorf("读取消息体失败: %w", err)
	}
	return magic, payload, nil
}
