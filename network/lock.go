package network

import (
	"os"
	"syscall"
)

// fileLock 是基于 flock 的进程间互斥锁。
//
// 白话：网络资源（网桥、nft 表、IP 地址池）是全局共享的，
// 两个 anolix 进程同时启动容器时，必须有人先到先得。
// flock 的锁跟着打开的文件描述符走，进程退出（哪怕被 SIGKILL）内核会自动释放，
// 不会留下「死锁文件」。
type fileLock struct {
	f *os.File
}

// acquireLock 打开（或创建）锁文件并阻塞直到拿到排他锁。
func acquireLock(path string) (*fileLock, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, err
	}
	return &fileLock{f: f}, nil
}

// Close 释放锁并关闭文件。
func (l *fileLock) Close() error {
	if l == nil || l.f == nil {
		return nil
	}
	_ = syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN)
	err := l.f.Close()
	l.f = nil
	return err
}
