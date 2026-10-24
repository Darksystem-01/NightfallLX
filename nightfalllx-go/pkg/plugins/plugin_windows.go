//go:build windows

package plugins

import (
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

// windowsDLLPlugin wraps an exported Windows DLL into the NightfallLX Plugin interface.
type windowsDLLPlugin struct {
	name     string
	handle   syscall.Handle
	nameProc uintptr
	execProc uintptr
}

func (p *windowsDLLPlugin) Name() string {
	if p.name != "" {
		return p.name
	}
	return "windows-dll-plugin"
}

func (p *windowsDLLPlugin) Execute(target string, client *http.Client) (string, error) {
	if p.execProc == 0 {
		return "", fmt.Errorf("plugin DLL does not export an 'Execute' procedure")
	}

	targetBytes, err := syscall.BytePtrFromString(target)
	if err != nil {
		return "", fmt.Errorf("encode target: %w", err)
	}

	buf := make([]byte, 64*1024)
	r1, _, errCall := syscall.SyscallN(
		p.execProc,
		uintptr(unsafe.Pointer(targetBytes)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	if r1 == 0 && errCall != 0 && errCall != syscall.Errno(0) {
		return "", fmt.Errorf("execute plugin procedure failed: %w", errCall)
	}

	n := int(r1)
	if n > 0 && n <= len(buf) {
		return strings.TrimSpace(string(buf[:n])), nil
	}

	for i, b := range buf {
		if b == 0 {
			return strings.TrimSpace(string(buf[:i])), nil
		}
	}
	return strings.TrimSpace(string(buf)), nil
}

// loadFilePlatform opens a dynamic link library (.dll) on Windows and resolves procedures.
func loadFilePlatform(path string) Loaded {
	result := Loaded{Path: path}

	handle, err := syscall.LoadLibrary(path)
	if err != nil {
		result.Error = fmt.Errorf("load windows plugin DLL: %w", err)
		return result
	}

	execProc, errExec := syscall.GetProcAddress(handle, "Execute")
	if errExec != nil || execProc == 0 {
		_ = syscall.FreeLibrary(handle)
		result.Error = fmt.Errorf("plugin DLL %q does not export required 'Execute' procedure", filepath.Base(path))
		return result
	}

	nameProc, _ := syscall.GetProcAddress(handle, "Name")
	pluginName := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))

	if nameProc != 0 {
		buf := make([]byte, 256)
		r1, _, _ := syscall.SyscallN(nameProc, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
		n := int(r1)
		if n > 0 && n <= len(buf) {
			pluginName = strings.TrimSpace(string(buf[:n]))
		} else {
			for i, b := range buf {
				if b == 0 {
					if s := strings.TrimSpace(string(buf[:i])); s != "" {
						pluginName = s
					}
					break
				}
			}
		}
	}

	result.Plugin = &windowsDLLPlugin{
		name:     pluginName,
		handle:   handle,
		nameProc: nameProc,
		execProc: execProc,
	}
	result.Name = pluginName
	return result
}
