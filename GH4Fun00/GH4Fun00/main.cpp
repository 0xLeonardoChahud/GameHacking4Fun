// Disabling warnings for libraries.
#pragma warning(push)
#pragma warning(disable: 4365 4668 5039 4820 5204 4625 4626 5027 4710 4191 5045 4711)

// Enables us to handle strings more easily.
#include <string>

// Managing bits in Dr7 registers. This is for convenience only.
#include <bitset>

// Windows API
#include <Windows.h>

// For demangling function names from Export Address Table (EAT).
#include <DbgHelp.h>

// For ASCII/UNICODE compatibility.
#include <tchar.h>

// For setting hardware breakpoints and handler functions.
#include <debugapi.h>

// For process enumeration and access.
#include <TlHelp32.h>

// Enables the use of RAII wrapped Windows API objects.
#include <wil/resource.h>
#pragma warning(pop)

#pragma comment(lib, "Dbghelp.lib")

// disable padding warnings.
#pragma warning(disable: 4820)

// disable warning for spectre mitigation.
#pragma warning(disable: 5045)

// Disabling function removal warning.
#pragma warning(disable: 4514)

// Disabling inline warning.
#pragma warning(disable: 4710)

// If we are using UNICODE, Windows API functions will expect wchar_t[] string arrays.
#ifdef UNICODE
using String = std::wstring;
#else
using String = std::string;
#endif

// Simple class for handling player's variables.
class Player {
public:

	Player() {
		m_valid = false;
		m_life = nullptr;
		m_proc.reset();
	}

	Player(const Player&) = delete;
	Player operator=(const Player&) = delete;

	Player(Player&&) = delete;
	Player operator=(Player&&) = delete;

	void init(const DWORD Pid) {
		m_proc.reset(::OpenProcess(PROCESS_ALL_ACCESS, false, Pid));
		if (!m_proc)
			m_valid = false;
		else
			m_valid = true;
	}

	void set_players_life_mem(PVOID ptr) {
		m_life = ptr;
	}

	PVOID get_lifes_addr() const { return m_life; }

	void set_life(const float value) {
		if (!m_valid)
			return;

		size_t written{ 0 };
		::WriteProcessMemory(
			m_proc.get(),
			m_life,
			&value,
			sizeof(value),
			&written
		);
	}

	float get_life() const {
		if (!m_valid)
			return -1;
		
		float ret{ -1 };
		size_t read{ 0 };
		::ReadProcessMemory(
			m_proc.get(),
			m_life,
			&ret,
			sizeof(float),
			&read
		);

		return ret;
	}

private:
	PVOID m_life;
	wil::unique_handle m_proc;
	bool m_valid;
};

// RAII for suspending and resuming thread.
class SRThread {
public:
	SRThread(HANDLE hThread) {
		m_thr = hThread;
		if (::SuspendThread(m_thr) == -1)
			m_suspended = false;	
		else 
			m_suspended = true;
	}

	~SRThread() {
		if (m_suspended)
			::ResumeThread(m_thr);
	}

private:
	bool m_suspended;
	HANDLE m_thr;
};

// Get process id based on the process name.
DWORD get_process_pid(const String& Name) {
	wil::unique_handle hSnap(::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
	if (!hSnap)
		return 0;

	PROCESSENTRY32 pew{ sizeof(PROCESSENTRY32) };

	if (!::Process32First(hSnap.get(), &pew))
		return 0;

	do {
		if (!String(pew.szExeFile).compare(Name)) {
			// found
			return pew.th32ProcessID;
		}
	} while (::Process32Next(hSnap.get(), &pew));

	return 0;
}

// Get DLL's module address from the remote process.
PVOID get_module_address(const String& ModuleName, const DWORD Pid, String& ModulePath) {
	wil::unique_handle hSnap(::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, Pid));
	if (!hSnap)
		return nullptr;

	MODULEENTRY32 mod{ sizeof(MODULEENTRY32) };
	if (!::Module32First(hSnap.get(), &mod))
		return nullptr;

	do {

		String curmod(mod.szExePath);
		curmod = curmod.substr(curmod.find_last_of(TEXT("\\")) + 1);

		if (curmod == ModuleName) {
			// found
			ModulePath = mod.szExePath;
			return mod.modBaseAddr;
		}

	} while (::Module32Next(hSnap.get(), &mod));

	return nullptr;
}

// Get function offset from the DLL's when it's loaded in memory.
int64_t get_fcn_rva(const std::string& FunctionName, const String& ModulePath) {
	wil::unique_handle hFile(::CreateFile(
		ModulePath.data(),
		GENERIC_READ,
		FILE_SHARE_READ,
		nullptr,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		nullptr
	));

	if (!hFile)
		return -1;

	wil::unique_handle hMap(
		::CreateFileMapping(
			hFile.get(),
			nullptr,
			PAGE_READONLY | SEC_IMAGE_NO_EXECUTE,
			0,
			0,
			nullptr
		)
	);

	if (!hMap)
		return -1;

	auto ptr = static_cast<PBYTE>(::MapViewOfFile(
		hMap.get(),
		FILE_MAP_READ,
		0,
		0,
		0
	));
	
	if (!ptr)
		return -1;

	auto pdos = reinterpret_cast<PIMAGE_DOS_HEADER>(ptr);
	auto pnt = reinterpret_cast<PIMAGE_NT_HEADERS>(ptr + pdos->e_lfanew);
	auto idd = pnt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	auto ied = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(ptr + idd.VirtualAddress);

	auto pe_rva = [ptr](DWORD value) {
		return (ptr + value);
		};

	auto aof = reinterpret_cast<PDWORD>(pe_rva(ied->AddressOfFunctions));
	auto aon = reinterpret_cast<PDWORD>(pe_rva(ied->AddressOfNames));
	int64_t ret_rva = -1;
	for (size_t i = 0; i < ied->NumberOfNames; i++) {

		auto fcn_rva = aof[i];
		auto fname = std::string(reinterpret_cast<char*>(pe_rva(aon[i])));
		std::string dfname;
		dfname.resize(fname.size() + 1);


		::UnDecorateSymbolName(fname.data(), const_cast<PSTR>(dfname.data()), static_cast<DWORD>(fname.size()), UNDNAME_NAME_ONLY);

		if (dfname.find(FunctionName) != std::string::npos) {
			// found function
			ret_rva = fcn_rva;
			break;
		}
	}

	::UnmapViewOfFile(ptr);

	return ret_rva;
}

// Enable hardware breakpoints on the remote process.
void enable_hwbp(const DWORD Pid, const PVOID Func, const uint64_t CodeOffset) {
	const PBYTE code = static_cast<PBYTE>(Func) + CodeOffset;

	wil::unique_handle hSnap(::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0));
	if (!hSnap)
		return;

	THREADENTRY32 te{ sizeof(THREADENTRY32) };

	if (!::Thread32First(hSnap.get(), &te))
		return;

	do {

		// Thread needs to belong to the game's process.
		if (te.th32OwnerProcessID == Pid) {

			// We will setup the debug registers only.
			CONTEXT ctx{ 0 };
			ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

			wil::unique_handle hThread(::OpenThread(THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, false, te.th32ThreadID));
			if (!hThread)
				continue;

			// Thread will be suspended from this point on until this object is destroyed.
			SRThread srt(hThread.get());

			if (!::GetThreadContext(hThread.get(), &ctx))
				continue;

			std::bitset<64> tmp(ctx.Dr7);
			tmp.set(0, true);
			tmp.set(16, false);
			tmp.set(17, false);
			tmp.set(18, false);
			tmp.set(19, false);

			ctx.Dr0 = reinterpret_cast<DWORD64>(code);
			ctx.Dr7 = tmp.to_ullong();

			if (!::SetThreadContext(hThread.get(), &ctx))
				continue;

		}


	} while (::Thread32Next(hSnap.get(), &te));
}

// Disable hardware breakpoints on the remote process.
void disable_hwbp(const DWORD Pid) {
	wil::unique_handle hSnap(::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0));
	if (!hSnap)
		return;

	THREADENTRY32 te{ sizeof(THREADENTRY32) };

	if (!::Thread32First(hSnap.get(), &te))
		return;

	do {

		if (te.th32OwnerProcessID == Pid) {
			// Thread to enable debugging.
			CONTEXT ctx{ 0 };
			ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

			wil::unique_handle hThread(::OpenThread(THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, false, te.th32ThreadID));
			if (!hThread)
				continue;

			// Thread will be suspended from this point on until this object is destroyed.
			SRThread srt(hThread.get());

			if (!::GetThreadContext(hThread.get(), &ctx))
				continue;

			std::bitset<64> tmp(ctx.Dr7);
			tmp.set(0, false);
			ctx.Dr0 = 0;
			ctx.Dr7 = tmp.to_ullong();
			
			if (!::SetThreadContext(hThread.get(), &ctx))
				continue;
		}


	} while (::Thread32Next(hSnap.get(), &te));
}

// Try to get player's life memory address.
PVOID try_get_players_health(const DWORD Pid, const PVOID Func, const uint64_t CodeOffset) {
	PBYTE code = static_cast<PBYTE>(Func) + CodeOffset;

	enable_hwbp(Pid, Func, CodeOffset);
	PVOID ret = nullptr;
	while (true) {
		DEBUG_EVENT de{ 0 };

		if (::WaitForDebugEvent(&de, INFINITE)) {
			do {
				if (
					de.dwDebugEventCode == EXCEPTION_DEBUG_EVENT &&
					de.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP &&
					de.u.Exception.ExceptionRecord.ExceptionAddress == (PVOID)code
					) {

					wil::unique_handle hThread{ ::OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, false, de.dwThreadId) };
					if (!hThread) {
						break;
					}

					CONTEXT ctx{ 0 };
					ctx.ContextFlags = CONTEXT_ALL;

					// Thread will be suspended from this point on until this object is destroyed.
					SRThread srt(hThread.get());

					if (!::GetThreadContext(hThread.get(), &ctx)) {
						break;
					}

					ret = reinterpret_cast<PVOID>(ctx.Rcx + 0x164);

					// We need to resume the thread here before disabling the breakpoints.
					// So we simply call the destructor.
					srt.~SRThread();

					disable_hwbp(Pid);
				}
			} while (false);

			::ContinueDebugEvent(
				de.dwProcessId,
				de.dwThreadId,
				DBG_CONTINUE
			);

			if (ret)
				break;
		}
	}


	return ret;
}

// Global variable for convenience only.
Player g_p;

// Function that performs the pipeline for extracting the player's memory life address.
bool bootstrap() {

	_tprintf(TEXT("[+] Bootstraping...\n"));

	// Main game executable.
	const String targetProcName = TEXT("FactoryGameEGS-Win64-Shipping.exe");

	// Target dll that has a function responsible for healing the character.
	const String targetModule = TEXT("FactoryGameEGS-FactoryGame-Win64-Shipping.dll");

	// The healing function name exported by the dll.
	const std::string targetFunction = "UFGHealthComponent::GetCurrentHealth";

	// The offset relative to the healing function that changes/access the player's life.
	const uint64_t codeOffset = 0x0;

	// The target dll path in the local system so we can obtain the offset of the function through EAT parsing.
	String targetModulePath;

	// Getting the game's process id.
	const DWORD targetPid = get_process_pid(targetProcName);

	// Initialize player's struct.
	g_p.init(targetPid);

	// If the game is not running. Nothing to do.
	if (!targetPid)
		return false;

	_tprintf(TEXT("[i] Target PID found: %lu\n"), targetPid);

	// Get target dll's base address.
	PBYTE module = static_cast<PBYTE>(get_module_address(targetModule, targetPid, targetModulePath));
	if (!module)
		return false;

	// Get healing function rva (this offset is relative to the dll loaded in memory).
	int64_t rva = get_fcn_rva(targetFunction, targetModulePath);
	if (rva == -1)
		return false;

	// Get healing function address on the remote process.
	PVOID fcn = module + rva;

	_tprintf(TEXT("[i] Function address found: 0x%p\n"), fcn);
	_tprintf(TEXT("[i] Code address: 0x%p\n"), (PBYTE)fcn + codeOffset);

	// Start debugging the remote process.
	if (!::DebugActiveProcess(targetPid))
		return false;

	// Enables us to kill this program without killing the game's process.
	::DebugSetProcessKillOnExit(false);

	// Try to get player's life address.
	PVOID players_life = try_get_players_health(targetPid, fcn, codeOffset);

	// Stop debugging the remote process.
	::DebugActiveProcessStop(targetPid);

	if (!players_life)
		return false;

	// Update player's life memory address.
	g_p.set_players_life_mem(players_life);

	return true;
}


int _tmain(const int argc, const TCHAR* const argv[]) {

	UNREFERENCED_PARAMETER(argc);
	UNREFERENCED_PARAMETER(argv);
	
	// Sample use.
	if (bootstrap()) {
		_tprintf(TEXT("[i] Player's life: 0x%p\n"), g_p.get_lifes_addr());
		_tprintf(TEXT("[i] Enabling god mode.\n"));
		while (true) {
			// Set life's variable value to 100.0f every second.
			::Sleep(512);
			g_p.set_life(99.0f);
		}
	}

	return 0;
}
