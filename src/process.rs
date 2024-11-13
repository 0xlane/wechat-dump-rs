use std::{cell::RefCell, collections::HashMap, rc::Rc};

use anyhow::{anyhow, Context, Result};
use windows::{
    core::PSTR,
    Wdk::System::Threading::{NtQueryInformationProcess, ProcessBasicInformation},
    Win32::{
        Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE, MAX_PATH},
        Storage::FileSystem::{
            GetFileVersionInfoExA, GetFileVersionInfoSizeExA, FILE_VER_GET_LOCALISED,
        },
        System::{
            Diagnostics::{
                Debug::ReadProcessMemory,
                ToolHelp::{
                    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
                    TH32CS_SNAPPROCESS,
                },
            },
            Threading::{
                OpenProcess, QueryFullProcessImageNameA, PEB, PROCESS_ACCESS_RIGHTS,
                PROCESS_BASIC_INFORMATION, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
                PROCESS_VM_READ, RTL_USER_PROCESS_PARAMETERS,
            },
        },
    },
};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ProcessInformatcion {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub exe: String,
    pub cmd: String,
}

#[derive(Debug, Clone)]
pub struct Process {
    pub pid: u32,
    _inner_handle: Rc<RefCell<HANDLE>>,
    _granted_access: RefCell<PROCESS_ACCESS_RIGHTS>,
}

impl Process {
    pub fn new(pid: u32) -> Self {
        Self {
            pid,
            _inner_handle: Rc::new(RefCell::new(INVALID_HANDLE_VALUE)),
            _granted_access: RefCell::new(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ),
        }
    }

    pub unsafe fn get_proc_info(&self) -> Result<ProcessInformatcion> {
        self.check_open()?;

        // Get pname/fullexepath
        let mut exe_len = MAX_PATH;
        let mut exe = [0; MAX_PATH as _];
        QueryFullProcessImageNameA(
            *self._inner_handle.borrow(),
            PROCESS_NAME_WIN32,
            PSTR::from_raw(exe.as_mut_ptr()),
            &mut exe_len,
        )
        .with_context(|| {
            format!(
                "Failed to get process name with PID {}: {}",
                self.pid,
                GetLastError().0
            )
        })?;
        let exe = String::from_utf8(exe.to_vec())
            .with_context(|| "Failed to convert win32 path to string.")?;
        let exe = exe.trim_matches('\x00').to_owned();
        let name = exe
            .split('\\')
            .last()
            .with_context(|| format!("Failed to get name from path: {}", exe))?
            .to_owned();

        // Get pid and ppid
        let mut pbi: PROCESS_BASIC_INFORMATION = std::mem::zeroed();
        let mut pbi_len = 0;
        let status = NtQueryInformationProcess(
            *self._inner_handle.borrow(),
            ProcessBasicInformation,
            &mut pbi as *mut _ as *mut _,
            std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as _,
            &mut pbi_len,
        );
        if status.is_err() {
            return Err(anyhow!(format!(
                "Failed to query process basic information with PID {}: {:X}",
                self.pid, status.0
            )));
        }
        let pid = pbi.UniqueProcessId as u32;
        let ppid = pbi.InheritedFromUniqueProcessId as u32;

        // Get cmd
        let cmd = if self._granted_access.borrow().contains(PROCESS_VM_READ) {
            let mut peb: PEB = std::mem::zeroed();
            ReadProcessMemory(
                *self._inner_handle.borrow(),
                pbi.PebBaseAddress as *const _,
                &mut peb as *mut _ as *mut _,
                std::mem::size_of::<PEB>(),
                None,
            )
            .with_context(|| {
                format!(
                    "Failed to read process peb with PID {}: {}",
                    self.pid,
                    GetLastError().0
                )
            })?;

            let mut proc_params: RTL_USER_PROCESS_PARAMETERS = std::mem::zeroed();
            ReadProcessMemory(
                *self._inner_handle.borrow(),
                peb.ProcessParameters as *const _,
                &mut proc_params as *mut _ as *mut _,
                std::mem::size_of::<RTL_USER_PROCESS_PARAMETERS>(),
                None,
            )
            .with_context(|| {
                format!(
                    "Failed to read process parameters with PID {}: {}",
                    self.pid,
                    GetLastError().0
                )
            })?;

            let mut buf = vec![0u16; (proc_params.CommandLine.Length / 2 + 1) as usize];
            ReadProcessMemory(
                *self._inner_handle.borrow(),
                proc_params.CommandLine.Buffer.as_ptr() as *const _,
                buf.as_mut_ptr() as *mut _,
                proc_params.CommandLine.Length as _,
                None,
            )
            .with_context(|| {
                format!(
                    "Failed to read process cmdline with PID {}: {}",
                    self.pid,
                    GetLastError().0
                )
            })?;
            String::from_utf16(buf.as_slice())
                .with_context(|| "Failed to convert UNICODE_STRING cmdline to string.")?.trim_matches('\x00').to_owned()
        } else {
            "".to_owned()
        };

        Ok(ProcessInformatcion {
            pid,
            ppid,
            name,
            exe,
            cmd,
        })
    }

    pub unsafe fn get_file_info(&self) -> Result<HashMap<String, String>> {
        let pi = self.get_proc_info()?;

        // The following code is refered from https://github.com/yalishandar/tasklist-rs/blob/5c3d0547a32b309538faac091da87128fdf7179b/src/infos/info.rs#L702.

        let mut temp: u32 = 0;

        let mut exe = pi.exe.as_bytes().to_vec();
        exe.push(0x00);

        let len = GetFileVersionInfoSizeExA(
            FILE_VER_GET_LOCALISED,
            PSTR(exe.as_mut_ptr()),
            &mut temp,
        );
        if len == 0 {
            return Err(anyhow!(format!(
                "Failed to get file version info size with {}: {}",
                pi.exe,
                GetLastError().0
            )));
        }

        let mut addr = vec![0u16; len as usize];
        let mut hash: HashMap<String, String> = HashMap::new();
        match GetFileVersionInfoExA(
            FILE_VER_GET_LOCALISED,
            PSTR(exe.as_mut_ptr()),
            0,
            len,
            addr.as_mut_ptr() as _,
        ) {
            Ok(_) => {
                let a = addr.split(|&x| x == 0);
                let mut temp: Vec<String> = vec![];
                for i in a.into_iter() {
                    let ds = String::from_utf16(&i)
                        .with_context(|| "Failed to convert osstring to string.")?;
                    if ds == "" {
                        continue;
                    } else {
                        temp.push(ds);
                    }
                }

                let mut index = 0;

                let s = temp.clone();

                for i in temp {
                    index += 1;
                    if i.contains("CompanyName") {
                        if s[index].contains("FileVersion")
                            || s[index].contains("LegalCopyright")
                            || s[index].contains("InternalName")
                            || s[index].contains("PrivateBuild")
                            || s[index].contains("CompanyName")
                            || s[index].contains("FileDescription")
                            || s[index].contains("OriginalFilename")
                            || s[index].contains("ProductName")
                            || s[index].contains("ProductVersion")
                        {
                            hash.insert("CompanyName".to_string(), String::from(""));
                        } else {
                            hash.insert("CompanyName".to_string(), s[index].clone());
                        }
                    } else if i.contains("FileDescription") {
                        if s[index].contains("FileVersion")
                            || s[index].contains("LegalCopyright")
                            || s[index].contains("InternalName")
                            || s[index].contains("PrivateBuild")
                            || s[index].contains("CompanyName")
                            || s[index].contains("FileDescription")
                            || s[index].contains("OriginalFilename")
                            || s[index].contains("ProductName")
                            || s[index].contains("ProductVersion")
                        {
                            hash.insert("FileDescription".to_string(), String::from(""));
                        } else {
                            hash.insert("FileDescription".to_string(), s[index].clone());
                        }
                    } else if i.contains("OriginalFilename") {
                        if s[index].contains("FileVersion")
                            || s[index].contains("LegalCopyright")
                            || s[index].contains("InternalName")
                            || s[index].contains("PrivateBuild")
                            || s[index].contains("CompanyName")
                            || s[index].contains("FileDescription")
                            || s[index].contains("OriginalFilename")
                            || s[index].contains("ProductName")
                            || s[index].contains("ProductVersion")
                        {
                            hash.insert("OriginalFilename".to_string(), String::from(""));
                        } else {
                            hash.insert("OriginalFilename".to_string(), s[index].clone());
                        }
                    } else if i.contains("ProductName") {
                        if s[index].contains("FileVersion")
                            || s[index].contains("LegalCopyright")
                            || s[index].contains("InternalName")
                            || s[index].contains("PrivateBuild")
                            || s[index].contains("CompanyName")
                            || s[index].contains("FileDescription")
                            || s[index].contains("OriginalFilename")
                            || s[index].contains("ProductName")
                            || s[index].contains("ProductVersion")
                        {
                            hash.insert("ProductName".to_string(), String::from(""));
                        } else {
                            hash.insert("ProductName".to_string(), s[index].clone());
                        }
                    } else if i.contains("ProductVersion") {
                        if s[index].contains("FileVersion")
                            || s[index].contains("LegalCopyright")
                            || s[index].contains("InternalName")
                            || s[index].contains("PrivateBuild")
                            || s[index].contains("CompanyName")
                            || s[index].contains("FileDescription")
                            || s[index].contains("OriginalFilename")
                            || s[index].contains("ProductName")
                            || s[index].contains("ProductVersion")
                        {
                            hash.insert("ProductVersion".to_string(), String::from(""));
                        } else {
                            hash.insert("ProductVersion".to_string(), s[index].clone());
                        }
                    } else if i.contains("PrivateBuild") {
                        if s[index].contains("FileVersion")
                            || s[index].contains("LegalCopyright")
                            || s[index].contains("InternalName")
                            || s[index].contains("PrivateBuild")
                            || s[index].contains("CompanyName")
                            || s[index].contains("FileDescription")
                            || s[index].contains("OriginalFilename")
                            || s[index].contains("ProductName")
                            || s[index].contains("ProductVersion")
                        {
                            hash.insert("PrivateBuild".to_string(), String::from(""));
                        } else {
                            hash.insert("PrivateBuild".to_string(), s[index].clone());
                        }
                    } else if i.contains("InternalName") {
                        if s[index].contains("FileVersion")
                            || s[index].contains("LegalCopyright")
                            || s[index].contains("InternalName")
                            || s[index].contains("PrivateBuild")
                            || s[index].contains("CompanyName")
                            || s[index].contains("FileDescription")
                            || s[index].contains("OriginalFilename")
                            || s[index].contains("ProductName")
                            || s[index].contains("ProductVersion")
                        {
                            hash.insert("InternalName".to_string(), String::from(""));
                        } else {
                            hash.insert("InternalName".to_string(), s[index].clone());
                        }
                    } else if i.contains("LegalCopyright") {
                        if s[index].contains("FileVersion")
                            || s[index].contains("LegalCopyright")
                            || s[index].contains("InternalName")
                            || s[index].contains("PrivateBuild")
                            || s[index].contains("CompanyName")
                            || s[index].contains("FileDescription")
                            || s[index].contains("OriginalFilename")
                            || s[index].contains("ProductName")
                            || s[index].contains("ProductVersion")
                        {
                            hash.insert("LegalCopyright".to_string(), String::from(""));
                        } else {
                            hash.insert("LegalCopyright".to_string(), s[index].clone());
                        }
                    } else if i.contains("FileVersion") {
                        if s[index].contains("FileVersion")
                            || s[index].contains("LegalCopyright")
                            || s[index].contains("InternalName")
                            || s[index].contains("PrivateBuild")
                            || s[index].contains("CompanyName")
                            || s[index].contains("FileDescription")
                            || s[index].contains("OriginalFilename")
                            || s[index].contains("ProductName")
                            || s[index].contains("ProductVersion")
                        {
                            hash.insert("FileVersion".to_string(), String::from(""));
                        } else {
                            hash.insert("FileVersion".to_string(), s[index].clone());
                        }
                    }
                }
                Ok(hash)
            }
            Err(_) => Err(anyhow!(format!(
                "Failed to get file version info with path {}: {}",
                pi.exe,
                GetLastError().0
            ))),
        }
    }

    unsafe fn check_open(&self) -> Result<()> {
        let mut _inner_handle = self._inner_handle.borrow_mut();
        if _inner_handle.is_invalid() {
            let mut handle = OpenProcess(*self._granted_access.borrow(), false, self.pid)
                .unwrap_or(INVALID_HANDLE_VALUE);

            if handle.is_invalid() {
                let mut access = self._granted_access.borrow_mut();
                *access = PROCESS_QUERY_LIMITED_INFORMATION;
                handle = OpenProcess(*access, false, self.pid).with_context(|| {
                    format!(
                        "Failed to open process with PID {}: {}",
                        self.pid,
                        GetLastError().0
                    )
                })?;
            }
            *_inner_handle = handle;
        }

        Ok(())
    }
}

#[derive(Debug)]
pub struct Proclist {
    handle: HANDLE,
    cur_proc: Process,
    proc_entry: PROCESSENTRY32W,
    index: usize,
}

impl Proclist {
    pub unsafe fn new() -> Result<Proclist> {
        let handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            .with_context(|| format!("Failed to create process snapshot: {}", GetLastError().0))?;
        let mut proc_entry: PROCESSENTRY32W = std::mem::zeroed();
        proc_entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as _;

        Process32FirstW(handle, &mut proc_entry)
            .with_context(|| format!("Failed to iter process: {}", GetLastError().0))?;

        Ok(Proclist {
            cur_proc: Process::new(proc_entry.th32ProcessID),
            index: 0,
            handle,
            proc_entry,
        })
    }
}

impl Iterator for Proclist {
    type Item = Process;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index != 0 {
            let result = unsafe { Process32NextW(self.handle, &mut self.proc_entry) };
            if result.is_err() {
                return None;
            }
        }

        // Filter out processes that cannot be opened
        loop {
            let ret = unsafe {
                OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION,
                    false,
                    self.proc_entry.th32ProcessID,
                )
            };
            if ret.is_err() {
                let result = unsafe { Process32NextW(self.handle, &mut self.proc_entry) };
                if result.is_err() {
                    return None;
                }
                continue;
            }
            unsafe {
                let _ = CloseHandle(ret.unwrap());
            }
            break;
        }

        self.cur_proc = Process::new(self.proc_entry.th32ProcessID);

        self.index += 1;

        Some(self.cur_proc.clone())
    }
}
