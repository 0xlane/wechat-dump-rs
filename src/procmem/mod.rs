use windows::Win32::{System::{Memory::{MEMORY_BASIC_INFORMATION, PAGE_PROTECTION_FLAGS, PAGE_TYPE, VIRTUAL_ALLOCATION_TYPE, VirtualQueryEx, MEM_MAPPED, MEM_IMAGE}, Threading::{OpenProcess, PROCESS_VM_READ, PROCESS_QUERY_INFORMATION}, ProcessStatus::GetMappedFileNameW}, Foundation::CloseHandle};

#[derive(Clone, Debug)]
pub struct ProcessMemoryInfo{
    pub base: usize,
    pub region_size: usize,
    pub state: VIRTUAL_ALLOCATION_TYPE,
    pub protect: PAGE_PROTECTION_FLAGS,
    pub mtype: PAGE_TYPE,
    pub filename: Option<String>,
    pub mbi: MEMORY_BASIC_INFORMATION,
}

impl From<MEMORY_BASIC_INFORMATION> for ProcessMemoryInfo {
    fn from(mbi: MEMORY_BASIC_INFORMATION) -> Self {
        ProcessMemoryInfo {
            base: mbi.BaseAddress as usize,
            region_size: mbi.RegionSize,
            state: mbi.State,
            protect: mbi.Protect,
            mtype: mbi.Type,
            filename: None,
            mbi: mbi,
        }
    }
}

pub fn get_mem_list(pid: u32) -> Vec<ProcessMemoryInfo> {
    let mut pmis = vec![];

    unsafe {
        let mut mbi = MEMORY_BASIC_INFORMATION::default();

        let hprocess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid).unwrap();
        let mut p: usize = 0x10000;
        while VirtualQueryEx(hprocess, Some(p as _), &mut mbi, std::mem::size_of::<MEMORY_BASIC_INFORMATION>() as usize) == std::mem::size_of::<MEMORY_BASIC_INFORMATION>() {
            let mut pmi = ProcessMemoryInfo::from(mbi);

            if mbi.Type == MEM_IMAGE || mbi.Type == MEM_MAPPED {
                let mut file_name = [0u16; 512];
                let file_name_len = GetMappedFileNameW(hprocess, mbi.BaseAddress, file_name.as_mut()) as usize;
                if file_name_len > 0 {
                    pmi.filename = Some(String::from_utf16(&file_name[0 .. file_name_len]).unwrap());
                }
            }

            pmis.push(pmi.clone());
            p = pmi.base + pmi.region_size;
        }

        CloseHandle(hprocess).unwrap();
    }

    return pmis;
}