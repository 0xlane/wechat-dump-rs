pub mod process;
pub mod procmem;

use std::{
    collections::HashSet,
    fs::{self, File},
    io::Read,
    ops::{Add, Sub},
    path::PathBuf,
};

use aes::cipher::{block_padding::NoPadding, BlockDecryptMut, KeyIvInit};
use anyhow::Result;
use hmac::{Hmac, Mac};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use pbkdf2::pbkdf2_hmac_array;
use process::Process;
use rayon::prelude::*;
use regex::Regex;
use sha1::Sha1;
use sha2::Sha512;
use windows::Win32::{
    Foundation::CloseHandle,
    System::{
        Diagnostics::Debug::ReadProcessMemory,
        Memory::{
            MEM_PRIVATE, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_READWRITE,
            PAGE_WRITECOPY,
        },
        Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ},
    },
};
use yara::Compiler;

use crate::procmem::ProcessMemoryInfo;

const RULES_V3: &str = r#"
    rule GetPhoneTypeStringOffset_v3
    {
        strings:
            $a = "iphone\x00" ascii fullword
            $b = "android\x00" ascii fullword

        condition:
            any of them
    }

    rule GetDataDir_v3
    {
        strings:
            $a = /([a-zA-Z]:\\|\\\\)([^\\:]{1,100}?\\){0,10}?WeChat Files\\[0-9a-zA-Z_-]{6,20}?\\/
        
        condition:
            $a
    }
"#;

const RULES_V4: &str = r#"
    rule GetDataDir
    {
        strings:
            $a = /([a-zA-Z]:\\|\\\\)([^\\:]{1,100}?\\){0,10}?xwechat_files\\[0-9a-zA-Z_-]{6,24}?\\db_storage\\/
        
        condition:
            $a
    }

    rule GetUserInfoOffset
    {
        strings:
            $a = /(.{16}[\x00-\x20]\x00{7}(\x0f|\x1f)\x00{7}){2}.{16}[\x01-\x20]\x00{7}(\x0f|\x1f)\x00{7}[0-9]{11}\x00{5}\x0b\x00{7}\x0f\x00{7}.{25}\x00{7}(\x2f|\x1f|\x0f)\x00{7}/s
        condition:
            $a
    }
"#;

#[derive(Debug, Clone)]
struct WechatInfo {
    pub pid: u32,
    pub version: String,
    pub account_name: String,
    pub nick_name: Option<String>,
    pub phone: Option<String>,
    pub data_dir: String,
    pub key: Option<String>,
}

impl std::fmt::Display for WechatInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.version.starts_with("4.") {
            write!(
                f,
                r#"=======================================
ProcessId: {}
WechatVersion: {}
AccountName: {}
NickName: {}
Phone: {}
DataDir: {}
key: {}
=======================================
"#,
                self.pid,
                self.version,
                self.account_name,
                self.nick_name.clone().unwrap_or("unknown".to_owned()),
                self.phone.clone().unwrap_or("unknown".to_owned()),
                self.data_dir,
                self.key.clone().unwrap_or("unknown".to_owned())
            )
        } else {
            write!(
                f,
                r#"=======================================
ProcessId: {}
WechatVersion: {}
AccountName: {}
DataDir: {}
key: {}
=======================================
"#,
                self.pid,
                self.version,
                self.account_name,
                self.data_dir,
                self.key.clone().unwrap_or("unknown".to_owned())
            )
        }
    }
}

fn get_pid_by_name(pname: &str) -> Vec<u32> {
    let mut result = vec![];
    unsafe {
        for pp in process::Proclist::new().unwrap() {
            let pi = pp.get_proc_info().unwrap();
            if pi.name == pname {
                result.push(pi.pid);
            }
        }
    }

    result.sort();

    result
}

fn get_pid_by_name_and_cmd_pattern(pname: &str, cmd_pattern: &str) -> Vec<u32> {
    let mut result = vec![];
    unsafe {
        for pp in process::Proclist::new().unwrap() {
            let pi = pp.get_proc_info().unwrap();
            if pi.name == pname && Regex::new(cmd_pattern).unwrap().find(&pi.cmd).is_some() {
                result.push(pi.pid);
            }
        }
    }

    result.sort();

    result
}

fn read_number<T: Sub + Add + Ord + Default>(pid: u32, addr: usize) -> Result<T> {
    unsafe {
        let hprocess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid)?;

        let mut result: T = T::default();

        ReadProcessMemory(
            hprocess,
            addr as _,
            std::mem::transmute(&mut result),
            std::mem::size_of::<T>(),
            None,
        )?;

        CloseHandle(hprocess)?;
        Ok(result)
    }
}

fn read_string(pid: u32, addr: usize, size: usize) -> Result<String> {
    unsafe {
        let hprocess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid)?;

        let mut buffer = vec![0; size];
        let _ = ReadProcessMemory(hprocess, addr as _, buffer.as_mut_ptr() as _, size, None);

        CloseHandle(hprocess)?;

        let buf_str = match buffer.iter().position(|&x| x == 0) {
            Some(pos) => String::from_utf8(buffer[..pos].to_vec())?,
            None => String::from_utf8(buffer)?,
        };

        if buf_str.len() != size {
            Err(anyhow::anyhow!(format!(
                "except {} characters, but found: {} --> {}",
                size,
                buf_str.len(),
                buf_str
            )))
        } else {
            Ok(buf_str)
        }
    }
}

fn read_string_or_ptr(pid: u32, addr: usize, size: usize) -> Result<String> {
    match read_string(pid, addr, size) {
        Ok(ss) => Ok(ss),
        Err(e) => {
            let str_ptr = read_number::<usize>(pid, addr)?;
            Ok(read_string(pid, str_ptr, size).map_err(|_| e)?)
        }
    }
}

fn read_bytes(pid: u32, addr: usize, size: usize) -> Result<Vec<u8>> {
    unsafe {
        let hprocess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid)?;

        let mut buffer = vec![0; size];
        let _ = ReadProcessMemory(hprocess, addr as _, buffer.as_mut_ptr() as _, size, None)?;

        CloseHandle(hprocess)?;

        Ok(buffer)
    }
}

fn get_proc_file_version(pid: u32) -> Option<String> {
    unsafe {
        let fi = Process::new(pid).get_file_info().ok();
        match fi {
            Some(fi) => fi.get("FileVersion").cloned(),
            None => None,
        }
    }
}

fn dump_wechat_info_v3(
    pid: u32,
    special_data_dir: Option<&PathBuf>,
    version: String,
) -> WechatInfo {
    let pmis = procmem::get_mem_list(pid);

    let wechatwin_all_mem_infos: Vec<&ProcessMemoryInfo> = pmis
        .iter()
        .filter(|x| x.filename.is_some() && x.filename.clone().unwrap().contains("WeChatWin.dll"))
        .collect();

    let wechatwin_writable_mem_infos: Vec<&ProcessMemoryInfo> = wechatwin_all_mem_infos
        .iter()
        .filter(|x| {
            (x.protect
                & (PAGE_READWRITE
                    | PAGE_WRITECOPY
                    | PAGE_EXECUTE_READWRITE
                    | PAGE_EXECUTE_WRITECOPY))
                .0
                > 0
        })
        .map(|x| *x)
        .collect();

    let wechat_writeable_private_mem_infos: Vec<&ProcessMemoryInfo> = pmis
        .iter()
        .filter(|x| (x.protect & (PAGE_READWRITE | PAGE_WRITECOPY)).0 > 0 && x.mtype == MEM_PRIVATE)
        .collect();

    // 使用 yara 匹配到登录设备的地址和数据目录
    let compiler = Compiler::new().unwrap();
    let compiler = compiler
        .add_rules_str(RULES_V3)
        .expect("Should have parsed rule");
    let rules = compiler
        .compile_rules()
        .expect("Should have compiled rules");
    let results = rules.scan_process(pid, 0).expect("Should have scanned");

    let phone_type_str_match = results
        .iter()
        .filter(|x| x.identifier == "GetPhoneTypeStringOffset_v3")
        .next()
        .expect("unbale to find phone type string")
        .strings
        .iter()
        .filter(|x| {
            x.matches.iter().any(|y| {
                wechatwin_writable_mem_infos
                    .iter()
                    .any(|z| y.base == z.base)
            })
        })
        .next()
        .expect("unbale to find phone type string")
        .matches
        .iter()
        .filter(|x| {
            wechatwin_writable_mem_infos
                .iter()
                .any(|y| x.base == y.base)
        })
        .next()
        .expect("unable to find phone type string");
    let phone_type_string_addr = phone_type_str_match.base + phone_type_str_match.offset;
    let phone_type_string_len_addr = phone_type_string_addr + 16;
    let phone_type_string_len = read_number::<usize>(pid, phone_type_string_len_addr)
        .expect("read phone type string len failed");
    let phone_type_string = read_string(pid, phone_type_string_addr, phone_type_string_len)
        .expect("read phone type string failed");
    let data_dir = if special_data_dir.is_some() {
        special_data_dir
            .unwrap()
            .clone()
            .into_os_string()
            .into_string()
            .unwrap()
    } else {
        let data_dir_match = results
            .iter()
            .filter(|x| x.identifier == "GetDataDir_v3")
            .next()
            .expect("unable to find data dir")
            .strings
            .first()
            .expect("unable to find data dir")
            .matches
            .iter()
            .filter(|x| {
                wechat_writeable_private_mem_infos
                    .iter()
                    .any(|pmi| pmi.base == x.base)
            })
            .next()
            .expect("unable to find data dir");
        String::from_utf8(data_dir_match.data.clone()).expect("data dir is invalid string")
    };

    println!("[+] login phone type is {}", phone_type_string);
    println!("[+] wechat data dir is {}", data_dir);

    let align = 2 * std::mem::size_of::<usize>(); // x64 -> 16, x86 -> 8

    // account_name 在 phone_type 前面，并且是 16 位补齐的，所以向前找，离得比较近不用找太远的
    let mut start = phone_type_string_addr - align;
    let mut account_name_addr = start;
    let mut account_name: Option<String> = None;
    let mut count = 0;
    while start >= phone_type_string_addr - align * 20 {
        // 名字长度>=16，就会变成指针，不直接存放字符串
        let result = {
            if let Ok(str_len) = read_number::<usize>(pid, start + 16) {
                if str_len <= 0 || str_len > 20 {
                    None
                } else {
                    read_string_or_ptr(pid, start, str_len).ok()
                }
            } else {
                None
            }
        };

        if let Some(ac) = result {
            // 微信号是字母、数字、下划线组合，6-20位
            let re = Regex::new(r"^[a-zA-Z0-9_]+$").unwrap();
            if re.is_match(&ac) && ac.len() >= 6 && ac.len() <= 20 {
                // 首次命中可能是原始的 wxid_，第二次是修改后的微信号，找不到第二次说明注册后没改过微信号
                account_name = Some(ac);
                account_name_addr = start;
                count += 1;
                if count == 2 {
                    break;
                }
            }
        }

        start -= align;
    }

    if account_name.is_none() {
        panic!("not found account name address");
    }
    let account_name = account_name.unwrap();
    println!("[+] account name is {}", account_name);

    // 读取一个文件准备暴力搜索key
    const IV_SIZE: usize = 16;
    const HMAC_SHA1_SIZE: usize = 20;
    const KEY_SIZE: usize = 32;
    const AES_BLOCK_SIZE: usize = 16;
    const SALT_SIZE: usize = 16;
    const PAGE_SIZE: usize = 4096;
    let mut db_file_path = PathBuf::from(data_dir.clone());
    db_file_path.push(r"Msg\Misc.db");
    let mut db_file = std::fs::File::open(&db_file_path)
        .expect(format!("{} is not exsit", db_file_path.display()).as_str());
    let mut buf = [0u8; PAGE_SIZE];
    db_file.read(&mut buf[..]).expect("read Misc.db is failed");

    // key 在微信号前面找
    let mut key: Option<String> = None;
    let mem_base = phone_type_str_match.base;
    let mut key_point_addr = account_name_addr - align;
    while key_point_addr >= mem_base {
        let key_addr =
            read_number::<usize>(pid, key_point_addr).expect("find key addr failed in memory");

        if wechat_writeable_private_mem_infos
            .iter()
            .any(|x| key_addr >= x.base && key_addr <= x.base + x.region_size)
        {
            let key_bytes =
                read_bytes(pid, key_addr, KEY_SIZE).expect("find key bytes failed in memory");
            if key_bytes.iter().filter(|&&x| x == 0x00).count() < 5 {
                // 验证 key 是否有效
                let start = SALT_SIZE;
                let end = PAGE_SIZE;

                // 获取到文件开头的 salt
                let salt = buf[..SALT_SIZE].to_owned();
                // salt 异或 0x3a 得到 mac_salt， 用于计算HMAC
                let mac_salt: Vec<u8> = salt.to_owned().iter().map(|x| x ^ 0x3a).collect();

                // 通过 key_bytes 和 salt 迭代64000次解出一个新的 key，用于解密
                let new_key = pbkdf2_hmac_array::<Sha1, KEY_SIZE>(&key_bytes, &salt, 64000);

                // 通过 key 和 mac_salt 迭代2次解出 mac_key
                let mac_key = pbkdf2_hmac_array::<Sha1, KEY_SIZE>(&new_key, &mac_salt, 2);

                // hash检验码对齐后长度 48，后面校验哈希用
                let mut reserve = IV_SIZE + HMAC_SHA1_SIZE;
                reserve = if (reserve % AES_BLOCK_SIZE) == 0 {
                    reserve
                } else {
                    ((reserve / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE
                };

                // 校验哈希
                type HamcSha1 = Hmac<Sha1>;

                unsafe {
                    let mut mac = HamcSha1::new_from_slice(&mac_key)
                        .expect("hmac_sha1 error, key length is invalid");
                    mac.update(&buf[start..end - reserve + IV_SIZE]);
                    mac.update(std::mem::transmute::<_, &[u8; 4]>(&(1u32)).as_ref());
                    let hash_mac = mac.finalize().into_bytes().to_vec();

                    let hash_mac_start_offset = end - reserve + IV_SIZE;
                    let hash_mac_end_offset = hash_mac_start_offset + hash_mac.len();
                    if hash_mac == &buf[hash_mac_start_offset..hash_mac_end_offset] {
                        println!("[v] found key at 0x{:x}", key_addr);
                        key = Some(hex::encode(key_bytes));
                        break;
                    }
                }
            }
        }

        key_point_addr -= align;
    }

    if key.is_none() {
        eprintln!("[!] no found key!!");
    }

    WechatInfo {
        pid,
        version,
        account_name,
        nick_name: None,
        phone: None,
        data_dir,
        key: key,
    }
}

fn dump_wechat_info_v4(
    pid: u32,
    special_data_dir: Option<&PathBuf>,
    version: String,
) -> WechatInfo {
    let pmis = procmem::get_mem_list(pid);

    let wechat_writeable_private_mem_infos: Vec<&ProcessMemoryInfo> = pmis
        .iter()
        .filter(|x| (x.protect & (PAGE_READWRITE | PAGE_WRITECOPY)).0 > 0 && x.mtype == MEM_PRIVATE)
        .collect();

    // 使用 yara 匹配到用户信息地址和数据目录
    let compiler = Compiler::new().unwrap();
    let compiler = compiler
        .add_rules_str(RULES_V4)
        .expect("Should have parsed rule");
    let rules = compiler
        .compile_rules()
        .expect("Should have compiled rules");
    let results = rules.scan_process(pid, 0).expect("Should have scanned");

    let user_info_match = results
        .iter()
        .filter(|x| x.identifier == "GetUserInfoOffset")
        .next()
        .expect("unbale to find user info")
        .strings
        .iter()
        .filter(|x| {
            x.matches.iter().any(|y| {
                wechat_writeable_private_mem_infos
                    .iter()
                    .any(|z| y.base == z.base)
            })
        })
        .next()
        .expect("unbale to find user info")
        .matches
        .iter()
        .filter(|x| {
            wechat_writeable_private_mem_infos
                .iter()
                .any(|y| x.base == y.base)
        })
        .next()
        .expect("unable to find user info");

    // let key_memory_info = wechat_writeable_private_mem_infos
    //     .iter()
    //     .find(|v| v.base == user_info_match.base)
    //     .unwrap();
    // let key_search_range = 0..key_memory_info.base + key_memory_info.region_size;

    let user_info_address = user_info_match.base + user_info_match.offset;
    let wxid_length =
        u64::from_le_bytes(user_info_match.data[0x10..0x10 + 0x8].try_into().unwrap());
    let wxid = read_string_or_ptr(pid, user_info_address, wxid_length as usize).unwrap();
    let account_name_length =
        u64::from_le_bytes(user_info_match.data[0x30..0x30 + 0x8].try_into().unwrap());
    let mut account_name =
        read_string_or_ptr(pid, user_info_address + 0x20, account_name_length as usize).unwrap();
    let nick_name_length =
        u64::from_le_bytes(user_info_match.data[0x50..0x50 + 0x8].try_into().unwrap());
    let nick_name =
        read_string_or_ptr(pid, user_info_address + 0x40, nick_name_length as usize).unwrap();
    let phone_length =
        u64::from_le_bytes(user_info_match.data[0x70..0x70 + 0x8].try_into().unwrap());
    let phone_str =
        read_string_or_ptr(pid, user_info_address + 0x60, phone_length as usize).unwrap();
    println!(
        "[+] found user info at 0x{:x} --> {}********",
        user_info_address,
        &phone_str[..3]
    );

    // non account name
    if account_name.is_empty() {
        account_name = wxid;
    } else if !wxid.is_empty() {
        account_name = format!("{}/{}", account_name, wxid)
    }

    let data_dir = if special_data_dir.is_some() {
        special_data_dir
            .unwrap()
            .clone()
            .into_os_string()
            .into_string()
            .unwrap()
    } else {
        let data_dir_match = results
            .iter()
            .filter(|x| x.identifier == "GetDataDir")
            .next()
            .expect("unbale to find data dir")
            .strings
            .iter()
            .filter(|x| {
                x.matches.iter().any(|y| {
                    wechat_writeable_private_mem_infos
                        .iter()
                        .any(|z| y.base == z.base)
                })
            })
            .next()
            .expect("unbale to find data dir")
            .matches
            .iter()
            .filter(|x| {
                wechat_writeable_private_mem_infos
                    .iter()
                    .any(|y| x.base == y.base)
            })
            .next()
            .expect("unable to find data dir");

        String::from_utf8(data_dir_match.data.clone())
            .unwrap()
            .replace("db_storage\\", "")
    };

    let mut compiler = Compiler::new().unwrap();
    compiler = compiler
        .add_rules_str(
            r#"
rule GetKeyAddrStub
{
    strings:
        $a = /.{6}\x00{2}\x00{8}\x20\x00{7}\x2f\x00{7}/
    condition:
        all of them
}
    "#,
        )
        .expect("rule error");
    let rules = compiler
        .compile_rules()
        .expect("Should have compiled rules");
    let results = rules.scan_process(pid, 0).expect("Should have scanned");
    if results.is_empty() {
        panic!("unable to find key stub str");
    }

    let mut key_stub_str_addresses = vec![];
    for result in results {
        if let Some(key_stub_str_matches) = result
            .strings
            .iter()
            .filter(|x| {
                x.matches.iter().any(|y| {
                    wechat_writeable_private_mem_infos
                        .iter()
                        .any(|z| y.base == z.base)
                })
            })
            .next()
        {
            let tmp = key_stub_str_matches
                .matches
                .iter()
                .filter(|x| {
                    wechat_writeable_private_mem_infos
                        .iter()
                        .any(|y| x.base == y.base)
                })
                .map(|x| u64::from_le_bytes(x.data[..8].try_into().unwrap()))
                .collect::<Vec<u64>>();
            key_stub_str_addresses.extend(tmp);
        }
    }

    let mut pre_addresses: HashSet<u64> = HashSet::new();
    key_stub_str_addresses.sort_by(|&a, &b| {
        a.abs_diff(user_info_address as _)
            .cmp(&b.abs_diff(user_info_address as _))
    });
    for cur_stub_addr in key_stub_str_addresses {
        // if cur_stub_addr < key_search_range.end as _ {
        if wechat_writeable_private_mem_infos.iter().any(|v| {
            cur_stub_addr >= v.base as _
                && cur_stub_addr <= (v.base + v.region_size - KEY_SIZE) as _
        }) {
            pre_addresses.insert(cur_stub_addr);
        }
        // }
    }

    if pre_addresses.is_empty() {
        panic!("unable to find key stub str");
    }

    // 读取一个文件准备暴力搜索key
    const IV_SIZE: usize = 16;
    const HMAC_SHA512_SIZE: usize = 64;
    const KEY_SIZE: usize = 32;
    const AES_BLOCK_SIZE: usize = 16;
    const SALT_SIZE: usize = 16;
    const PAGE_SIZE: usize = 4096;
    const ROUND_COUNT: u32 = 256000;
    let mut db_file_path = PathBuf::from(data_dir.clone());
    db_file_path.push(r"db_storage\biz\biz.db");
    let mut db_file = std::fs::File::open(&db_file_path)
        .expect(format!("{} is not exsit", db_file_path.display()).as_str());
    let mut buf = [0u8; PAGE_SIZE];
    db_file.read(&mut buf[..]).expect("read biz.db is failed");

    // HMAC_SHA512算法比较耗时，使用多线程跑
    let n_job = pre_addresses.len();

    println!("[+] found pre address count: {}", n_job);
    println!("[+] searching key in pre addresses...");

    let mp = MultiProgress::new();
    let progress_style = ProgressStyle::with_template("{prefix:.bold.dim} {wide_msg}").unwrap();

    let key_addr = pre_addresses
        .into_iter()
        .par_bridge()
        .find_any(|&cur_key_offset| {
            // println!("{:x}", cur_key_offset);
            let pb = mp.add(ProgressBar::new(3));
            pb.set_style(progress_style.clone());
            pb.set_prefix(format!("[v]"));
            pb.set_message(format!("read bytes from 0x{cur_key_offset:x}..."));
            let key_bytes = read_bytes(pid, cur_key_offset as usize, KEY_SIZE).expect(&format!(
                "find key bytes failed in memory: {:X}",
                cur_key_offset
            ));
            if key_bytes.iter().filter(|&&x| x.is_ascii_alphanumeric()).count() < 20    // limit number of including ascii alphanumeric
                && key_bytes.iter().filter(|&&x| x == 0).count() < 10
            // limit number of including zero
            {
                // 验证 key 是否有效
                let start = SALT_SIZE;
                let end = PAGE_SIZE;

                // 获取到文件开头的 salt
                let salt = buf[..SALT_SIZE].to_owned();
                // salt 异或 0x3a 得到 mac_salt， 用于计算HMAC
                let mac_salt: Vec<u8> = salt.to_owned().iter().map(|x| x ^ 0x3a).collect();

                // 通过 key_bytes 和 salt 迭代 ROUND_COUNT 次解出一个新的 key，用于解密
                let new_key = pbkdf2_hmac_array::<Sha512, KEY_SIZE>(&key_bytes, &salt, ROUND_COUNT);

                // 通过 key 和 mac_salt 迭代 2 次解出 mac_key
                let mac_key = pbkdf2_hmac_array::<Sha512, KEY_SIZE>(&new_key, &mac_salt, 2);
                // let real_key = [&mac_key, &mac_salt[..]].concat(); // sqlcipher_rawkey

                // hash检验码对齐后长度 48，后面校验哈希用
                let mut reserve = IV_SIZE + HMAC_SHA512_SIZE;
                reserve = if (reserve % AES_BLOCK_SIZE) == 0 {
                    reserve
                } else {
                    ((reserve / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE
                };

                // 校验哈希
                pb.set_message(format!("verify hmac..."));
                type HamcSha512 = Hmac<Sha512>;

                unsafe {
                    let mut mac = HamcSha512::new_from_slice(&mac_key)
                        .expect("hmac_sha512 error, key length is invalid");
                    mac.update(&buf[start..end - reserve + IV_SIZE]);
                    mac.update(std::mem::transmute::<_, &[u8; 4]>(&(1u32)).as_ref()); // pageno
                    let hash_mac = mac.finalize().into_bytes().to_vec();

                    let hash_mac_start_offset = end - reserve + IV_SIZE;
                    let hash_mac_end_offset = hash_mac_start_offset + hash_mac.len();
                    if hash_mac == &buf[hash_mac_start_offset..hash_mac_end_offset] {
                        pb.finish_with_message(format!("found key at 0x{cur_key_offset:x}"));
                        // let key = hex::encode(key_bytes);
                        // println!("key is {}", key);
                        return true;
                        // }
                    }
                }
            }
            pb.finish_and_clear();
            return false;
        });

    let key = key_addr.map(|v| {
        let key_bytes = read_bytes(pid, v as _, KEY_SIZE).unwrap();
        hex::encode(key_bytes)
    });

    if key.is_none() {
        eprintln!("[!] no found key!!");
    }

    WechatInfo {
        pid,
        version,
        account_name,
        nick_name: Some(nick_name),
        phone: Some(phone_str),
        data_dir,
        key: key,
    }
}

fn dump_wechat_info(pid: u32, special_data_dir: Option<&PathBuf>) -> WechatInfo {
    let version = get_proc_file_version(pid).unwrap_or_else(|| "unknown".to_owned());
    println!("[+] wechat version is {}", version);

    if version.starts_with("4.") {
        dump_wechat_info_v4(pid, special_data_dir, version)
    } else {
        dump_wechat_info_v3(pid, special_data_dir, version)
    }
}

fn scan_db_files(dir: String) -> Result<Vec<PathBuf>> {
    let spinner_style = ProgressStyle::with_template("{spinner} {wide_msg}")
        .unwrap()
        .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ ");
    let pb = ProgressBar::new(!0);
    pb.set_style(spinner_style);

    fn scan_file(pb: &ProgressBar, dir: PathBuf) -> Result<Vec<PathBuf>> {
        let mut result = vec![];

        let entries = fs::read_dir(dir)?
            .filter_map(Result::ok)
            .collect::<Vec<_>>();
        for entry in entries {
            let path = entry.path();
            if path.is_dir() {
                result.extend(scan_file(pb, path)?);
            } else if let Some(ext) = path.extension() {
                if ext == "db" {
                    pb.set_message(path.display().to_string());
                    pb.tick();
                    result.push(path);
                }
            }
        }

        Ok(result)
    }

    let result = scan_file(&pb, dir.into());
    pb.finish_and_clear();
    result
}

fn read_file_content(path: &PathBuf) -> Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    Ok(buffer)
}

fn decrypt_db_file_v3(path: &PathBuf, pkey: &String) -> Result<Vec<u8>> {
    const IV_SIZE: usize = 16;
    const HMAC_SHA1_SIZE: usize = 20;
    const KEY_SIZE: usize = 32;
    const AES_BLOCK_SIZE: usize = 16;
    const ROUND_COUNT: u32 = 64000;
    const PAGE_SIZE: usize = 4096;
    const SALT_SIZE: usize = 16;
    const SQLITE_HEADER: &str = "SQLite format 3";

    let mut buf = read_file_content(path)?;

    // 如果开头是 SQLITE_HEADER，说明不需要解密
    if buf.starts_with(SQLITE_HEADER.as_bytes()) {
        return Ok(buf);
    }

    let mut decrypted_buf: Vec<u8> = vec![];

    // 获取到文件开头的 salt，用于解密 key
    let salt = buf[..16].to_owned();
    // salt 异或 0x3a 得到 mac_salt， 用于计算HMAC
    let mac_salt: Vec<u8> = salt.to_owned().iter().map(|x| x ^ 0x3a).collect();

    unsafe {
        // 通过 pkey 和 salt 迭代 ROUND_COUNT 次解出一个新的 key，用于解密
        let pass = hex::decode(pkey)?;
        let key = pbkdf2_hmac_array::<Sha1, KEY_SIZE>(&pass, &salt, ROUND_COUNT);

        // 通过 key 和 mac_salt 迭代2次解出 mac_key
        let mac_key = pbkdf2_hmac_array::<Sha1, KEY_SIZE>(&key, &mac_salt, 2);

        // 开头是 sqlite 头
        decrypted_buf.extend(SQLITE_HEADER.as_bytes());
        decrypted_buf.push(0x00);

        // hash检验码对齐后长度 48，后面校验哈希用
        let mut reserve = IV_SIZE + HMAC_SHA1_SIZE;
        reserve = if (reserve % AES_BLOCK_SIZE) == 0 {
            reserve
        } else {
            ((reserve / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE
        };

        // 每页大小4096，分别解密
        let total_page = buf.len() / PAGE_SIZE;
        for cur_page in 0..total_page {
            let offset = if cur_page == 0 { SALT_SIZE } else { 0 };
            let start: usize = cur_page * PAGE_SIZE;
            let end: usize = start + PAGE_SIZE;

            // 搞不懂，这一堆0是干啥的，文件大小直接翻倍了
            if buf[start..end].iter().all(|&x| x == 0) {
                decrypted_buf.extend(&buf[start..]);
                break;
            }

            // 校验哈希
            type HamcSha1 = Hmac<Sha1>;

            let mut mac = HamcSha1::new_from_slice(&mac_key)?;
            mac.update(&buf[start + offset..end - reserve + IV_SIZE]);
            mac.update(std::mem::transmute::<_, &[u8; 4]>(&(cur_page as u32 + 1)).as_ref());
            let hash_mac = mac.finalize().into_bytes().to_vec();

            let hash_mac_start_offset = end - reserve + IV_SIZE;
            let hash_mac_end_offset = hash_mac_start_offset + hash_mac.len();
            if hash_mac != &buf[hash_mac_start_offset..hash_mac_end_offset] {
                return Err(anyhow::anyhow!("Hash verification failed"));
            }

            // aes-256-cbc 解密内容
            type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

            let iv = &buf[end - reserve..end - reserve + IV_SIZE];
            decrypted_buf.extend(
                Aes256CbcDec::new(&key.into(), iv.into())
                    .decrypt_padded_mut::<NoPadding>(&mut buf[start + offset..end - reserve])
                    .map_err(anyhow::Error::msg)?,
            );
            decrypted_buf.extend(&buf[end - reserve..end]);
        }
    }

    Ok(decrypted_buf)
}

fn decrypt_db_file_v4(path: &PathBuf, pkey: &String) -> Result<Vec<u8>> {
    const IV_SIZE: usize = 16;
    const HMAC_SHA256_SIZE: usize = 64;
    const KEY_SIZE: usize = 32;
    const AES_BLOCK_SIZE: usize = 16;
    const ROUND_COUNT: u32 = 256000;
    const PAGE_SIZE: usize = 4096;
    const SALT_SIZE: usize = 16;
    const SQLITE_HEADER: &str = "SQLite format 3";

    let mut buf = read_file_content(path)?;

    // 如果开头是 SQLITE_HEADER，说明不需要解密
    if buf.starts_with(SQLITE_HEADER.as_bytes()) {
        return Ok(buf);
    }

    let mut decrypted_buf: Vec<u8> = vec![];

    // 获取到文件开头的 salt，用于解密 key
    let salt = buf[..16].to_owned();
    // salt 异或 0x3a 得到 mac_salt， 用于计算HMAC
    let mac_salt: Vec<u8> = salt.to_owned().iter().map(|x| x ^ 0x3a).collect();

    unsafe {
        // 通过 pkey 和 salt 迭代 ROUND_COUNT 次解出一个新的 key，用于解密
        let pass = hex::decode(pkey)?;
        let key = pbkdf2_hmac_array::<Sha512, KEY_SIZE>(&pass, &salt, ROUND_COUNT);

        // 通过 key 和 mac_salt 迭代2次解出 mac_key
        let mac_key = pbkdf2_hmac_array::<Sha512, KEY_SIZE>(&key, &mac_salt, 2);

        // 开头是 sqlite 头
        decrypted_buf.extend(SQLITE_HEADER.as_bytes());
        decrypted_buf.push(0x00);

        // hash检验码对齐后长度 48，后面校验哈希用
        let mut reserve = IV_SIZE + HMAC_SHA256_SIZE;
        reserve = if (reserve % AES_BLOCK_SIZE) == 0 {
            reserve
        } else {
            ((reserve / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE
        };

        // 每页大小4096，分别解密
        let total_page = buf.len() / PAGE_SIZE;
        for cur_page in 0..total_page {
            let offset = if cur_page == 0 { SALT_SIZE } else { 0 };
            let start: usize = cur_page * PAGE_SIZE;
            let end: usize = start + PAGE_SIZE;

            // 校验哈希
            type HamcSha512 = Hmac<Sha512>;

            let mut mac = HamcSha512::new_from_slice(&mac_key)?;
            mac.update(&buf[start + offset..end - reserve + IV_SIZE]);
            mac.update(std::mem::transmute::<_, &[u8; 4]>(&(cur_page as u32 + 1)).as_ref());
            let hash_mac = mac.finalize().into_bytes().to_vec();

            let hash_mac_start_offset = end - reserve + IV_SIZE;
            let hash_mac_end_offset = hash_mac_start_offset + hash_mac.len();
            if hash_mac != &buf[hash_mac_start_offset..hash_mac_end_offset] {
                return Err(anyhow::anyhow!("Hash verification failed"));
            }

            // aes-256-cbc 解密内容
            type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

            let iv = &buf[end - reserve..end - reserve + IV_SIZE];
            decrypted_buf.extend(
                Aes256CbcDec::new(&key.into(), iv.into())
                    .decrypt_padded_mut::<NoPadding>(&mut buf[start + offset..end - reserve])
                    .map_err(anyhow::Error::msg)?,
            );
            decrypted_buf.extend(&buf[end - reserve..end]);
        }
    }

    Ok(decrypted_buf)
}

fn convert_to_sqlcipher_rawkey(pkey: &str, path: &PathBuf, is_v4: bool) -> Result<String> {
    const KEY_SIZE: usize = 32;
    const ROUND_COUNT_V4: u32 = 256000;
    const ROUND_COUNT_V3: u32 = 64000;
    const SALT_SIZE: usize = 16;

    let mut file = File::open(path)?;
    let mut salt = vec![0; SALT_SIZE];
    file.read(salt.as_mut())?;

    let pass = hex::decode(pkey)?;
    let key = if is_v4 {
        pbkdf2_hmac_array::<Sha512, KEY_SIZE>(&pass, &salt, ROUND_COUNT_V4)
    } else {
        pbkdf2_hmac_array::<Sha1, KEY_SIZE>(&pass, &salt, ROUND_COUNT_V3)
    };
    let rawkey = [key.as_slice(), &salt].concat();
    Ok(format!("0x{}", hex::encode(rawkey)))
}

fn dump_all_by_pid(wechat_info: &WechatInfo, output: &PathBuf) {
    if wechat_info.key.is_none() {
        eprintln!("[!] wechat key is none");
        eprintln!("[!] stop dump!!");
        return;
    }
    let key = wechat_info.key.clone().unwrap();

    let msg_dir = if wechat_info.version.starts_with("4.0") {
        wechat_info.data_dir.clone() + "db_storage"
    } else {
        wechat_info.data_dir.clone() + "Msg"
    };
    let dbfiles = scan_db_files(msg_dir.clone()).unwrap();
    println!("[+] scanned {} files in {}", dbfiles.len(), &msg_dir);

    // 创建输出目录
    if output.is_file() {
        panic!("[!] the output path must be a directory");
    }
    let mut output_dir = output.components().collect::<PathBuf>();
    output_dir.push(format!("wechat_{}", wechat_info.pid));
    if !output_dir.exists() {
        std::fs::create_dir_all(&output_dir).unwrap();
    }

    let progress_stype = ProgressStyle::with_template("{prefix:.bold.dim} {spinner} {wide_msg}")
        .unwrap()
        .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ ");
    let pb = ProgressBar::new(dbfiles.len() as _);
    pb.set_style(progress_stype);

    dbfiles.par_iter().for_each(|dbfile| {
        pb.inc(1);
        pb.set_prefix(format!("[{}/?]", pb.position()));
        pb.set_message(format!("decrypting: {}", dbfile.display().to_string()));
        let mut db_file_dir = PathBuf::new();
        let mut dest = PathBuf::new();
        db_file_dir.push(&output_dir);
        db_file_dir.push(
            dbfile
                .parent()
                .unwrap()
                .strip_prefix(PathBuf::from(msg_dir.clone()))
                .unwrap(),
        );
        dest.push(db_file_dir.clone());
        dest.push(dbfile.file_name().unwrap());

        if !db_file_dir.exists() {
            std::fs::create_dir_all(db_file_dir).unwrap();
        }

        if wechat_info.version.starts_with("4.0") {
            std::fs::write(dest, decrypt_db_file_v4(&dbfile, &key).unwrap()).unwrap();
        } else {
            std::fs::write(dest, decrypt_db_file_v3(&dbfile, &key).unwrap()).unwrap();
        }
    });
    pb.finish_with_message("decryption complete!!");
    println!("[+] output to {}", output_dir.to_str().unwrap());
    println!();
}

fn cli() -> clap::Command {
    use clap::{arg, value_parser, Command};

    Command::new("wechat-dump-rs")
        .version("1.0.27")
        .about("A wechat db dump tool")
        .author("REinject")
        .help_template("{name} ({version}) - {author}\n{about}\n{all-args}")
        .disable_version_flag(true)
        .arg(arg!(-p --pid <PID> "pid of wechat").value_parser(value_parser!(u32)))
        .arg(
            arg!(-k --key <KEY> "key for offline decryption of db file")
                .value_parser(value_parser!(String)),
        )
        .arg(arg!(-f --file <PATH> "special a db file path").value_parser(value_parser!(PathBuf)))
        .arg(
            arg!(-d --"data-dir" <PATH> "special wechat data dir path (pid is required)")
                .value_parser(value_parser!(PathBuf)),
        )
        .arg(
            arg!(-o --output <PATH> "decrypted database output path")
                .value_parser(value_parser!(PathBuf)),
        )
        .arg(arg!(-a --all "dump key and decrypt db files"))
        .arg(
            arg!(--vv <VERSION> "wechat db file version")
                .value_parser(["3", "4"])
                .default_value("4"),
        )
        .arg(arg!(-r --rawkey "convert db key to sqlcipher raw key (file is required)"))
}

fn main() {
    // 解析参数
    let matches = cli().get_matches();

    let all = matches.get_flag("all");
    let output = match matches.get_one::<PathBuf>("output") {
        Some(o) => PathBuf::from(o),
        None => PathBuf::from(format!(
            "{}{}",
            std::env::temp_dir().to_str().unwrap(),
            "wechat_dump"
        )),
    };

    let key_option = matches.get_one::<String>("key");
    let file_option = matches.get_one::<PathBuf>("file");
    let data_dir_option = matches.get_one::<PathBuf>("data-dir");
    let pid_option = matches.get_one::<u32>("pid");

    match (pid_option, key_option, file_option) {
        (None, None, None) => {
            let pids = [
                get_pid_by_name("WeChat.exe"),
                get_pid_by_name_and_cmd_pattern("Weixin.exe", r#"Weixin\.exe"?\s*$"#),
            ]
            .concat();
            if pids.is_empty() {
                panic!("WeChat is not running!!")
            }
            for pid in pids {
                let wechat_info = dump_wechat_info(pid, None);

                // 需要对所有db文件进行解密
                if all {
                    dump_all_by_pid(&wechat_info, &output);
                } else {
                    println!("{}", wechat_info);
                    println!();
                }
            }
        }
        (Some(&pid), None, None) => {
            let wechat_info = dump_wechat_info(pid, data_dir_option);

            // 需要对所有db文件进行解密
            if all {
                dump_all_by_pid(&wechat_info, &output);
            } else {
                println!("{}", wechat_info);
                println!();
            }
        }
        (None, Some(key), Some(file)) => {
            if !file.exists() {
                panic!("the target file does not exist");
            }

            let is_v4 = if matches.get_one::<String>("vv").unwrap() == "4" {
                true
            } else {
                false
            };

            // convert db key to sqlcipher rawkey
            let b_rawkey = matches.get_flag("rawkey");
            if b_rawkey {
                if file.is_dir() {
                    panic!("the target file is a directory.");
                }

                let rawkey = convert_to_sqlcipher_rawkey(&key, &file, is_v4).unwrap();
                println!("{}", rawkey);

                return;
            }
            // convert end

            match file.is_dir() {
                true => {
                    let dbfiles = scan_db_files(file.to_str().unwrap().to_string()).unwrap();
                    println!(
                        "scanned {} files in {}",
                        dbfiles.len(),
                        &file.to_str().unwrap()
                    );
                    println!("decryption in progress, please wait...");

                    // 创建输出目录
                    if output.is_file() {
                        panic!("the output path must be a directory");
                    }
                    if !output.exists() {
                        std::fs::create_dir_all(&output).unwrap();
                    }

                    for dbfile in dbfiles {
                        let mut db_file_dir = PathBuf::new();
                        let mut dest = PathBuf::new();
                        db_file_dir.push(&output);
                        db_file_dir.push(
                            dbfile
                                .parent()
                                .unwrap()
                                .strip_prefix(PathBuf::from(&file))
                                .unwrap(),
                        );
                        dest.push(db_file_dir.clone());
                        dest.push(dbfile.file_name().unwrap());

                        if !db_file_dir.exists() {
                            std::fs::create_dir_all(db_file_dir).unwrap();
                        }

                        if is_v4 {
                            std::fs::write(dest, decrypt_db_file_v4(&dbfile, &key).unwrap())
                                .unwrap();
                        } else {
                            std::fs::write(dest, decrypt_db_file_v3(&dbfile, &key).unwrap())
                                .unwrap();
                        }
                    }
                    println!("decryption complete!!");
                    println!("output to {}", output.to_str().unwrap());
                    println!();
                }
                false => {
                    if is_v4 {
                        std::fs::write(&output, decrypt_db_file_v4(&file, &key).unwrap()).unwrap();
                    } else {
                        std::fs::write(&output, decrypt_db_file_v3(&file, &key).unwrap()).unwrap();
                    }
                    println!("output to {}", output.to_str().unwrap());
                }
            }
        }
        _ => panic!("param error"),
    }
}
