use glob::glob;
use glob::Pattern;
use json::JsonValue;
use path_slash::PathExt;
use std::collections::HashMap;
use std::collections::LinkedList;
use std::env;
use std::fs;
use std::fs::File;
use std::io;
use std::io::Read;
use std::io::Seek;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use threadpool::ThreadPool;
use threadpool_scope::scope_with;
use walkdir::{DirEntry, WalkDir};
use winreg::RegKey;
use zip::result::ZipError;
use zip::write::SimpleFileOptions;

use normalize_path::NormalizePath;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr::null_mut;
use winapi::um::winuser::{MessageBoxW, MB_OK, MB_SYSTEMMODAL};

fn to_wide_string(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn show_message_box(title: &str, message: &str) {
    let title_wide = to_wide_string(title);
    let message_wide = to_wide_string(message);

    unsafe {
        MessageBoxW(
            null_mut(),
            message_wide.as_ptr(),
            title_wide.as_ptr(),
            MB_OK | MB_SYSTEMMODAL,
        );
    }
}

fn extract_dep_files_from_json(filename: &Path, node: &mut JsonValue, files: &mut Vec<String>) {
    if node.is_object() {
        for (_, value) in node.entries_mut() {
            extract_dep_files_from_json(filename, value, files);
        }
    } else if node.is_array() {
        for value in node.members_mut() {
            extract_dep_files_from_json(filename, value, files);
        }
    } else if node.is_string() {
        let node_str = node.as_str().unwrap();
        if node_str.contains(":/") {
            if node_str.starts_with("SELF") {
                files.push(node_str.split(":").collect::<Vec<&str>>()[1][1..].to_string());
            } else {
                files.push(node_str.to_string());
            }
        } else if node_str.ends_with(".jpg")
            || node_str.ends_with(".png")
            || node_str.ends_with(".tif")
        {
            let abs_path = filename.parent().unwrap().join(node_str).normalize();
            files.push(
                abs_path
                    .to_slash_lossy()
                    .to_string()
                    .to_string()
                    .replace(r"\", "/"),
            );
        } else if node_str.starts_with("/") {
            files.push(node_str.to_string()[1..].to_string());
        }
    }
}

fn find_latest_varname(var_name: &str, var_files: &HashMap<String, LinkedList<PathBuf>>) -> String {
    if !var_name.ends_with(".latest") {
        return var_name.to_string() + ".var";
    }
    let mut f_varname = var_name;
    let mut f_var_max_version = 0u32;
    for key in var_files.keys().into_iter() {
        let parts = key.split(".").collect::<Vec<&str>>();
        if parts.len() < 4 {
            continue;
        }
        let of_parts = var_name.split(".").collect::<Vec<&str>>();
        if !(parts[0] == of_parts[0] && parts[1] == of_parts[1]) {
            continue;
        }
        let version: u32 = match parts[2].parse::<u32>() {
            Ok(v) => v,
            Err(_) => continue,
        };
        if version > f_var_max_version {
            f_var_max_version = version;
            f_varname = key;
        }
    }
    return f_varname.to_string();
}

fn extract_filelist_from_var(var_path: &Path) -> Vec<String> {
    let archive = match zip::ZipArchive::new(
        fs::File::open(var_path)
            .expect(format!("Could not open file {}", var_path.to_string_lossy()).as_str()),
    ) {
        Ok(ret) => ret,
        Err(_) => {
            println!("zipfile {} is invaild", var_path.to_string_lossy());
            show_message_box(
                "Error/错误",
                format!("zipfile {} is invaild", var_path.to_string_lossy()).as_str(),
            );
            panic!()
        }
    };
    archive
        .file_names()
        .map(|x| x.to_string())
        .collect::<Vec<String>>()
}

fn extract_file_from_var(filename: &str, var_path: &PathBuf) -> String {
    let mut archive = match zip::ZipArchive::new(
        fs::File::open(var_path)
            .expect(format!("Could not open file {}", var_path.to_string_lossy()).as_str()),
    ) {
        Ok(ret) => ret,
        Err(_) => {
            println!("zipfile {} is invaild", var_path.to_string_lossy());
            show_message_box(
                "Error/错误",
                format!("zipfile {} is invaild", var_path.to_string_lossy()).as_str(),
            );
            panic!()
        }
    };
    let mut file = match archive.by_name(filename) {
        Ok(tfile) => tfile,
        Err(_) => {
            println!("file error, ignore");
            return json::object! {}.to_string();
        }
    };
    let mut text = String::new();
    file.read_to_string(&mut text).unwrap();
    text
}

fn handle_nested_dep_files(filename: &str, var_path: &PathBuf) -> Vec<String> {
    let mut files = Vec::<String>::new();
    if filename.ends_with(".vmi") {
        files.push(filename[0..filename.len() - 3].to_string() + "vmb");
    } else if filename.ends_with(".vam") {
        let basename = filename[0..filename.len() - 3].to_string();
        files.push(basename.clone() + "vaj");
        files.push(basename.clone() + "vab");
        files.push(basename.clone() + "jpg");
        files.push(basename.clone() + "png");
        files.push(basename.clone() + "tif");
        let json_str = extract_file_from_var(&(basename + "vaj"), var_path);
        let mut json_obj = json::parse(&json_str).unwrap_or(json::object! {});
        let mut dep_files = Vec::new();
        extract_dep_files_from_json(Path::new(filename), &mut json_obj, &mut dep_files);
        files.extend(dep_files);
    } else if filename.ends_with(".cslist") {
        for line in extract_file_from_var(filename, var_path).lines() {
            if line.starts_with("/") {
                files.push(line[1..].to_string());
            } else {
                let abs_path = Path::new(filename)
                    .parent()
                    .unwrap()
                    .join(line.trim())
                    .normalize();
                files.push(
                    abs_path
                        .to_slash_lossy()
                        .to_string()
                        .to_string()
                        .replace(r"\", "/"),
                );
            }
        }
    } else if filename.ends_with(".json") {
        let basename = filename[0..filename.len() - 4].to_string();
        files.push(basename.clone() + "jpg");
        files.push(basename.clone() + "png");
        files.push(basename.clone() + "tif");
        let json_str = extract_file_from_var(filename, var_path);
        let mut json_obj = json::parse(&json_str).unwrap();
        let mut dep_files = Vec::new();
        extract_dep_files_from_json(Path::new(filename), &mut json_obj, &mut dep_files);
        files.extend(dep_files);
    }
    files = files.into_iter().map(|x| x).collect::<Vec<String>>();
    files
}

fn extract_dep_from_var(
    var_name: &str,
    target_folder: &Path,
    file_lists: &Vec<String>,
    var_files: &HashMap<String, LinkedList<PathBuf>>,
) {
    let var_path;
    if var_name.ends_with(".var") {
        var_path = Path::new(var_name);
    } else {
        let f_var_name = find_latest_varname(var_name, var_files);
        var_path = match var_files.get(&f_var_name) {
            Some(p) => p.front().unwrap(),
            None => return,
        };
    }

    let mut extend_file_lists = file_lists
        .iter()
        .map(|x| x.clone())
        .collect::<Vec<String>>()
        .into_iter()
        .filter(|x| !fs::exists(target_folder.join(&x)).unwrap())
        .collect::<Vec<String>>();
    for file in file_lists {
        extend_file_lists.extend(handle_nested_dep_files(
            file,
            &PathBuf::new().join(var_path),
        ));
    }
    let mut archive = match zip::ZipArchive::new(
        fs::File::open(var_path)
            .expect(format!("Could not open file {}", var_path.to_string_lossy()).as_str()),
    ) {
        Ok(ret) => ret,
        Err(_) => {
            println!("zipfile {} is invaild", var_path.to_string_lossy());
            panic!()
        }
    };
    let var_unpack_path = Path::new(target_folder);
    for i in 0..archive.len() {
        let mut file = match archive.by_index(i) {
            Ok(tfile) => tfile,
            Err(_) => {
                println!("file error, ignore");
                continue;
            }
        };
        let outpath = match file.enclosed_name() {
            Some(path) => path,
            None => continue,
        };

        let realoutpath = var_unpack_path.join(&outpath);

        if !file.is_dir() {
            if extend_file_lists
                .iter()
                .find(|x| x.to_lowercase() == outpath.to_string_lossy().to_string().to_lowercase())
                .is_some()
            {
                if let Some(p) = realoutpath.parent() {
                    if !p.exists() {
                        fs::create_dir_all(p).unwrap();
                    }
                }
                let mut outfile = fs::File::create(&realoutpath).unwrap();
                io::copy(&mut file, &mut outfile).unwrap();
            }
        }
    }
    let mut extra_var_file_lists: HashMap<String, Vec<String>> = HashMap::new();
    for file in extend_file_lists.iter() {
        if !file.contains(":") {
            continue;
        }
        let parts = file.split(":").collect::<Vec<&str>>();
        if !extra_var_file_lists.contains_key(parts[0]) {
            extra_var_file_lists.insert(parts[0].to_string(), Vec::new());
        }
        extra_var_file_lists
            .get_mut(parts[0])
            .unwrap()
            .push(parts[1][1..].to_string());
    }
    let pool = ThreadPool::new(12);
    scope_with(&pool, |scope| {
        for (k, v) in extra_var_file_lists.iter() {
            scope.execute(move || {
                extract_dep_from_var(k, var_unpack_path, v, var_files);
            });
        }
    });
}

fn generate_meta_json(var_unpack_path: &Path) {
    let meta_json_path = var_unpack_path.join("meta.json");
    let meta_json_str =
        fs::read_to_string(&meta_json_path).expect("Should have been able to read the file");
    let mut meta_json = match json::parse(&meta_json_str) {
        Ok(json_obj) => json_obj,
        Err(_) => {
            show_message_box(
                "Error/错误",
                "Package meta data is incorrect\n此数据包元数据错误",
            );
            panic!();
        }
    };
    let mut file_lists = Vec::<String>::new();
    let pattern = format!(
        "{}/**/*",
        Pattern::escape(var_unpack_path.as_os_str().to_str().unwrap())
    );
    for entry in glob(&pattern).expect("Failed to read glob pattern") {
        let en = entry.unwrap();
        if !en.is_file() || en.file_name().unwrap() == "meta.json" {
            continue;
        }
        let path = en
            .strip_prefix(var_unpack_path)
            .unwrap()
            .to_slash()
            .unwrap()
            .to_string();
        file_lists.push(path);
    }
    meta_json["contentList"] = json::from(file_lists);
    meta_json["dependencies"] = json::object! {};
    meta_json["hadReferenceIssues"] = json::from("false");
    meta_json["referenceIssues"] = json::array![];
    fs::write(&meta_json_path, json::stringify_pretty(meta_json, 4)).expect("Unable to write file");
}

fn zip_dir<T>(
    it: &mut dyn Iterator<Item = DirEntry>,
    prefix: &Path,
    writer: T,
    method: zip::CompressionMethod,
) -> anyhow::Result<()>
where
    T: Write + Seek,
{
    let mut zip: zip::ZipWriter<T> = zip::ZipWriter::new(writer);
    let options = SimpleFileOptions::default()
        .compression_method(method)
        .large_file(true)
        .with_alignment(4096);

    let prefix = Path::new(prefix);
    let mut buffer = Vec::new();
    for entry in it {
        let path = entry.path();
        let name = path.strip_prefix(prefix).unwrap();
        let path_as_string = name.to_slash().unwrap();

        // Write file or directory explicitly
        // Some unzip tools unzip files with directory paths correctly, some do not!
        if path.is_file() {
            zip.start_file(path_as_string, options)?;
            let mut f = File::open(path)?;

            f.read_to_end(&mut buffer)?;
            zip.write_all(&buffer)?;
            buffer.clear();
        } else if !name.as_os_str().is_empty() {
            // Only if not root! Avoids path spec / warning
            // and mapname conversion failed error on unzip
            zip.add_directory(path_as_string, options)?;
        }
    }
    zip.finish()?;
    Ok(())
}

fn zip_one_file(
    src_dir: &Path,
    dst_file: &Path,
    method: zip::CompressionMethod,
) -> anyhow::Result<()> {
    if !Path::new(src_dir).is_dir() {
        println!(
            "Path {} is not directory, error.",
            src_dir.as_os_str().to_str().unwrap()
        );
        return Err(ZipError::FileNotFound.into());
    }
    fs::create_dir_all(dst_file.parent().unwrap()).unwrap();

    let path = Path::new(dst_file);
    let file = File::create(path).unwrap();

    let walkdir = WalkDir::new(src_dir);
    let it = walkdir.into_iter();

    zip_dir(&mut it.filter_map(|e| e.ok()), src_dir, file, method)?;
    Ok(())
}

fn rewrite_dep_files_from_json(node: &mut JsonValue, record: &mut Vec<String>) {
    if node.is_object() {
        for (_, value) in node.entries_mut() {
            rewrite_dep_files_from_json(value, record);
        }
    } else if node.is_array() {
        for value in node.members_mut() {
            rewrite_dep_files_from_json(value, record);
        }
    } else if node.is_string() {
        let node_str = node.as_str().unwrap();
        if node_str.contains(":/") {
            if !node_str.starts_with("SELF") {
                record.push(node_str.to_string());
                let parts = node_str.split(":").collect::<Vec<&str>>();
                *node = JsonValue::from(String::from("SELF:") + parts[1]);
            }
        }
    }
}

fn rewrite_all_json_file(var_unpack_path: &Path) {
    let mut paths = glob(
        format!(
            "{}/**/*.json",
            Pattern::escape(var_unpack_path.as_os_str().to_str().unwrap())
        )
        .as_str(),
    )
    .unwrap()
    .map(|x| x.unwrap())
    .collect::<Vec<PathBuf>>();
    paths.extend(
        glob(
            format!(
                "{}/**/*.vaj",
                Pattern::escape(var_unpack_path.as_os_str().to_str().unwrap())
            )
            .as_str(),
        )
        .unwrap()
        .map(|x| x.unwrap())
        .collect::<Vec<PathBuf>>(),
    );
    let mut record = Vec::<String>::new();
    for entry in paths {
        let json_str = fs::read_to_string(&entry).unwrap();
        let mut json_obj = json::parse(&json_str).unwrap_or(json::object! {});
        rewrite_dep_files_from_json(&mut json_obj, &mut record);
        fs::write(&entry, json::stringify_pretty(json_obj, 4)).unwrap();
    }
    fs::write(var_unpack_path.join("record.list"), record.join("\n")).unwrap();
}

fn repack_bundled_var(
    var_path: &str,
    tmp_folder: &str,
    var_files: &HashMap<String, LinkedList<PathBuf>>,
) -> PathBuf {
    let var_unpack_path = Path::new(tmp_folder).join(Path::new(var_path).file_name().unwrap());

    let mut filelist = extract_filelist_from_var(Path::new(var_path));
    filelist = filelist
        .into_iter()
        .filter(|x| x.ends_with(".json"))
        .collect::<Vec<String>>();
    extract_dep_from_var(var_path, &var_unpack_path, &filelist, var_files);
    generate_meta_json(&var_unpack_path);
    rewrite_all_json_file(&var_unpack_path);
    let dst_file = Path::new(var_path).parent().unwrap().join(
        String::from("[Bundled]") + Path::new(var_path).file_name().unwrap().to_str().unwrap(),
    );
    zip_one_file(&var_unpack_path, &dst_file, zip::CompressionMethod::Stored).unwrap();
    if fs::exists(&tmp_folder).unwrap() {
        fs::remove_dir_all(&tmp_folder).unwrap();
    }
    dst_file
}

fn generate_var_list(var_folder: &str) -> HashMap<String, LinkedList<PathBuf>> {
    let mut var_files: HashMap<String, LinkedList<PathBuf>> = HashMap::new();
    for entry in glob(format!("{}/**/*.var", Pattern::escape(var_folder)).as_str())
        .expect("Failed to read glob pattern")
    {
        match entry {
            Ok(path) => {
                if !path.is_file() {
                    continue;
                }
                let filename = String::from(path.file_name().unwrap().to_str().unwrap());
                if !var_files.contains_key(&filename) {
                    var_files.insert(filename.clone(), LinkedList::new());
                }
                var_files.get_mut(&filename).unwrap().push_back(path);
            }
            Err(_) => panic!(),
        }
    }
    var_files
}

fn find_game_folder(var_path: &Path) -> Option<(PathBuf, PathBuf)> {
    let mut current_dir = var_path.parent();
    let mut child_dir = PathBuf::new();

    while let Some(dir) = current_dir {
        let vam_exe_path = dir.join("VaM.exe");
        if vam_exe_path.exists() {
            return Some((dir.to_path_buf(), child_dir));
        }
        current_dir = dir.parent();
        child_dir = dir.to_path_buf();
    }
    None
}

fn main() {
    let args: Vec<_> = env::args().collect();
    let vam_exe_path = Path::new(args.get(0).unwrap())
        .parent()
        .unwrap()
        .join("VaM.exe");
    if !vam_exe_path.exists() {
        show_message_box(
            "Error/错误",
            "Please path progame as same folder as VaM.exe\n请将程序文件放在VaM.exe所在目录",
        );
        return;
    }
    if args.len() == 1 {
        let hkcr = RegKey::predef(winreg::enums::HKEY_CLASSES_ROOT);
        let (var_key, _) = match hkcr.create_subkey(".var") {
            Ok((key, dis)) => (key, dis),
            Err(_) => {
                show_message_box(
                    "Error/错误",
                    "Please try again with 'runas administrator'\n请使用右键菜单'以管理员身份运行'",
                );
                return;
            }
        };
        var_key.set_value("", &"VamDataFile").unwrap();

        if hkcr.open_subkey("VamDataFile").is_ok() {
            hkcr.delete_subkey_all("VamDataFile").unwrap();
            show_message_box(
                "Remove Bundled Var Context Menu/移除BundledVar上下文菜单",
                "Done, Generate Bundled Var Context Menu removed\nGenerate Bundled Var上下文菜单已移除",
            );
            return;
        }
        let (var_file_key, _) = hkcr.create_subkey("VamDataFile").unwrap();
        let shell_path = "shell\\GenerateBundledVar";
        let (icon_key, _) = var_file_key.create_subkey("DefaultIcon").unwrap();
        icon_key
            .set_value("", &format!("\"{}\",0", vam_exe_path.to_slash_lossy()))
            .unwrap();
        let (shell_key, _) = var_file_key.create_subkey(shell_path).unwrap();
        shell_key.set_value("", &"Generate Bundled Var").unwrap();
        let (command_key, _) = shell_key.create_subkey("command").unwrap();
        command_key
            .set_value("", &format!("\"{}\" \"%1\"", args.get(0).unwrap()))
            .unwrap();
        show_message_box(
            "Add Var File Context Menu/添加Var类型文件上下文菜单",
            "Done, Generate Bundled Var Context Menu added\nNow you can right click .var file and choose 'Generate Bundled Var'\n\nGenerate Bundled Var上下文菜单已添加,请在.var文件右键菜单选择'Generate Bundled Var'",
        );
    }
    let var_path = Path::new(args.get(1).unwrap());
    let (vam_folder, var_folder) = match find_game_folder(var_path) {
        Some((game_folder, var_folder)) => (game_folder, var_folder),
        None => {
            println!("Please put VarBundler.exe under VaM folder which includes VaM.exe \n请将VarBundler.exe放在VaM.exe同级目录下");
            show_message_box("Error/错误", "Please put VarBundler.exe under VaM folder which includes VaM.exe \n请将VarBundler.exe放在VaM.exe同级目录下");
            return;
        }
    };
    println!(
        "repacking {name} to bundled var\n正在将{name}重打包为bundled var",
        name = var_path.to_string_lossy()
    );
    let dst_tmp_folder = &PathBuf::from(&vam_folder).join("VarBundler");
    let var_list = generate_var_list(&var_folder.to_string_lossy());
    let filename = repack_bundled_var(
        var_path.to_str().unwrap(),
        &dst_tmp_folder.to_string_lossy(),
        &var_list,
    );

    show_message_box(
        "Success/成功",
        format!(
            "Done, please get bundled file at {name}\n已打包完成,文件位于{name}",
            name = filename.to_string_lossy()
        )
        .as_str(),
    );
}
