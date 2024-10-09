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
use walkdir::{DirEntry, WalkDir};
use zip::result::ZipError;
use zip::write::SimpleFileOptions;

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

fn extract_dep_list(node: &mut JsonValue, files: &mut Vec<String>) {
    if node.is_object() {
        for (_, value) in node.entries_mut() {
            extract_dep_list(value, files);
        }
    } else if node.is_array() {
        for value in node.members_mut() {
            extract_dep_list(value, files);
        }
    } else if node.is_string() {
        let node_str = node.as_str().unwrap();
        if node_str.contains(":/") {
            files.push(node_str.to_string());
            *node = JsonValue::from(
                node_str.replace(&node_str[0..node_str.find(":/").unwrap()], "SELF"),
            );
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

fn copy_dep_from_var(
    var_name: &str,
    target_folder: &Path,
    file_lists: &Vec<String>,
    var_files: &HashMap<String, LinkedList<PathBuf>>,
) {
    let mut is_plugin = false;
    for file in file_lists.iter() {
        if file.ends_with("cslist") {
            is_plugin = true;
            break;
        }
    }
    let f_var_name = find_latest_varname(var_name, var_files);
    let var_path = match var_files.get(&f_var_name) {
        Some(p) => p.front().unwrap(),
        None => return,
    };
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
    let mut extra_file_lists = Vec::<String>::new();
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
        if outpath.extension().is_some_and(|x| x == "vaj") {
            let mut vaj_json_str = String::new();
            file.read_to_string(&mut vaj_json_str).unwrap();
            let mut vaj_json = json::parse(&vaj_json_str).unwrap();
            let mut files = Vec::new();
            extract_dep_list(&mut vaj_json, &mut files);
            for file in files {
                let parts = file.split(":/").collect::<Vec<&str>>();
                println!("in vaj file: {}", parts[1]);
                extra_file_lists.push(parts[1].to_string());
            }
        }
    }

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
            if outpath.to_string_lossy() == "meta.json" {
                continue;
            }

            if is_plugin
                || file_lists
                    .iter()
                    .any(|x| outpath.to_string_lossy().starts_with(x))
                || extra_file_lists.contains(&outpath.to_string_lossy().to_string())
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
}

fn generate_meta_json(var_unpack_path: &Path) {
    let meta_json_path = var_unpack_path.join("meta.json");
    let meta_json_str =
        fs::read_to_string(&meta_json_path).expect("Should have been able to read the file");
    let mut meta_json = json::parse(&meta_json_str).unwrap();
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
    let mut zip = zip::ZipWriter::new(writer);
    let options = SimpleFileOptions::default()
        .compression_method(method)
        .unix_permissions(0o755)
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

fn get_norm_filename(filename: &str) -> String {
    if filename.ends_with(".vmi") {
        return String::from(&filename[0..filename.len() - 4]);
    }
    if filename.ends_with(".vam") {
        return Path::new(filename)
            .parent()
            .unwrap()
            .to_string_lossy()
            .to_string();
    }
    return String::from(filename);
}

fn repack_bundled_var(
    var_path: &str,
    tmp_folder: &str,
    var_files: &HashMap<String, LinkedList<PathBuf>>,
) -> PathBuf {
    let mut archive = match zip::ZipArchive::new(
        fs::File::open(var_path).expect(format!("Could not open file {}", var_path).as_str()),
    ) {
        Ok(ret) => ret,
        Err(_) => {
            println!("zipfile {} is invaild", var_path);
            panic!()
        }
    };

    let var_unpack_path = Path::new(tmp_folder).join(Path::new(var_path).file_name().unwrap());
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

        let realoutpath = var_unpack_path.join(outpath);

        if file.is_dir() {
            fs::create_dir_all(&realoutpath).unwrap();
        } else {
            if let Some(p) = realoutpath.parent() {
                if !p.exists() {
                    fs::create_dir_all(p).unwrap();
                }
            }
            let mut outfile = fs::File::create(&realoutpath).unwrap();
            io::copy(&mut file, &mut outfile).unwrap();
        }
    }

    let pattern = format!(
        "{}/**/*.json",
        Pattern::escape(var_unpack_path.as_os_str().to_str().unwrap())
    );

    for entry in glob(&pattern).expect("Failed to read glob pattern") {
        let scene_json_path = entry.unwrap();
        let scene_json_str =
            fs::read_to_string(&scene_json_path).expect("Should have been able to read the file");
        let mut scene_json = json::parse(&scene_json_str).unwrap();
        let mut files = Vec::new();
        extract_dep_list(&mut scene_json, &mut files);
        let modified_scene_json = json::stringify_pretty(scene_json, 4);
        fs::write(&scene_json_path, modified_scene_json).expect("Unable to write file");

        let mut var_file_lists: HashMap<String, Vec<String>> = HashMap::new();
        for file in files.iter() {
            let parts = file.split(":/").collect::<Vec<&str>>();
            if !var_file_lists.contains_key(parts[0]) {
                var_file_lists.insert(parts[0].to_string(), Vec::new());
            }
            var_file_lists
                .get_mut(parts[0])
                .unwrap()
                .push(get_norm_filename(parts[1]));
        }
        for (k, v) in var_file_lists.iter() {
            copy_dep_from_var(k, &var_unpack_path, v, var_files);
        }
    }
    generate_meta_json(&var_unpack_path);
    let dst_file = Path::new(tmp_folder).join(
        String::from("[Bundled]")
            + Path::new(var_path)
                .file_name()
                .unwrap()
                .to_string_lossy()
                .to_string()
                .as_str(),
    );
    zip_one_file(&var_unpack_path, &dst_file, zip::CompressionMethod::Stored).unwrap();
    if fs::exists(&var_unpack_path).unwrap() {
        fs::remove_dir_all(&var_unpack_path).unwrap();
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

fn main() {
    let args: Vec<_> = env::args().collect();
    //std::env::set_current_dir(Path::new(args.get(0).unwrap()).parent().unwrap()).unwrap();
    if !fs::exists("VaM.exe").unwrap() {
        println!("Please put VarBundler.exe under VaM folder which includes VaM.exe \n请将VarBundler.exe放在VaM.exe同级目录下");
        show_message_box("Error/错误", "Please put VarBundler.exe under VaM folder which includes VaM.exe \n请将VarBundler.exe放在VaM.exe同级目录下");
        return;
    }
    //let target = args.get(1).unwrap();
    let target = r"C:\Games\VAM\VAM-VAM\AddonPackages_xxx\02月第一周场景周更新内容\andywongusa全场景\地铁痴娘最终版\Subway Game Final\andywongusa.SubwayFinal.1.var";
    println!(
        "repacking {name} to bundled var\n正在将{name}重打包为bundled var",
        name = target
    );

    let vam_folder = env::current_dir().unwrap();
    // let var_folder = &vam_folder.join("AddonPackages");
    // let dst_tmp_folder = &PathBuf::from(&vam_folder).join("VarBundler");
    let var_folder = &vam_folder.join("AddonPackages_xxx");
    let dst_tmp_folder = &PathBuf::from(&vam_folder).join("AddonPackages");
    let var_list = generate_var_list(&var_folder.to_string_lossy());
    let filename = repack_bundled_var(target, &dst_tmp_folder.to_string_lossy(), &var_list);

    show_message_box(
        "Success/成功",
        format!(
            "Done, please get bundled file at {name}\n已打包完成,文件位于{name}",
            name = filename.to_string_lossy()
        )
        .as_str(),
    );
}
