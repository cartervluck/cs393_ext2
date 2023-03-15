#![feature(int_roundings)]

mod structs;
use crate::structs::{BlockGroupDescriptor, DirectoryEntry, Inode, Superblock};
use std::mem;
use null_terminated::NulStr;
use uuid::Uuid;
use zerocopy::ByteSlice;
use std::fmt;
use rustyline::{DefaultEditor, Result};

#[repr(C)]
#[derive(Debug)]
pub struct Ext2 {
    pub superblock: &'static Superblock,
    pub block_groups: &'static [BlockGroupDescriptor],
    pub blocks: Vec<&'static [u8]>,
    pub block_size: usize,
    pub uuid: Uuid,
    pub block_offset: usize, // <- our "device data" actually starts at this index'th block of the device
                             // so we have to subtract this number before indexing blocks[]
}

const EXT2_MAGIC: u16 = 0xef53;
const EXT2_START_OF_SUPERBLOCK: usize = 1024;
const EXT2_END_OF_SUPERBLOCK: usize = 2048;

impl Ext2 {
    pub fn new<B: ByteSlice + std::fmt::Debug>(device_bytes: B, start_addr: usize) -> Ext2 {
        // https://wiki.osdev.org/Ext2#Superblock
        // parse into Ext2 struct - without copying

        // the superblock goes from bytes 1024 -> 2047
        let header_body_bytes = device_bytes.split_at(EXT2_END_OF_SUPERBLOCK);

        let superblock = unsafe {
            &*(header_body_bytes
                .0
                .split_at(EXT2_START_OF_SUPERBLOCK)
                .1
                .as_ptr() as *const Superblock)
        };
        assert_eq!(superblock.magic, EXT2_MAGIC);
        // at this point, we strongly suspect these bytes are indeed an ext2 filesystem

        println!("superblock:\n{:?}", superblock);
        println!("size of Inode struct: {}", mem::size_of::<Inode>());

        let block_group_count = superblock
            .blocks_count
            .div_ceil(superblock.blocks_per_group) as usize;

        let block_size: usize = 1024 << superblock.log_block_size;
        println!(
            "there are {} block groups and block_size = {}",
            block_group_count, block_size
        );
        let block_groups_rest_bytes = header_body_bytes.1.split_at(block_size);

        let block_groups = unsafe {
            std::slice::from_raw_parts(
                block_groups_rest_bytes.0.as_ptr() as *const BlockGroupDescriptor,
                block_group_count,
            )
        };

        println!("block group 0: {:?}", block_groups[0]);

        let blocks = unsafe {
            std::slice::from_raw_parts(
                block_groups_rest_bytes.1.as_ptr() as *const u8,
                // would rather use: device_bytes.as_ptr(),
                superblock.blocks_count as usize * block_size,
            )
        }
        .chunks(block_size)
        .collect::<Vec<_>>();

        let offset_bytes = (blocks[0].as_ptr() as usize) - start_addr;
        let block_offset = offset_bytes / block_size;
        let uuid = Uuid::from_bytes(superblock.fs_id);
        Ext2 {
            superblock,
            block_groups,
            blocks,
            block_size,
            uuid,
            block_offset,
        }
    }

    // given a (1-indexed) inode number, return that #'s inode structure
    pub fn get_inode(&self, inode: usize) -> &Inode {
        let group: usize = (inode - 1) / self.superblock.inodes_per_group as usize;
        let index: usize = (inode - 1) % self.superblock.inodes_per_group as usize;

        // println!("in get_inode, inode num = {}, index = {}, group = {}", inode, index, group);
        let inode_table_block = (self.block_groups[group].inode_table_block) as usize - self.block_offset;
        // println!("in get_inode, block number of inode table {}", inode_table_block);
        let inode_table = unsafe {
            std::slice::from_raw_parts(
                self.blocks[inode_table_block].as_ptr()
                    as *const Inode,
                self.superblock.inodes_per_group as usize,
            )
        };
        // probably want a Vec of BlockGroups in our Ext structure so we don't have to slice each time,
        // but this works for now.
        // println!("{:?}", inode_table);
        &inode_table[index]
    }

    pub fn read_dir_inode(&self, inode: usize) -> std::io::Result<Vec<(usize, &NulStr)>> {
        let mut ret = Vec::new();
        let root = self.get_inode(inode);
        // println!("in read_dir_inode, #{} : {:?}", inode, root);
        // println!("following direct pointer to data block: {}", root.direct_pointer[0]);
        let entry_ptr = self.blocks[root.direct_pointer[0] as usize - self.block_offset].as_ptr();
        let mut byte_offset: isize = 0;
        while byte_offset < root.size_low as isize { // <- todo, support large directories
            let directory = unsafe { 
                &*(entry_ptr.offset(byte_offset) as *const DirectoryEntry) 
            };
            // println!("{:?}", directory);
            byte_offset += directory.entry_size as isize;
            ret.push((directory.inode as usize, &directory.name));
        } 
        Ok(ret)
    }

    pub fn read_dir_block(&self, block: usize) -> std::io::Result<Vec<&u8>> {
        let size: isize = 1 << (self.superblock.log_block_size + 10);
        let entry_ptr = self.blocks[block - self.block_offset].as_ptr();
        let mut byte_offset: isize = 0;
        let mut ret = Vec::new();
        while byte_offset < size {
          let dat = unsafe {
            &*(entry_ptr.offset(byte_offset) as *const u8)
          };
          byte_offset += 1;
          ret.push(dat);
        }
        Ok(ret)
    }
}

impl fmt::Debug for Inode<> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.size_low == 0 && self.size_high == 0 {
            f.debug_struct("").finish()
        } else {
            f.debug_struct("Inode")
            .field("type_perm", &self.type_perm)
            .field("size_low", &self.size_low)
            .field("direct_pointers", &self.direct_pointer)
            .field("indirect_pointer", &self.indirect_pointer)
            .finish()
        }
    }
}

fn parse_path(from: &str) -> Vec<&str> {
    from.split('/')
        .collect()
}

fn relative_path<'a>(path: &'a str, from: Vec<(usize, &'a NulStr)>, fs: &'a Ext2) -> std::result::Result<usize, &'a str> {
    let mut target: Vec<(usize, &NulStr)> = (from).to_vec();
    let mut target_inode: usize = 2;
    let mut temp: Vec<(usize, &NulStr)> = target.clone();
    for child in parse_path(path).iter() {
        let mut found = false;
        for (addr, name) in target.iter() {
            if name.to_string().eq(child) {
                temp = match fs.read_dir_inode(*addr) { // if we find a matching child, set target to that and iterate
                    Ok(dir_listing) => dir_listing,
                    Err(_) => { println!("unable to read cwd"); break; } // dir has child, but child cannot be read
                };
                target_inode = *addr;
                found = true;
                break;
            }
        }
        if !found {
            return Err("No file or directory found with that path.");
        } else {
            target = temp.clone();
        }
    }
    Ok(target_inode)
}

fn main() -> Result<()> {
    let disk = include_bytes!("../myfs.ext2");
    let start_addr: usize = disk.as_ptr() as usize;
    let ext2 = Ext2::new(&disk[..], start_addr);

    let mut current_working_inode:usize = 2;

    let mut rl = DefaultEditor::new()?;
    loop {
        // fetch the children of the current working directory
        let dirs = match ext2.read_dir_inode(current_working_inode) {
            Ok(dir_listing) => {
                dir_listing
            },
            Err(_) => {
                println!("unable to read cwd");
                break;
            }
        };

        let buffer = rl.readline(":> ");
        if let Ok(line) = buffer {
            if line.starts_with("ls") {
                // `ls` prints our cwd's children
                // TODO: support arguments to ls (print that directory's children instead)
                let mut target = dirs;
                let args = line.split(' ').collect::<Vec<&str>>();
                if args.len() > 1 {
                    target = match relative_path(args[1],target.clone(),&ext2) {
                        Ok(t) => match ext2.read_dir_inode(t) { Ok(d) => d, Err(_) => target },
                        Err(_) => target,
                    };
                }
                for dir in &target {
                    print!("{}\t", dir.1);
                }
                println!();    
            } else if line.starts_with("cd") {
                // `cd` with no arguments, cd goes back to root
                // `cd dir_name` moves cwd to that directory
                let elts: Vec<&str> = line.split(' ').collect();
                if elts.len() == 1 {
                    current_working_inode = 2;
                } else {
                    let mut found_self = false;
                    let target = match relative_path(elts[1],dirs.clone(),&ext2) {
                        Ok(t) => { found_self = true; t },
                        Err(_) => { println!("unable to locate {}, cwd unchanged", elts[1]); current_working_inode },
                    };
                    if found_self { 
                        let inode: &Inode = ext2.get_inode(target);
                        // check if directory flag is set (& DIRECTORY masks out other flags, == DIRECTORY compares flag)
                        if inode.type_perm & structs::TypePerm::DIRECTORY == structs::TypePerm::DIRECTORY{
                            current_working_inode = target;
                        } else {
                            println!("Destination is not a directory, cwd unchanged.");
                        }
                    }
                }
            } else if line.starts_with("mkdir") {
                // `mkdir childname`
                // create a directory with the given name, add a link to cwd
                // consider supporting `-p path/to_file` to create a path of directories
                println!("mkdir not yet implemented");
            } else if line.starts_with("cat") {
                // `cat filename`
                // print the contents of filename to stdout
                // if it's a directory, print a nice error
                let elts: Vec<&str> = line.split(' ').collect();
                if elts.len() == 1 {
                    println!("Command `cat` expected one argument, no arguments given.");
                } else {
                    let mut found_file = false;
                    let target = match relative_path(elts[1],dirs.clone(),&ext2) {
                        Ok(t) => { found_file = true; t },
                        Err(_) => { println!("unable to locate {}, cwd unchanged", elts[1]); current_working_inode },
                    };
                    if found_file { 
                        let inode: &Inode = ext2.get_inode(target);
                        // check if directory flag is set (& DIRECTORY masks out other flags, == DIRECTORY compares flag)
                        if inode.type_perm & structs::TypePerm::FILE == structs::TypePerm::FILE {
                            let mut current_size: usize = 0;
                            for direct in inode.direct_pointer {
                              let block = ext2.read_dir_block(direct as usize);
                              match block {
                                Ok(b) => {
                                  for c in b {
                                    print!("{}", *c as char);
                                  }
                                },
                                Err(e) => println!("{}",e),
                              }
                              current_size += 1 << (ext2.superblock.log_block_size + 10);
                              if current_size > inode.size_low.try_into().unwrap() {
                                break
                              }
                            }
                        } else {
                            println!("Destination is not a file.");
                        }
                    }
                }
            } else if line.starts_with("rm") {
                // `rm target`
                // unlink a file or empty directory
                println!("rm not yet implemented");
            } else if line.starts_with("mount") {
                // `mount host_filename mountpoint`
                // mount an ext2 filesystem over an existing empty directory
                println!("mount not yet implemented");
            } else if line.starts_with("link") {
                // `link arg_1 arg_2`
                // create a hard link from arg_1 to arg_2
                // consider what to do if arg2 does- or does-not end in "/"
                // and/or if arg2 is an existing directory name
                println!("link not yet implemented");
            } else if line.starts_with("quit") || line.starts_with("exit") {
                break;
            }
        } else {
            println!("bye!");
            break;
        }
    }
    Ok(())
}
